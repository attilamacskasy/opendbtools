Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-UserDatabases {
    param(
        [Parameter(Mandatory)] [string] $ServerInstance,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential,
        [switch] $IncludeSystem
    )
    $query = if ($IncludeSystem) {
        "SELECT name FROM sys.databases ORDER BY name ASC;"
    } else {
        "SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name ASC;"
    }
    $params = @{ ServerInstance = $ServerInstance; Query = $query }
    try {
        if ($UseSqlAuth) {
            $params.Username = $Credential.UserName
            $params.Password = $Credential.GetNetworkCredential().Password
        }
    $rows = Invoke-Sqlcmd @params -Database 'master' -TrustServerCertificate -Encrypt Optional
        return ($rows | ForEach-Object { $_.name })
    } catch {
        Write-Log -Message 'Failed to enumerate databases' -Level ERROR -Data @{ instance=$ServerInstance; error=$_.Exception.Message }
        throw
    }
}

function New-BackupFileName {
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string] $Instance,
        [Parameter(Mandatory)] [string] $Database
    )
    $ts = Get-Date -Format 'yyyyMMddTHHmmss'
    return ("{0}-{1}-{2}-{3}.bak" -f $Server, $Instance, $Database, $ts)
}

function Get-BackupCompressionCapability {
    param(
        [Parameter(Mandatory)] [string] $ServerInstance,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    try {
        $q = "SELECT CAST(SERVERPROPERTY('EngineEdition') AS int) AS EngineEdition, CAST(SERVERPROPERTY('Edition') AS nvarchar(256)) AS Edition;"
        $params = @{ ServerInstance=$ServerInstance; Query=$q; Database='master' }
        if ($UseSqlAuth) { $params.Username = $Credential.UserName; $params.Password = $Credential.GetNetworkCredential().Password }
        $row = Invoke-Sqlcmd @params -TrustServerCertificate -Encrypt Optional -ErrorAction Stop | Select-Object -First 1
        if ($row) {
            $engine = [int]$row.EngineEdition
            $edition = [string]$row.Edition
            $supported = ($engine -ne 4) # 4 = Express Edition (no compression)
            return [pscustomobject]@{ Supported=$supported; EngineEdition=$engine; Edition=$edition }
        }
    } catch {}
    return [pscustomobject]@{ Supported=$false; EngineEdition=$null; Edition=$null }
}

function Invoke-BackupDatabases {
    param(
        [Parameter(Mandatory)] [string] $ServerInstance,
        [Parameter(Mandatory)] [string[]] $DatabaseNames,
        [Parameter(Mandatory)] [string] $TargetFolder,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    if (-not (Test-Path -LiteralPath $TargetFolder)) {
        try { New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null } catch {}
    }
    $server = $env:COMPUTERNAME
    $hasSlash = ($ServerInstance -like '*\*')
    $instanceName = if ($hasSlash) { ($ServerInstance -split '\\')[-1] } else { 'MSSQLSERVER' }
    $results = @()
    $svcAccount = Get-SqlServiceAccount -ServerInstance $ServerInstance -UseSqlAuth:$UseSqlAuth -Credential $Credential
    $authMode = if ($UseSqlAuth) { 'Sql' } else { 'Windows' }
    $clientUser = if ($UseSqlAuth) { $Credential.UserName } else { ([Security.Principal.WindowsIdentity]::GetCurrent().Name) }
    $cap = Get-BackupCompressionCapability -ServerInstance $ServerInstance -UseSqlAuth:$UseSqlAuth -Credential $Credential
    Write-Log -Message 'Backup capability' -Level DEBUG -Data @{ edition=$cap.Edition; engineEdition=$cap.EngineEdition; compressionSupported=$cap.Supported }
    foreach ($db in $DatabaseNames) {
        $bak = Join-Path -Path $TargetFolder -ChildPath (New-BackupFileName -Server $server -Instance $instanceName -Database $db)
        $opts = @('INIT')
        if ($cap.Supported) { $opts += 'COMPRESSION' }
        $opts += 'STATS = 5'
        $optList = ($opts -join ', ')
        $tsql = @"
BACKUP DATABASE [$db]
TO DISK = N'$bak'
WITH $optList;
"@
        try {
            Write-Log -Message 'Backing up database' -Level ACTION -Data @{ db=$db; file=$bak; instance=$ServerInstance; auth=$authMode; runAs=$clientUser; sqlServiceAccount=$svcAccount; compressionUsed=$cap.Supported }
            Write-Log -Message 'Backup T-SQL' -Level DEBUG -Data @{ tsql=$tsql }
            if ($UseSqlAuth) {
                Invoke-Sqlcmd -ServerInstance $ServerInstance -Username $Credential.UserName -Password ($Credential.GetNetworkCredential().Password) -Query $tsql -QueryTimeout 0 -TrustServerCertificate -Encrypt Optional
            } else {
                Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $tsql -QueryTimeout 0 -TrustServerCertificate -Encrypt Optional
            }
            $results += [pscustomobject]@{ Database=$db; File=$bak; Success=$true; Error=$null }
        } catch {
            $errMsg = $_.Exception.Message
            $errType = $_.Exception.GetType().FullName
            $results += [pscustomobject]@{ Database=$db; File=$bak; Success=$false; Error=$errMsg }
            Write-Log -Message 'Backup failed' -Level ERROR -Data @{ db=$db; file=$bak; error=$errMsg; errorType=$errType; instance=$ServerInstance; auth=$authMode; runAs=$clientUser; sqlServiceAccount=$svcAccount }
        }
    }
    return $results
}

function Get-SqlServiceAccount {
    param(
        [Parameter(Mandatory)][string]$ServerInstance,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    # First, try querying SQL's own DMV for the service account
    try {
        $q = "SELECT TOP 1 service_account FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server (%' ORDER BY servicename;"
        $params = @{ ServerInstance=$ServerInstance; Query=$q; Database='master' }
        if ($UseSqlAuth) { $params.Username = $Credential.UserName; $params.Password = $Credential.GetNetworkCredential().Password }
        $row = Invoke-Sqlcmd @params -TrustServerCertificate -Encrypt Optional -ErrorAction Stop | Select-Object -First 1
        if ($row -and $row.service_account) { return [string]$row.service_account }
    } catch {}
    # Fallback to Windows service lookup
    try {
        $svcName = if ($ServerInstance -like '*\*') { 'MSSQL$' + (($ServerInstance -split '\\')[-1]) } else { 'MSSQLSERVER' }
        $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcName) -ErrorAction SilentlyContinue
        if ($svc) { return $svc.StartName }
    } catch {}
    try {
        $svcName = if ($ServerInstance -like '*\*') { 'MSSQL$' + (($ServerInstance -split '\\')[-1]) } else { 'MSSQLSERVER' }
        $wmi = Get-WmiObject -Class Win32_Service -Filter ("Name='{0}'" -f $svcName) -ErrorAction SilentlyContinue
        if ($wmi) { return $wmi.StartName }
    } catch {}
    return '(unknown)'
}

function Get-DefaultBackupDirectory {
    param(
        [Parameter(Mandatory)][string]$ServerInstance,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    try {
        $tsql = @"
DECLARE @dir NVARCHAR(4000);
EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'BackupDirectory', @dir OUTPUT;
SELECT @dir AS BackupDirectory;
"@
        $params = @{ ServerInstance=$ServerInstance; Query=$tsql; Database='master' }
        if ($UseSqlAuth) { $params.Username = $Credential.UserName; $params.Password = $Credential.GetNetworkCredential().Password }
        $row = Invoke-Sqlcmd @params -TrustServerCertificate -Encrypt Optional -ErrorAction Stop | Select-Object -First 1
        if ($row -and $row.BackupDirectory) { return [string]$row.BackupDirectory }
    } catch {}
    return $null
}

function Test-SqlEngineWriteAccess {
    param(
        [Parameter(Mandatory)][string]$ServerInstance,
        [Parameter(Mandatory)][string]$TargetFolder,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    # Generate a unique test file path
    $ticks = [DateTime]::UtcNow.Ticks
    $testFile = Join-Path -Path $TargetFolder -ChildPath ("__opendbtools_write_test_{0}.bak" -f $ticks)
    $svcAccount = Get-SqlServiceAccount -ServerInstance $ServerInstance -UseSqlAuth:$UseSqlAuth -Credential $Credential
    $tsql = @"
BEGIN TRY
    BACKUP DATABASE [master] TO DISK = N'$testFile' WITH INIT, COPY_ONLY, STATS = 1;
END TRY
BEGIN CATCH
    THROW;
END CATCH
"@
    try {
        if ($UseSqlAuth) {
            Invoke-Sqlcmd -ServerInstance $ServerInstance -Username $Credential.UserName -Password ($Credential.GetNetworkCredential().Password) -Query $tsql -QueryTimeout 0 -TrustServerCertificate -Encrypt Optional -ErrorAction Stop | Out-Null
        } else {
            Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $tsql -QueryTimeout 0 -TrustServerCertificate -Encrypt Optional -ErrorAction Stop | Out-Null
        }
        # Cleanup test file from host filesystem (if accessible)
        try { if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force } } catch {}
        return [pscustomobject]@{ Success=$true; ServiceAccount=$svcAccount; TestFile=$testFile; Error=$null }
    } catch {
        $msg = $_.Exception.Message
        return [pscustomobject]@{ Success=$false; ServiceAccount=$svcAccount; TestFile=$testFile; Error=$msg }
    }
}

function ConvertFrom-BackupFileName {
    param([Parameter(Mandatory)][string]$FileName)
    # Expect: server-instance-db-yyyymmddThhmmss.bak
    try {
        $n = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
        $parts = $n -split '-'
        if ($parts.Length -lt 4) { return $null }
        $server = $parts[0]
        $instance = $parts[1]
        $db = ($parts[2..($parts.Length-2)] -join '-')
        $ts = $parts[-1]
        $dt = [datetime]::ParseExact($ts, 'yyyyMMddTHHmmss', $null)
        return [pscustomobject]@{ Server=$server; Instance=$instance; Database=$db; Timestamp=$dt }
    } catch { return $null }
}

function Get-BackupFiles {
    param([Parameter(Mandatory)][string[]]$Paths)
    $items = @()
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            Get-ChildItem -LiteralPath $p -Recurse -Filter '*.bak' -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $meta = ConvertFrom-BackupFileName -FileName $_.Name
                    if ($meta) {
                        $items += [pscustomobject]@{ FullName=$_.FullName; Server=$meta.Server; Instance=$meta.Instance; Database=$meta.Database; Timestamp=$meta.Timestamp }
                    }
                }
        } catch {}
    }
    $items = $items | Sort-Object -Property Timestamp -Descending
    return ,$items
}

function Invoke-RestoreFromBackup {
    param(
        [Parameter(Mandatory)][string]$ServerInstance,
        [Parameter(Mandatory)][string]$BackupFile,
        [string]$TargetDbName,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    if (-not (Test-Path -LiteralPath $BackupFile)) {
        return [pscustomobject]@{ Success=$false; Error='Backup file not found' }
    }
    if (-not $TargetDbName) {
    $parsed = ConvertFrom-BackupFileName -FileName ([System.IO.Path]::GetFileName($BackupFile))
        $TargetDbName = if ($parsed) { $parsed.Database } else { $null }
    }
    if (-not $TargetDbName) { return [pscustomobject]@{ Success=$false; Error='Target database name missing' } }

    $tsql = @"
IF DB_ID(N'$TargetDbName') IS NOT NULL
BEGIN
    ALTER DATABASE [$TargetDbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
END
RESTORE DATABASE [$TargetDbName]
FROM DISK = N'$BackupFile'
WITH REPLACE, STATS = 5;
IF DB_ID(N'$TargetDbName') IS NOT NULL
BEGIN
    ALTER DATABASE [$TargetDbName] SET MULTI_USER;
END
"@
    try {
        if ($UseSqlAuth) {
            Invoke-Sqlcmd -ServerInstance $ServerInstance -Username $Credential.UserName -Password ($Credential.GetNetworkCredential().Password) -Query $tsql -QueryTimeout 0 -TrustServerCertificate -Encrypt Optional
        } else {
            Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $tsql -QueryTimeout 0 -TrustServerCertificate -Encrypt Optional
        }
        return [pscustomobject]@{ Success=$true; Error=$null }
    } catch {
        return [pscustomobject]@{ Success=$false; Error=$_.Exception.Message }
    }
}

function Get-ServerIdentityInfo {
    param(
        [Parameter(Mandatory)][string]$ServerInstance,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    $info = [ordered]@{ Login=$null; OriginalLogin=$null; SystemUser=$null; IsSysadmin=$null; Roles=@() }
    try {
        $q1 = @"
SELECT
  SUSER_SNAME()   AS Login,
  ORIGINAL_LOGIN() AS OriginalLogin,
  SYSTEM_USER     AS SystemUser,
  IS_SRVROLEMEMBER('sysadmin')    AS IsSysadmin
;"@
        $params = @{ ServerInstance=$ServerInstance; Query=$q1; Database='master' }
        if ($UseSqlAuth) { $params.Username = $Credential.UserName; $params.Password = $Credential.GetNetworkCredential().Password }
        $row = Invoke-Sqlcmd @params -TrustServerCertificate -Encrypt Optional -ErrorAction Stop | Select-Object -First 1
        if ($row) {
            $info.Login = [string]$row.Login
            $info.OriginalLogin = [string]$row.OriginalLogin
            $info.SystemUser = [string]$row.SystemUser
            $info.IsSysadmin = [int]$row.IsSysadmin
        }
    } catch {}
    try {
        # Get explicit server role memberships for the current login or its mapped SQL login name
        $q2 = @"
DECLARE @who sysname = SUSER_SNAME();
SELECT rp.name AS role_name
FROM sys.server_role_members srm
JOIN sys.server_principals rp ON rp.principal_id = srm.role_principal_id
JOIN sys.server_principals mp ON mp.principal_id = srm.member_principal_id
WHERE mp.name = @who
ORDER BY rp.name;
"@
        $params2 = @{ ServerInstance=$ServerInstance; Query=$q2; Database='master'; Variable=@{ who = $info.Login } }
        if ($UseSqlAuth) { $params2.Username = $Credential.UserName; $params2.Password = $Credential.GetNetworkCredential().Password }
        $rows = Invoke-Sqlcmd @params2 -TrustServerCertificate -Encrypt Optional -ErrorAction SilentlyContinue
        if ($rows) { $info.Roles = @($rows | ForEach-Object { [string]$_.role_name }) }
    } catch {}
    return [pscustomobject]$info
}


