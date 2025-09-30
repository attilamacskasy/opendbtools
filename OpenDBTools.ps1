#requires -Version 5.1
<#
 OpenDBTools.ps1
 Interactive backup/restore for Microsoft SQL Server (Express first).
 Kerberos/Windows auth first, fallback to SQL Auth. Cross-server restore.
 Uses JSON config cache and OpenIDSync logging module (unchanged).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AppName = 'OpenDBTools'
$script:ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'
$script:ModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'modules'

# Dot-source logging and helper modules
. (Join-Path $script:ModulesPath '50_OpenIDSync_Logging.ps1')
. (Join-Path $script:ModulesPath 'AuthModule.ps1')
. (Join-Path $script:ModulesPath 'SqlServerModule.ps1')

function New-DirectoryIfMissing($Path) {
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $dir = [System.IO.Path]::GetDirectoryName($Path)
        if ([string]::IsNullOrWhiteSpace($dir)) { return }
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
}

function Grant-FolderModifyToAccount {
    param(
        [Parameter(Mandatory)][string]$FolderPath,
        [Parameter(Mandatory)][string]$Account
    )
    # Explain why this is needed
    Write-Log -Message 'Granting NTFS permissions is required so the SQL Server service can write .bak files to the target folder.' -Level INFO -Data @{ folder=$FolderPath; account=$Account }
    $cmdText = ('icacls "{0}" /grant "{1}:(OI)(CI)M" /T' -f $FolderPath, $Account)
    Write-Log -Message 'About to run permission command' -Level PROMPT -Data @{ command=$cmdText }
    $proceed = Get-YesNo -Question ('Run this command now? {0}' -f $cmdText) -DefaultYes:$true
    if (-not $proceed) { return [pscustomobject]@{ Success=$false; ExitCode=$null; Output='User declined' } }
    try {
        # Execute icacls with properly quoted arguments
        $output = & icacls "$FolderPath" /grant ("{0}:(OI)(CI)M" -f $Account) /T 2>&1
        $code = $LASTEXITCODE
        Write-Log -Message 'icacls execution result' -Level DEBUG -Data @{ exitCode=$code; output=($output -join '\n') }
        if ($code -eq 0) {
            Write-Log -Message 'Permissions granted (Modify for service account)' -Level RESULT -Data @{ folder=$FolderPath; account=$Account }
            return [pscustomobject]@{ Success=$true; ExitCode=$code; Output=($output -join "`n") }
        } else {
            Write-Log -Message 'Failed to grant permissions' -Level ERROR -Data @{ folder=$FolderPath; account=$Account; exitCode=$code; output=($output -join '\n') }
            return [pscustomobject]@{ Success=$false; ExitCode=$code; Output=($output -join "`n") }
        }
    } catch {
        Write-Log -Message 'Exception while running icacls' -Level ERROR -Data @{ error=$_.Exception.Message }
        return [pscustomobject]@{ Success=$false; ExitCode=$null; Output=$_.Exception.Message }
    }
}

function Get-Config {
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) {
        $cfg = [ordered]@{
            defaultSqlInstance    = ''
            backupPaths           = @{ local = 'backup'; remote = '' }
            knownBackupLocations  = @()
            excludeSystemDbs      = $true
            logging               = @{ level = 'Information'; logPath = 'logs\\opendbtools.log' }
            modulesChecked        = @{ SqlServer = $false }
            lastUsedSettings      = @{ sqlInstance = ''; operation = ''; backupLocation = 'local' }
        }
        ($cfg | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
    }
    $raw = Get-Content -LiteralPath $script:ConfigPath -Encoding UTF8 -Raw
    $cfg = ConvertFrom-Json -InputObject $raw
    # Ensure keys exist
    $props = $cfg.PSObject.Properties
    if (-not $props['backupPaths']) { $cfg | Add-Member -NotePropertyName backupPaths -NotePropertyValue (@{ local='backup'; remote='' }) }
    elseif ($null -eq $cfg.backupPaths) { $cfg.backupPaths = @{ local='backup'; remote='' } }

    if (-not $props['knownBackupLocations']) { $cfg | Add-Member -NotePropertyName knownBackupLocations -NotePropertyValue (@()) }
    elseif ($null -eq $cfg.knownBackupLocations) { $cfg.knownBackupLocations = @() }
    elseif ($cfg.knownBackupLocations -isnot [System.Array]) { $cfg.knownBackupLocations = @($cfg.knownBackupLocations) }

    if (-not $props['excludeSystemDbs']) { $cfg | Add-Member -NotePropertyName excludeSystemDbs -NotePropertyValue $true }
    elseif ($null -eq $cfg.excludeSystemDbs) { $cfg.excludeSystemDbs = $true }

    if (-not $props['logging']) { $cfg | Add-Member -NotePropertyName logging -NotePropertyValue (@{ level='Information'; logPath='logs\\opendbtools.log' }) }
    elseif ($null -eq $cfg.logging) { $cfg.logging = @{ level='Information'; logPath='logs\\opendbtools.log' } }

    if (-not $props['modulesChecked']) { $cfg | Add-Member -NotePropertyName modulesChecked -NotePropertyValue (@{ SqlServer = $false }) }
    elseif ($null -eq $cfg.modulesChecked) { $cfg.modulesChecked = @{ SqlServer = $false } }

    if (-not $props['lastUsedSettings']) { $cfg | Add-Member -NotePropertyName lastUsedSettings -NotePropertyValue (@{ sqlInstance=''; operation=''; backupLocation='local' }) }
    elseif ($null -eq $cfg.lastUsedSettings) { $cfg.lastUsedSettings = @{ sqlInstance=''; operation=''; backupLocation='local' } }
    return $cfg
}

function Set-Config([object]$cfg) {
    try {
        ($cfg | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
    } catch {
        Write-Log -Message 'Failed to save configuration' -Level ERROR -Data @{ path=$script:ConfigPath; error=$_.Exception.Message }
        throw
    }
}

function Install-SqlServerModuleIfMissing([ref]$cfg) {
    if ($cfg.Value.modulesChecked -and $cfg.Value.modulesChecked.SqlServer) {
        return
    }
    Write-Log -Message 'Checking SqlServer PowerShell module' -Level ACTION
    $mod = Get-Module -ListAvailable -Name SqlServer | Select-Object -First 1
    if (-not $mod) {
        Write-Log -Message 'SqlServer module not found. Installing (CurrentUser)...' -Level WARN
        try {
            # Ensure TLS 1.2 for PowerShellGet
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
            $nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue
            if (-not $nuget) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null }
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
            Install-Module -Name SqlServer -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Log -Message 'SqlServer module installed' -Level RESULT
        } catch {
            Write-Log -Message 'Failed to install SqlServer module' -Level ERROR -Data @{ error=$_.Exception.Message }
            throw
        }
    } else {
        Write-Log -Message ('SqlServer module found (v{0})' -f $mod.Version) -Level RESULT
    }
    $cfg.Value.modulesChecked.SqlServer = $true
    Set-Config -cfg $cfg.Value
}

function Get-YesNo([string]$Question, [bool]$DefaultYes=$true) {
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        Write-Log -Message $Question -Level PROMPT
        $ans = Read-Host "$Question $suffix"
        if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }
        switch ($ans.ToLowerInvariant()) {
            'y' { return $true }
            'yes' { return $true }
            'n' { return $false }
            'no' { return $false }
        }
    }
}

function Get-MenuChoice([string]$Title, [string[]]$Options, [int]$DefaultIndex = -1) {
    Write-Host ''
    Write-Log -Message $Title -Level PROMPT
    for ($i=0; $i -lt $Options.Count; $i++) {
        Write-Host ("{0}) {1}" -f ($i+1), $Options[$i])
    }
    while ($true) {
        $resp = Read-Host 'Enter number'
        [int]$n = 0
        if ([int]::TryParse($resp, [ref]$n)) {
            if ($n -ge 1 -and $n -le $Options.Count) { return ($n-1) }
        }
        if ($DefaultIndex -ge 0 -and [string]::IsNullOrWhiteSpace($resp)) { return $DefaultIndex }
    }
}

function Get-DatabaseSelection($dbList) {
    Write-Host ''
    Write-Log -Message 'Select database(s) to process' -Level PROMPT
    for ($i=0; $i -lt $dbList.Count; $i++) {
        Write-Host ("{0}) {1}" -f ($i+1), $dbList[$i])
    }
    Write-Host '* ) All databases'
    while ($true) {
        $resp = Read-Host 'Enter numbers separated by comma (e.g. 1,3) or * for all'
        if ($resp -eq '*') { return @('*') }
        $parts = $resp -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $idx = @()
        $ok = $true
        foreach ($p in $parts) {
            [int]$n = 0
            if ([int]::TryParse($p, [ref]$n)) {
                if ($n -ge 1 -and $n -le $dbList.Count) { $idx += ($n-1) } else { $ok=$false; break }
            } else { $ok=$false; break }
        }
        if ($ok -and $idx.Count -gt 0) { return $idx }
    }
}

function Main {
    $cfg = Get-Config
    # Initialize logging
    $logPath = Join-Path -Path $PSScriptRoot -ChildPath $cfg.logging.logPath
    New-DirectoryIfMissing -Path $logPath
    Initialize-Logger -FilePath $logPath -AppName $script:AppName | Out-Null
    Write-Log -Message 'Starting OpenDBTools' -Level INFO -Data @{ version='MVP'; host=$env:COMPUTERNAME }

    try {
    Install-SqlServerModuleIfMissing ([ref]$cfg)

        # Instance detection / selection
        $instances = @(Get-LocalSqlInstances)
        if (-not $instances -or $instances.Count -eq 0) {
            Write-Log -Message 'No SQL Server instances detected on this machine' -Level ERROR
            throw 'No SQL Server instances found.'
        }
        $instStrings = @($instances | ForEach-Object { $_.ServerInstance })
        $defaultIdx = -1
        if ($cfg.defaultSqlInstance) {
            $defaultIdx = [array]::IndexOf($instStrings, $cfg.defaultSqlInstance)
        }
    $idx = Get-MenuChoice -Title 'Select SQL Server instance' -Options $instStrings -DefaultIndex $defaultIdx
        $serverInstance = $instStrings[$idx]
        $cfg.defaultSqlInstance = $serverInstance
        $cfg.lastUsedSettings.sqlInstance = $serverInstance
        Set-Config -cfg $cfg

        # Operation choice
    $opIdx = Get-MenuChoice -Title 'What do you want to do today?' -Options @('Backup','Restore') -DefaultIndex 0
        $operation = if ($opIdx -eq 0) { 'Backup' } else { 'Restore' }
        $cfg.lastUsedSettings.operation = $operation
    Set-Config -cfg $cfg

        # Authentication attempt
        Write-Log -Message 'Authenticating to SQL Server (Windows first)...' -Level ACTION -Data @{ instance=$serverInstance }
        $auth = Test-And-Authenticate -ServerInstance $serverInstance
        if (-not $auth.Success) {
            Write-Log -Message 'Authentication failed' -Level ERROR -Data @{ instance=$serverInstance; error=$auth.Error }
            throw 'Authentication failed.'
        }
        $effectiveInstance = if ($auth.ResolvedInstance) { $auth.ResolvedInstance } else { $serverInstance }
        Write-Log -Message ('Authenticated using {0}' -f $auth.Mode) -Level RESULT -Data @{ effectiveInstance=$effectiveInstance }
        # Log server-side identity/role info for diagnostics
        try {
            $ident = Get-ServerIdentityInfo -ServerInstance $effectiveInstance -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential
            Write-Log -Message 'SQL connection identity' -Level INFO -Data @{
                login=$ident.Login; originalLogin=$ident.OriginalLogin; systemUser=$ident.SystemUser; isSysadmin=$ident.IsSysadmin; roles=($ident.Roles -join ', ')
            }
        } catch {}
        if ($effectiveInstance -ne $cfg.defaultSqlInstance) {
            $cfg.defaultSqlInstance = $effectiveInstance
            Set-Config -cfg $cfg
        }

        if ($operation -eq 'Backup') {
            # Include system DBs?
            $includeSystem = -not $cfg.excludeSystemDbs
            $includeSystem = Get-YesNo -Question 'Include system databases (master, model, msdb, tempdb)?' -DefaultYes:$false

            $dbs = @(Get-UserDatabases -ServerInstance $effectiveInstance -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential -IncludeSystem:$includeSystem)
            if (-not $dbs -or $dbs.Count -eq 0) { Write-Log -Message 'No databases found to back up' -Level ERROR; throw 'No databases.' }
            $selection = Get-DatabaseSelection -dbList $dbs
            $selectedDbs = if ($selection -eq @('*')) { $dbs } else { $selection | ForEach-Object { $dbs[$_] } }
            $selectedDbs = @($selectedDbs)

            # Local backup path (always back up locally first)
            $localPath = $cfg.backupPaths.local
            # If user configured a bare folder name, resolve relative to script root
            if ($localPath -and -not ($localPath -match '^[A-Za-z]:\\|^\\\\')) {
                $resolved = Join-Path -Path $PSScriptRoot -ChildPath $localPath
                $confirm = Get-YesNo -Question ("Use '{0}' (resolved to '{1}') as the local backup path?" -f $localPath, $resolved) -DefaultYes:$true
                if ($confirm) { $localPath = $resolved } else { $localPath = Read-Host 'Enter full path for local backup folder' }
                $cfg.backupPaths.local = $localPath
                Set-Config -cfg $cfg
            }
            if ([string]::IsNullOrWhiteSpace($localPath)) {
                $localPath = Read-Host 'Enter local backup folder path (accessible by SQL Server service account)'
                $cfg.backupPaths.local = $localPath
                Set-Config -cfg $cfg
            }
            # Create local directory if missing (host filesystem)
            if (-not (Test-Path -LiteralPath $localPath)) {
                try { New-Item -ItemType Directory -Path $localPath -Force | Out-Null } catch {
                    Write-Log -Message 'Cannot create local backup folder on host filesystem' -Level ERROR -Data @{ path=$localPath; error=$_.Exception.Message }
                    throw
                }
            }
            # Ask if we should also copy to remote after local backup completes
            $copyRemote = $false
            $copyRemote = Get-YesNo -Question 'Do you want to copy the local backup to the remote target after local backup completes?' -DefaultYes:$false
            $remotePath = $cfg.backupPaths.remote
            if ($copyRemote) {
                if ([string]::IsNullOrWhiteSpace($remotePath)) {
                    $remotePath = Read-Host 'Enter remote backup folder path (UNC or accessible path)'
                }
                if (-not [string]::IsNullOrWhiteSpace($remotePath)) {
                    try { if (-not (Test-Path -LiteralPath $remotePath)) { New-Item -ItemType Directory -Path $remotePath -Force | Out-Null } } catch {}
                    $cfg.backupPaths.remote = $remotePath
                    if ($cfg.knownBackupLocations -notcontains $remotePath) { $cfg.knownBackupLocations += $remotePath }
                    Set-Config -cfg $cfg
                } else {
                    $copyRemote = $false
                }
            }

            # Track in known locations (local)
            if ($cfg.knownBackupLocations -notcontains $localPath) { $cfg.knownBackupLocations += $localPath; Set-Config -cfg $cfg }
            $selCount = @($selectedDbs).Count
            # Preflight: check SQL Engine write access to local folder by attempting a COPY_ONLY backup of master
            Write-Log -Message 'Preflight: checking SQL Engine write access to target folder' -Level ACTION -Data @{ target=$localPath }
            $pre = Test-SqlEngineWriteAccess -ServerInstance $effectiveInstance -TargetFolder $localPath -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential
            if (-not $pre.Success) {
                Write-Log -Message 'Preflight write test failed' -Level ERROR -Data @{ target=$localPath; error=$pre.Error; sqlServiceAccount=$pre.ServiceAccount; testFile=$pre.TestFile }
                $suggest = Get-DefaultBackupDirectory -ServerInstance $effectiveInstance -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential
                if ($suggest) {
                    Write-Log -Message 'SQL default backup directory discovered' -Level INFO -Data @{ defaultBackupDirectory=$suggest }
                }
                $msg = "SQL Server service account '$($pre.ServiceAccount)' cannot write to '$localPath'."
                # Offer one-click grant permissions for the service account
                if ($pre.ServiceAccount -and $pre.ServiceAccount -ne '(unknown)') {
                    $doGrant = Get-YesNo -Question ("Do you want to grant Modify permissions on '$localPath' to '$($pre.ServiceAccount)' now? (required so SQL Server can write .bak files)") -DefaultYes:$true
                    if ($doGrant) {
                        $grantRes = Grant-FolderModifyToAccount -FolderPath $localPath -Account $pre.ServiceAccount
                        if ($grantRes.Success) {
                            # Retry preflight once after granting
                            $pre = Test-SqlEngineWriteAccess -ServerInstance $effectiveInstance -TargetFolder $localPath -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential
                        } else {
                            Write-Log -Message 'Permission grant did not succeed' -Level WARN -Data @{ target=$localPath; account=$pre.ServiceAccount }
                        }
                    }
                }
                # If still failing, allow switching folder
                if (-not $pre.Success) {
                if ($suggest) { $msg += " Suggested writable directory: '$suggest'." }
                $useAlt = Get-YesNo -Question ("$msg Do you want to use a different folder?") -DefaultYes:$true
                if ($useAlt) {
                    $alt = if ($suggest) { Read-Host ("Enter backup target folder (Enter for default: $suggest)") } else { Read-Host 'Enter backup target folder (full path accessible by SQL Server)' }
                    if ([string]::IsNullOrWhiteSpace($alt) -and $suggest) { $alt = $suggest }
                    if (-not [string]::IsNullOrWhiteSpace($alt)) {
                        try { if (-not (Test-Path -LiteralPath $alt)) { New-Item -ItemType Directory -Path $alt -Force | Out-Null } } catch {}
                        $localPath = $alt
                        if ($cfg.knownBackupLocations -notcontains $localPath) { $cfg.knownBackupLocations += $localPath }
                        $cfg.backupPaths.local = $localPath
                        Set-Config -cfg $cfg
                        # Re-run preflight once
                        $pre2 = Test-SqlEngineWriteAccess -ServerInstance $effectiveInstance -TargetFolder $localPath -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential
                        if (-not $pre2.Success) {
                            Write-Log -Message 'Preflight write test still failing after change' -Level ERROR -Data @{ target=$localPath; error=$pre2.Error; sqlServiceAccount=$pre2.ServiceAccount; testFile=$pre2.TestFile }
                            throw 'SQL Server cannot write to the selected backup folder.'
                        }
                    } else {
                        throw 'Backup aborted by user (no writable folder chosen).'
                    }
                } else {
                    throw 'SQL Server cannot write to the selected backup folder.'
                }
                }
            } else {
                Write-Log -Message 'Preflight write test succeeded' -Level RESULT -Data @{ target=$localPath; sqlServiceAccount=$pre.ServiceAccount }
            }
            Write-Log -Message 'Starting backup' -Level ACTION -Data @{ count=$selCount; target=$localPath }
            $results = Invoke-BackupDatabases -ServerInstance $effectiveInstance -DatabaseNames $selectedDbs -TargetFolder $localPath -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential
            $ok = ($results | Where-Object { $_.Success } | Measure-Object).Count
            $fail = ($results | Where-Object { -not $_.Success } | Measure-Object).Count
            Write-Log -Message 'Backup completed' -Level RESULT -Data @{ success=$ok; failed=$fail; target=$localPath }
            if ($cfg.knownBackupLocations -notcontains $localPath) { $cfg.knownBackupLocations += $localPath; Set-Config -cfg $cfg }

            # Optional remote copy
            if ($copyRemote -and $remotePath) {
                Write-Log -Message 'Copying local backups to remote target' -Level ACTION -Data @{ remote=$remotePath }
                $copyOk = 0; $copyFail = 0
                $successFiles = @($results | Where-Object { $_.Success } | ForEach-Object { $_.File })
                foreach ($src in $successFiles) {
                    try {
                        $dest = Join-Path -Path $remotePath -ChildPath ([System.IO.Path]::GetFileName($src))
                        Write-Log -Message 'Copying backup to remote' -Level DEBUG -Data @{ source=$src; destination=$dest }
                        Copy-Item -LiteralPath $src -Destination $dest -Force
                        $copyOk++
                    } catch {
                        $copyFail++
                        Write-Log -Message 'Remote copy failed' -Level ERROR -Data @{ source=$src; remote=$remotePath; error=$_.Exception.Message }
                    }
                }
                Write-Log -Message 'Remote copy completed' -Level RESULT -Data @{ success=$copyOk; failed=$copyFail; remote=$remotePath }
            }
        } else {
            # Restore
            $searchPaths = @()
            if ($cfg.backupPaths.local) { $searchPaths += $cfg.backupPaths.local }
            if ($cfg.backupPaths.remote) { $searchPaths += $cfg.backupPaths.remote }
            if ($cfg.knownBackupLocations) { $searchPaths += $cfg.knownBackupLocations }
            $searchPaths = $searchPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            if (-not $searchPaths -or $searchPaths.Count -eq 0) {
                $p = Read-Host 'Enter a folder path to scan for .bak files'
                if ($p) { $searchPaths = @($p) }
            }
            $files = @(Get-BackupFiles -Paths $searchPaths)
            if (-not $files -or $files.Count -eq 0) {
                Write-Log -Message 'No backup files found' -Level ERROR -Data @{ paths = ($searchPaths -join ';') }
                throw 'No .bak files found.'
            }
            # Display table newest-first
            Write-Host ''
            Write-Log -Message 'Available backups (newest first)' -Level INFO
            for ($i=0; $i -lt $files.Count; $i++) {
                $f = $files[$i]
                Write-Host ("{0}) {1} | {2} | {3} | {4}" -f ($i+1), $f.Server, $f.Instance, $f.Database, $f.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))
                Write-Host ("     {0}" -f $f.FullName)
            }
            $sel = Get-MenuChoice -Title 'Select a backup to restore' -Options (@($files | ForEach-Object { $_.FullName }))
            $choice = $files[$sel]

            # Choose target instance (can be different)
            $idx2 = Get-MenuChoice -Title 'Select target SQL Server instance for restore' -Options $instStrings -DefaultIndex $idx
            $targetInstance = $instStrings[$idx2]
            if ($targetInstance -ne $serverInstance) {
                Write-Log -Message 'Re-authenticating for target instance' -Level ACTION -Data @{ instance=$targetInstance }
                $auth = Test-And-Authenticate -ServerInstance $targetInstance
                if (-not $auth.Success) { Write-Log -Message 'Authentication to target failed' -Level ERROR; throw 'Auth failed' }
                $effectiveInstance = if ($auth.ResolvedInstance) { $auth.ResolvedInstance } else { $targetInstance }
            }

            # Restore
            Write-Log -Message 'Starting restore' -Level ACTION -Data @{ file=$choice.FullName; targetInstance=$targetInstance }
            $res = Invoke-RestoreFromBackup -ServerInstance $effectiveInstance -BackupFile $choice.FullName -UseSqlAuth:($auth.Mode -eq 'Sql') -Credential $auth.Credential -TargetDbName $choice.Database
            if ($res.Success) {
                Write-Log -Message 'Restore completed' -Level RESULT -Data @{ database=$choice.Database; instance=$targetInstance }
            } else {
                Write-Log -Message 'Restore failed' -Level ERROR -Data @{ error=$res.Error; file=$choice.FullName }
                throw 'Restore failed.'
            }
        }

        Write-Log -Message 'All done.' -Level RESULT
    } catch {
        Write-Log -Message 'Critical failure' -Level ERROR -Data @{ error=$_.Exception.Message; script='OpenDBTools.ps1' }
        Exit 1
    } finally {
        Close-Logger | Out-Null
    }
}

Main
