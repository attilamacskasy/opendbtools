Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LocalSqlInstances {
    # Discover SQL instances quickly via registry and service names
    $instances = @()
    try {
        $hklm = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
        if (Test-Path $hklm) {
            $kv = Get-Item -LiteralPath $hklm
                foreach ($name in $kv.GetValueNames()) {
                # Build server\instance string
                $instName = if ($name -eq 'MSSQLSERVER') { $env:COMPUTERNAME } else { "$($env:COMPUTERNAME)\\$name" }
                $instances += [pscustomobject]@{ ServerInstance = $instName; InstanceName=$name }
            }
        }
    } catch {}

    # Fallback: service names MSSQL$<instance>
    try {
        $svc = Get-Service -Name 'MSSQL$*' -ErrorAction SilentlyContinue
        foreach ($s in $svc) {
            if ($s.Status -eq 'Running') {
                $name = $s.Name -replace '^MSSQL\$',''
                $instName = if ($name -eq 'MSSQLSERVER') { $env:COMPUTERNAME } else { "$($env:COMPUTERNAME)\\$name" }
                if (-not ($instances.ServerInstance -contains $instName)) {
                    $instances += [pscustomobject]@{ ServerInstance = $instName; InstanceName=$name }
                }
            }
        }
    } catch {}

    # If nothing found, try default SQLEXPRESS
    if ($instances.Count -eq 0) {
        $instances += [pscustomobject]@{ ServerInstance = "$($env:COMPUTERNAME)\\SQLEXPRESS"; InstanceName='SQLEXPRESS' }
    }
    return $instances
}

function Test-InstanceConnection {
    param(
        [Parameter(Mandatory)] [string] $ServerInstance,
        [switch] $UseSqlAuth,
        [System.Management.Automation.PSCredential] $Credential
    )
    $tryList = New-Object System.Collections.Generic.List[string]
    $tryList.Add($ServerInstance)
    if ($UseSqlAuth) {
        $tryList.Add("tcp:$ServerInstance")
    } else {
        # Windows auth: add tcp/np/lpc and localhost variants if local
        $tryList.Add("tcp:$ServerInstance")
        $localPrefix = "$($env:COMPUTERNAME)\\"
        if ($ServerInstance.StartsWith($localPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $inst = $ServerInstance.Substring($localPrefix.Length)
            $tryList.Add("localhost\$inst")
            $tryList.Add("tcp:localhost\$inst")
            $tryList.Add("np:$($env:COMPUTERNAME)\$inst")
            $tryList.Add("np:localhost\$inst")
            $tryList.Add("lpc:localhost\$inst")
        }
    }
    foreach ($target in $tryList) {
        try {
            Write-Log -Message ('Auth probe using {0}' -f $target) -Level DEBUG
            if ($UseSqlAuth) {
                Invoke-Sqlcmd -ServerInstance $target -Username $Credential.UserName -Password ($Credential.GetNetworkCredential().Password) -Database 'master' -Query 'SELECT 1' -ConnectionTimeout 5 -TrustServerCertificate -Encrypt Optional | Out-Null
            } else {
                Invoke-Sqlcmd -ServerInstance $target -Database 'master' -Query 'SELECT 1' -ConnectionTimeout 5 -TrustServerCertificate -Encrypt Optional | Out-Null
            }
            return [pscustomobject]@{ Success=$true; Instance=$target }
        } catch {
            Write-Log -Message ('Auth probe failed: {0}' -f $_.Exception.Message) -Level DEBUG
        }
    }
    return [pscustomobject]@{ Success=$false; Instance=$null }
}

function Test-And-Authenticate {
    param(
        [Parameter(Mandatory)] [string] $ServerInstance
    )
    # Try Windows auth first
    $win = Test-InstanceConnection -ServerInstance $ServerInstance
    if ($win.Success) {
        return [pscustomobject]@{ Success=$true; Mode='Windows'; Credential=$null; ResolvedInstance=$win.Instance }
    }
    Write-Log -Message 'Windows auth failed or disabled; prompting for SQL Auth (sa/username+password)' -Level WARN
    $cred = $null
    try { $cred = Get-Credential -Message 'Enter SQL username and password (e.g., sa) for SQL Authentication' } catch {}
    if ($cred) {
        $sql = Test-InstanceConnection -ServerInstance $ServerInstance -UseSqlAuth -Credential $cred
        if ($sql.Success) {
            return [pscustomobject]@{ Success=$true; Mode='Sql'; Credential=$cred; ResolvedInstance=$sql.Instance }
        }
    }
    return [pscustomobject]@{ Success=$false; Mode='None'; Credential=$null; Error='Unable to authenticate using Windows or SQL Auth.' }
}


