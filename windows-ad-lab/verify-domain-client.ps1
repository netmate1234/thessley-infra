param(
    [string] $DomainName = 'lab.thessley.test',
    [string] $DomainController = 'THESSLEY-DC1.lab.thessley.test',
    [string] $DomainControllerIp = '192.168.1.79'
)

$ErrorActionPreference = 'Stop'
$checks = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param([string] $Name, [ValidateSet('PASS', 'WARN', 'FAIL')] [string] $State, [string] $Detail)
    $checks.Add([pscustomobject]@{ Check = $Name; State = $State; Detail = $Detail })
}

Write-Host 'Read-only Thessley AD client verification' -ForegroundColor Cyan
Write-Host "Domain: $DomainName  DC: $DomainController ($DomainControllerIp)"
Write-Host "Computer: $env:COMPUTERNAME  User: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

try {
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.PartOfDomain -and $computer.Domain -ieq $DomainName) {
        Add-Check 'Domain membership' 'PASS' "$($computer.Domain)"
    } elseif ($computer.PartOfDomain) {
        Add-Check 'Domain membership' 'FAIL' "Joined to unexpected domain '$($computer.Domain)'"
    } else {
        Add-Check 'Domain membership' 'FAIL' 'This computer is not domain joined.'
    }
} catch {
    Add-Check 'Domain membership' 'FAIL' $_.Exception.Message
}

try {
    $lan = Get-NetIPConfiguration | Where-Object {
        $_.IPv4Address | Where-Object { $_.IPAddress -like '192.168.1.*' }
    } | Select-Object -First 1
    if (-not $lan) {
        Add-Check 'LAN address and DNS' 'FAIL' 'No active 192.168.1.x adapter found.'
    } else {
        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $lan.InterfaceIndex -AddressFamily IPv4 |
            Select-Object -ExpandProperty ServerAddresses)
        if ($dns -contains $DomainControllerIp) {
            Add-Check 'LAN DNS resolver' 'PASS' "$($lan.InterfaceAlias): $($dns -join ', ')"
        } else {
            Add-Check 'LAN DNS resolver' 'FAIL' "$($lan.InterfaceAlias) uses '$($dns -join ', ')'; expected $DomainControllerIp."
        }
    }
} catch {
    Add-Check 'LAN address and DNS' 'FAIL' $_.Exception.Message
}

try {
    $srv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction Stop
    $targets = @($srv | Select-Object -ExpandProperty NameTarget | ForEach-Object { $_.TrimEnd('.') })
    if ($targets -contains $DomainController) {
        Add-Check 'AD DNS discovery' 'PASS' ($targets -join ', ')
    } else {
        Add-Check 'AD DNS discovery' 'FAIL' "SRV record did not list $($DomainController): $($targets -join ', ')"
    }
} catch {
    Add-Check 'AD DNS discovery' 'FAIL' $_.Exception.Message
}

foreach ($port in @(53, 88, 389, 445)) {
    try {
        $reachable = Test-NetConnection -ComputerName $DomainControllerIp -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
        Add-Check "DC TCP $port" $(if ($reachable) { 'PASS' } else { 'FAIL' }) "${DomainControllerIp}:$port"
    } catch {
        Add-Check "DC TCP $port" 'FAIL' $_.Exception.Message
    }
}

try {
    $secureChannel = Test-ComputerSecureChannel -ErrorAction Stop
    Add-Check 'Machine secure channel' $(if ($secureChannel) { 'PASS' } else { 'FAIL' }) "Test-ComputerSecureChannel returned $secureChannel"
} catch {
    Add-Check 'Machine secure channel' 'FAIL' $_.Exception.Message
}

try {
    $timeStatus = (& w32tm.exe /query /status 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0) {
        $source = ($timeStatus -split "`r?`n" | Where-Object { $_ -match '^Source:' } | Select-Object -First 1)
        Add-Check 'Windows time service' 'PASS' ($source -replace '^Source:\s*', '')
    } else {
        Add-Check 'Windows time service' 'WARN' ($timeStatus -replace "`r?`n", ' ')
    }
} catch {
    Add-Check 'Windows time service' 'WARN' $_.Exception.Message
}

try {
    $sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Add-Check 'Current account SID' 'PASS' $sid
    $smartCardOid = '1.3.6.1.4.1.311.20.2.2'
    $sidExtensionOid = '1.3.6.1.4.1.311.25.2'
    $certs = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value }) -contains $smartCardOid
    })
    if (-not $certs) {
        Add-Check 'SmartcardLogon certificate' 'WARN' 'No user certificate with the Smart Card Logon EKU is installed.'
    } else {
        foreach ($cert in $certs) {
            $hasSidMapping = @($cert.Extensions | Where-Object { $_.Oid.Value -eq $sidExtensionOid }).Count -gt 0
            $state = if ($cert.NotAfter -le (Get-Date)) { 'FAIL' } else { 'WARN' }
            $detail = "thumbprint=$($cert.Thumbprint); expires=$($cert.NotAfter.ToString('u')); SID extension present=$hasSidMapping; strong SID match requires separate verification"
            Add-Check 'SmartcardLogon certificate' $state $detail
        }
    }
} catch {
    Add-Check 'User certificate' 'WARN' $_.Exception.Message
}

Write-Host ''
$checks | Format-Table -AutoSize -Wrap
Write-Host 'This script only reads status. It does not change DNS, time, certificates, accounts, firewall rules, or sign-in policy.'

if ($checks.State -contains 'FAIL') { exit 1 }
