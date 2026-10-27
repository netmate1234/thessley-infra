$ErrorActionPreference = 'Stop'

# Run elevated on the disposable Windows client. The domain controller must be
# reachable on the physical 192.168.1.x LAN. Active adapters use the lab DNS
# server during domain join; non-LAN adapters are excluded from DNS registration.
# Previous resolver and registration settings are restored if setup fails.
$DomainName = 'lab.thessley.test'
$NetbiosName = 'THESSLEYLAB'
$DomainController = 'THESSLEY-DC1.lab.thessley.test'
$DomainControllerIp = '192.168.1.79'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) { throw 'Run this script from an elevated PowerShell prompt.' }

$lan = Get-NetIPConfiguration | Where-Object {
    $_.IPv4Address | Where-Object { $_.IPAddress -like '192.168.1.*' }
} | Select-Object -First 1
if (-not $lan) {
    throw "No 192.168.1.x LAN address is active. Connect the LAN adapter, then rerun. Do not use the 192.168.122.x NAT address for domain DNS."
}

Write-Host "Client LAN address: $($lan.IPv4Address[0].IPv4Address)"
Write-Host "Setting DNS on '$($lan.InterfaceAlias)' to $DomainControllerIp."
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
if (-not ($adapters | Where-Object { $_.ifIndex -eq $lan.InterfaceIndex })) {
    throw 'The active LAN interface is not in the adapter list. Check the network connection, then rerun.'
}
$oldDns = @{}
$oldRegistration = @{}
foreach ($adapter in $adapters) {
    $oldDns[$adapter.ifIndex] = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
    $oldRegistration[$adapter.ifIndex] = (Get-DnsClient -InterfaceIndex $adapter.ifIndex).RegisterThisConnectionsAddress
}

try {
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DomainControllerIp
        if ($adapter.ifIndex -ne $lan.InterfaceIndex) {
            Set-DnsClient -InterfaceIndex $adapter.ifIndex -RegisterThisConnectionsAddress $false
        }
    }
    $srv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -Server $DomainControllerIp -ErrorAction Stop
    if (-not ($srv | Where-Object { $_.NameTarget.TrimEnd('.') -ieq $DomainController })) {
        throw "AD DNS did not return $DomainController for $DomainName. Check the DC LAN address and DNS service."
    }

    Write-Host 'Synchronizing time from the domain controller before Kerberos setup.'
    w32tm.exe /config "/manualpeerlist:$DomainControllerIp,0x8" /syncfromflags:manual /update | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure the client time source.' }
    Restart-Service W32Time
    w32tm.exe /resync /rediscover | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Windows time sync failed. Correct the client clock before joining the domain.' }

    $credential = Get-Credential -UserName "$NetbiosName\Administrator" -Message 'Enter the lab domain Administrator password.'
    Add-Computer -DomainName $DomainName -Server $DomainController -Credential $credential -PassThru | Out-Host
} catch {
    foreach ($adapter in $adapters) {
        $previous = $oldDns[$adapter.ifIndex]
        if ($previous) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $previous -ErrorAction SilentlyContinue
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
        if ($null -ne $oldRegistration[$adapter.ifIndex]) {
            Set-DnsClient -InterfaceIndex $adapter.ifIndex -RegisterThisConnectionsAddress $oldRegistration[$adapter.ifIndex] -ErrorAction SilentlyContinue
        }
    }
    throw
}
Write-Host "Joined $DomainName. Restarting; afterward sign in as $NetbiosName\martin."
Restart-Computer -Force
