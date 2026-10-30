# Pin the current DC LAN address without touching its separate management NIC.
param(
    [string] $AdapterAlias = 'Ethernet',
    [string] $IPAddress = '192.168.1.79',
    [string] $SubnetMask = '255.255.255.0',
    [string] $Gateway = '192.168.1.254'
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell session.'
}
$adapter = Get-NetAdapter -Name $AdapterAlias -ErrorAction Stop
$config = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
$currentAddress = @($config.IPv4Address | ForEach-Object IPAddress)
$currentGateway = @($config.IPv4DefaultGateway | ForEach-Object NextHop)
if ($IPAddress -notin $currentAddress) {
    throw "Refusing to change the DC address: $IPAddress is not currently assigned to $AdapterAlias."
}
if ($Gateway -notin $currentGateway) {
    throw "Refusing to change the DC route: expected gateway $Gateway is not currently configured."
}
$adapterConfig = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter.ifIndex)"
if (-not $adapterConfig.DHCPEnabled) {
    Write-Host "$AdapterAlias already uses a static address."
    exit 0
}

Write-Host "Setting $AdapterAlias to static $IPAddress/24; management interface is unchanged."
& netsh.exe interface ipv4 set address "name=$AdapterAlias" source=static "address=$IPAddress" `
    "mask=$SubnetMask" "gateway=$Gateway" gwmetric=1
if ($LASTEXITCODE -ne 0) { throw "netsh failed while setting the static IPv4 address (exit $LASTEXITCODE)." }
& netsh.exe interface ipv4 set dnsservers "name=$AdapterAlias" source=static "address=$IPAddress" register=primary validate=no
if ($LASTEXITCODE -ne 0) { throw "netsh failed while setting the DC's DNS resolver (exit $LASTEXITCODE)." }
Start-Sleep -Seconds 2
$updated = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
if ($IPAddress -notin @($updated.IPv4Address | ForEach-Object IPAddress) -or
    $Gateway -notin @($updated.IPv4DefaultGateway | ForEach-Object NextHop)) {
    throw 'Static IP verification failed. Management SSH remains on the separate adapter; inspect the LAN NIC locally.'
}
if ((Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).Dhcp -ne 'Disabled') {
    throw 'The LAN adapter still reports DHCP enabled.'
}
Write-Host "Static DC LAN endpoint confirmed: https://$IPAddress`:47810"
