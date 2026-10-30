param([switch]$FromTimer)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and
    $identity.User.Value -ne 'S-1-5-18') {
    throw 'Run the rollback from elevated PowerShell or let the SYSTEM timer handle it.'
}
$providerId = '{8A2755BF-64B7-4D39-9C48-67A6A27F5E91}'
$taskName = 'Thessley-AD-Ticket-Logon-Test-Rollback'
$serviceName = 'ThessleyADTicketBrokerTest'
$providerPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classPath = "SOFTWARE\Classes\CLSID\$providerId"
$configRoot = 'HKLM:\SOFTWARE\Thessley\ADCredentialProvider\Users'

$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    $registry.DeleteSubKeyTree($providerPath, $false)
    $registry.DeleteSubKeyTree($classPath, $false)
} finally { $registry.Dispose() }

Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    sc.exe delete $serviceName | Out-Null
    for ($i = 0; $i -lt 20 -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Milliseconds 250
    }
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'The ticket-test provider registration was removed, but the broker service remains. Remove the service before retrying.'
}

if (Test-Path -LiteralPath $configRoot) {
    foreach ($key in Get-ChildItem -LiteralPath $configRoot) {
        Remove-ItemProperty -LiteralPath $key.PSPath -Name TicketLogonTest -ErrorAction SilentlyContinue
    }
}
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Output 'The isolated ticket-test provider, broker service, and per-SID test flags were removed. Other sign-in providers were not changed.'
