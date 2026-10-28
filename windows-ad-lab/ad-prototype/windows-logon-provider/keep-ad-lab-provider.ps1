$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session after confirming a successful sign-in.'
}

$taskName = 'Thessley-AD-Lab-Provider-Rollback'
$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
if (-not (Test-Path -LiteralPath $providerKey)) { throw 'The lab tile is not registered; there is no setup to keep.' }
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) { throw 'Rollback task identity is unexpected; recovery was not changed.' }
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Could not stop the automatic rollback.' }
Write-Output 'Automatic rollback stopped. The isolated AD lab tile remains registered.'
