param([switch]$FromTimer)
$ErrorActionPreference = 'Stop'

$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$taskName = 'Thessley-AD-Lab-Provider-Rollback'
$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classKey = "HKLM:\SOFTWARE\Classes\CLSID\$providerId"

Remove-Item -LiteralPath $providerKey -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $classKey -Recurse -Force -ErrorAction SilentlyContinue

if ($FromTimer) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

Write-Output 'The isolated Thessley AD provider registration has been removed.'
