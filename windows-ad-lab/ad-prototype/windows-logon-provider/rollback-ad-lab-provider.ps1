param([switch]$FromTimer)
$ErrorActionPreference = 'Stop'

$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$taskName = 'Thessley-AD-Lab-Provider-Rollback'
$providerPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classPath = "SOFTWARE\Classes\CLSID\$providerId"
$logPath = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider\rollback.log'

try {
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $registry.DeleteSubKeyTree($providerPath, $false)
        $registry.DeleteSubKeyTree($classPath, $false)
    } finally {
        $registry.Dispose()
    }
    Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) Removed the AD provider keys from the 64-bit registry view."
} catch {
    Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) Rollback failed: $($_.Exception.Message)"
    throw
}

if ($FromTimer) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
}

Write-Output 'The isolated Thessley AD provider registration has been removed.'
