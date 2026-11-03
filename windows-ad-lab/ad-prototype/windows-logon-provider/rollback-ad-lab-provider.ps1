param([switch]$FromTimer)
$ErrorActionPreference = 'Stop'

$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$taskName = 'Thessley-AD-Lab-Provider-Rollback'
$pivTaskName = 'Thessley-AD-PIV-Phone-Reader'
$providerPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classPath = "SOFTWARE\Classes\CLSID\$providerId"
$logPath = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider\rollback.log'

try {
    Stop-ScheduledTask -TaskName $pivTaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $pivTaskName -Confirm:$false -ErrorAction SilentlyContinue
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    $pivTimeoutRestored = $false
    try {
        $registry.DeleteSubKeyTree($providerPath, $false)
        $registry.DeleteSubKeyTree($classPath, $false)
        $configRoot = $registry.OpenSubKey('SOFTWARE\Thessley\ADCredentialProvider\Users', $true)
        if ($configRoot) {
            try {
                foreach ($sid in $configRoot.GetSubKeyNames()) {
                    $accountConfig = $configRoot.OpenSubKey($sid, $true)
                    if (-not $accountConfig) { continue }
                    try {
                        if ($accountConfig.GetValue('PivPhoneSigning', 0) -eq 1) {
                            $accountConfig.SetValue('PivPhoneSigning', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                        $accountConfig.DeleteValue('PivPhoneRequestId', $false)
                        $savedPresent = $accountConfig.GetValue('PivPreviousTransactionTimeoutPresent', $null)
                        if ($null -ne $savedPresent -and -not $pivTimeoutRestored) {
                            $savedValue = $accountConfig.GetValue('PivPreviousTransactionTimeout', $null)
                            $ksp = $registry.OpenSubKey(
                                'SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Smart Card Key Storage Provider',
                                $true)
                            if (-not $ksp) { throw 'Could not restore the smart-card KSP timeout during provider rollback.' }
                            try {
                                if ($savedPresent -eq 1) {
                                    if ($null -eq $savedValue -or [uint64]$savedValue -gt [uint32]::MaxValue) {
                                        throw 'The saved smart-card KSP timeout is invalid.'
                                    }
                                    $ksp.SetValue('TransactionTimeoutMilliseconds', [int]$savedValue,
                                        [Microsoft.Win32.RegistryValueKind]::DWord)
                                } else {
                                    $ksp.DeleteValue('TransactionTimeoutMilliseconds', $false)
                                }
                            } finally { $ksp.Dispose() }
                            $accountConfig.DeleteValue('PivPreviousTransactionTimeoutPresent', $false)
                            $accountConfig.DeleteValue('PivPreviousTransactionTimeout', $false)
                            $pivTimeoutRestored = $true
                        }
                    } finally { $accountConfig.Dispose() }
                }
            } finally { $configRoot.Dispose() }
        }
    } finally {
        $registry.Dispose()
    }
    Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) Removed the AD provider keys, disabled PIV test mode, and restored its saved smart-card timeout when present."
} catch {
    Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) Rollback failed: $($_.Exception.Message)"
    throw
}

if ($FromTimer) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
}

Write-Output 'The isolated Thessley AD provider registration has been removed.'
