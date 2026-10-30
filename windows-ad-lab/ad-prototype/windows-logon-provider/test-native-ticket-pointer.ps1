param(
    [Parameter(Mandatory = $true)][string]$DllPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [ValidateRange(5, 30)][int]$RollbackMinutes = 10
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from elevated PowerShell on the disposable Clone 1 VM.'
}

$providerId = '{8A2755BF-64B7-4D39-9C48-67A6A27F5E91}'
$keyPath = "HKLM:\SOFTWARE\Classes\CLSID\$providerId\InprocServer32"
$taskName = 'Thessley-Ticket-Native-Pointer-Rollback'
$dir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-ticket-logon-test'
$backupPathFile = Join-Path $dir 'native-pointer-previous-dll.txt'
$rollbackScript = Join-Path $dir 'restore-native-pointer.ps1'

if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf)) { throw "DLL missing: $DllPath" }
$actualHash = (Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash
if ($actualHash -ne $ExpectedSha256) { throw "DLL hash mismatch: $actualHash" }
if (-not (Test-Path -LiteralPath $keyPath)) { throw 'The isolated ticket-test provider is not registered.' }
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "Rollback task $taskName already exists; inspect it before proceeding."
}

$previousDll = (Get-Item -LiteralPath $keyPath).GetValue('')
if (-not $previousDll -or -not (Test-Path -LiteralPath $previousDll -PathType Leaf)) {
    throw 'The currently registered provider DLL is missing; refusing to switch it.'
}
if ($previousDll -eq $DllPath) { throw 'The native-pointer DLL is already registered.' }
$previousHash = (Get-FileHash -LiteralPath $previousDll -Algorithm SHA256).Hash
Set-Content -LiteralPath $backupPathFile -Value $previousDll -Encoding ascii

$rollbackContents = @'
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SOFTWARE\Classes\CLSID\{8A2755BF-64B7-4D39-9C48-67A6A27F5E91}\InprocServer32'
$backup = Join-Path $env:ProgramData 'ThessleyPamWin\ad-ticket-logon-test\native-pointer-previous-dll.txt'
$old = (Get-Content -LiteralPath $backup -Raw).Trim()
if (-not (Test-Path -LiteralPath $old -PathType Leaf)) { throw 'Previous provider DLL is missing.' }
& reg.exe add 'HKLM\SOFTWARE\Classes\CLSID\{8A2755BF-64B7-4D39-9C48-67A6A27F5E91}\InprocServer32' /ve /t REG_SZ /d $old /f | Out-Null
if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $key).GetValue('') -ne $old) { throw 'Could not restore the previous provider DLL registration.' }
'Previous Thessley ticket provider restored.' | Set-Content -LiteralPath (Join-Path $env:ProgramData 'ThessleyPamWin\ad-ticket-logon-test\native-pointer-rollback.log') -Encoding ascii
'@
Set-Content -LiteralPath $rollbackScript -Value $rollbackContents -Encoding ascii

$runAt = (Get-Date).AddMinutes($RollbackMinutes)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackScript`""
$trigger = New-ScheduledTaskTrigger -Once -At $runAt
$systemPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $systemPrincipal -Settings $settings -Force | Out-Null
$task = Get-ScheduledTask -TaskName $taskName
$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
$taskPrincipalSid = ([Security.Principal.NTAccount]$task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value
if ($task.State -ne 'Ready' -or $taskPrincipalSid -ne 'S-1-5-18' -or
    $taskInfo.NextRunTime -le (Get-Date) -or $taskInfo.NextRunTime -gt $runAt.AddMinutes(2)) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw 'Rollback verification failed; provider registration was not changed.'
}

try {
    Set-Item -LiteralPath $keyPath -Value $DllPath
    if ((Get-Item -LiteralPath $keyPath).GetValue('') -ne $DllPath) {
        throw 'The provider registration did not retain the new DLL path.'
    }
} catch {
    & $rollbackScript
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}

Write-Output "Native-pointer test DLL is registered: $DllPath"
Write-Output "SHA-256: $actualHash"
Write-Output "Previous DLL preserved: $previousDll ($previousHash)"
Write-Output "SYSTEM rollback verified for $($taskInfo.NextRunTime)."
Write-Output 'The existing TPM/VSC provider and built-in password/PIN providers were not changed.'
