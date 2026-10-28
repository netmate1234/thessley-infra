param([ValidateRange(5, 30)][int]$RollbackMinutes = 10)
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

Assert-Administrator

$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$taskName = 'Thessley-AD-Lab-Provider-Rollback'
$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classKey = "HKLM:\SOFTWARE\Classes\CLSID\$providerId"
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider'
$dllSource = Join-Path $source 'ThessleyADCredentialProvider.dll'
$viewerSource = Join-Path $source 'ThessleyADQrViewer.exe'
$rollbackSource = Join-Path $source 'rollback-ad-lab-provider.ps1'
$keepSource = Join-Path $source 'keep-ad-lab-provider.ps1'

if (Test-Path -LiteralPath $providerKey) { throw 'The AD lab tile is already registered. Do not install it twice.' }
if (Test-Path -LiteralPath $classKey) { throw 'The AD lab CLSID is already registered. Refusing to overwrite it.' }
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'A previous AD lab provider rollback task exists. Resolve that setup before reinstalling.'
}
foreach ($file in @($dllSource, $viewerSource, $rollbackSource, $keepSource)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required package file is missing: $file" }
}
if (Test-Path -LiteralPath $installDir) {
    throw "The protected install directory already exists; inspect it before continuing: $installDir"
}

$registeredTask = $false
try {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item -LiteralPath $dllSource, $viewerSource, $rollbackSource, $keepSource -Destination $installDir

    & icacls.exe $installDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict provider files to SYSTEM and Administrators.' }

    # Arm and verify recovery before adding either Credential Provider registry key.
    $rollbackPath = Join-Path $installDir 'rollback-ad-lab-provider.ps1'
    $at = (Get-Date).AddMinutes($RollbackMinutes)
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackPath`" -FromTimer"
    $trigger = New-ScheduledTaskTrigger -Once -At $at
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Removes the experimental Thessley AD logon tile unless explicitly kept.' | Out-Null
    $registeredTask = $true

    $task = Get-ScheduledTask -TaskName $taskName
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
    if ($task.State -ne 'Ready' -or $taskInfo.NextRunTime -le (Get-Date) -or
        $taskInfo.NextRunTime -gt $at.AddMinutes(2) -or
        $task.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) {
        throw "Rollback task verification failed (state=$($task.State), principal=$($task.Principal.UserId), next=$($taskInfo.NextRunTime)). No provider registration was made."
    }

    New-Item -Path $providerKey -Force | Out-Null
    Set-Item -LiteralPath $providerKey -Value 'Thessley AD Passkey (Lab)'
    New-Item -Path (Join-Path $classKey 'InprocServer32') -Force | Out-Null
    Set-Item -LiteralPath (Join-Path $classKey 'InprocServer32') -Value (Join-Path $installDir 'ThessleyADCredentialProvider.dll')
    New-ItemProperty -LiteralPath (Join-Path $classKey 'InprocServer32') -Name 'ThreadingModel' -Value 'Apartment' -PropertyType String -Force | Out-Null

    Write-Output "Experimental Thessley AD tile registered for the lab account only. Recovery is armed until $($taskInfo.NextRunTime)."
    Write-Output "To keep after verifying a successful domain sign-in, run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $installDir 'keep-ad-lab-provider.ps1')`""
    Write-Output "To roll back now: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$rollbackPath`" -FromTimer"
    Write-Output 'Existing Thessley local tile, VSC smart-card tile, PIN, and password provider registrations were not modified.'
}
catch {
    Remove-Item -LiteralPath $providerKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $classKey -Recurse -Force -ErrorAction SilentlyContinue
    if ($registeredTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    throw
}
