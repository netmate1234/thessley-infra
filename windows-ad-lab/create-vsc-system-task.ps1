# Lab fallback for creating the TPM virtual smart card from SYSTEM context.
# Run from an elevated PowerShell prompt on the joined client.
$ErrorActionPreference = 'Stop'
$taskName = 'Thessley-ADLab-Create-Virtual-SmartCard'
$work = Join-Path $env:ProgramData 'Thessley\ADLab\VscProvisioning'
$commandFile = Join-Path $work 'create-vsc.cmd'
$outputFile = Join-Path $work 'create-vsc.txt'
New-Item -ItemType Directory -Path $work -Force | Out-Null
Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue

@(
    '@echo off'
    "tpmvscmgr.exe create /name ThessleyADTest /adminkey RANDOM /pin DEFAULT /generate > `"$outputFile`" 2>&1"
    "echo ExitCode: %ERRORLEVEL% >> `"$outputFile`""
) | Set-Content -LiteralPath $commandFile -Encoding ascii

try {
    $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\cmd.exe" -Argument "/c $commandFile"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName

    $deadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Seconds 2
        $state = (Get-ScheduledTask -TaskName $taskName).State
    } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)

    if ($state -eq 'Running') { throw "Provisioning task is still running; inspect $outputFile before retrying." }
    if (-not (Test-Path -LiteralPath $outputFile)) { throw "The task ended without output; inspect Task Scheduler history for $taskName." }
    $bytes = [IO.File]::ReadAllBytes($outputFile)
    $encoding = if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        [Text.Encoding]::Unicode
    } else {
        [Text.Encoding]::Default
    }
    $text = $encoding.GetString($bytes)
    Write-Host $text
    if ($text -notmatch 'ExitCode:\s*0') { throw 'The TPM virtual smart-card task did not succeed.' }
    Write-Warning 'This disposable lab card uses its documented default PIN 12345678. Change the PIN after validating sign-in.'
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $commandFile -Force -ErrorAction SilentlyContinue
}
