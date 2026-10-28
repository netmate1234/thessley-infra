#Requires -RunAsAdministrator
<#
Enable the Thessley AD SSH approval gate for one AD security group.

The user must already have a working SSH authentication factor (normally an
SSH public key), a phone enrolled for this computer, and membership in the
AD group authorized by the Thessley AD API. This script adds that AD group to
the PC's local Administrators group, replaces the prototype's per-user AD
Match block with a group Match block, validates sshd_config, and arms an
automatic rollback before restarting sshd.
#>
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$')]
    [string]$Domain = 'THESSLEYLAB',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')]
    [string]$GroupSamAccountName = 'ThessleyQRWorkstationAdmins',
    [ValidateRange(5, 60)]
    [int]$RollbackMinutes = 15
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}

$root = Join-Path $env:ProgramData 'ThessleyPamWin'
$config = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
$forceCommandFile = Join-Path $root 'ad-ssh-gate.cmd'
$pythonGate = Join-Path $root 'app\ad_ssh_gate_main.py'
$taskName = "ThessleyADSSHGroupRollback-$($Domain)-$($GroupSamAccountName)"
$qualifiedGroup = "$($Domain.ToLowerInvariant())\$($GroupSamAccountName.ToLowerInvariant())"
$groupAccount = [Security.Principal.NTAccount]::new($qualifiedGroup)
$groupSid = $groupAccount.Translate([Security.Principal.SecurityIdentifier])
$adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$administrators = Get-LocalGroup -SID $adminSid

foreach ($path in @($config, $sshd, $forceCommandFile, $pythonGate)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Thessley/OpenSSH file is missing: $path"
    }
}
if (-not (Get-ScheduledTask -TaskName 'ThessleyPamWin' -ErrorAction SilentlyContinue)) {
    throw 'The Thessley SYSTEM approval service is not installed.'
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "A rollback is already armed for $qualifiedGroup. Confirm or let it expire first."
}

$original = [IO.File]::ReadAllText($config)
$newline = if ($original.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = [regex]::Split($original, "\r?\n")
$begins = @(); $ends = @()
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '^# BEGIN THESSLEY AD SSH QR ') { $begins += $i }
    if ($lines[$i] -match '^# END THESSLEY AD SSH QR ') { $ends += $i }
}
if ($begins.Count -ne 1 -or $ends.Count -ne 1 -or $ends[0] -le $begins[0]) {
    throw 'Expected exactly one valid managed Thessley AD SSH block. sshd_config was not changed.'
}

$launcher = [IO.File]::ReadAllText($forceCommandFile)
$pythonMatch = [regex]::Match($launcher, '"([^"\r\n]+python\.exe)"', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
if (-not $pythonMatch.Success) { throw 'Could not determine the installed Python executable.' }
$python = $pythonMatch.Groups[1].Value
$command = '"' + $python.Replace('"', '\"') + '" -I -X utf8 "' + $pythonGate.Replace('"', '\"') + '"'
$block = @(
    "# BEGIN THESSLEY AD SSH QR GROUP $qualifiedGroup",
    "Match Group $qualifiedGroup",
    '    AllowTcpForwarding no',
    '    AllowAgentForwarding no',
    '    PermitTTY yes',
    "    ForceCommand $command",
    "# END THESSLEY AD SSH QR GROUP $qualifiedGroup"
)
$newLines = @()
if ($begins[0] -gt 0) { $newLines += $lines[0..($begins[0] - 1)] }
$newLines += $block
if ($ends[0] + 1 -lt $lines.Length) { $newLines += $lines[($ends[0] + 1)..($lines.Length - 1)] }
$newText = $newLines -join $newline
if ($original.EndsWith("`n")) { $newText += $newline }

$backupDir = Join-Path $root 'backups'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $backupDir "sshd_config.ad-group.$stamp.bak"
Copy-Item -LiteralPath $config -Destination $backup
$existingAdminGroup = @(Get-LocalGroupMember -Group $administrators | Where-Object { $_.SID.Value -eq $groupSid.Value })
$addedAdminGroup = -not [bool]$existingAdminGroup
$rollbackScript = Join-Path $root "rollback-ad-ssh-group-$stamp.ps1"
$backupLiteral = "'" + $backup.Replace("'", "''") + "'"
$configLiteral = "'" + $config.Replace("'", "''") + "'"
$taskLiteral = "'" + $taskName.Replace("'", "''") + "'"
$groupLiteral = "'" + $qualifiedGroup.Replace("'", "''") + "'"
$rollbackBody = @"
`$ErrorActionPreference = 'Stop'
Copy-Item -LiteralPath $backupLiteral -Destination $configLiteral -Force
Restart-Service sshd -Force
if ('$($addedAdminGroup.ToString().ToLowerInvariant())' -eq 'true') {
    Remove-LocalGroupMember -Group 'Administrators' -Member $groupLiteral -ErrorAction SilentlyContinue
}
Unregister-ScheduledTask -TaskName $taskLiteral -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'Original SSH config restored by Thessley AD group rollback.'
"@

# Build and verify the rollback task before the first live change.
$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Set-Content -LiteralPath $rollbackScript -Value $rollbackBody -Encoding ascii
$action = New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackScript`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Restores the prior AD SSH configuration unless group QR SSH is verified." | Out-Null
try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
    $principalSid = ([Security.Principal.NTAccount]::new([string]$task.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
    if (-not $task.Settings.Enabled -or $principalSid -ne 'S-1-5-18' -or
        $taskInfo.NextRunTime -le (Get-Date) -or $taskInfo.NextRunTime -gt (Get-Date).AddMinutes($RollbackMinutes + 2)) {
        throw 'Rollback task verification failed.'
    }
} catch {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw "SSH configuration was not changed because its rollback could not be verified: $($_.Exception.Message)"
}

try {
    $existing = @(Get-LocalGroupMember -Group $administrators | Where-Object { $_.SID.Value -eq $groupSid.Value })
    if (-not $existing) {
        Add-LocalGroupMember -Group $administrators -Member $qualifiedGroup
    }
    [IO.File]::WriteAllText($config, $newText, [Text.UTF8Encoding]::new($false))
    $validation = & $sshd -t -f $config 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sshd_config validation failed: $($validation -join ' ')" }
    $written = [IO.File]::ReadAllText($config)
    if (-not $written.Contains("Match Group $qualifiedGroup") -or -not $written.Contains("ForceCommand $command")) {
        throw 'The expected group Match/ForceCommand block was not written.'
    }
    Restart-Service sshd -Force
    if ((Get-Service sshd).Status -ne 'Running') { throw 'sshd did not return to Running.' }
} catch {
    Copy-Item -LiteralPath $backup -Destination $config -Force
    Restart-Service sshd -Force -ErrorAction SilentlyContinue
    if ($addedAdminGroup) {
        Remove-LocalGroupMember -Group $administrators -Member $qualifiedGroup -ErrorAction SilentlyContinue
    }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}

Write-Host "AD QR SSH approval and local Administrators membership enabled for $qualifiedGroup."
Write-Host "Config backup: $backup"
Write-Host "Automatic rollback in $RollbackMinutes minutes. Keep the maintenance SSH session open and test a new domain-account SSH session."
Write-Host "After the QR test succeeds, confirm with: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
Write-Host 'SFTP is not supported by this ForceCommand shell gate.'
