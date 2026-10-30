#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^S-1-(?:[0-9]+-)+[0-9]+$')]
    [string]$GroupSid,
    [string]$StateRoot = "$env:ProgramData\ThessleyAD"
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$groupSidObject = [Security.Principal.SecurityIdentifier]::new($GroupSid)
$group = Get-ADGroup -Identity $groupSidObject -Properties GroupCategory,GroupScope
if ($group.GroupCategory -ne 'Security' -or $group.GroupScope -ne 'Global') {
    throw 'The authorization entry must identify a Global security group.'
}

$configPath = Join-Path $StateRoot 'service.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "AD API configuration is missing: $configPath"
}
$taskName = 'ThessleyADApi'
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) {
    throw 'The AD API task is not running as SYSTEM; refusing to change its policy.'
}
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
if ($config.allowed_group_sids -isnot [array]) {
    throw 'service.json does not have a valid allowed_group_sids array.'
}
$before = @($config.allowed_group_sids | ForEach-Object { [string]$_ })
foreach ($sid in $before) {
    if ($sid -notmatch '^S-1-(?:[0-9]+-)+[0-9]+$') { throw 'Existing group policy contains an invalid SID.' }
}
if ($GroupSid -in $before) {
    Write-Output "The group is already allowed: $($group.SamAccountName) ($GroupSid)."
    exit 0
}

$backupDir = Join-Path $StateRoot 'backups'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$backupPath = Join-Path $backupDir ("service-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Copy-Item -LiteralPath $configPath -Destination $backupPath
& icacls.exe $backupPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the service configuration backup.' }

$wasRunning = $task.State -eq 'Running'
$config.allowed_group_sids = @($before + $GroupSid | Select-Object -Unique)
$temporaryPath = "$configPath.$([guid]::NewGuid().ToString('N')).tmp"
$replaceBackupPath = "$configPath.$([guid]::NewGuid().ToString('N')).replace-bak"
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($temporaryPath, ($config | ConvertTo-Json -Depth 12) + "`n", $utf8)
try {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $stopDeadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    } while ($task.State -eq 'Running' -and (Get-Date) -lt $stopDeadline)
    if ($task.State -eq 'Running') { throw 'The AD API task did not stop; refusing to replace its configuration.' }

    # .NET Framework on supported Windows Server releases requires a valid
    # backup filename here; passing $null throws and can interrupt the API.
    [IO.File]::Replace($temporaryPath, $configPath, $replaceBackupPath, $true)
    if ($wasRunning) {
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds(30)
        $listening = $false
        do {
            Start-Sleep -Milliseconds 500
            $listening = [bool](Get-NetTCPConnection -State Listen -LocalPort 47810 -ErrorAction SilentlyContinue)
        } while (-not $listening -and (Get-Date) -lt $deadline)
        if (-not $listening) { throw 'The AD API listener did not return after the policy update.' }
    }
    Remove-Item -LiteralPath $replaceBackupPath -Force -ErrorAction SilentlyContinue
} catch {
    Copy-Item -LiteralPath $backupPath -Destination $configPath -Force
    if ($wasRunning) {
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        $recoveryDeadline = (Get-Date).AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 500
            $recovered = [bool](Get-NetTCPConnection -State Listen -LocalPort 47810 -ErrorAction SilentlyContinue)
        } while (-not $recovered -and (Get-Date) -lt $recoveryDeadline)
        if (-not $recovered) { throw "Policy update failed and the API listener did not recover. Original config is at $backupPath. $($_.Exception.Message)" }
    }
    throw
} finally {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $replaceBackupPath -Force -ErrorAction SilentlyContinue
}
Write-Output "Allowed group added: $($group.SamAccountName) ($GroupSid)."
Write-Output "Original service config backup: $backupPath"
Write-Output 'No workstation local Administrators mapping was changed.'
