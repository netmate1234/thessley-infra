#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$root = Join-Path $env:ProgramData 'ThessleyPamWin'
$live = Join-Path $root 'ad-prototype'
$stage = Join-Path $root 'ad-prototype.new'
$backup = Join-Path $root ('ad-prototype.backup-' + (Get-Date -Format 'yyyyMMddHHmmss'))
$failed = Join-Path $root ('ad-prototype.failed-' + (Get-Date -Format 'yyyyMMddHHmmss'))
$python = Join-Path $env:ProgramFiles 'Python313\python.exe'
$pythonw = Join-Path $env:ProgramFiles 'Python313\pythonw.exe'
$icon = Join-Path $live 'thessley.ico'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Thessley'
$shortcut = Join-Path $startMenu 'Add phone for Windows sign-in.lnk'

if (-not (Test-Path -LiteralPath $stage -PathType Container)) {
    throw "Staged AD prototype is missing: $stage"
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Machine Python is missing: $python"
}
if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) {
    throw "Machine Python without a console window is missing: $pythonw"
}

$hadPrevious = Test-Path -LiteralPath $live -PathType Container
if ($hadPrevious) {
    Move-Item -LiteralPath $live -Destination $backup
}

try {
    Move-Item -LiteralPath $stage -Destination $live
    & $python -I -X utf8 (Join-Path $live 'ad_main.py') --help *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "The isolated AD prototype import check failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) {
        throw "The Thessley enrollment icon is missing: $icon"
    }
    New-Item -ItemType Directory -Path $startMenu -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    $link.TargetPath = $pythonw
    $link.Arguments = "-I -X utf8 `"$(Join-Path $live 'ad_enroll_gui.py')`""
    $link.WorkingDirectory = $live
    $link.IconLocation = "$icon,0"
    $link.Description = 'Enroll the signed-in Windows account phone with Thessley Passkey.'
    $link.Save()
    Write-Output "Isolated AD prototype installed at $live"
    Write-Output "Start Menu shortcut installed: $shortcut"
    if ($hadPrevious) {
        Write-Output "Previous isolated prototype retained at $backup"
    }
}
catch {
    if (Test-Path -LiteralPath $live -PathType Container) {
        Move-Item -LiteralPath $live -Destination $failed
    }
    if ($hadPrevious -and (Test-Path -LiteralPath $backup -PathType Container)) {
        Move-Item -LiteralPath $backup -Destination $live
    }
    throw
}
