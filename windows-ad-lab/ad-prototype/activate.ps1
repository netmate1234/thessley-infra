#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$root = Join-Path $env:ProgramData 'ThessleyPamWin'
$live = Join-Path $root 'ad-prototype'
$stage = Join-Path $root 'ad-prototype.new'
$backup = Join-Path $root ('ad-prototype.backup-' + (Get-Date -Format 'yyyyMMddHHmmss'))
$failed = Join-Path $root ('ad-prototype.failed-' + (Get-Date -Format 'yyyyMMddHHmmss'))
$python = Join-Path $env:ProgramFiles 'Python313\python.exe'

if (-not (Test-Path -LiteralPath $stage -PathType Container)) {
    throw "Staged AD prototype is missing: $stage"
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Machine Python is missing: $python"
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
    & (Join-Path $live 'install-start-menu-shortcut.ps1')
    Write-Output "Isolated AD prototype installed at $live"
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
