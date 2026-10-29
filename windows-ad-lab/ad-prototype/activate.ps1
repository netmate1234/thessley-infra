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

# The launchers are part of the installed interface, not optional decoration.
# Recreate them in staging so a truncated/missing .cmd in a download cannot
# silently leave an apparently installed but unusable AD CLI or enrollment UI.
$testLauncher = @'
@echo off
setlocal
set "ROOT=%ProgramData%\ThessleyPamWin\ad-prototype"
set "PYTHON=%ProgramFiles%\Python313\python.exe"
if not exist "%PYTHON%" (
  echo Machine Python was not found at "%PYTHON%".
  exit /b 1
)
"%PYTHON%" -I -X utf8 "%ROOT%\ad_main.py" %*
exit /b %ERRORLEVEL%
'@
$enrollLauncher = @'
@echo off
setlocal
set "ROOT=%ProgramData%\ThessleyPamWin\ad-prototype"
set "PYTHONW=%ProgramFiles%\Python313\pythonw.exe"
if not exist "%PYTHONW%" (
  echo Machine Python with Tkinter was not found at "%PYTHONW%".
  pause
  exit /b 1
)
start "Thessley AD phone enrollment" "%PYTHONW%" -I -X utf8 "%ROOT%\ad_enroll_gui.py"
'@
$testLauncherPath = Join-Path $stage 'thessley-ad-test.cmd'
$enrollLauncherPath = Join-Path $stage 'thessley-ad-enroll.cmd'
[IO.File]::WriteAllText($testLauncherPath, $testLauncher, [Text.Encoding]::ASCII)
[IO.File]::WriteAllText($enrollLauncherPath, $enrollLauncher, [Text.Encoding]::ASCII)
foreach ($required in @(
    (Join-Path $stage 'ad_main.py'),
    (Join-Path $stage 'ad_enroll_gui.py'),
    $testLauncherPath,
    $enrollLauncherPath
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf) -or
        (Get-Item -LiteralPath $required).Length -eq 0) {
        throw "Required AD prototype file is missing or empty: $required"
    }
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
    $installedTestLauncher = Join-Path $live 'thessley-ad-test.cmd'
    if ((Get-Item -LiteralPath $installedTestLauncher).Length -eq 0) {
        throw 'The installed AD test launcher is empty.'
    }
    & $installedTestLauncher --help *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "The installed AD test launcher check failed with exit code $LASTEXITCODE."
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
