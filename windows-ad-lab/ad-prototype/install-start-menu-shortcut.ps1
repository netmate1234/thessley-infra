#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$root = Join-Path $env:ProgramData 'ThessleyPamWin\ad-prototype'
$gui = Join-Path $root 'ad_enroll_gui.py'
$pythonw = Join-Path $env:ProgramFiles 'Python313\pythonw.exe'
$sourceIcon = Join-Path $PSScriptRoot 'thessley.ico'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Thessley'
$installedIcon = Join-Path $startMenu 'thessley.ico'
$shortcut = Join-Path $startMenu 'Add phone for Windows sign-in.lnk'

foreach ($required in @($gui, $pythonw, $sourceIcon)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required enrollment file is missing: $required"
    }
}

New-Item -ItemType Directory -Path $startMenu -Force | Out-Null
if ([IO.Path]::GetFullPath($sourceIcon) -ne [IO.Path]::GetFullPath($installedIcon)) {
    Copy-Item -LiteralPath $sourceIcon -Destination $installedIcon -Force
}
& icacls.exe $installedIcon /grant '*S-1-5-32-545:R' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not make the Thessley icon readable to Windows Start menu users.' }

$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($shortcut)
$link.TargetPath = $pythonw
$link.Arguments = "-I -X utf8 `"$gui`""
$link.WorkingDirectory = $root
$link.IconLocation = "$installedIcon,0"
$link.Description = 'Enroll the signed-in Windows account phone with Thessley Passkey.'
$link.Save()
Write-Output "Start Menu shortcut installed: $shortcut"
