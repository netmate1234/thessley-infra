param([string] $InstallRoot = "$env:ProgramFiles\ThessleyAD\Python")
$ErrorActionPreference = 'Stop'
$version = '3.13.17'
$url = "https://www.python.org/ftp/python/$version/python-$version-amd64.exe"
$sha256 = '5da012101ba2e17113a9a1cd901e9ce1441086f2b7ecb5de06ec94163899a190'
$installer = Join-Path $env:TEMP "python-$version-amd64.exe"

$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session.'
}
New-Item -ItemType Directory -Path (Split-Path -Parent $InstallRoot) -Force | Out-Null
if (-not (Test-Path -LiteralPath $InstallRoot)) {
    Write-Host "Downloading pinned Python $version from python.org..."
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $sha256) { Remove-Item -LiteralPath $installer -Force; throw 'Python installer SHA-256 did not match.' }
    $arguments = @('/quiet', 'InstallAllUsers=1', "TargetDir=`"$InstallRoot`"", 'Include_launcher=0',
        'Include_pip=1', 'Include_test=0', 'Include_doc=0', 'Include_tcltk=0', 'Include_dev=0',
        'PrependPath=0', 'Shortcuts=0')
    $process = Start-Process -FilePath $installer -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "Python installer failed with exit code $($process.ExitCode)." }
} else {
    Write-Host "Using existing Python at $InstallRoot"
}
$python = Join-Path $InstallRoot 'python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "Python was not installed at $python." }
$installed = & $python -I -c 'import platform; print(platform.python_version())'
if ($LASTEXITCODE -ne 0 -or $installed.Trim() -ne $version) {
    throw "Expected Python $version; found '$($installed.Trim())'."
}
Write-Host 'Installing pinned Thessley AD service dependencies...'
& $python -I -m pip install --disable-pip-version-check --no-warn-script-location --only-binary=:all: 'cryptography==46.0.5' 'qrcode==8.2'
if ($LASTEXITCODE -ne 0) { throw 'Pinned Thessley AD service dependency installation failed.' }
$cryptoVersion = & $python -I -c 'import cryptography; print(cryptography.__version__)'
if ($LASTEXITCODE -ne 0 -or $cryptoVersion.Trim() -ne '46.0.5') {
    throw "Python dependency verification failed (cryptography $($cryptoVersion.Trim()))."
}
$qrVersion = & $python -I -c 'from importlib.metadata import version; print(version("qrcode"))'
if ($LASTEXITCODE -ne 0 -or $qrVersion.Trim() -ne '8.2') {
    throw "Python dependency verification failed (qrcode $($qrVersion.Trim()))."
}
Write-Host "Python $version, cryptography $($cryptoVersion.Trim()), and qrcode $($qrVersion.Trim()) verified."
