param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string] $ExpectedSha256
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this update from an elevated PowerShell session.'
}

$source = Join-Path $env:PUBLIC 'Documents\ThessleyADQrViewer-wake-fix.exe'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider'
$target = Join-Path $installDir 'ThessleyADQrViewer-wake-safe.exe'
$referenceViewer = Join-Path $installDir 'ThessleyADQrViewer.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Staged QR viewer not found: $source" }
if (-not (Test-Path -LiteralPath $referenceViewer -PathType Leaf)) { throw "Installed QR viewer not found: $referenceViewer" }
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
    throw 'Staged QR viewer SHA-256 does not match the expected build.'
}

$temporary = Join-Path $installDir "ThessleyADQrViewer-wake-safe.new-$($ExpectedSha256.ToUpperInvariant()).exe"
try {
    Copy-Item -LiteralPath $source -Destination $temporary -Force
    Set-Acl -LiteralPath $temporary -AclObject (Get-Acl -LiteralPath $referenceViewer)
    if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
        throw 'Staged QR viewer copy failed SHA-256 verification.'
    }
    Move-Item -LiteralPath $temporary -Destination $target -Force
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
        throw 'Installed QR viewer failed SHA-256 verification.'
    }
} catch {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    throw
}

Write-Output "QR viewer updated and verified ($ExpectedSha256)."
Write-Output "Installed side-by-side: $target"
Write-Output 'No credential-provider registration, policy, or rollback task was changed.'
