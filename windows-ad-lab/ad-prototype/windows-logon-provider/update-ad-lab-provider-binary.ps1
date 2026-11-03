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

$source = Join-Path $env:PUBLIC 'Documents\ThessleyADCredentialProvider-request-id-fix.dll'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider'
$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$registration = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$providerId\InprocServer32"
if (-not (Test-Path -LiteralPath $registration)) { throw 'The AD lab provider registration was not found.' }
$target = [string](Get-Item -LiteralPath $registration).GetValue('')
if ([string]::IsNullOrWhiteSpace($target)) { throw 'The registered provider DLL path is empty.' }
$target = [IO.Path]::GetFullPath($target)
if ([IO.Path]::GetDirectoryName($target) -ine [IO.Path]::GetFullPath($installDir) -or
    [IO.Path]::GetFileName($target) -notlike 'ThessleyADCredentialProvider*.dll') {
    throw "Registered provider DLL is outside the Thessley AD lab install directory: $target"
}
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Staged provider DLL not found: $source" }
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Installed provider DLL not found: $target" }
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
    throw 'Staged provider SHA-256 does not match the expected build.'
}

$newTarget = Join-Path $installDir "ThessleyADCredentialProvider-$($ExpectedSha256.ToUpperInvariant()).dll"
$newFileCreated = $false
if (-not (Test-Path -LiteralPath $newTarget -PathType Leaf)) {
    Copy-Item -LiteralPath $source -Destination $newTarget -ErrorAction Stop
    $newFileCreated = $true
}
try {
    if ((Get-FileHash -LiteralPath $newTarget -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
        throw 'Staged versioned provider DLL SHA-256 does not match the expected build.'
    }
    if ($newFileCreated) {
        Set-Acl -LiteralPath $newTarget -AclObject (Get-Acl -LiteralPath $target)
    }

    $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SOFTWARE\Classes\CLSID\$providerId\InprocServer32", $true)
    if (-not $registryKey) { throw 'Could not open the provider registration for update.' }
    $registeredPath = [string]$registryKey.GetValue('')
    if ([IO.Path]::GetFullPath($registeredPath) -ine $target) {
        throw 'The provider registration changed while the update was being prepared.'
    }
    $registryKey.SetValue('', $newTarget, [Microsoft.Win32.RegistryValueKind]::String)
    $registryPathChanged = $true
    $registryKey.Flush()
    if ([IO.Path]::GetFullPath([string]$registryKey.GetValue('')) -ine [IO.Path]::GetFullPath($newTarget)) {
        throw 'The provider registration did not retain the new DLL path.'
    }
} catch {
    if ($registryPathChanged -and $registryKey) {
        try {
            $registryKey.SetValue('', $target, [Microsoft.Win32.RegistryValueKind]::String)
            $registryKey.Flush()
        } catch { }
    }
    if ($newFileCreated) { Remove-Item -LiteralPath $newTarget -Force -ErrorAction SilentlyContinue }
    throw
} finally {
    if ($registryKey) { $registryKey.Dispose() }
}

Write-Output "Provider DLL updated and verified ($ExpectedSha256)."
Write-Output "Registered DLL: $newTarget"
Write-Output "Previous DLL retained: $target"
Write-Output 'No other Credential Provider, rollback task, or sign-in registration was changed.'
