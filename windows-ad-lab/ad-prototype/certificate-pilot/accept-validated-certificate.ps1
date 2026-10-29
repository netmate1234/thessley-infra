#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][Guid] $RequestId,
    [Parameter(Mandatory = $true)][string] $CertificatePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $ExpectedSha256
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ThessleyPamWin\ad-agent\certificate-requests'))
$id = $RequestId.ToString('N')
$manifestPath = Join-Path $root "$id.json"
$requestStore = "Cert:\LocalMachine\Request"
$myStore = "Cert:\LocalMachine\My"
$manifest = $null
$certificate = $null
$requestCertificate = $null
$installed = $null
$sha = $null
$key = $null

function Save-Manifest($Data) {
    $temporaryPath = "$manifestPath.new"
    if (Test-Path -LiteralPath $temporaryPath) {
        $temporary = Get-Item -LiteralPath $temporaryPath -Force
        if (($temporary.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The temporary manifest path is a reparse point.'
        }
        throw 'A prior manifest update is incomplete; preserve it for recovery.'
    }
    $json = $Data | ConvertTo-Json -Compress
    $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        [Array]::Clear($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    Move-Item -LiteralPath $temporaryPath -Destination $manifestPath -Force | Out-Null
}

try {
    foreach ($path in @($root, $manifestPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A protected request path is a reparse point.'
        }
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.version -ne 1 -or [string]$manifest.request_id -cne $id -or
        [string]$manifest.provider_name -cne 'Microsoft Software Key Storage Provider' -or
        $manifest.provider_type -ne 0 -or $manifest.key_spec -ne 0 -or
        $manifest.machine_key -ne $true -or $manifest.exportable -ne $false -or
        [string]$manifest.key_container -cne "ThessleyAD-$id" -or
        [string]$manifest.request_subject -cne "CN=Thessley temporary sign-in $id" -or
        [string]$manifest.csr_path -cne (Join-Path $root "$id.csr.der") -or
        [string]$manifest.csr_sha256 -notmatch '^[a-f0-9]{64}$' -or
        [string]$manifest.request_thumbprint -notmatch '^[a-fA-F0-9]{40}$' -or
        $manifest.state -notin @('ready', 'installing', 'certificate-installed')) {
        throw 'The protected CSR manifest does not match this generated request.'
    }
    $expires = [DateTime]::Parse([string]$manifest.expires_utc).ToUniversalTime()
    if ($expires -le [DateTime]::UtcNow) { throw 'The local key-retention window has expired.' }

    $fullCertificatePath = [IO.Path]::GetFullPath($CertificatePath)
    $file = Get-Item -LiteralPath $fullCertificatePath -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -lt 256 -or $file.Length -gt 64KB) {
        throw 'The certificate path is a reparse point or its size is outside the accepted bounds.'
    }
    $certificateBytes = [IO.File]::ReadAllBytes($fullCertificatePath)
    $sha = [Security.Cryptography.SHA256]::Create()
    $digest = ([BitConverter]::ToString($sha.ComputeHash($certificateBytes))).Replace('-', '').ToLowerInvariant()
    if ($digest -cne $ExpectedSha256.ToLowerInvariant()) { throw 'The certificate digest differs from the Thessley fetch receipt.' }
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$certificateBytes)
    [Array]::Clear($certificateBytes, 0, $certificateBytes.Length)
    if ($certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
        throw 'The fetched certificate is not currently valid.'
    }
    $ekuExtension = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if (-not $ekuExtension) { throw 'The fetched certificate has no EKU extension.' }
    $eku = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension -ArgumentList $ekuExtension, $false
    if (-not (@($eku.EnhancedKeyUsages | ForEach-Object { $_.Value }) -contains '1.3.6.1.4.1.311.20.2.2')) {
        throw 'The fetched certificate is not marked for Smart Card Logon.'
    }

    $thumbprint = ([string]$certificate.Thumbprint).ToUpperInvariant()
    $installedPath = Join-Path $myStore $thumbprint
    $installed = Get-Item -LiteralPath $installedPath -ErrorAction SilentlyContinue
    if (-not $installed -and $manifest.state -eq 'certificate-installed') {
        throw 'The manifest says this certificate was installed, but it is missing from LocalMachine\My.'
    }
    if (-not $installed) {
        $requestThumbprint = ([string]$manifest.request_thumbprint).ToUpperInvariant()
        $requestPath = Join-Path $requestStore $requestThumbprint
        $requestCertificate = Get-Item -LiteralPath $requestPath -ErrorAction Stop
        if ([string]$requestCertificate.Thumbprint -cne $requestThumbprint -or
            [string]$requestCertificate.Subject -cne [string]$manifest.request_subject -or
            [string]$requestCertificate.PublicKey.Oid.Value -cne [string]$certificate.PublicKey.Oid.Value -or
            -not [Convert]::ToBase64String($requestCertificate.GetPublicKey()).Equals(
                [Convert]::ToBase64String($certificate.GetPublicKey()), [StringComparison]::Ordinal)) {
            throw 'The issued certificate public key does not match the exact pending machine request.'
        }
        if ($manifest.state -eq 'ready') {
            $manifest.state = 'installing'
            Save-Manifest $manifest
        }
        $null = & "$env:SystemRoot\System32\certreq.exe" -accept -machine $fullCertificatePath 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -accept failed with exit code $LASTEXITCODE. The manifest was retained for retry/recovery." }
        $installed = Get-Item -LiteralPath $installedPath -ErrorAction Stop
    }
    if ([string]$installed.Thumbprint -cne $thumbprint -or -not $installed.HasPrivateKey -or
        [string]$installed.PublicKey.Oid.Value -cne [string]$certificate.PublicKey.Oid.Value -or
        -not [Convert]::ToBase64String($installed.GetPublicKey()).Equals(
            [Convert]::ToBase64String($certificate.GetPublicKey()), [StringComparison]::Ordinal)) {
        throw 'Windows did not install the exact certificate with its matching machine private key.'
    }
    $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($installed)
    if ($null -eq $key) { throw 'The installed certificate does not expose its RSA private key.' }

    $manifest.state = 'certificate-installed'
    $manifest | Add-Member -NotePropertyName installed_certificate_thumbprint -NotePropertyValue $thumbprint -Force | Out-Null
    $manifest | Add-Member -NotePropertyName installed_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force | Out-Null
    Save-Manifest $manifest
    [pscustomobject]@{
        status = 'certificate-installed-and-key-linked'
        request_id = $id
        certificate_thumbprint = $thumbprint
        certificate_sha256 = $digest
        store = 'Cert:\LocalMachine\My'
        sign_in_enabled = $false
    } | ConvertTo-Json -Compress
}
finally {
    if ($key) { $key.Dispose() }
    if ($installed) { $installed.Dispose() }
    if ($requestCertificate) { $requestCertificate.Dispose() }
    if ($certificate) { $certificate.Dispose() }
    if ($sha) { $sha.Dispose() }
}
