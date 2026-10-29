#Requires -RunAsAdministrator
param(
    [Guid] $RequestId,
    [switch] $SweepExpired,
    [ValidateSet('Expired', 'Cancelled', 'SignInSucceeded')]
    [string] $Reason = 'Expired'
)
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ThessleyPamWin\ad-agent\certificate-requests'))
$providerName = 'Microsoft Software Key Storage Provider'
if (Test-Path -LiteralPath $root) {
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The protected certificate-request folder cannot be a reparse point.'
    }
}
if (-not $SweepExpired -and $RequestId -eq [Guid]::Empty) {
    throw 'Specify one request ID or use -SweepExpired.'
}
if ($SweepExpired -and $RequestId -ne [Guid]::Empty) {
    throw 'Use either -RequestId or -SweepExpired, not both.'
}
if ($SweepExpired -and $Reason -ne 'Expired') {
    throw 'A sweep can remove expired requests only.'
}

$manifests = if ($SweepExpired) {
    @(Get-ChildItem -LiteralPath $root -Filter '*.json' -File -ErrorAction SilentlyContinue)
} else {
    $manifestPath = Join-Path $root ("{0}.json" -f $RequestId.ToString('N'))
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'The request manifest was not found.' }
    ,(Get-Item -LiteralPath $manifestPath)
}

foreach ($file in $manifests) {
    $manifest = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $id = [string]$manifest.request_id
    if ($manifest.version -ne 1 -or $manifest.state -notin @('key-created', 'ready', 'key-deleted') -or
        $id -notmatch '^[a-f0-9]{32}$' -or
        $file.FullName -ne (Join-Path $root "$id.json") -or
        $manifest.provider_name -ne $providerName -or $manifest.provider_type -ne 0 -or
        $manifest.key_spec -ne 0 -or $manifest.machine_key -ne $true -or
        $manifest.exportable -ne $false -or
        [string]$manifest.key_container -ne "ThessleyAD-$id" -or
        [string]$manifest.request_subject -ne "CN=Thessley temporary sign-in $id") {
        throw "Refusing to clean an invalid or unexpected CSR manifest: $($file.Name)"
    }
    if ($manifest.state -eq 'ready' -and (
        [string]$manifest.csr_sha256 -notmatch '^[a-f0-9]{64}$' -or
        [string]$manifest.request_thumbprint -notmatch '^[a-fA-F0-9]{40}$')) {
        throw "Refusing to clean an incomplete ready-state manifest: $($file.Name)"
    }
    $csrPath = Join-Path $root "$id.csr.der"
    if ([IO.Path]::GetFullPath([string]$manifest.csr_path) -ne $csrPath) {
        throw "Refusing a CSR path outside the protected request folder: $($file.Name)"
    }
    $expires = [DateTime]::Parse([string]$manifest.expires_utc).ToUniversalTime()
    if ($Reason -eq 'Expired' -and $expires -gt [DateTime]::UtcNow) {
        continue
    }
    if ($Reason -ne 'Expired' -and -not $SweepExpired -and $RequestId.ToString('N') -ne $id) {
        throw 'The requested cleanup ID does not match its manifest.'
    }

    $requestCerts = if ($manifest.state -in @('ready', 'key-deleted') -and
        [string]$manifest.request_thumbprint -match '^[a-fA-F0-9]{40}$') {
        $requestPath = "Cert:\LocalMachine\Request\$($manifest.request_thumbprint)"
        if (Test-Path -LiteralPath $requestPath) { ,(Get-Item -LiteralPath $requestPath) } else { @() }
    } elseif (Test-Path -LiteralPath 'Cert:\LocalMachine\Request') {
        @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\Request' -ErrorAction Stop |
            Where-Object { $_.Subject -eq $manifest.request_subject })
    } else { @() }
    foreach ($requestCert in $requestCerts) {
        if ($requestCert.Subject -ne $manifest.request_subject) {
            throw "The request-store certificate did not match the temporary request $id; it was not removed."
        }
        Remove-Item -LiteralPath $requestCert.PSPath -Force
    }

    if ($manifest.state -ne 'key-deleted') {
        & "$env:SystemRoot\System32\certutil.exe" -delkey -csp $providerName ([string]$manifest.key_container) *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Windows could not delete the temporary CNG key for request $id. The manifest was retained."
        }
        $manifest.state = 'key-deleted'
        $manifest | ConvertTo-Json -Compress | Set-Content -LiteralPath $file.FullName -Encoding UTF8
    }
    if (Test-Path -LiteralPath $csrPath) { Remove-Item -LiteralPath $csrPath -Force }
    Remove-Item -LiteralPath $file.FullName -Force
    Write-Output "Removed temporary certificate request $id ($Reason)."
}
