#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][Guid] $RequestId,
    [Parameter(Mandatory = $true)][switch] $ConfirmCertificateRevoked
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'ThessleyPamWin\ad-agent\certificate-requests'))
$id = $RequestId.ToString('N')
$manifestPath = Join-Path $root "$id.json"
$manifest = $null

try {
    foreach ($path in @($root, $manifestPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A protected request path is a reparse point.'
        }
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.version -ne 1 -or $manifest.state -ne 'certificate-installed' -or
        [string]$manifest.request_id -cne $id -or
        [string]$manifest.provider_name -cne 'Microsoft Software Key Storage Provider' -or
        [string]$manifest.key_container -cne "ThessleyAD-$id" -or
        [string]$manifest.installed_certificate_thumbprint -notmatch '^[A-Fa-f0-9]{40}$' -or
        [string]$manifest.csr_path -cne (Join-Path $root "$id.csr.der")) {
        throw 'The manifest does not identify a completed Thessley certificate installation.'
    }
    $thumbprint = ([string]$manifest.installed_certificate_thumbprint).ToUpperInvariant()
    $csrPath = Join-Path $root "$id.csr.der"
    if (Test-Path -LiteralPath $csrPath) {
        $csr = Get-Item -LiteralPath $csrPath -Force
        if (($csr.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The CSR path is a reparse point; nothing was removed.'
        }
    }
    $certificatePath = "Cert:\LocalMachine\My\$thumbprint"
    $certificate = Get-Item -LiteralPath $certificatePath -ErrorAction SilentlyContinue
    if ($certificate) {
        if ([string]$certificate.Thumbprint -cne $thumbprint) {
            throw 'The LocalMachine certificate does not match the protected manifest.'
        }
        Remove-Item -LiteralPath $certificatePath -Force
    }

    & "$env:SystemRoot\System32\certutil.exe" -delkey -csp 'Microsoft Software Key Storage Provider' ([string]$manifest.key_container) *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows could not delete the generated private key. The protected manifest was retained.'
    }
    if (Test-Path -LiteralPath $csrPath) {
        Remove-Item -LiteralPath $csrPath -Force
    }
    Remove-Item -LiteralPath $manifestPath -Force
    Write-Output "Removed the locally installed certificate and generated key for request $id."
}
finally {
    if ($certificate) { $certificate.Dispose() }
}
