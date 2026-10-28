<#
.SYNOPSIS
  Read-only inspection of Martin's existing TPM virtual-smart-card certificate.
.DESCRIPTION
  Run from an interactive THESSLEYLAB\martin PowerShell session on the joined
  client. The local SSH maintenance identity has a different CurrentUser store.
  This script does not enroll, remove, export, or use the private key.
#>
[CmdletBinding()]
param(
    [string]$Thumbprint = '12693C9F323CC1F4C54616237F10ECC2ABA7CBF1'
)

$ErrorActionPreference = 'Stop'
$normalizedThumbprint = ($Thumbprint -replace '\s', '').ToUpperInvariant()

if ($env:USERDOMAIN -ne 'THESSLEYLAB' -or $env:USERNAME -ne 'martin') {
    throw 'Run this read-only check from the interactive THESSLEYLAB\martin session, not the local SSH maintenance account.'
}

$certificate = Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' |
    Where-Object { $_.Thumbprint -eq $normalizedThumbprint } |
    Select-Object -First 1

if (-not $certificate) {
    throw "Certificate $normalizedThumbprint is not visible in this user's Personal certificate store. No certificate was changed."
}

$eku = @(
    foreach ($extension in $certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $extension.EnhancedKeyUsages) {
                '{0} ({1})' -f $oid.FriendlyName, $oid.Value
            }
        }
    }
)

Write-Host 'Read-only certificate metadata (no private-key operation performed)' -ForegroundColor Cyan
[pscustomobject]@{
    Subject       = $certificate.Subject
    Issuer        = $certificate.Issuer
    Thumbprint    = $certificate.Thumbprint
    NotBefore     = $certificate.NotBefore
    NotAfter      = $certificate.NotAfter
    HasPrivateKey = $certificate.HasPrivateKey
    EKUs          = $eku -join '; '
} | Format-List

Write-Host 'Provider/container metadata from certutil (read-only):' -ForegroundColor Cyan
& certutil.exe -user -store My $normalizedThumbprint
if ($LASTEXITCODE -ne 0) {
    throw "certutil could not inspect the user certificate (exit $LASTEXITCODE). No certificate was changed."
}

Write-Host 'No enrollment, removal, export, or private-key signing was performed.' -ForegroundColor Green
