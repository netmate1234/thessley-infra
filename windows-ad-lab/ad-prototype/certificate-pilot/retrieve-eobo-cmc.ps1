#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CAConfig,
    [Parameter(Mandatory = $true)][long] $RequestId
)

$ErrorActionPreference = 'Stop'
$request = $null
try {
    if ($CAConfig -notmatch '^[A-Za-z0-9.-]{1,253}\\[A-Za-z0-9_. -]{1,64}$') {
        throw 'CAConfig must be a configured CA name in ComputerName\CAName form.'
    }
    if ($RequestId -lt 1 -or $RequestId -gt [int]::MaxValue) {
        throw 'The CA request ID must be a positive 32-bit integer.'
    }

    $request = New-Object -ComObject CertificateAuthority.Request
    # RetrievePending updates the COM request object with the current disposition.
    $disposition = [int]$request.RetrievePending([int]$RequestId, $CAConfig)
    if ($disposition -in @(0, 5)) { # CR_DISP_INCOMPLETE / CR_DISP_UNDER_SUBMISSION
        [ordered]@{
            result = 'pending'
            ca_request_id = [int]$RequestId
            disposition = $disposition
        } | ConvertTo-Json -Compress
        return
    }
    if ($disposition -ne 3) { # CR_DISP_ISSUED
        $message = [string]$request.GetDispositionMessage()
        if ($message.Length -gt 240) { $message = $message.Substring(0, 240) }
        throw "The CA request is not issued (disposition $disposition): $message"
    }

    $certificateBase64 = ([string]$request.GetCertificate(1)) -replace '\s', ''
    if ($certificateBase64.Length -lt 344 -or $certificateBase64.Length -gt 87384) {
        throw 'The CA returned an invalid or oversized certificate.'
    }
    $certificateDer = [Convert]::FromBase64String($certificateBase64)
    if ($certificateDer.Length -lt 256 -or $certificateDer.Length -gt 64KB
            -or [Convert]::ToBase64String($certificateDer) -cne $certificateBase64) {
        [Array]::Clear($certificateDer, 0, $certificateDer.Length)
        throw 'The CA response is not a canonical DER certificate.'
    }
    try {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateDer)
        if ($certificate.RawData.Length -ne $certificateDer.Length) {
            throw 'The CA response is not one X.509 leaf certificate.'
        }
        $certificate.Dispose()
        [ordered]@{
            result = 'issued'
            ca_request_id = [int]$RequestId
            certificate_der_b64 = $certificateBase64
        } | ConvertTo-Json -Compress
    }
    finally {
        [Array]::Clear($certificateDer, 0, $certificateDer.Length)
        $certificateBase64 = $null
    }
}
finally {
    if ($null -ne $request -and [Runtime.InteropServices.Marshal]::IsComObject($request)) {
        try { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($request) | Out-Null } catch { }
    }
}
