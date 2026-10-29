#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CsrPath,
    [Parameter(Mandatory = $true)][string] $ExpectedCsrSha256,
    [Parameter(Mandatory = $true)][string] $ThessleyRequestId,
    [Parameter(Mandatory = $true)][string] $MachineId,
    [Parameter(Mandatory = $true)][string] $RequesterName,
    [Parameter(Mandatory = $true)][string] $TemplateName,
    [Parameter(Mandatory = $true)][string] $EnrollmentAgentThumbprint
)

$ErrorActionPreference = 'Stop'

# Builds a signed CMC/EOBO request for review only. This script never submits
# the request to AD CS and never exports the Enrollment Agent private key.
# Keep the Enrollment Agent key on the central domain controller. Do not copy
# this helper or that key to an enrolled workstation.
$comObjects = [System.Collections.Generic.List[object]]::new()
$signingCertificate = $null
$certificateStore = $null
$chain = $null
$csrDer = $null
$hash = $null

try {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    if (-not $computer.PartOfDomain -or [int]$computer.DomainRole -notin @(4, 5)) {
        throw 'This issuer helper may run only on a domain controller; keep the Enrollment Agent key off workstations.'
    }
    if ($ExpectedCsrSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The approved CSR digest must be 64 lowercase hexadecimal characters.'
    }
    if ($ThessleyRequestId -cnotmatch '^[A-Za-z0-9_-]{8,128}$') {
        throw 'The Thessley request ID is invalid.'
    }
    if ($MachineId -cnotmatch '^[a-f0-9]{32}$') {
        throw 'The paired machine ID is invalid.'
    }
    if ($RequesterName -notmatch '^[A-Za-z0-9_.@-]{1,128}\\[A-Za-z0-9_.-]{1,64}$') {
        throw 'RequesterName must be a qualified AD account name.'
    }
    if ($TemplateName -notmatch '^[A-Za-z0-9_-]{1,64}$') {
        throw 'The certificate template name is invalid.'
    }
    $agentThumbprint = ($EnrollmentAgentThumbprint -replace '\s', '').ToUpperInvariant()
    if ($agentThumbprint -notmatch '^[A-F0-9]{40}$') {
        throw 'Enrollment Agent thumbprint must be a 40-character SHA-1 certificate thumbprint.'
    }

    $csrItem = Get-Item -LiteralPath $CsrPath -Force
    if ($csrItem.PSIsContainer -or ($csrItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The CSR path must be a regular file, not a directory or reparse point.'
    }
    $csrDer = [IO.File]::ReadAllBytes($csrItem.FullName)
    if ($csrDer.Length -lt 256 -or $csrDer.Length -gt 32KB) {
        throw 'The DER CSR is outside the allowed size range.'
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    # Keep this helper compatible with Windows PowerShell 5.1/.NET Framework.
    $digestBytes = $hash.ComputeHash($csrDer)
    $actualDigest = ([BitConverter]::ToString($digestBytes)).Replace('-', '').ToLowerInvariant()
    [Array]::Clear($digestBytes, 0, $digestBytes.Length)
    if (-not [string]::Equals($actualDigest, $ExpectedCsrSha256, [StringComparison]::Ordinal)) {
        throw 'The CSR file does not match the digest approved by the phone.'
    }

    $certificateStore = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::My,
        [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $certificateStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matches = @($certificateStore.Certificates | Where-Object {
        $_.Thumbprint -and $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -ceq $agentThumbprint
    })
    if ($matches.Count -ne 1) { throw 'The configured Enrollment Agent certificate is missing or ambiguous.' }
    $signingCertificate = $matches[0]
    $now = [DateTime]::UtcNow
    if (-not $signingCertificate.HasPrivateKey
            -or $now -lt $signingCertificate.NotBefore.ToUniversalTime()
            -or $now -gt $signingCertificate.NotAfter.ToUniversalTime()) {
        throw 'The Enrollment Agent certificate is expired, not yet valid, or has no private key.'
    }
    $ekuExtensions = @($signingCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($ekuExtensions.Count -ne 1) { throw 'The Enrollment Agent certificate must have exactly one EKU extension.' }
    $eku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExtensions[0]
    $agentEku = @($eku.EnhancedKeyUsages | Where-Object {
        $_.Value -eq '1.3.6.1.4.1.311.20.2.1'
    })
    if ($agentEku.Count -ne 1) {
        throw 'The configured signer lacks the Certificate Request Agent EKU.'
    }
    $keyUsageExtensions = @($signingCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
    if ($keyUsageExtensions.Count -ne 1) { throw 'The Enrollment Agent certificate must have exactly one Key Usage extension.' }
    $keyUsage = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]$keyUsageExtensions[0]
    if (($keyUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
        throw 'The Enrollment Agent certificate is not permitted to sign certificate requests.'
    }
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
    $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
    if (-not $chain.Build($signingCertificate)) {
        $chainErrors = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() } | Select-Object -Unique)
        throw "The Enrollment Agent chain or revocation check failed: $($chainErrors -join ', ')."
    }

    $pkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    $comObjects.Add($pkcs10)
    $pkcs10.InitializeDecode([Convert]::ToBase64String($csrDer), 1)

    $cmc = New-Object -ComObject X509Enrollment.CX509CertificateRequestCmc
    $comObjects.Add($cmc)
    $cmc.InitializeFromInnerRequestTemplateName($pkcs10, $TemplateName)
    $cmc.RequesterName = $RequesterName

    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
    $comObjects.Add($signer)
    # XCN_CRYPT_STRING_HEXRAW=12; VerifySilent=1. The private key stays in
    # LocalMachine\My and is used through its KSP/CSP without export.
    $signer.Initialize($true, 1, 12, $agentThumbprint)
    $signer.Silent = $true
    $null = $cmc.SignerCertificates.Add($signer)

    $enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
    $comObjects.Add($enrollment)
    $enrollment.InitializeFromRequest($cmc)
    $cmcBase64 = [string]$enrollment.CreateRequest(1)
    $cmcBase64 = $cmcBase64 -replace '\s', ''
    if ($cmcBase64.Length -lt 256 -or $cmcBase64.Length -gt 128KB) {
        throw 'CertEnroll returned an invalid or oversized CMC request.'
    }

    [ordered]@{
        result = 'eobo_cmc_prepared'
        submitted = $false
        thessley_request_id = $ThessleyRequestId
        machine_id = $MachineId
        csr_sha256 = $actualDigest
        requester = $RequesterName
        template = $TemplateName
        enrollment_agent_thumbprint = $agentThumbprint
        cmc_base64 = $cmcBase64
    } | ConvertTo-Json -Compress
}
finally {
    if ($chain) { $chain.Dispose() }
    if ($signingCertificate) { $signingCertificate.Dispose() }
    if ($certificateStore) { $certificateStore.Close(); $certificateStore.Dispose() }
    if ($hash) { $hash.Dispose() }
    if ($csrDer) { [Array]::Clear($csrDer, 0, $csrDer.Length) }
    foreach ($comObject in $comObjects) {
        if ([Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
            try { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject) | Out-Null } catch { }
        }
    }
}
