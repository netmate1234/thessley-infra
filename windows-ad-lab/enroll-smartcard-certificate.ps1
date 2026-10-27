param(
    [string] $ExpectedDomain = 'THESSLEYLAB',
    [string] $ExpectedUpn = 'martin@lab.thessley.test'
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$expectedName = "$ExpectedDomain\$($ExpectedUpn.Split('@')[0])"
$smartCardOid = '1.3.6.1.4.1.311.20.2.2'

function Get-CertificateEkuOids {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if (-not $extension) { return @() }
    $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $extension, $extension.Critical
    )
    return @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
}

if ($identity.Name -ine $expectedName) {
    throw "Sign in as $expectedName before enrolling the lab certificate."
}

$existing = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    (Get-CertificateEkuOids -Certificate $_) -contains $smartCardOid
})

if (-not $existing) {
    Import-Module PKI -ErrorAction Stop
    $result = Get-Certificate -Template 'SmartcardLogon' `
        -CertStoreLocation 'Cert:\CurrentUser\My' -ErrorAction Stop
    if ($result.Status -ne 'Issued') {
        throw "AD CS did not issue the certificate (status: $($result.Status))."
    }
}

$verifier = Join-Path $PSScriptRoot 'verify-smartcard-certificate.ps1'
if (-not (Test-Path -LiteralPath $verifier)) {
    throw "Certificate verifier not found: $verifier"
}
& $verifier -ExpectedDomain $ExpectedDomain -ExpectedUpn $ExpectedUpn
