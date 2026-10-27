param(
    [string] $ExpectedDomain = 'THESSLEYLAB',
    [string] $ExpectedUpn = 'martin@lab.thessley.test'
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$expectedName = "$ExpectedDomain\$($ExpectedUpn.Split('@')[0])"
$smartCardOid = '1.3.6.1.4.1.311.20.2.2'
$clientAuthOid = '1.3.6.1.5.5.7.3.2'
$sidExtensionOid = '1.3.6.1.4.1.311.25.2'

Write-Host 'Read-only SmartcardLogon certificate verification' -ForegroundColor Cyan
Write-Host "Current account: $($identity.Name)"
Write-Host "Current SID: $($identity.User.Value)"

if ($identity.Name -ine $expectedName) {
    Write-Error "Sign in as $expectedName before running this verifier."
    exit 1
}

$certificates = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value }) -contains $smartCardOid
})

if (-not $certificates) {
    Write-Error "No SmartcardLogon certificate is installed in this domain user's personal certificate store."
    exit 1
}

$failed = $false
foreach ($certificate in $certificates) {
    $upn = $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::UpnName, $false)
    $ekuOids = @($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    $sidExtension = $certificate.Extensions | Where-Object { $_.Oid.Value -eq $sidExtensionOid } | Select-Object -First 1
    $embeddedSid = if ($sidExtension) {
        $raw = [Text.Encoding]::ASCII.GetString($sidExtension.RawData)
        $match = [regex]::Match($raw, 'S-1-5-(?:\d+-)+\d+')
        if ($match.Success) { $match.Value } else { $null }
    } else { $null }

    $checks = [ordered]@{
        'Smart Card Logon EKU' = $ekuOids -contains $smartCardOid
        'Client Authentication EKU' = $ekuOids -contains $clientAuthOid
        'UPN matches domain account' = $upn -ieq $ExpectedUpn
        'SID extension matches current account' = $embeddedSid -eq $identity.User.Value
        'Private key present' = $certificate.HasPrivateKey
        'Certificate is current' = $certificate.NotBefore -le (Get-Date) -and $certificate.NotAfter -gt (Get-Date)
    }

    Write-Host ''
    Write-Host "Certificate: $($certificate.Thumbprint)"
    Write-Host "Subject: $($certificate.Subject)"
    Write-Host "UPN: $upn"
    Write-Host "SID in certificate: $(if ($embeddedSid) { $embeddedSid } else { 'missing or unreadable' })"
    Write-Host "Valid until: $($certificate.NotAfter.ToString('u'))"
    foreach ($check in $checks.GetEnumerator()) {
        $state = if ($check.Value) { 'PASS' } else { 'FAIL' }
        Write-Host ("{0}: {1}" -f $state, $check.Key)
        if (-not $check.Value) { $failed = $true }
    }
}

Write-Host ''
Write-Host 'This only checks the user certificate and SID binding. It does not prove Windows PKINIT sign-in or phone-backed private-key signing.'
if ($failed) { exit 1 }
