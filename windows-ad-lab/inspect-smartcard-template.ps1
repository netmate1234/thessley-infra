# Read-only comparison of the source and lab TPM smart-card template objects.
Import-Module ActiveDirectory -ErrorAction Stop
$base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
foreach ($name in @('SmartcardLogon', 'ThessleyVscLogon')) {
    $template = Get-ADObject -LDAPFilter "(cn=$name)" -SearchBase $base -Properties `
        displayName, flags, revision, pKIDefaultCSPs, pKIDefaultKeySpec, pKIKeyUsage,
        pKIExtendedKeyUsage, msPKI-Cert-Template-OID, msPKI-Template-Schema-Version,
        msPKI-Template-Minor-Revision, msPKI-Enrollment-Flag, msPKI-Certificate-Name-Flag
    if (-not $template) { Write-Host "${name}: not found"; continue }
    Write-Host "`n[$name]"
    $template | Format-List Name,displayName,flags,revision,pKIDefaultCSPs,pKIDefaultKeySpec,
        pKIKeyUsage,pKIExtendedKeyUsage,msPKI-Cert-Template-OID,
        msPKI-Template-Schema-Version,msPKI-Template-Minor-Revision,
        msPKI-Enrollment-Flag,msPKI-Certificate-Name-Flag
}
