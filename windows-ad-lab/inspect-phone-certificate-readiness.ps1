[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9 _-]{1,64}$')]
    [string]$TemplateName = 'Copy 2 of Smartcard Logon'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$rootDse = Get-ADRootDSE
$templateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
$template = Get-ADObject -SearchBase $templateBase -LDAPFilter "(cn=$TemplateName)" -Properties `
    displayName, msPKI-RA-Signature, msPKI-Minimal-Key-Size, pKIExtendedKeyUsage,
    msPKI-Certificate-Application-Policy

if (-not $template) {
    throw "Certificate template '$TemplateName' was not found in AD."
}

$caBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
$cas = @(Get-ADObject -SearchBase $caBase -LDAPFilter '(objectClass=pKIEnrollmentService)' `
    -Properties dNSHostName, certificateTemplates, displayName)
$publishedBy = @($cas | Where-Object { $_.certificateTemplates -contains $template.Name })

$enrollRight = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$templateAcl = Get-Acl -Path "AD:\$($template.DistinguishedName)"
$enrollers = @($templateAcl.Access | Where-Object {
    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
    $_.ObjectType -eq $enrollRight
} | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)

$agentOid = '1.3.6.1.4.1.311.20.2.1'
$agentCerts = @(
    Get-ChildItem Cert:\LocalMachine\My, Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.EnhancedKeyUsageList.ObjectId.Value -contains $agentOid } |
        Select-Object @{Name='Store';Expression={$_.PSParentPath}}, Subject, Thumbprint, NotAfter, HasPrivateKey
)

$caService = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
$caConfigRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$caConfig = Get-ChildItem -Path $caConfigRoot -ErrorAction SilentlyContinue | Select-Object -First 1
$policyPath = if ($caConfig) {
    Join-Path $caConfig.PSPath 'PolicyModules\CertificateAuthority_MicrosoftDefault.Policy'
}
$policy = if ($policyPath) { Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue }

[pscustomobject]@{
    Check = 'Template'
    Value = "$($template.Name) / $($template.displayName)"
}
[pscustomobject]@{
    Check = 'Published by CA'
    Value = if ($publishedBy.Count) { ($publishedBy | ForEach-Object displayName) -join ', ' } else { 'No' }
}
[pscustomobject]@{
    Check = 'Enrollment Agent signatures required'
    Value = [int]$template.'msPKI-RA-Signature'
}
[pscustomobject]@{
    Check = 'Minimum key size'
    Value = [int]$template.'msPKI-Minimal-Key-Size'
}
[pscustomobject]@{
    Check = 'Template EKUs'
    Value = (@($template.pKIExtendedKeyUsage) -join ', ')
}
[pscustomobject]@{
    Check = 'Template application policy OIDs'
    Value = (@($template.'msPKI-Certificate-Application-Policy') -join ', ')
}
[pscustomobject]@{
    Check = 'Direct Certificate-Enrollment ACEs'
    Value = if ($enrollers.Count) { $enrollers -join ', ' } else { 'None found' }
}
[pscustomobject]@{
    Check = 'Enrollment Agent certs in current-user / machine stores'
    Value = if ($agentCerts.Count) { $agentCerts.Count } else { 'None found' }
}
[pscustomobject]@{
    Check = 'CA service'
    Value = if ($caService) { $caService.Status } else { 'Not found' }
}
[pscustomobject]@{
    Check = 'CA policy EditFlags (hex)'
    Value = if ($policy) { '0x{0:X}' -f [int]$policy.EditFlags } else { 'Not readable' }
}

if ($agentCerts.Count) {
    $agentCerts | Format-List
}

Write-Output ''
Write-Output 'Read-only inventory only. It does not change templates, CA settings, certificates, or Windows sign-in.'
Write-Output 'This inventory does not inspect CA Enrollment Agent Restrictions; inspect those in the Certification Authority console before publication.'
Write-Output 'A clean inventory is not proof of strong SID mapping or successful KDC PKINIT; inspect an issued pilot certificate and verify a fresh KDC logon separately.'
