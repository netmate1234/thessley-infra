# Create a separate lab-only certificate template for a TPM virtual smart card.
# Run elevated on THESSLEY-DC1. The existing SmartcardLogon template is untouched.

$ErrorActionPreference = 'Stop'
$templateName = 'ThessleyVscLogon'
$displayName = 'Thessley TPM Virtual Smart Card Logon'
$sourceTemplate = 'SmartcardLogon'
$provider = 'Microsoft Base Smart Card Crypto Provider'
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module ADCSAdministration -ErrorAction Stop
$configuration = (Get-ADRootDSE).configurationNamingContext
$templateDn = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configuration"
$oidContainerDn = "CN=OID,CN=Public Key Services,CN=Services,$configuration"
$changed = $false

if (-not (Get-Service CertSvc -ErrorAction SilentlyContinue)) {
    throw 'Certificate Services (CertSvc) is not installed on this host.'
}

$existingTemplate = Get-ADObject -Identity $templateDn -ErrorAction SilentlyContinue
if (-not $existingTemplate) {
    $dump = @(& certutil.exe -dsTemplate $sourceTemplate 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) { throw "Could not read the source template '$sourceTemplate'." }

    $lines = @($dump | Where-Object {
        $_ -notmatch '^CertUtil: -dsTemplate command completed successfully\.' -and
        $_ -notmatch '^\s*(whenCreated|whenChanged|uSNCreated|uSNChanged|objectGUID|msPKI-Cert-Template-OID)\s*='
    })
    if ($lines -notcontains "[$sourceTemplate]") { throw 'The source template dump was incomplete.' }

    $lines = @($lines | ForEach-Object {
        $_ -replace '^\[SmartcardLogon\]$', "[$templateName]" `
           -replace '^(\s*cn\s*=\s*)"SmartcardLogon"\s*$', "`$1`"$templateName`"" `
           -replace '^(\s*displayName\s*=\s*).+$', "`$1`"$displayName`"" `
           -replace '^(\s*name\s*=\s*)"SmartcardLogon"\s*$', "`$1`"$templateName`"" `
           -replace '^(\s*distinguishedName\s*=\s*)"CN=SmartcardLogon,', "`$1`"CN=$templateName," `
           -replace '^(\s*Template\s*=\s*)"SmartcardLogon"\s*$', "`$1`"$templateName`""
    })

    if ($lines -notcontains "[$templateName]") { throw 'Failed to rename the cloned template section.' }
    if (-not ($lines -match '^\s*pKIDefaultCSPs\s*=')) {
        $keySpecIndex = -1
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -match '^\s*pKIDefaultKeySpec\s*=') { $keySpecIndex = $index; break }
        }
        if ($keySpecIndex -lt 0) { throw 'Source template has no pKIDefaultKeySpec field.' }
        $lines = @($lines[0..$keySpecIndex]) + "    pKIDefaultCSPs = `"1,$provider`"" + @($lines[($keySpecIndex + 1)..($lines.Count - 1)])
    } else {
        $lines = @($lines | ForEach-Object {
            if ($_ -match '^\s*pKIDefaultCSPs\s*=') { "    pKIDefaultCSPs = `"1,$provider`"" } else { $_ }
        })
    }

    $work = Join-Path $env:ProgramData 'Thessley\ADLab\VscTemplate'
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $templateFile = Join-Path $work "$templateName.inf"
    $lines | Set-Content -LiteralPath $templateFile -Encoding ascii
    & certutil.exe -dsAddTemplate $templateFile
    if ($LASTEXITCODE -ne 0) { throw "Could not add '$templateName' to Active Directory." }
    $changed = $true
}

$template = & certutil.exe -dsTemplate $templateName 2>&1 | ForEach-Object { $_.ToString() }
if ($LASTEXITCODE -ne 0 -or -not ($template -match [regex]::Escape($provider))) {
    throw "Template '$templateName' is missing its required smart-card CSP setting."
}

$martin = Get-ADUser -Identity martin -Properties SID -ErrorAction Stop
$enrollRight = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$templateObject = Get-ADObject -Identity $templateDn -Properties displayName -ErrorAction Stop
if ($templateObject.displayName -ne $displayName) {
    Set-ADObject -Identity $templateDn -Replace @{ displayName = $displayName } -ErrorAction Stop
    $changed = $true
}

# Certificate templates need both an OID value and a corresponding
# msPKI-Enterprise-Oid object in the forest OID container. certutil's
# -dsAddTemplate clone path does not generate either one for this template.
# Use the forest-assigned enterprise OID root; never reuse the source
# SmartcardLogon template's OID.
$templateObject = Get-ADObject -Identity $templateDn -Properties 'msPKI-Cert-Template-OID' -ErrorAction Stop
$templateOid = [string]$templateObject.'msPKI-Cert-Template-OID'
$oidRootObject = Get-ADObject -Identity $oidContainerDn -Properties 'msPKI-Cert-Template-OID' -ErrorAction Stop
$oidRoot = [string]$oidRootObject.'msPKI-Cert-Template-OID'
if ([string]::IsNullOrWhiteSpace($oidRoot)) { throw 'The forest OID container has no enterprise OID root.' }

if ([string]::IsNullOrWhiteSpace($templateOid)) {
    $oidObject = $null
    $attempt = 0
    do {
        $attempt++
        if ($attempt -gt 20) { throw 'Could not allocate a unique certificate-template OID after 20 attempts.' }
        $arc = Get-Random -Minimum 10000000 -Maximum 99999999
        $candidateOid = "$oidRoot.1.$arc"
        $oidObject = Get-ADObject -SearchBase $oidContainerDn -LDAPFilter "(msPKI-Cert-Template-OID=$candidateOid)" -ErrorAction Stop
    } while ($oidObject)

    $oidObjectName = "1.$arc.$([guid]::NewGuid().ToString('N').ToUpperInvariant())"
    $newOidObject = New-ADObject -Name $oidObjectName -Type 'msPKI-Enterprise-Oid' -Path $oidContainerDn -PassThru `
        -OtherAttributes @{
            displayName = $displayName
            flags = [int]1
            'msPKI-Cert-Template-OID' = $candidateOid
        } -ErrorAction Stop
    try {
        Set-ADObject -Identity $templateDn -Replace @{ 'msPKI-Cert-Template-OID' = $candidateOid } -ErrorAction Stop
    } catch {
        Remove-ADObject -Identity $newOidObject.DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
        throw
    }
    $templateOid = $candidateOid
    $changed = $true
} else {
    $oidObject = Get-ADObject -SearchBase $oidContainerDn -LDAPFilter "(msPKI-Cert-Template-OID=$templateOid)" -ErrorAction Stop
    if (-not $oidObject) {
        # Repair a partially created template by registering its already
        # assigned OID rather than silently issuing a different identifier.
        $lastArc = ($templateOid -split '\.')[-1]
        $oidObjectName = "1.$lastArc.$([guid]::NewGuid().ToString('N').ToUpperInvariant())"
        New-ADObject -Name $oidObjectName -Type 'msPKI-Enterprise-Oid' -Path $oidContainerDn -OtherAttributes @{
            displayName = $displayName
            flags = [int]1
            'msPKI-Cert-Template-OID' = $templateOid
        } -ErrorAction Stop
        $changed = $true
    }
}

$martinSid = $martin.SID.Value
$domainSid = (Get-ADDomain).DomainSID.Value
$descriptorLine = $template | Where-Object { $_ -match '^\s*nTSecurityDescriptor\s*=' } | Select-Object -First 1
$expectedEnrollAce = "(OA;;CR;$enrollRight;;$martinSid)"
$expectedAdminAce = "(OA;;RPWPCR;$enrollRight;;DA)"
$expectedEnterpriseAce = "(OA;;RPWPCR;$enrollRight;;$domainSid-519)"
if (-not $descriptorLine -or $descriptorLine -notlike "*$expectedEnrollAce*" -or
    $descriptorLine -notlike "*$expectedAdminAce*" -or
    $descriptorLine -notlike "*$expectedEnterpriseAce*" -or
    $descriptorLine -match "\(OA;;[^)]*;$enrollRight;;AU\)") {
    throw 'The cloned template enrollment ACL is not restricted to Martin and the domain administration groups.'
}

$issuedTemplates = (& certutil.exe -CATemplates 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Could not read the templates currently issued by this CA.' }
if ($issuedTemplates -notmatch [regex]::Escape($templateName)) {
    Add-CATemplate -Name $templateName -Confirm:$false -ErrorAction Stop | Out-Null
    $changed = $true
}

if ($changed) { Restart-Service CertSvc -ErrorAction Stop }
$issuedTemplates = (& certutil.exe -CATemplates 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
if ($LASTEXITCODE -ne 0 -or $issuedTemplates -notmatch [regex]::Escape($templateName)) {
    throw "The CA did not report '$templateName' as an available issuance template."
}

Write-Host "Ready: $displayName"
Write-Host "Template: $templateName"
Write-Host "Template OID: $templateOid"
Write-Host "Provider: $provider"
Write-Host "Enrollment allowed for: THESSLEYLAB\martin (SID $martinSid) plus domain administration groups."
Write-Host 'The original SmartcardLogon template and Windows sign-in providers were not modified.'
