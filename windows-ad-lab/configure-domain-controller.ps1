$ErrorActionPreference = 'Stop'

# Thessley disposable AD lab only. This installs AD DS and an Enterprise Root CA
# on the same Server Core VM; do not use this layout in production.
$DomainName = 'lab.thessley.test'
$NetbiosName = 'THESSLEYLAB'
$ServerName = 'THESSLEY-DC1'
$CaName = 'THESSLEY-LAB-CA'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) { throw 'Run this script from an elevated PowerShell prompt.' }

# Put Swedish input first, per the workstation keyboard preference.
$sv = New-WinUserLanguageList -Language 'sv-SE'
Set-WinUserLanguageList -LanguageList $sv -Force
Set-WinDefaultInputMethodOverride -InputTip '041D:0000041D'

if ($env:COMPUTERNAME -ne $ServerName) {
    Rename-Computer -NewName $ServerName -Force
    Write-Host "Renamed this server to $ServerName. Restart it, sign in again, and rerun this script."
    Restart-Computer -Force
    exit
}

$net = Get-NetIPConfiguration | Where-Object {
    $_.IPv4Address | Where-Object { $_.IPAddress -like '192.168.1.*' }
} | Select-Object -First 1
if (-not $net) { throw 'The server has no 192.168.1.x LAN address. Connect the primary NIC to the LAN first.' }
$lanIp = $net.IPv4Address[0].IPv4Address
Write-Host "LAN address: $lanIp; gateway: $($net.IPv4DefaultGateway.NextHop)"

$addsFeature = Get-WindowsFeature AD-Domain-Services
if (-not $addsFeature.Installed) {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Host
}

$forest = $null
try {
    $forest = Get-ADForest -ErrorAction Stop
} catch {
    # A successful promotion can finish before AD DS starts serving queries on
    # the first boot. Detect that specific state and perform one recovery
    # restart instead of trying to promote the server a second time.
    $ntds = Get-CimInstance Win32_Service -Filter "Name='NTDS'" -ErrorAction SilentlyContinue
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $promotionPending = $computer.PartOfDomain -and
        $computer.Domain -ieq $DomainName -and
        $ntds.StartMode -eq 'Auto' -and
        (Test-Path (Join-Path $env:windir 'NTDS\ntds.dit'))
    if ($promotionPending) {
        $markerPath = 'HKLM:\SOFTWARE\Thessley\ADLab'
        $markerName = 'PromotionRecoveryRestarted'
        $alreadyRestarted = (Get-ItemProperty -Path $markerPath -Name $markerName -ErrorAction SilentlyContinue).$markerName
        if (-not $alreadyRestarted) {
            New-Item -Path $markerPath -Force | Out-Null
            Set-ItemProperty -Path $markerPath -Name $markerName -Value 1 -Type DWord
            Write-Host 'The forest is promoted but AD DS is not serving yet. Restarting once to finish startup; rerun this script afterward.'
            Restart-Computer -Force
            exit
        }
        throw 'AD DS is still unavailable after its recovery restart. Check the Directory Service event log before continuing.'
    }
    if ($_.Exception -is [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]) {
        # Expected on the first run, before Install-ADDSForest has promoted this host.
        $forest = $null
    } else {
        throw
    }
}

if ($forest) {
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Thessley\ADLab' -Name 'PromotionRecoveryRestarted' -ErrorAction SilentlyContinue
}
if (-not $forest) {
    # AD CS must not be installed before the first forest/domain-controller
    # promotion. Remove the role if a previous attempt installed both roles.
    $adcsFeature = Get-WindowsFeature ADCS-Cert-Authority
    if ($adcsFeature.Installed) {
        $removeResult = Uninstall-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
        $removeResult | Out-Host
        if ($removeResult.RestartNeeded -eq 'Yes') {
            Write-Host 'Restart required to finish removing AD CS. Rerun this script after the server restarts.'
            Restart-Computer -Force
            exit
        }
    }
    $dsrm = Read-Host 'Enter the Directory Services Restore Mode password' -AsSecureString
    Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $NetbiosName `
        -InstallDNS -SafeModeAdministratorPassword $dsrm -Force -NoRebootOnCompletion
    Write-Host 'Forest promotion completed. Restarting the server to start AD DS and DNS.'
    Restart-Computer -Force
    exit
}

if ($forest.RootDomain.ToLowerInvariant() -ne $DomainName) {
    throw "This server is already in forest '$($forest.RootDomain)', not the expected lab forest '$DomainName'."
}

$adcsFeature = Get-WindowsFeature ADCS-Cert-Authority
if (-not $adcsFeature.Installed) {
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Host
}
Import-Module ADCSDeployment
$caConfigPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$caConfigured = Test-Path -LiteralPath (Join-Path $caConfigPath $CaName)
if (-not $caConfigured) {
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName $CaName `
        -KeyLength 3072 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -Force
}

Import-Module ADCSAdministration
foreach ($template in @('KerberosAuthentication', 'SmartcardLogon')) {
    $enabled = $false
    for ($attempt = 1; $attempt -le 6 -and -not $enabled; $attempt++) {
        try {
            Add-CATemplate -Name $template -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host "Enabled CA template: $template"
            $enabled = $true
        } catch {
            if ($_.FullyQualifiedErrorId -match 'EntryAlreadyExists') {
                Write-Host "CA template already enabled: $template"
                $enabled = $true
            } elseif ($_.Exception.ToString() -match 'RPC server is unavailable|RPC_S_SERVER_UNAVAILABLE|0x800706ba|1722' -and $attempt -lt 6) {
                Write-Host "CA RPC is not ready for $template (attempt $attempt/6); restarting the CA service and retrying."
                Start-Service CertSvc -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
            } else {
                throw
            }
        }
    }
}

$kdcEku = '1.3.6.1.5.2.3.5'
$kdcCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.NotAfter -gt (Get-Date) -and $_.EnhancedKeyUsageList.ObjectId.Value -contains $kdcEku
} | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $kdcCertificate) {
    Write-Host 'Requesting a DC Kerberos Authentication certificate from the local enterprise CA.'
    certreq.exe -enroll -machine -q KerberosAuthentication | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "KerberosAuthentication certificate enrollment failed (certreq exit $LASTEXITCODE)." }
    $kdcCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.NotAfter -gt (Get-Date) -and $_.EnhancedKeyUsageList.ObjectId.Value -contains $kdcEku
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $kdcCertificate) { throw 'The CA returned success, but no KDC Authentication certificate was found in LocalMachine\My.' }
    Restart-Service KDC -Force
}
Write-Host "KDC Authentication certificate: $($kdcCertificate.Thumbprint)"

# The DC is multihomed: advertise only its LAN IPv4 address in DNS. The NAT
# management NIC and public/link-local IPv6 addresses must not be returned to
# domain clients as DC endpoints.
$net = Get-NetIPConfiguration | Where-Object {
    $_.IPv4Address | Where-Object { $_.IPAddress -like '192.168.1.*' }
} | Select-Object -First 1
$lanIp = $net.IPv4Address[0].IPv4Address
$dnsBackupPath = Join-Path $env:ProgramData ("Thessley\ADLab\DnsBackup\" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $dnsBackupPath -Force | Out-Null
Get-DnsServerSetting -All | Export-Clixml -LiteralPath (Join-Path $dnsBackupPath 'dns-settings.xml')
Get-DnsClientServerAddress | Export-Clixml -LiteralPath (Join-Path $dnsBackupPath 'dns-client-addresses.xml')
$dnsRecordBackup = @()
foreach ($entry in @(
    @{ Zone = $DomainName; Name = $ServerName },
    @{ Zone = $DomainName; Name = '@' },
    @{ Zone = "_msdcs.$DomainName"; Name = 'gc' }
)) {
    $dnsRecordBackup += Get-DnsServerResourceRecord -ZoneName $entry.Zone -Name $entry.Name -ErrorAction SilentlyContinue
}
$dnsRecordBackup | Export-Clixml -LiteralPath (Join-Path $dnsBackupPath 'dns-records.xml')

foreach ($adapter in (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })) {
    Set-DnsClient -InterfaceIndex $adapter.ifIndex -RegisterThisConnectionsAddress $false
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $lanIp
}
$dnsServerSettings = Get-DnsServerSetting -All
$dnsServerSettings.ListeningIpAddress = @($lanIp)
Set-DnsServerSetting -InputObject $dnsServerSettings
Restart-Service DNS

$recordsToKeep = @(
    @{ Zone = $DomainName; Name = $ServerName },
    @{ Zone = $DomainName; Name = '@' },
    @{ Zone = "_msdcs.$DomainName"; Name = 'gc' }
)
foreach ($entry in $recordsToKeep) {
    $records = Get-DnsServerResourceRecord -ZoneName $entry.Zone -Name $entry.Name -ErrorAction SilentlyContinue
    $badRecords = $records | Where-Object {
        $_.RecordType -eq 'AAAA' -or
        ($_.RecordType -eq 'A' -and [string]$_.RecordData.IPv4Address -ne $lanIp)
    }
    if ($badRecords) { $badRecords | Remove-DnsServerResourceRecord -ZoneName $entry.Zone -Force -Confirm:$false }
    $goodA = Get-DnsServerResourceRecord -ZoneName $entry.Zone -Name $entry.Name -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordType -eq 'A' -and [string]$_.RecordData.IPv4Address -eq $lanIp }
    if (-not $goodA) {
        Add-DnsServerResourceRecordA -ZoneName $entry.Zone -Name $entry.Name -IPv4Address $lanIp -ErrorAction Stop
    }
}
Clear-DnsServerCache -Force
Clear-DnsClientCache
Write-Host "DNS listener and affected-record backup: $dnsBackupPath"
try { Add-DnsServerForwarder -IPAddress $net.IPv4DefaultGateway.NextHop -PassThru | Out-Null } catch { }

# A dedicated non-admin domain account for credential-provider tests.
Import-Module ActiveDirectory
if (-not (Get-ADUser -Filter "SamAccountName -eq 'martin'" -ErrorAction SilentlyContinue)) {
    $testPassword = Read-Host 'Enter a temporary password for the domain test account martin' -AsSecureString
    New-ADUser -Name 'Martin Thessley Lab' -SamAccountName 'martin' `
        -UserPrincipalName "martin@$DomainName" -AccountPassword $testPassword `
        -Enabled $true -ChangePasswordAtLogon $false
}

# Keep certificate enrollment scoped to the single lab test user. Do not grant
# Domain Users enrollment on the smart-card template for this prototype.
$martin = Get-ADUser -Identity martin -Properties SID
$configuration = (Get-ADRootDSE).configurationNamingContext
$templatePath = "AD:\CN=SmartcardLogon,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configuration"
$martinAccount = New-Object System.Security.Principal.NTAccount("$NetbiosName\martin")
$enrollRight = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$templateAcl = Get-Acl -Path $templatePath
$enrollAceExists = $templateAcl.Access | Where-Object {
    $_.IdentityReference -eq $martinAccount -and
    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
    $_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
    $_.ObjectType -eq $enrollRight
}
if (-not $enrollAceExists) {
    $enrollAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $martinAccount,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $enrollRight
    )
    $templateAcl.AddAccessRule($enrollAce)
    Set-Acl -Path $templatePath -AclObject $templateAcl
}

Write-Host "AD forest: $((Get-ADForest).RootDomain)"
Write-Host "CA: $CaName"
Write-Host "Test account SID: $($martin.SID.Value)"
Write-Host 'SmartcardLogon enrollment is granted only to martin for lab testing.'
Write-Host 'Swedish keyboard input is configured for the Administrator profile.'
Write-Host 'Next: join the client, enroll a user certificate, and verify its strong AD SID mapping.'
