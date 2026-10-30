#Requires -RunAsAdministrator
param([string]$TestUser = 'startmenutest')
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain = Get-ADDomain
$user = Get-ADUser -Identity $TestUser -Properties Enabled
if (-not $user.Enabled) { throw "The test account is disabled: $TestUser" }

$privilegedSids = @(
    "$($domain.DomainSID.Value)-512", # Domain Admins
    "$($domain.DomainSID.Value)-516", # Domain Controllers
    "$($domain.DomainSID.Value)-519", # Enterprise Admins (if present in this domain)
    'S-1-5-32-544'                    # Built-in Administrators
)
$workstationAdmin = Get-ADGroup -Identity 'ThessleyQRWorkstationAdmins' -ErrorAction SilentlyContinue
if ($workstationAdmin) { $privilegedSids += $workstationAdmin.SID.Value }
$memberSids = @(Get-ADPrincipalGroupMembership -Identity $user |
    ForEach-Object { $_.SID.Value })
$privilegedMembership = @($memberSids | Where-Object { $_ -in $privilegedSids })
if ($privilegedMembership.Count) {
    throw "Refusing a low-privilege test setup: $TestUser is already in a privileged group ($($privilegedMembership -join ', '))."
}

$groupSam = 'ThessleyQRWorkstationUsers'
$group = Get-ADGroup -Filter "SamAccountName -eq '$groupSam'" -ErrorAction SilentlyContinue
if (-not $group) {
    New-ADGroup -Name 'Thessley QR Workstation Users' -SamAccountName $groupSam `
        -GroupScope Global -GroupCategory Security -Path $domain.UsersContainer
    $group = Get-ADGroup -Identity $groupSam
}
if ($group.GroupScope -ne 'Global' -or $group.GroupCategory -ne 'Security') {
    throw "The existing $groupSam group is not a Global security group."
}
$alreadyMember = Get-ADGroupMember -Identity $group -Recursive |
    Where-Object { $_.SID.Value -eq $user.SID.Value }
if (-not $alreadyMember) { Add-ADGroupMember -Identity $group -Members $user }

[PSCustomObject]@{
    TestUser = $user.SamAccountName
    UserSID = $user.SID.Value
    SignInGroup = $group.SamAccountName
    GroupSID = $group.SID.Value
    LocalAdministratorRightsAdded = $false
    ExistingPrivilegedGroupMemberships = 'none'
} | Format-List
