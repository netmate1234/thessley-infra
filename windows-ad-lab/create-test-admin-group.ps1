#Requires -RunAsAdministrator
# Create the least-privilege AD group used by the Thessley sign-in lab.
# This deliberately does not add the test user to Domain Admins.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$groupName = 'Thessley AD Sign-in Administrators'
$samName = 'ThessleyADSignInAdmins'
$testUserName = 'martin'
$domain = Get-ADDomain

$group = Get-ADGroup -Filter "SamAccountName -eq '$samName'" -ErrorAction SilentlyContinue
if (-not $group) {
    New-ADGroup -Name $groupName -SamAccountName $samName -GroupScope Global `
        -GroupCategory Security -Path $domain.UsersContainer
    $group = Get-ADGroup -Identity $samName
}

$user = Get-ADUser -Identity $testUserName
$alreadyMember = Get-ADGroupMember -Identity $group -Recursive |
    Where-Object { $_.SID.Value -eq $user.SID.Value }
if (-not $alreadyMember) {
    Add-ADGroupMember -Identity $group -Members $user
}

$group = Get-ADGroup -Identity $samName
[PSCustomObject]@{
    GroupName = $group.Name
    GroupSID = $group.SID.Value
    Member = $user.SamAccountName
    MemberSID = $user.SID.Value
    DomainAdminsMembershipChanged = $false
} | Format-List
