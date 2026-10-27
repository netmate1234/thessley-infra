$ErrorActionPreference = 'Stop'

$group = 'THESSLEYLAB\ThessleyADSignInAdmins'
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$administrators = Get-LocalGroup -SID $administratorsSid
$members = @(Get-LocalGroupMember -Group $administrators)

if (-not ($members | Where-Object { $_.SID.Value -eq 'S-1-5-21-1719900462-4250469598-2954734011-1105' })) {
    Add-LocalGroupMember -Group $administrators -Member $group
}

Get-LocalGroupMember -Group $administrators |
    Select-Object Name, ObjectClass, SID |
    Format-Table -AutoSize
