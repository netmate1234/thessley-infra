param(
    [Parameter(Mandatory = $true)][ValidatePattern('^S-1-5-21-(?:[0-9]+-){2}[0-9]+-[0-9]+$')][string]$Sid,
    [switch]$Disable
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from elevated PowerShell on Clone 1.'
}

$sidObject = [Security.Principal.SecurityIdentifier]::new($Sid)
$account = $sidObject.Translate([Security.Principal.NTAccount]).Value
$keyPath = "HKLM:\SOFTWARE\Thessley\ADCredentialProvider\Users\$Sid"
if ($Disable) {
    if (Test-Path -LiteralPath $keyPath) {
        Remove-ItemProperty -LiteralPath $keyPath -Name TicketLogonTest -ErrorAction SilentlyContinue
    }
    Write-Output "Ticket-logon test disabled for $account ($Sid)."
    exit 0
}

New-Item -Path $keyPath -Force | Out-Null
New-ItemProperty -LiteralPath $keyPath -Name TicketLogonTest -PropertyType DWord -Value 1 -Force | Out-Null
Write-Output "Ticket-logon test enabled for $account ($Sid)."
Write-Output 'This only enables the separate experimental tile on Clone 1; the regular VSC provider and Windows recovery options remain registered.'
