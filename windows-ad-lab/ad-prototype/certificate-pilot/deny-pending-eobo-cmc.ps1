#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CAConfig,
    [Parameter(Mandatory = $true)][long] $RequestId
)

$ErrorActionPreference = 'Stop'
$admin = $null
try {
    if ($CAConfig -notmatch '^[A-Za-z0-9.-]{1,253}\\[A-Za-z0-9_. -]{1,64}$') {
        throw 'CAConfig must be a configured CA name in ComputerName\CAName form.'
    }
    if ($RequestId -lt 1 -or $RequestId -gt [int]::MaxValue) {
        throw 'The CA request ID must be a positive 32-bit integer.'
    }
    $admin = New-Object -ComObject CertificateAuthority.Admin
    # DenyRequest only denies a still-pending request; it does not revoke issued certificates.
    $null = $admin.DenyRequest($CAConfig, [int]$RequestId)
    [ordered]@{
        result = 'pending_request_denied'
        ca_request_id = [int]$RequestId
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $admin -and [Runtime.InteropServices.Marshal]::IsComObject($admin)) {
        try { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($admin) | Out-Null } catch { }
    }
}
