param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')]
    [string]$Domain
)

$ErrorActionPreference = 'Stop'
$keyPath = 'HKLM:\SOFTWARE\Thessley\ADCredentialProvider'
New-Item -Path $keyPath -Force | Out-Null
New-ItemProperty -Path $keyPath -Name 'DefaultDomain' -PropertyType String -Value $Domain -Force | Out-Null
Write-Host "Configured the Thessley Other user tile to prefill domain '$Domain'."
Write-Host 'Users can change the domain field before requesting phone approval.'
