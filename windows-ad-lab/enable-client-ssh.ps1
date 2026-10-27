param(
    [string]$TargetUser = 'Martin',
    [string]$ManagementClient = '192.168.122.1'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) { throw 'Run this script from an elevated PowerShell prompt.' }

$publicKeyPath = Join-Path $PSScriptRoot 'thessley-vm-debug.pub'
if (-not (Test-Path -LiteralPath $publicKeyPath)) {
    throw "The management public key file is missing: $publicKeyPath"
}
$publicKey = (Get-Content -LiteralPath $publicKeyPath -Raw).Trim()
if ($publicKey -notmatch '^ssh-ed25519\s+[A-Za-z0-9+/]+=*(\s+.*)?$') {
    throw 'The management public key file is not a valid Ed25519 public key.'
}

$capabilityName = 'OpenSSH.Server~~~~0.0.1.0'
$capability = Get-WindowsCapability -Online -Name $capabilityName
if ($capability.State -ne 'Installed') {
    Write-Host 'Installing the Windows OpenSSH Server capability. This may take a few minutes.'
    Add-WindowsCapability -Online -Name $capabilityName | Out-Host
    $capability = Get-WindowsCapability -Online -Name $capabilityName
}
if ($capability.State -ne 'Installed') {
    throw "OpenSSH Server is not installed (state: $($capability.State)). No SSH firewall rule was added."
}

$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
if (-not (Test-Path -LiteralPath $sshd)) { throw "OpenSSH is reported installed, but sshd.exe is missing at $sshd." }

# Use the built-in administrator key file for elevated accounts and also the
# target user's profile key file. Firewall and authorized_keys both restrict
# this lab key to the hypervisor management gateway.
$restrictedKey = "from=`"$ManagementClient`" $publicKey"
$adminDirectory = Join-Path $env:ProgramData 'ssh'
New-Item -ItemType Directory -Path $adminDirectory -Force | Out-Null
$adminKeys = Join-Path $adminDirectory 'administrators_authorized_keys'
if (-not (Test-Path -LiteralPath $adminKeys)) { New-Item -ItemType File -Path $adminKeys -Force | Out-Null }
if (-not (Select-String -LiteralPath $adminKeys -SimpleMatch $publicKey -Quiet -ErrorAction SilentlyContinue)) {
    Add-Content -LiteralPath $adminKeys -Value $restrictedKey -Encoding ascii
}
icacls.exe $adminKeys /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the administrator authorized-key file.' }

$localUser = Get-LocalUser -Name $TargetUser -ErrorAction Stop
$profile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $localUser.SID.Value } | Select-Object -First 1
if (-not $profile -or -not $profile.LocalPath) { throw "Could not find the local profile for '$TargetUser'." }
$userSshDirectory = Join-Path $profile.LocalPath '.ssh'
New-Item -ItemType Directory -Path $userSshDirectory -Force | Out-Null
$userKeys = Join-Path $userSshDirectory 'authorized_keys'
if (-not (Test-Path -LiteralPath $userKeys)) { New-Item -ItemType File -Path $userKeys -Force | Out-Null }
if (-not (Select-String -LiteralPath $userKeys -SimpleMatch $publicKey -Quiet -ErrorAction SilentlyContinue)) {
    Add-Content -LiteralPath $userKeys -Value $restrictedKey -Encoding ascii
}
icacls.exe $userSshDirectory /inheritance:r /grant "*$($localUser.SID.Value):(OI)(CI)F" /grant '*S-1-5-18:(OI)(CI)F' /T /C | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Could not secure the authorized-key files for '$TargetUser'." }

# Validate sshd configuration before changing the firewall or service.
& $sshd -t
if ($LASTEXITCODE -ne 0) { throw 'OpenSSH configuration validation failed; check C:\ProgramData\ssh\sshd_config.' }

# Disable the broad inbox rule, then create a narrow rule for the host-side
# libvirt gateway only. This does not alter other Windows firewall rules.
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue |
    Disable-NetFirewallRule -ErrorAction SilentlyContinue
$ruleName = 'Thessley-ADLab-OpenSSH'
$rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if ($rule) {
    Set-NetFirewallRule -Name $ruleName -Enabled True -Direction Inbound -Action Allow -Profile Any
    Set-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -RemoteAddress $ManagementClient
    Set-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -Protocol TCP -LocalPort 22
} else {
    New-NetFirewallRule -Name $ruleName -DisplayName 'Thessley AD lab SSH (hypervisor only)' `
        -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 22 `
        -RemoteAddress $ManagementClient | Out-Null
}

Set-Service sshd -StartupType Automatic
Start-Service sshd

Write-Host "OpenSSH is running. TCP 22 is allowed only from $ManagementClient."
Write-Host "The lab public key is installed for local account '$TargetUser' and administrator accounts."
Write-Host 'No passwords or sign-in policies were changed.'
