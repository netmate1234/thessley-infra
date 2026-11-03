param(
    [ValidateSet('Enable', 'Confirm', 'Rollback', 'Status')]
    [string]$Mode = 'Enable',
    [ValidateRange(5, 30)]
    [int]$RollbackMinutes = 10,
    [string]$ExpectedProviderSha256,
    [string]$ExpectedAgentSha256,
    [switch]$FromRollbackTask
)
$ErrorActionPreference = 'Stop'

$taskName = 'Thessley-AD-Phone2FA-Rollback'
$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$passwordProviderId = '{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}'
$policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$policyName = 'ExcludedCredentialProviders'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider'
$agentPath = Join-Path $env:ProgramData 'ThessleyPamWin\ad-prototype\thessley_pam_win\ad_cli.py'
$providerRegistration = "HKLM:\SOFTWARE\Classes\CLSID\$providerId\InprocServer32"
$statePath = Join-Path $installDir 'phone-2fa-state.json'
$managedScript = Join-Path $installDir 'phone-2fa-policy.ps1'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script in an elevated PowerShell session.'
    }
}

function Read-State {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $null }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($state.Version -ne 1 -or $state.TaskName -ne $taskName) {
        throw 'The phone 2FA rollback state is invalid; do not overwrite it.'
    }
    return $state
}

function Set-PolicyList([string[]]$ids, [bool]$exists) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        if ($exists) {
            $key = $base.CreateSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
            if (-not $key) { throw 'Could not open the Windows sign-in policy key.' }
            $key.SetValue($policyName, ($ids -join ','), [Microsoft.Win32.RegistryValueKind]::String)
            $key.Flush()
            $key.Dispose()
        } else {
            $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', $true)
            if ($key) {
                $key.DeleteValue($policyName, $false)
                $key.Flush()
                $key.Dispose()
            }
        }
    } finally { $base.Dispose() }
}

function Set-ProviderDllPath([string]$path) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey("SOFTWARE\Classes\CLSID\$providerId\InprocServer32", $true)
        if (-not $key) { throw 'Could not update the Thessley provider registration.' }
        $key.SetValue('', $path, [Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
        $key.Dispose()
    } finally { $base.Dispose() }
}

function Restore-Policy([object]$state) {
    $original = @($state.OriginalExcludedProviders)
    $originalHadPassword = $original -contains $passwordProviderId
    if ($originalHadPassword) {
        Set-PolicyList $original ([bool]$state.OriginalPolicyValueExisted)
        return
    }

    $currentExists = $false
    $current = @()
    if (Test-Path -LiteralPath $policyPath) {
        $key = Get-Item -LiteralPath $policyPath
        $currentExists = $key.GetValueNames() -contains $policyName
        if ($currentExists) {
            $current = @(([string]$key.GetValue($policyName) -split ',') |
                ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
    }
    if ($current -contains $passwordProviderId) {
        $remaining = @($current | Where-Object { $_ -ne $passwordProviderId })
        Set-PolicyList $remaining ($remaining.Count -gt 0 -or [bool]$state.OriginalPolicyValueExisted)
    }
}

function Remove-RollbackTask {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

Assert-Administrator

switch ($Mode) {
    'Status' {
        $state = Read-State
        if (-not $state) { Write-Output 'No Thessley phone 2FA rollback is pending.'; exit 0 }
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Write-Output "Rollback deadline: $($state.Deadline)"
        Write-Output "Password provider excluded: $((Get-ItemProperty -LiteralPath $policyPath -Name $policyName -ErrorAction SilentlyContinue).$policyName)"
        Write-Output "Rollback task state: $(if ($task) { $task.State } else { 'missing' })"
        exit 0
    }
    'Confirm' {
        $state = Read-State
        if (-not $state) { throw 'There is no pending Thessley phone 2FA setup to confirm.' }
        Remove-RollbackTask
        Remove-Item -LiteralPath $statePath -Force
        Remove-Item -LiteralPath $state.BackupAgentPath -Force -ErrorAction SilentlyContinue
        Write-Output 'Phone 2FA setup confirmed. Automatic rollback stopped.'
        exit 0
    }
    'Rollback' {
        $state = Read-State
        if (-not $state) { Remove-RollbackTask; Write-Output 'No rollback state remains.'; exit 0 }

        if (Test-Path -LiteralPath $providerRegistration) {
            $currentDll = [string](Get-Item -LiteralPath $providerRegistration).GetValue('')
            if ($currentDll -and [IO.Path]::GetFullPath($currentDll) -ieq [IO.Path]::GetFullPath([string]$state.NewProviderPath)) {
                Set-ProviderDllPath ([string]$state.PreviousProviderPath)
            }
        }
        $agentCurrentlyExpected = $false
        if (Test-Path -LiteralPath $agentPath -PathType Leaf) {
            $agentCurrentlyExpected = (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash -eq
                [string]$state.ExpectedAgentSha256
        }
        if ($agentCurrentlyExpected -and (Test-Path -LiteralPath $state.BackupAgentPath -PathType Leaf)) {
            Copy-Item -LiteralPath $state.BackupAgentPath -Destination $agentPath -Force
        }
        Restore-Policy $state
        Remove-RollbackTask
        Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
        Write-Output 'Phone 2FA setup rolled back. The next sign-in screen will use the restored provider policy.'
        exit 0
    }
    'Enable' { }
}

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'A phone 2FA rollback task is already active. Confirm or roll it back before starting another setup.'
}
if (Test-Path -LiteralPath $statePath) { throw 'A prior phone 2FA state file remains. Inspect it before proceeding.' }
if (-not (Test-Path -LiteralPath $providerRegistration)) { throw 'The Thessley AD credential provider is not registered.' }
if (-not (Test-Path -LiteralPath $agentPath -PathType Leaf)) { throw 'The Thessley AD agent is not installed.' }

$sourceDll = Join-Path $env:PUBLIC 'Documents\ThessleyADCredentialProvider-other-user.dll'
$sourceAgent = Join-Path $env:PUBLIC 'Documents\ThessleyAD-ad_cli.py'
if (-not (Test-Path -LiteralPath $sourceDll -PathType Leaf)) { throw "Staged provider DLL not found: $sourceDll" }
if (-not (Test-Path -LiteralPath $sourceAgent -PathType Leaf)) { throw "Staged AD agent CLI not found: $sourceAgent" }

$providerHash = (Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash
$agentHash = (Get-FileHash -LiteralPath $sourceAgent -Algorithm SHA256).Hash
if ($ExpectedProviderSha256 -and $providerHash -ne $ExpectedProviderSha256.ToUpperInvariant()) { throw 'Staged provider DLL hash mismatch.' }
if ($ExpectedAgentSha256 -and $agentHash -ne $ExpectedAgentSha256.ToUpperInvariant()) { throw 'Staged AD agent CLI hash mismatch.' }
if (-not (Select-String -LiteralPath $sourceAgent -SimpleMatch 'approval-start-user' -Quiet)) {
    throw 'The staged AD agent CLI does not contain the Other user account resolver.'
}

$providerKey = Get-Item -LiteralPath $providerRegistration
$previousDll = [string]$providerKey.GetValue('')
if ([string]::IsNullOrWhiteSpace($previousDll) -or -not (Test-Path -LiteralPath $previousDll -PathType Leaf)) {
    throw 'The registered provider DLL is missing; refusing to update it.'
}
$installFull = [IO.Path]::GetFullPath($installDir)
if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($previousDll)) -ine $installFull) {
    throw 'The registered provider DLL is outside the protected Thessley installation directory.'
}

$policyKey = if (Test-Path -LiteralPath $policyPath) { Get-Item -LiteralPath $policyPath } else { $null }
$policyExisted = $policyKey -and ($policyKey.GetValueNames() -contains $policyName)
$originalPolicy = if ($policyExisted) { [string]$policyKey.GetValue($policyName) } else { '' }
$excluded = @($originalPolicy -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($excluded -contains $passwordProviderId) {
    throw 'Windows already has the Password provider excluded. Resolve the existing policy before continuing.'
}

$backupAgent = Join-Path $installDir 'ad_cli.py.before-phone-2fa'
if (Test-Path -LiteralPath $backupAgent) { throw 'A previous AD agent backup exists; inspect it before continuing.' }
Copy-Item -LiteralPath $agentPath -Destination $backupAgent
$newDll = Join-Path $installDir "ThessleyADCredentialProvider-$providerHash.dll"
if (-not (Test-Path -LiteralPath $newDll)) { Copy-Item -LiteralPath $sourceDll -Destination $newDll }
if ((Get-FileHash -LiteralPath $newDll -Algorithm SHA256).Hash -ne $providerHash) {
    Remove-Item -LiteralPath $backupAgent -Force
    throw 'Versioned provider DLL failed its post-copy hash check.'
}
Set-Acl -LiteralPath $newDll -AclObject (Get-Acl -LiteralPath $previousDll)

$deadline = (Get-Date).AddMinutes($RollbackMinutes)
$state = [ordered]@{
    Version = 1
    TaskName = $taskName
    Deadline = $deadline.ToString('o')
    PreviousProviderPath = $previousDll
    NewProviderPath = $newDll
    BackupAgentPath = $backupAgent
    ExpectedAgentSha256 = $agentHash
    OriginalPolicyValueExisted = [bool]$policyExisted
    OriginalExcludedProviders = @($excluded)
}
$state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
Set-Acl -LiteralPath $statePath -AclObject (Get-Acl -LiteralPath $agentPath)

# The managed copy is what both the scheduled rollback and admin commands use.
$thisScript = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
if ($thisScript -ine [IO.Path]::GetFullPath($managedScript)) {
    Copy-Item -LiteralPath $thisScript -Destination $managedScript -Force
    Set-Acl -LiteralPath $managedScript -AclObject (Get-Acl -LiteralPath $agentPath)
}

$argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode Rollback -FromRollbackTask' -f $managedScript
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $argument
$trigger = New-ScheduledTaskTrigger -Once -At $deadline
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null

try {
    Copy-Item -LiteralPath $sourceAgent -Destination $agentPath -Force
    Set-ProviderDllPath $newDll
    Set-PolicyList -ids @($excluded + $passwordProviderId) -exists $true

    $actualPolicy = [string](Get-ItemProperty -LiteralPath $policyPath -Name $policyName).$policyName
    $actualDll = [string](Get-Item -LiteralPath $providerRegistration).GetValue('')
    if ($actualPolicy -notmatch [regex]::Escape($passwordProviderId) -or
        [IO.Path]::GetFullPath($actualDll) -ine [IO.Path]::GetFullPath($newDll) -or
        (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash -ne $agentHash) {
        throw 'Post-change verification failed.'
    }
} catch {
    & $managedScript -Mode Rollback -FromRollbackTask
    throw
}

Write-Output "Thessley Other user provider installed and verified. Password provider hidden until $($deadline.ToString('HH:mm:ss'))."
Write-Output "The password exclusion is machine-wide, including local passwords, RDP and Run as. Local account recovery is through the Thessley tile."
Write-Output 'Pre-enroll authorized domain accounts before testing; an unknown or unenrolled account will be refused.'
Write-Output "After a successful QR sign-in, confirm with: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$managedScript`" -Mode Confirm"
Write-Output "Check or manually roll back with: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$managedScript`" -Mode Status (or -Mode Rollback)"
