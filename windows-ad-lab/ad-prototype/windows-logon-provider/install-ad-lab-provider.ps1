param(
    [ValidateRange(5, 30)][int]$RollbackMinutes = 10,
    [string]$PivCertificatePath
)
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

Assert-Administrator

$providerId = '{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
$taskName = 'Thessley-AD-Lab-Provider-Rollback'
$providerPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classPath = "SOFTWARE\Classes\CLSID\$providerId"
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider'
$dllSource = Join-Path $source 'ThessleyADCredentialProvider.dll'
$viewerSource = Join-Path $source 'ThessleyADQrViewer.exe'
$rollbackSource = Join-Path $source 'rollback-ad-lab-provider.ps1'
$keepSource = Join-Path $source 'keep-ad-lab-provider.ps1'
$configureSource = Join-Path $source 'configure-ad-lab-user.ps1'
$configurePivSource = Join-Path $source 'configure-ad-lab-piv-phone-test.ps1'
$pivReaderSource = Join-Path (Split-Path -Parent $source) 'certificate-pilot\piv-phone-reader-poc.py'
$pivTaskName = 'Thessley-AD-PIV-Phone-Reader'
$pivReaderTaskRegistered = $false
$pivSid = $null
$pivCertInstallDir = $installDir
$pivPython = Join-Path $env:ProgramFiles 'Python313\python.exe'

$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    if ($registry.OpenSubKey($providerPath) -or $registry.OpenSubKey($classPath)) {
        throw 'The AD lab tile is already registered. Do not install it twice.'
    }
} finally {
    $registry.Dispose()
}
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
$configRoot = $null
try {
    $configRoot = $registry.OpenSubKey('SOFTWARE\Thessley\ADCredentialProvider\Users', $false)
    $configuredCount = 0
    if ($configRoot) {
        foreach ($sid in $configRoot.GetSubKeyNames()) {
            $accountConfig = $configRoot.OpenSubKey($sid, $false)
            if (-not $accountConfig) { continue }
            try {
                $container = $accountConfig.GetValue('ContainerName', '')
                $providerName = $accountConfig.GetValue('ProviderName', '')
                $keySpec = $accountConfig.GetValue('KeySpec', 0)
                $isVsc = -not [string]::IsNullOrWhiteSpace([string]$container) -and
                    -not [string]::IsNullOrWhiteSpace([string]$providerName) -and
                    [int]$keySpec -in @(1, 2)
                $piv = [int]$accountConfig.GetValue('PivPhoneSigning', 0) -eq 1 -and
                    [int]$accountConfig.GetValue('PivKeySpec', 0) -in @(1, 2) -and
                    -not [string]::IsNullOrWhiteSpace([string]$accountConfig.GetValue('PivContainerName', '')) -and
                    -not [string]::IsNullOrWhiteSpace([string]$accountConfig.GetValue('PivReaderName', '')) -and
                    -not [string]::IsNullOrWhiteSpace([string]$accountConfig.GetValue('PivProviderName', ''))
                if ($isVsc -or $piv) {
                    $configuredCount++
                }
                if ($piv) {
                    if ($pivSid) { throw 'Only one account can use the PIV phone-sign test on this lab PC.' }
                    $pivSid = $sid
                }
            } finally {
                $accountConfig.Dispose()
            }
        }
    }
    if ($configuredCount -lt 1) {
        throw "No AD account is configured. Run configure-ad-lab-user.ps1 elevated with the account SID and that account's VSC container metadata before installing the tile."
    }
} finally {
    if ($configRoot) { $configRoot.Dispose() }
    $registry.Dispose()
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'A previous AD lab provider rollback task exists. Resolve that setup before reinstalling.'
}
foreach ($file in @($dllSource, $viewerSource, $rollbackSource, $keepSource, $configureSource, $configurePivSource)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required package file is missing: $file" }
}
if ($pivSid) {
    if ([string]::IsNullOrWhiteSpace($PivCertificatePath)) {
        throw 'PIV phone-sign mode needs -PivCertificatePath for the certificate matching the enrolled phone key.'
    }
    $PivCertificatePath = [IO.Path]::GetFullPath($PivCertificatePath)
    foreach ($required in @($pivReaderSource, $PivCertificatePath, $pivPython)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "PIV phone-sign mode is configured, but a required file is missing: $required"
        }
    }
    if ([IO.Path]::GetExtension($PivCertificatePath) -notin @('.cer', '.der')) {
        throw 'Provide the public PIV certificate as a .cer or .der file.'
    }
    if (Get-ScheduledTask -TaskName $pivTaskName -ErrorAction SilentlyContinue) {
        throw 'The PIV phone-reader task already exists. Resolve the previous test setup before reinstalling.'
    }
}
if (Test-Path -LiteralPath $installDir) {
    # A timed rollback deliberately keeps its protected files for diagnosis.
    # Preserve that directory, then create a clean location for this install.
    $orphanedDir = "$installDir-previous-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Move-Item -LiteralPath $installDir -Destination $orphanedDir
}

$registeredTask = $false
try {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    # Protect the directory first, then copy files so they inherit its two
    # explicit ACEs. Recursively protecting after copy can leave the files
    # with an empty DACL, making the DLL and rollback script unreadable even
    # to SYSTEM.
    $installAcl = Get-Acl -LiteralPath $installDir
    $installAcl.SetAccessRuleProtection($true, $false)
    $installAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $installAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $installAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $installDir -AclObject $installAcl

    $pinDir = Join-Path $installDir 'pins'
    New-Item -ItemType Directory -Path $pinDir -Force | Out-Null
    $pinAcl = Get-Acl -LiteralPath $pinDir
    $pinAcl.SetAccessRuleProtection($true, $false)
    $pinAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $pinAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    $pinAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $pinDir -AclObject $pinAcl

    # Keep the user's encrypted QR-only PIN seed across a reinstall. The value
    # is DPAPI LocalMachine protected and SID-scoped; do not force another PIN
    # prompt simply because the provider package was refreshed.
    $previousPinDir = if ($orphanedDir) { Join-Path $orphanedDir 'pins' } else { $null }
    if ($previousPinDir -and (Test-Path -LiteralPath $previousPinDir -PathType Container)) {
        foreach ($pinFile in Get-ChildItem -LiteralPath $previousPinDir -File -Force) {
            Copy-Item -LiteralPath $pinFile.FullName -Destination $pinDir -Force
        }
    }

    Copy-Item -LiteralPath $dllSource, $viewerSource, $rollbackSource, $keepSource, $configureSource, $configurePivSource -Destination $installDir
    foreach ($file in Get-ChildItem -LiteralPath $installDir -File) {
        $fileAcl = Get-Acl -LiteralPath $file.FullName
        $allowedSids = @($fileAcl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl
        } | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
        if ('S-1-5-18' -notin $allowedSids -or 'S-1-5-32-544' -notin $allowedSids) {
            throw "The staged file ACL is missing SYSTEM or Administrators access: $($file.Name)"
        }
    }

    if ($pivSid) {
        New-Item -ItemType Directory -Path $pivCertInstallDir -Force | Out-Null
        Copy-Item -LiteralPath $pivReaderSource -Destination $pivCertInstallDir -Force
        $pivCertPath = Join-Path $pivCertInstallDir 'piv-phone-logon.cer'
        Copy-Item -LiteralPath $PivCertificatePath -Destination $pivCertPath -Force
        $pivScriptPath = Join-Path $pivCertInstallDir 'piv-phone-reader-poc.py'
        foreach ($protectedFile in @($pivScriptPath, $pivCertPath)) {
            $fileAcl = Get-Acl -LiteralPath $protectedFile
            $allowedSids = @($fileAcl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl
            } | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
            if ('S-1-5-18' -notin $allowedSids -or 'S-1-5-32-544' -notin $allowedSids) {
                throw "The PIV relay file ACL is missing SYSTEM or Administrators access: $protectedFile"
            }
        }
        $pivArguments = '-I "{0}" --user-sid "{1}" --certificate "{2}"' -f $pivScriptPath, $pivSid, $pivCertPath
        $pivAction = New-ScheduledTaskAction -Execute $pivPython -Argument $pivArguments -WorkingDirectory $pivCertInstallDir
        $pivTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Seconds 20)
        $pivPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $pivSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -RestartCount 20 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $pivTaskName -Action $pivAction -Trigger $pivTrigger `
            -Principal $pivPrincipal -Settings $pivSettings `
            -Description 'Runs the disposable Thessley PIV phone-sign relay at the Windows sign-in screen.' | Out-Null
        $pivReaderTaskRegistered = $true
        $pivTask = Get-ScheduledTask -TaskName $pivTaskName
        if ($pivTask.State -notin @('Ready', 'Running') -or $pivTask.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) {
            throw 'The PIV phone-reader startup task could not be verified as a SYSTEM task.'
        }
        Start-ScheduledTask -TaskName $pivTaskName
        $relayStarted = $false
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            Start-Sleep -Milliseconds 500
            $pivTask = Get-ScheduledTask -TaskName $pivTaskName
            if ($pivTask.State -eq 'Running') { $relayStarted = $true; break }
        }
        if (-not $relayStarted) {
            $lastResult = (Get-ScheduledTaskInfo -TaskName $pivTaskName).LastTaskResult
            throw "The PIV phone-reader task did not stay running (last result $lastResult). Check the relay log and Python imports."
        }
    }
    foreach ($pinFile in Get-ChildItem -LiteralPath $pinDir -File -Force) {
        $fileAcl = Get-Acl -LiteralPath $pinFile.FullName
        $allowedSids = @($fileAcl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl
        } | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
        if ('S-1-5-18' -notin $allowedSids -or 'S-1-5-32-544' -notin $allowedSids) {
            throw "The preserved PIN file ACL is missing SYSTEM or Administrators access: $($pinFile.Name)"
        }
    }

    # Arm and verify recovery before adding either Credential Provider registry key.
    $rollbackPath = Join-Path $installDir 'rollback-ad-lab-provider.ps1'
    $at = (Get-Date).AddMinutes($RollbackMinutes)
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackPath`" -FromTimer"
    $trigger = New-ScheduledTaskTrigger -Once -At $at
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Removes the experimental Thessley AD logon tile unless explicitly kept.' | Out-Null
    $registeredTask = $true

    $task = Get-ScheduledTask -TaskName $taskName
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
    if ($task.State -ne 'Ready' -or $taskInfo.NextRunTime -le (Get-Date) -or
        $taskInfo.NextRunTime -gt $at.AddMinutes(2) -or
        $task.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) {
        throw "Rollback task verification failed (state=$($task.State), principal=$($task.Principal.UserId), next=$($taskInfo.NextRunTime)). No provider registration was made."
    }

    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $provider = $registry.CreateSubKey($providerPath)
        $provider.SetValue('', 'Thessley AD Passkey (Lab)', [Microsoft.Win32.RegistryValueKind]::String)
        $provider.Dispose()

        $class = $registry.CreateSubKey($classPath)
        $class.SetValue('', 'Thessley AD Passkey (Lab)', [Microsoft.Win32.RegistryValueKind]::String)
        $class.Dispose()

        $inproc = $registry.CreateSubKey("$classPath\InprocServer32")
        $inproc.SetValue('', (Join-Path $installDir 'ThessleyADCredentialProvider.dll'), [Microsoft.Win32.RegistryValueKind]::String)
        $inproc.SetValue('ThreadingModel', 'Apartment', [Microsoft.Win32.RegistryValueKind]::String)
        $inproc.Dispose()
    } finally {
        $registry.Dispose()
    }

    Write-Output "Experimental Thessley AD tile registered for $configuredCount configured account SID(s). Recovery is armed until $($taskInfo.NextRunTime)."
    if ($pivSid) {
        Write-Output "The PIV phone-sign relay is running as SYSTEM and will restart at boot for SID $pivSid."
        Write-Output "PIV relay log: $(Join-Path $env:PUBLIC 'piv-phone-reader-poc.log')"
    }
    Write-Output "To keep after verifying a successful domain sign-in, run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $installDir 'keep-ad-lab-provider.ps1')`""
    Write-Output "To roll back now: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$rollbackPath`" -FromTimer"
    Write-Output 'Existing Thessley local tile, VSC smart-card tile, PIN, and password provider registrations were not modified.'
}
catch {
    if ($pivReaderTaskRegistered) {
        Stop-ScheduledTask -TaskName $pivTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $pivTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $registry.DeleteSubKeyTree($providerPath, $false)
        $registry.DeleteSubKeyTree($classPath, $false)
    } finally {
        $registry.Dispose()
    }
    if ($pivReaderTaskRegistered) {
        Unregister-ScheduledTask -TaskName $pivTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($registeredTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    throw
}
