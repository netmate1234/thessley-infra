param([ValidateRange(5, 30)][int]$RollbackMinutes = 10)
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
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'A previous AD lab provider rollback task exists. Resolve that setup before reinstalling.'
}
foreach ($file in @($dllSource, $viewerSource, $rollbackSource, $keepSource)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required package file is missing: $file" }
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

    Copy-Item -LiteralPath $dllSource, $viewerSource, $rollbackSource, $keepSource -Destination $installDir
    foreach ($file in Get-ChildItem -LiteralPath $installDir -File) {
        $fileAcl = Get-Acl -LiteralPath $file.FullName
        $allowedSids = @($fileAcl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl
        } | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
        if ('S-1-5-18' -notin $allowedSids -or 'S-1-5-32-544' -notin $allowedSids) {
            throw "The staged file ACL is missing SYSTEM or Administrators access: $($file.Name)"
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

    Write-Output "Experimental Thessley AD tile registered for the lab account only. Recovery is armed until $($taskInfo.NextRunTime)."
    Write-Output "To keep after verifying a successful domain sign-in, run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $installDir 'keep-ad-lab-provider.ps1')`""
    Write-Output "To roll back now: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$rollbackPath`" -FromTimer"
    Write-Output 'Existing Thessley local tile, VSC smart-card tile, PIN, and password provider registrations were not modified.'
}
catch {
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $registry.DeleteSubKeyTree($providerPath, $false)
        $registry.DeleteSubKeyTree($classPath, $false)
    } finally {
        $registry.Dispose()
    }
    if ($registeredTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    throw
}
