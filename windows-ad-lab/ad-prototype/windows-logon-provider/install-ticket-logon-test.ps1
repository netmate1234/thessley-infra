param(
    [ValidateRange(5, 30)][int]$RollbackMinutes = 15,
    [Parameter(Mandatory = $true)][switch]$ConfirmDisposableLabVm,
    [switch]$KeepInstalled
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from elevated PowerShell on Clone 1.'
}
if (-not $ConfirmDisposableLabVm) {
    throw 'This experiment is limited to a disposable VM. Re-run with -ConfirmDisposableLabVm only on Clone 1.'
}

$providerId = '{8A2755BF-64B7-4D39-9C48-67A6A27F5E91}'
$taskName = 'Thessley-AD-Ticket-Logon-Test-Rollback'
$serviceName = 'ThessleyADTicketBrokerTest'
$providerPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classPath = "SOFTWARE\Classes\CLSID\$providerId"
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-ticket-logon-test'
$sourceDllName = 'ThessleyADTicketTestCredentialProvider.dll'
$dllHash = (Get-FileHash -LiteralPath (Join-Path $source $sourceDllName) -Algorithm SHA256).Hash.ToLowerInvariant().Substring(0, 16)
$dllName = "ThessleyADTicketTestCredentialProvider-$dllHash.dll"
$brokerName = 'ThessleyADTicketBroker.exe'
$viewerName = 'ThessleyADQrViewer.exe'
$rollbackName = 'rollback-ticket-logon-test.ps1'

$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    if ($registry.OpenSubKey($providerPath) -or $registry.OpenSubKey($classPath)) {
        throw 'The separate ticket-test provider is already registered.'
    }
} finally { $registry.Dispose() }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'The ticket broker service already exists; stop and inspect it before continuing.'
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'A ticket-test rollback task already exists. Resolve it before installing again.'
}

$configRoot = 'HKLM:\SOFTWARE\Thessley\ADCredentialProvider\Users'
$configuredSids = @()
if (Test-Path -LiteralPath $configRoot) {
    foreach ($key in Get-ChildItem -LiteralPath $configRoot) {
        $mode = (Get-ItemProperty -LiteralPath $key.PSPath -Name TicketLogonTest -ErrorAction SilentlyContinue).TicketLogonTest
        if ($mode -eq 1 -and $key.PSChildName -match '^S-1-5-21-(?:[0-9]+-){2}[0-9]+-[0-9]+$') {
            $configuredSids += $key.PSChildName
        }
    }
}
if ($configuredSids.Count -ne 1) {
    throw "Enable TicketLogonTest for exactly one disposable low-privilege AD account SID first; found $($configuredSids.Count)."
}

foreach ($name in @($sourceDllName, $brokerName, $viewerName, $rollbackName)) {
    $path = Join-Path $source $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Package file is missing: $path" }
}
$registeredTask = $false
$registeredService = $false
try {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $acl = Get-Acl -LiteralPath $installDir
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $installDir -AclObject $acl
    # Keep the old test DLL intact if LogonUI still has it mapped. Preserve
    # diagnostic logs in a prior test folder when refreshing the experiment.
    Copy-Item -LiteralPath (Join-Path $source $sourceDllName) `
        -Destination (Join-Path $installDir $dllName) -Force
    Copy-Item -LiteralPath (Join-Path $source $brokerName),
        (Join-Path $source $viewerName), (Join-Path $source $rollbackName) `
        -Destination $installDir -Force

    $rollbackPath = Join-Path $installDir $rollbackName
    $taskInfo = $null
    if (-not $KeepInstalled) {
        $at = (Get-Date).AddMinutes($RollbackMinutes)
        $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackPath`" -FromTimer"
        $trigger = New-ScheduledTaskTrigger -Once -At $at
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $taskPrincipal -Settings $settings `
            -Description 'Removes only the isolated Thessley Kerberos ticket-logon test provider and broker.' | Out-Null
        $registeredTask = $true

        $task = Get-ScheduledTask -TaskName $taskName
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
    # TaskScheduler exposes this account under the Windows UI language (for
    # example, "Système" on French installs). Check the invariant SID from
    # the task XML first, then fall back to SID translation for older systems.
    $taskPrincipalSid = $null
    try {
        $taskXml = [xml](Export-ScheduledTask -TaskName $taskName -ErrorAction Stop)
        $xmlUserId = [string]$taskXml.Task.Principals.Principal.UserId
        if ($xmlUserId -match '^S-1-') { $taskPrincipalSid = $xmlUserId }
    } catch { }
    if (-not $taskPrincipalSid) {
        $taskUserId = [string]$task.Principal.UserId
        if ($taskUserId -match '^S-1-') {
            $taskPrincipalSid = $taskUserId
        } else {
            try {
                $taskPrincipalSid = [Security.Principal.NTAccount]::new($taskUserId).Translate(
                    [Security.Principal.SecurityIdentifier]).Value
            } catch { }
        }
    }
        if ($task.State -ne 'Ready' -or $taskPrincipalSid -ne 'S-1-5-18' -or
            $taskInfo.NextRunTime -le (Get-Date) -or $taskInfo.NextRunTime -gt $at.AddMinutes(2)) {
            throw "Timed rollback verification failed (state=$($task.State), principalSID=$taskPrincipalSid, nextRun=$($taskInfo.NextRunTime)); no ticket provider or broker was activated."
        }
    }

    $brokerPath = Join-Path $installDir $brokerName
    New-Service -Name $serviceName -DisplayName 'Thessley AD ticket-logon test broker' `
        -Description 'Clone 1 feasibility test; volatile one-use host-ticket handoff to LogonUI.' `
        -BinaryPathName "`"$brokerPath`"" -StartupType Automatic | Out-Null
    $registeredService = $true
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $service -or $service.StartName -ne 'LocalSystem') {
        throw 'Ticket broker did not register as LocalSystem.'
    }
    Start-Service -Name $serviceName
    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 250
        $service = Get-Service -Name $serviceName
    } while ($service.Status -ne 'Running' -and (Get-Date) -lt $deadline)
    if ($service.Status -ne 'Running') { throw 'Ticket broker service did not stay running.' }
    $pipeCheck = [IO.Pipes.NamedPipeClientStream]::new('.', 'ThessleyADTicketBrokerV1', [IO.Pipes.PipeDirection]::InOut)
    try { $pipeCheck.Connect(1500) } finally { $pipeCheck.Dispose() }

    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $provider = $registry.CreateSubKey($providerPath)
        $provider.SetValue('', 'Thessley AD Ticket Test (Clone 1 only)', [Microsoft.Win32.RegistryValueKind]::String)
        $provider.Dispose()
        $class = $registry.CreateSubKey($classPath)
        $class.SetValue('', 'Thessley AD Ticket Test (Clone 1 only)', [Microsoft.Win32.RegistryValueKind]::String)
        $class.Dispose()
        $inproc = $registry.CreateSubKey("$classPath\InprocServer32")
        $inproc.SetValue('', (Join-Path $installDir $dllName), [Microsoft.Win32.RegistryValueKind]::String)
        $inproc.SetValue('ThreadingModel', 'Apartment', [Microsoft.Win32.RegistryValueKind]::String)
        $inproc.Dispose()
    } finally { $registry.Dispose() }

    Write-Output "Experimental ticket tile registered only for SID $($configuredSids[0])."
    if ($KeepInstalled) {
        Write-Output 'Automatic rollback is disabled by -KeepInstalled. Standard Windows password/PIN recovery remains enabled.'
    } else {
        Write-Output "Automatic rollback is armed for $($taskInfo.NextRunTime); do not stop that timer."
    }
    Write-Output 'The existing TPM/VSC provider and Windows password/PIN sign-in options were left registered.'
    Write-Output 'This proves only the Clone 1 LogonUI handoff; it is not the phone PKINIT flow or physical-PC deployment.'
} catch {
    $rollbackPath = Join-Path $installDir $rollbackName
    if ($registeredService) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        for ($i = 0; $i -lt 20 -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue); $i++) {
            Start-Sleep -Milliseconds 250
        }
    }
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $registry.DeleteSubKeyTree($providerPath, $false)
        $registry.DeleteSubKeyTree($classPath, $false)
    } finally { $registry.Dispose() }
    if ($registeredTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $configRoot) {
        foreach ($key in Get-ChildItem -LiteralPath $configRoot) {
            Remove-ItemProperty -LiteralPath $key.PSPath -Name TicketLogonTest -ErrorAction SilentlyContinue
        }
    }
    throw
}
