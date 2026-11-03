param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string] $ExpectedSha256
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this update from an elevated PowerShell session.'
}

$taskName = 'Thessley-AD-PIV-Phone-Reader'
$source = Join-Path $env:PUBLIC 'piv-phone-reader-poc.py'
$target = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider\piv-phone-reader-poc.py'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Staged PIV helper not found: $source" }
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Installed PIV helper not found: $target" }
$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
if ($sourceHash -ne $ExpectedSha256.ToUpperInvariant()) { throw 'Staged PIV helper SHA-256 does not match the expected build.' }

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) { throw 'PIV reader task is not running as SYSTEM.' }
$backup = "$target.before-response-chaining-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $target -Destination $backup -ErrorAction Stop
$wasRunning = $task.State -eq 'Running'

try {
    if ($wasRunning) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        } while ($task.State -eq 'Running' -and (Get-Date) -lt $deadline)
        if ($task.State -eq 'Running') { throw 'PIV reader task did not stop; helper was not replaced.' }
    }

    Copy-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop
    & icacls.exe $target /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore the protected PIV helper ACL.' }
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
        throw 'Installed PIV helper hash verification failed.'
    }

    if ($wasRunning) {
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        } while ($task.State -ne 'Running' -and (Get-Date) -lt $deadline)
        if ($task.State -ne 'Running') { throw 'PIV reader task did not return to Running state.' }
    }
} catch {
    if ($wasRunning) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    Copy-Item -LiteralPath $backup -Destination $target -Force -ErrorAction SilentlyContinue
    if ($wasRunning) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw
}

Write-Output "PIV helper updated and verified ($ExpectedSha256)."
Write-Output "Rollback copy: $backup"
