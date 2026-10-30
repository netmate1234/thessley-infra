#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# Isolated CSR/key-generation proof. This does not contact the CA, install a
# certificate, register a logon provider, or change Windows sign-in policy.
$root = Join-Path $env:ProgramData 'ThessleyPamWin\ad-agent\certificate-requests'
$requestId = [Guid]::NewGuid().ToString('N')
$containerPrefix = "ThessleyAD-$requestId"
$containerName = $null
$keyCreated = $false
$csrPath = $null
$manifestPath = $null
$manifest = $null
$providerName = 'Microsoft Software Key Storage Provider'
$requestLifetime = [TimeSpan]::FromHours(24)
$rsa = $null

function Set-ProtectedDirectory([string] $Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $directory = Get-Item -LiteralPath $Path -Force
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The protected certificate-request folder cannot be a reparse point.'
    }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Remove-GeneratedKey([string] $Container) {
    if (-not $Container -or $Container -notmatch '^ThessleyAD-[a-f0-9]{32}$') {
        throw 'Refusing to delete a key container outside the generated request namespace.'
    }
    & "$env:SystemRoot\System32\certutil.exe" -delkey -csp $providerName $Container *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'The temporary CNG key could not be removed; its manifest was retained for recovery.'
    }
}

function Save-Manifest([System.Collections.IDictionary] $Data, [string] $Path) {
    $temporaryPath = "$Path.new"
    $json = $Data | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

try {
    Set-ProtectedDirectory $root
    $csrPath = Join-Path $root "$requestId.csr.der"
    $manifestPath = Join-Path $root "$requestId.json"
    $subjectName = "CN=Thessley temporary sign-in $requestId"

    $key = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $key.ProviderName = $providerName
    $key.ProviderType = 0
    $rsa = New-Object -ComObject X509Enrollment.CObjectId
    $rsa.InitializeFromValue('1.2.840.113549.1.1.1')
    $key.Algorithm = $rsa
    $key.MachineContext = $true
    $key.Length = 3072
    $key.KeySpec = 0
    $key.ExportPolicy = 0
    # RSA smart-card/PKINIT logon needs both signing and key exchange. In
    # X509PrivateKeyUsageFlags these are ALLOW_SIGNING (0x2) and ALLOW_DECRYPT
    # (0x1); this is distinct from KERB_SMARTCARD_CSP_INFO.KeySpec at logon.
    $key.KeyUsage = 3
    $key.Silent = $true
    $key.ContainerName = $containerPrefix
    $key.SecurityDescriptor = 'D:P(A;;GA;;;SY)(A;;GA;;;BA)'
    $key.Create()
    $keyCreated = $true
    if (($key.KeyUsage -band 3) -ne 3) {
        throw 'The generated RSA key does not permit both signing and key exchange.'
    }
    $containerName = [string]$key.ContainerName
    if ($containerName -ne $containerPrefix) {
        throw 'Windows returned an unexpected temporary key-container name.'
    }
    $now = [DateTime]::UtcNow
    $manifest = [ordered]@{
        version = 1
        state = 'key-created'
        request_id = $requestId
        created_utc = $now.ToString('o')
        expires_utc = $now.Add($requestLifetime).ToString('o')
        csr_path = $csrPath
        csr_sha256 = ''
        request_thumbprint = ''
        request_subject = $subjectName
        provider_name = $providerName
        provider_type = 0
        key_spec = 0
        key_container = $containerName
        machine_key = $true
        exportable = $false
    }
    Save-Manifest $manifest $manifestPath

    $request = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    # ContextMachine is required because this key lives in the machine KSP.
    $request.InitializeFromPrivateKey(2, $key, $null)
    $distinguishedName = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $distinguishedName.Encode($subjectName, 0)
    $request.Subject = $distinguishedName

    $sha256 = New-Object -ComObject X509Enrollment.CObjectId
    $sha256.InitializeFromValue('2.16.840.1.101.3.4.2.1')
    $request.SignatureInformation.HashAlgorithm = $sha256

    $enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
    $enrollment.InitializeFromRequest($request)
    $encoded = [string]$enrollment.CreateRequest(1) # Base64 DER PKCS#10
    $base64 = $encoded -replace '\s', ''
    $der = [Convert]::FromBase64String($base64)
    if ($der.Length -lt 256 -or $der.Length -gt 65536) {
        throw 'Windows returned a malformed or oversized certificate request.'
    }

    $stream = [IO.File]::Open($csrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($der, 0, $der.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $shaProvider = [Security.Cryptography.SHA256]::Create()
    try {
        $digestBytes = $shaProvider.ComputeHash($der)
        $digest = ([BitConverter]::ToString($digestBytes)).Replace('-', '').ToLowerInvariant()
        [Array]::Clear($digestBytes, 0, $digestBytes.Length)
    } finally { $shaProvider.Dispose() }
    $pending = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\Request' -ErrorAction Stop |
        Where-Object { $_.Subject -eq $subjectName })
    if ($pending.Count -ne 1) {
        throw 'Windows did not create exactly one matching pending request-store record.'
    }
    $manifest.state = 'ready'
    $manifest.csr_sha256 = $digest
    $manifest.request_thumbprint = [string]$pending[0].Thumbprint
    Save-Manifest $manifest $manifestPath
    Set-ProtectedDirectory $root
    [pscustomobject]@{
        request_id = $requestId
        csr_path = $csrPath
        csr_sha256 = $digest
        key_container = $containerName
        provider_name = $providerName
        expires_utc = $manifest.expires_utc
    } | ConvertTo-Json -Compress
}
catch {
    $keyRemoved = -not $keyCreated
    if ($keyCreated) {
        try { Remove-GeneratedKey $containerName; $keyRemoved = $true }
        catch {
            if ($manifestPath -and -not (Test-Path -LiteralPath $manifestPath) -and $containerName) {
                $now = [DateTime]::UtcNow
                $manifest = [ordered]@{
                    version = 1
                    state = 'key-created'
                    request_id = $requestId
                    created_utc = $now.ToString('o')
                    expires_utc = $now.Add($requestLifetime).ToString('o')
                    csr_path = $csrPath
                    csr_sha256 = ''
                    request_thumbprint = ''
                    request_subject = $subjectName
                    provider_name = $providerName
                    provider_type = 0
                    key_spec = 0
                    key_container = $containerName
                    machine_key = $true
                    exportable = $false
                }
                try { Save-Manifest $manifest $manifestPath } catch { }
            }
            Write-Warning "Temporary key cleanup failed for request $requestId. Keep its manifest for manual recovery."
        }
    }
    if ($keyRemoved) {
        try {
            if ($keyCreated -and $manifestPath -and (Test-Path -LiteralPath $manifestPath)) {
                $manifest.state = 'key-deleted'
                Save-Manifest $manifest $manifestPath
            }
            if ($subjectName -and (Test-Path -LiteralPath 'Cert:\LocalMachine\Request')) {
                $requests = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\Request' |
                    Where-Object { $_.Subject -eq $subjectName })
                foreach ($requestCert in $requests) {
                    if ($requestCert.Subject -ne $subjectName) { throw 'Unexpected request-store record.' }
                    Remove-Item -LiteralPath $requestCert.PSPath -Force
                }
            }
            foreach ($path in @($csrPath, $manifestPath, "$manifestPath.new")) {
                if ($path -and (Test-Path -LiteralPath $path)) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            }
        } catch {
            Write-Warning 'Temporary request-store cleanup failed; inspect the protected manifest before retrying.'
        }
    }
    throw
}
finally {
    if ($der) { [Array]::Clear($der, 0, $der.Length) }
    if ($base64) { $base64 = $null }
    if ($encoded) { $encoded = $null }
    foreach ($comObject in @($request, $key, $enrollment, $distinguishedName, $sha256, $rsa)) {
        if ($null -ne $comObject -and [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
            try { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject) | Out-Null } catch { }
        }
    }
}
