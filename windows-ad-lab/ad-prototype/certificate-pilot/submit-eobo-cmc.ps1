#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CAConfig,
    [Parameter(Mandatory = $true)][string] $TemplateName,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string] $CmcJson
)

begin {
    $ErrorActionPreference = 'Stop'
    $inputLines = [System.Collections.Generic.List[string]]::new()
}

process {
    if ($inputLines.Count -ge 1) { throw 'Provide exactly one CMC JSON object.' }
    if (-not $CmcJson -or $CmcJson.Length -gt 200KB) { throw 'The CMC JSON input is empty or too large.' }
    $inputLines.Add($CmcJson)
}

end {
    $request = $null
    try {
        if ($inputLines.Count -ne 1) { throw 'Provide exactly one CMC JSON object.' }
        if ($CAConfig -notmatch '^[A-Za-z0-9.-]{1,253}\\[A-Za-z0-9_. -]{1,64}$') {
            throw 'CAConfig must be a configured CA name in ComputerName\CAName form.'
        }
        if ($TemplateName -notmatch '^[A-Za-z0-9_-]{1,64}$') {
            throw 'The certificate template short name is invalid.'
        }

        $bundle = ConvertFrom-Json -InputObject $inputLines[0]
        $expectedFields = @(
            'result', 'submitted', 'csr_sha256', 'requester', 'template',
            'enrollment_agent_thumbprint', 'cmc_base64'
        )
        if ($null -eq $bundle -or $bundle -isnot [System.Management.Automation.PSCustomObject]
                -or (@($bundle.PSObject.Properties.Name | Sort-Object) -join ',') -ne
                   (@($expectedFields | Sort-Object) -join ',')
                -or $bundle.result -ne 'eobo_cmc_prepared' -or $bundle.submitted -ne $false
                -or $bundle.template -cne $TemplateName
                -or $bundle.csr_sha256 -notmatch '^[a-f0-9]{64}$'
                -or $bundle.requester -notmatch '^[A-Za-z0-9_.@-]{1,128}\\[A-Za-z0-9_.-]{1,64}$'
                -or $bundle.enrollment_agent_thumbprint -notmatch '^[A-F0-9]{40}$'
                -or $bundle.cmc_base64 -isnot [string]
                -or $bundle.cmc_base64.Length -lt 256 -or $bundle.cmc_base64.Length -gt 128KB) {
            throw 'The CMC bundle is malformed or does not match the explicitly selected template.'
        }
        $cmcBytes = [Convert]::FromBase64String($bundle.cmc_base64)
        if ([Convert]::ToBase64String($cmcBytes) -cne $bundle.cmc_base64) {
            [Array]::Clear($cmcBytes, 0, $cmcBytes.Length)
            throw 'The CMC request is not canonical base64.'
        }
        [Array]::Clear($cmcBytes, 0, $cmcBytes.Length)

        # CR_IN_BASE64=1, CR_IN_CMC=0x400, CR_OUT_BASE64=1. The CA performs the actual
        # enrollment-agent/template authorization; this helper cannot bypass it.
        $request = New-Object -ComObject CertificateAuthority.Request
        $submitFlags = 1 -bor 0x400
        $disposition = [int]$request.Submit(
            $submitFlags, $bundle.cmc_base64, "CertificateTemplate:$TemplateName", $CAConfig)
        $requestId = [int]$request.GetRequestId()
        if ($requestId -lt 0) { throw 'The CA returned an invalid request ID.' }

        if ($disposition -eq 3) { # CR_DISP_ISSUED
            $certificateBase64 = ([string]$request.GetCertificate(1)) -replace '\s', ''
            if ($certificateBase64.Length -lt 344 -or $certificateBase64.Length -gt 87384) {
                throw 'The CA returned an invalid or oversized certificate.'
            }
            $certificateDer = [Convert]::FromBase64String($certificateBase64)
            if ($certificateDer.Length -lt 256 -or $certificateDer.Length -gt 64KB
                    -or [Convert]::ToBase64String($certificateDer) -cne $certificateBase64) {
                [Array]::Clear($certificateDer, 0, $certificateDer.Length)
                throw 'The CA response is not a canonical DER certificate.'
            }
            [ordered]@{
                result = 'issued'
                request_id = $requestId
                csr_sha256 = $bundle.csr_sha256
                requester = $bundle.requester
                template = $TemplateName
                certificate_der_b64 = $certificateBase64
            } | ConvertTo-Json -Compress
            [Array]::Clear($certificateDer, 0, $certificateDer.Length)
        } elseif ($disposition -eq 5) { # CR_DISP_UNDER_SUBMISSION
            [ordered]@{
                result = 'pending'
                request_id = $requestId
                csr_sha256 = $bundle.csr_sha256
                requester = $bundle.requester
                template = $TemplateName
            } | ConvertTo-Json -Compress
        } else {
            $message = [string]$request.GetDispositionMessage()
            if ($message.Length -gt 240) { $message = $message.Substring(0, 240) }
            throw "The CA did not issue or pend the request (disposition $disposition): $message"
        }
    }
    finally {
        if ($null -ne $request -and [Runtime.InteropServices.Marshal]::IsComObject($request)) {
            try { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($request) | Out-Null } catch { }
        }
    }
}
