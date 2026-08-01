Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "certificate-helpers.ps1")

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$representations = @(
    $codeSigningOid,
    [Security.Cryptography.Oid]::new($codeSigningOid),
    [PSCustomObject]@{ Value = $codeSigningOid }
)

foreach ($representation in $representations) {
    $certificate = [PSCustomObject]@{
        EnhancedKeyUsageList = @(
            [PSCustomObject]@{ ObjectId = $representation }
        )
    }
    Assert-True `
        -Condition (Test-CertificateEnhancedKeyUsage `
            -Certificate $certificate `
            -RequiredOid $codeSigningOid) `
        -Message "A supported EKU object-id representation was rejected."
}

$wrongCertificate = [PSCustomObject]@{
    EnhancedKeyUsageList = @(
        [PSCustomObject]@{ ObjectId = "1.3.6.1.5.5.7.3.1" }
    )
}
Assert-True `
    -Condition (-not (Test-CertificateEnhancedKeyUsage `
        -Certificate $wrongCertificate `
        -RequiredOid $codeSigningOid)) `
    -Message "A certificate without the code-signing EKU was accepted."

Write-Host "Certificate helper tests passed."
