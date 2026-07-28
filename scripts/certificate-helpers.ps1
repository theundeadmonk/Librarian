Set-StrictMode -Version Latest

function Get-EnhancedKeyUsageOidValue {
    param(
        [Parameter(Mandatory)]
        [object]$ObjectId
    )

    if ($ObjectId -is [string]) {
        return $ObjectId
    }
    if ($ObjectId -is [Security.Cryptography.Oid]) {
        return $ObjectId.Value
    }

    $valueProperty = $ObjectId.PSObject.Properties["Value"]
    if ($null -ne $valueProperty) {
        return [string]$valueProperty.Value
    }

    return [string]$ObjectId
}

function Test-CertificateEnhancedKeyUsage {
    param(
        [Parameter(Mandatory)]
        [object]$Certificate,

        [Parameter(Mandatory)]
        [string]$RequiredOid
    )

    foreach ($usage in @($Certificate.EnhancedKeyUsageList)) {
        if ((Get-EnhancedKeyUsageOidValue -ObjectId $usage.ObjectId) -eq
            $RequiredOid) {
            return $true
        }
    }
    return $false
}
