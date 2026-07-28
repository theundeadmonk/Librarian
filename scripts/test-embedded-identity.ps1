[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$MtPath,

    [Parameter(Mandatory)]
    [string]$Configuration,

    [Parameter(Mandatory)]
    [ValidateSet("x64")]
    [string]$Platform
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Configuration -ne "Release") {
    throw "Embedded package identity is validated only for Release binaries."
}
if (-not (Test-Path -LiteralPath $MtPath -PathType Leaf)) {
    throw "mt.exe was not found at '$MtPath'."
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$outputDirectory = Join-Path $repoRoot "artifacts\package\embedded-manifests"
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$expectedPackageName = "TheUndeadMonk.Librarian.Development"
$expectedPublisher = "CN=Librarian Development"
$binaries = [ordered]@{
    VaultAgent = Join-Path (
        Join-Path $repoRoot "target\x86_64-pc-windows-msvc\release"
    ) "librarian-vault-agent.exe"
    ChromiumNativeHost = Join-Path (
        Join-Path $repoRoot "target\x86_64-pc-windows-msvc\release"
    ) "librarian-chromium-native-host.exe"
    Desktop = Join-Path (
        Join-Path $repoRoot "$Platform\$Configuration\Librarian.Windows"
    ) "Librarian.Windows.exe"
}

foreach ($applicationId in $binaries.Keys) {
    $binaryPath = $binaries[$applicationId]
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw "Release binary was not built at '$binaryPath'."
    }

    $manifestPath = Join-Path $outputDirectory "$applicationId.manifest"
    & $MtPath `
        -nologo `
        "-inputresource:$binaryPath;#1" `
        "-out:$manifestPath"
    if ($LASTEXITCODE -ne 0) {
        throw "mt.exe failed to read '$binaryPath' with exit code $LASTEXITCODE."
    }

    [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
    $namespaceManager = New-Object Xml.XmlNamespaceManager($manifest.NameTable)
    $namespaceManager.AddNamespace("assembly", "urn:schemas-microsoft-com:asm.v1")
    $namespaceManager.AddNamespace("msix", "urn:schemas-microsoft-com:msix.v1")
    $msix = $manifest.SelectSingleNode(
        "/assembly:assembly/msix:msix",
        $namespaceManager
    )
    if (-not $msix) {
        throw "'$binaryPath' is missing embedded MSIX identity metadata."
    }
    if ($msix.packageName -ne $expectedPackageName -or
        $msix.publisher -ne $expectedPublisher -or
        $msix.applicationId -ne $applicationId) {
        throw "'$binaryPath' has mismatched embedded identity metadata."
    }
}

Write-Host "Release binary identity validation passed."
Write-Host "Binaries: $($binaries.Count)"
