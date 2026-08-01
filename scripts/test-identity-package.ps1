[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ManifestPath,

    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$ExpectedVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path $PSScriptRoot -Parent
$cargoManifestPath = Join-Path $repoRoot "Cargo.toml"
$cargoManifest = Get-Content -LiteralPath $cargoManifestPath -Raw
$workspaceVersionMatch = [regex]::Match(
    $cargoManifest,
    '(?ms)^\[workspace\.package\].*?^version\s*=\s*"(?<version>\d+\.\d+\.\d+)"'
)
if (-not $workspaceVersionMatch.Success) {
    throw "Could not read the workspace package version from '$cargoManifestPath'."
}
$workspaceVersion = "$($workspaceVersionMatch.Groups["version"].Value).0"
if (-not $ExpectedVersion) {
    $ExpectedVersion = $workspaceVersion
}
foreach ($part in $ExpectedVersion.Split(".")) {
    if ([uint32]$part -gt 65535) {
        throw "Identity package version part '$part' exceeds 65535."
    }
}

$expectedPackageName = "TheUndeadMonk.Librarian.Development"
$expectedPublisher = "CN=Librarian Development"
$expectedApplications = [ordered]@{
    VaultAgent = "Librarian.VaultAgent.exe"
    Desktop = "Librarian.Windows.exe"
    ChromiumNativeHost = "Librarian.ChromiumNativeHost.exe"
}

$resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath).Path
[xml]$manifest = Get-Content -LiteralPath $resolvedManifest -Raw
$namespaceManager = New-Object Xml.XmlNamespaceManager($manifest.NameTable)
$namespaceManager.AddNamespace(
    "foundation",
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
)
$namespaceManager.AddNamespace(
    "uap",
    "http://schemas.microsoft.com/appx/manifest/uap/windows10"
)
$namespaceManager.AddNamespace(
    "uap10",
    "http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
)
$namespaceManager.AddNamespace(
    "rescap",
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
)

$package = $manifest.SelectSingleNode("/foundation:Package", $namespaceManager)
$ignorableNamespaces = @(
    $package.GetAttribute("IgnorableNamespaces").Split(
        [char[]]@(" ", "`t", "`r", "`n"),
        [StringSplitOptions]::RemoveEmptyEntries
    )
)
foreach ($namespace in @("uap", "uap10", "rescap")) {
    if ($namespace -notin $ignorableNamespaces) {
        throw "Identity package must mark '$namespace' as an ignorable namespace."
    }
}

$expectedTopLevelOrder = @(
    "Identity",
    "Properties",
    "Resources",
    "Dependencies",
    "Capabilities",
    "Applications"
)
$actualTopLevelOrder = @(
    $package.ChildNodes |
        Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element } |
        ForEach-Object { $_.LocalName }
)
if (($actualTopLevelOrder -join ",") -ne ($expectedTopLevelOrder -join ",")) {
    throw (
        "Identity package top-level elements must follow Microsoft's external-location " +
        "template order. Expected '$($expectedTopLevelOrder -join ", ")'; found " +
        "'$($actualTopLevelOrder -join ", ")'."
    )
}

$identity = $manifest.SelectSingleNode(
    "/foundation:Package/foundation:Identity",
    $namespaceManager
)
if (-not $identity) {
    throw "Identity package manifest is missing its Identity element."
}
if ($identity.Name -ne $expectedPackageName) {
    throw "Unexpected package name '$($identity.Name)'."
}
if ($identity.Publisher -ne $expectedPublisher) {
    throw "Unexpected package publisher '$($identity.Publisher)'."
}
if ($identity.ProcessorArchitecture -ne "neutral") {
    throw "Identity package architecture must be neutral."
}
if ($identity.Version -ne $ExpectedVersion) {
    throw (
        "Identity package version '$($identity.Version)' does not match workspace " +
        "or requested fixture version '$ExpectedVersion'."
    )
}

$allowExternalContent = $manifest.SelectSingleNode(
    "/foundation:Package/foundation:Properties/uap10:AllowExternalContent",
    $namespaceManager
)
if (-not $allowExternalContent -or $allowExternalContent.InnerText -ne "true") {
    throw "Identity package must set AllowExternalContent to true."
}

foreach ($capability in @("runFullTrust", "unvirtualizedResources")) {
    $node = $manifest.SelectSingleNode(
        "/foundation:Package/foundation:Capabilities/rescap:Capability[@Name='$capability']",
        $namespaceManager
    )
    if (-not $node) {
        throw "Identity package is missing the '$capability' capability."
    }
}

$applications = $manifest.SelectNodes(
    "/foundation:Package/foundation:Applications/foundation:Application",
    $namespaceManager
)
if ($applications.Count -ne $expectedApplications.Count) {
    throw (
        "Expected $($expectedApplications.Count) application identities, " +
        "found $($applications.Count)."
    )
}

foreach ($applicationId in $expectedApplications.Keys) {
    $application = $manifest.SelectSingleNode(
        (
            "/foundation:Package/foundation:Applications/" +
            "foundation:Application[@Id='$applicationId']"
        ),
        $namespaceManager
    )
    if (-not $application) {
        throw "Identity package is missing application '$applicationId'."
    }
    if ($application.Executable -ne $expectedApplications[$applicationId]) {
        throw "Application '$applicationId' has an unexpected executable path."
    }
    if ($application.GetAttribute("TrustLevel", $namespaceManager.LookupNamespace("uap10")) -ne "mediumIL") {
        throw "Application '$applicationId' must use mediumIL."
    }
    if ($application.GetAttribute("RuntimeBehavior", $namespaceManager.LookupNamespace("uap10")) -ne "win32App") {
        throw "Application '$applicationId' must use win32App runtime behavior."
    }

    $visualElements = $application.SelectSingleNode("uap:VisualElements", $namespaceManager)
    if (-not $visualElements -or $visualElements.AppListEntry -ne "none") {
        throw "Application '$applicationId' must remain hidden from the app list."
    }
}

$passkeyProvider = $manifest.SelectSingleNode(
    (
        "/foundation:Package/foundation:Applications/" +
        "foundation:Application[@Id='PasskeyProvider']"
    ),
    $namespaceManager
)
if ($passkeyProvider) {
    throw (
        "The identity fixture must not register a passkey provider before issue #18 " +
        "supplies the production executable."
    )
}

$externalManifestPaths = [ordered]@{
    Desktop = "apps\windows\Librarian.Windows\app.manifest"
    VaultAgent = "crates\vault-agent\app.manifest"
    ChromiumNativeHost = "platform\chromium-native-host\app.manifest"
}

foreach ($applicationId in $externalManifestPaths.Keys) {
    $externalManifestPath = Join-Path $repoRoot $externalManifestPaths[$applicationId]
    [xml]$externalManifest = Get-Content -LiteralPath $externalManifestPath -Raw
    $externalNamespaceManager = New-Object Xml.XmlNamespaceManager(
        $externalManifest.NameTable
    )
    $externalNamespaceManager.AddNamespace("assembly", "urn:schemas-microsoft-com:asm.v1")
    $externalNamespaceManager.AddNamespace("msix", "urn:schemas-microsoft-com:msix.v1")

    $assemblyIdentity = $externalManifest.SelectSingleNode(
        "/assembly:assembly/assembly:assemblyIdentity",
        $externalNamespaceManager
    )
    if (-not $assemblyIdentity) {
        throw "'$externalManifestPath' is missing its assembly identity."
    }
    if ($assemblyIdentity.GetAttribute("version") -ne $workspaceVersion) {
        throw (
            "'$externalManifestPath' assembly version " +
            "'$($assemblyIdentity.GetAttribute("version"))' does not match workspace " +
            "version '$workspaceVersion'."
        )
    }

    $msix = $externalManifest.SelectSingleNode(
        "/assembly:assembly/msix:msix",
        $externalNamespaceManager
    )
    if (-not $msix) {
        throw "'$externalManifestPath' is missing MSIX identity metadata."
    }
    if ($msix.packageName -ne $expectedPackageName -or
        $msix.publisher -ne $expectedPublisher -or
        $msix.applicationId -ne $applicationId) {
        throw "'$externalManifestPath' does not match application '$applicationId'."
    }
}

Write-Host "Identity package manifest validation passed."
Write-Host "Manifest: $resolvedManifest"
Write-Host "Version: $ExpectedVersion"
Write-Host "Applications: $($expectedApplications.Count)"
