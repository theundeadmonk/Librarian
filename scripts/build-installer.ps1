[CmdletBinding()]
param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$ProductVersion,

    [ValidatePattern("^[a-p]{32}$")]
    [string]$ChromeExtensionId = "abcdefghijklmnopabcdefghijklmnop",

    [ValidatePattern("^[a-p]{32}$")]
    [string]$EdgeExtensionId = "ponmlkjihgfedcbaponmlkjihgfedcba",

    [ValidatePattern("^[A-Fa-f0-9]{40}$")]
    [string]$DevelopmentCertificateThumbprint,

    [switch]$SuppressMsiValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "native-process-arguments.ps1")

function Invoke-CheckedProcess {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [string]$WorkingDirectory
    )

    Write-Host ""
    Write-Host "==> $Label"

    $argumentText = Join-NativeProcessArguments -Arguments $Arguments

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $argumentText
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables["Path"] = $env:Path

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "$Label could not start '$FilePath'."
    }

    try {
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()

        $output = $standardOutput.Result
        $errorOutput = $standardError.Result
        if ($output) {
            Write-Host $output.TrimEnd()
        }
        if ($errorOutput) {
            Write-Host $errorOutput.TrimEnd()
        }
        if ($process.ExitCode -ne 0) {
            throw "$Label failed with exit code $($process.ExitCode)."
        }
    } finally {
        $process.Dispose()
    }
}

function Reset-ArtifactDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$ArtifactRoot
    )

    $resolvedRoot = [IO.Path]::GetFullPath($ArtifactRoot).TrimEnd("\")
    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd("\")
    if (-not $resolvedPath.StartsWith(
            "$resolvedRoot\",
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Refusing to reset non-artifact path '$resolvedPath'."
    }

    if (Test-Path -LiteralPath $resolvedPath) {
        Remove-Item -LiteralPath $resolvedPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $resolvedPath | Out-Null
}

function Copy-RuntimeTree {
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    $excludedNames = @(
        "AppxManifest.xml",
        "Librarian.Windows.build.appxrecipe"
    )
    $excludedExtensions = @(".exp", ".lib", ".pdb")
    $resolvedSource = (Resolve-Path -LiteralPath $Source).Path.TrimEnd("\")

    foreach ($file in Get-ChildItem -LiteralPath $resolvedSource -File -Recurse) {
        if ($file.Name -in $excludedNames -or
            $file.Extension -in $excludedExtensions) {
            continue
        }

        $relativePath = $file.FullName.Substring($resolvedSource.Length + 1)
        $destinationPath = Join-Path $Destination $relativePath
        $destinationDirectory = Split-Path $destinationPath -Parent
        New-Item -ItemType Directory -Path $destinationDirectory -Force |
            Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destinationPath
    }
}

function Get-WorkspaceVersion {
    param(
        [Parameter(Mandatory)]
        [string]$CargoManifestPath
    )

    $manifest = Get-Content -LiteralPath $CargoManifestPath -Raw
    $match = [regex]::Match(
        $manifest,
        '(?ms)^\[workspace\.package\].*?^version\s*=\s*"(?<version>\d+\.\d+\.\d+)"'
    )
    if (-not $match.Success) {
        throw "Could not read the workspace version from '$CargoManifestPath'."
    }
    return "$($match.Groups["version"].Value).0"
}

function Set-EmbeddedManifestVersion {
    param(
        [Parameter(Mandatory)]
        [string]$ManifestSource,

        [Parameter(Mandatory)]
        [string]$RenderedManifest,

        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string]$Version,

        [Parameter(Mandatory)]
        [string]$ManifestTool,

        [Parameter(Mandatory)]
        [string]$RepoRoot
    )

    [xml]$manifest = Get-Content -LiteralPath $ManifestSource -Raw
    $namespaceManager = New-Object Xml.XmlNamespaceManager($manifest.NameTable)
    $namespaceManager.AddNamespace(
        "assembly",
        "urn:schemas-microsoft-com:asm.v1"
    )
    $identity = $manifest.SelectSingleNode(
        "/assembly:assembly/assembly:assemblyIdentity",
        $namespaceManager
    )
    if (-not $identity) {
        throw "'$ManifestSource' has no assembly identity to version."
    }
    $identity.SetAttribute("version", $Version)

    $settings = New-Object Xml.XmlWriterSettings
    $settings.Encoding = New-Object Text.UTF8Encoding($false)
    $settings.Indent = $true
    $settings.NewLineChars = [Environment]::NewLine
    $writer = [Xml.XmlWriter]::Create($RenderedManifest, $settings)
    try {
        $manifest.Save($writer)
    } finally {
        $writer.Dispose()
    }

    Invoke-CheckedProcess `
        -Label "Stamp $(Split-Path $Executable -Leaf) identity manifest" `
        -FilePath $ManifestTool `
        -Arguments @(
            "-nologo",
            "-manifest",
            $RenderedManifest,
            "-outputresource:$Executable;#1"
        ) `
        -WorkingDirectory $RepoRoot
}

function Resolve-DevelopmentCertificate {
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    $normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    $matches = @()
    foreach ($store in @(
        "Cert:\CurrentUser\My\$normalized",
        "Cert:\LocalMachine\My\$normalized"
    )) {
        if (Test-Path -LiteralPath $store) {
            $matches += Get-Item -LiteralPath $store
        }
    }

    if ($matches.Count -ne 1) {
        throw (
            "The development signing certificate must resolve exactly once in " +
            "CurrentUser\My or LocalMachine\My."
        )
    }

    $certificate = $matches[0]
    if (-not $certificate.HasPrivateKey) {
        throw "The development signing certificate has no private key."
    }
    if ($certificate.NotBefore -gt [DateTime]::Now -or
        $certificate.NotAfter -lt [DateTime]::Now) {
        throw "The development signing certificate is not currently valid."
    }
    if ($certificate.Subject -ne "CN=Librarian Development") {
        throw (
            "The identity fixture requires the exact development subject " +
            "'CN=Librarian Development'."
        )
    }

    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $hasCodeSigning = @(
        $certificate.EnhancedKeyUsageList |
            Where-Object { $_.ObjectId.Value -eq $codeSigningOid }
    ).Count -gt 0
    if (-not $hasCodeSigning) {
        throw "The development certificate is not valid for code signing."
    }

    return [PSCustomObject]@{
        Certificate = $certificate
        MachineStore = $certificate.PSPath -like "*LocalMachine*"
        Thumbprint = $normalized
    }
}

function Invoke-Sign {
    param(
        [Parameter(Mandatory)]
        [string]$SignTool,

        [Parameter(Mandatory)]
        [PSCustomObject]$SigningIdentity,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$RepoRoot
    )

    $arguments = @("sign", "/fd", "SHA256", "/sha1", $SigningIdentity.Thumbprint)
    if ($SigningIdentity.MachineStore) {
        $arguments += "/sm"
    }
    $arguments += $Path
    Invoke-CheckedProcess `
        -Label "Sign $(Split-Path $Path -Leaf)" `
        -FilePath $SignTool `
        -Arguments $arguments `
        -WorkingDirectory $RepoRoot

    Invoke-CheckedProcess `
        -Label "Verify $(Split-Path $Path -Leaf)" `
        -FilePath $SignTool `
        -Arguments @("verify", "/pa", "/all", $Path) `
        -WorkingDirectory $RepoRoot
}

$toolchain = & (Join-Path $PSScriptRoot "bootstrap.ps1") -PassThru
$repoRoot = $toolchain.RepoRoot
$dotnet = $toolchain.DotNet
if (-not $ProductVersion) {
    $ProductVersion = Get-WorkspaceVersion (
        Join-Path $repoRoot "Cargo.toml"
    )
}
$versionParts = @($ProductVersion.Split(".") | ForEach-Object { [uint32]$_ })
if ($versionParts[0] -gt 255 -or $versionParts[1] -gt 255 -or
    $versionParts[2] -gt 65535 -or $versionParts[3] -gt 65535) {
    throw (
        "Installer product version '$ProductVersion' exceeds Windows " +
        "Installer or MSIX field limits."
    )
}
if ($versionParts[3] -ne 0) {
    throw (
        "Installer product version '$ProductVersion' uses a nonzero revision. " +
        "Windows Installer compares only the first three fields, so coherent " +
        "upgrades require the fourth field to remain zero."
    )
}

$artifactsRoot = Join-Path $repoRoot "artifacts"
$installerRoot = Join-Path $artifactsRoot "installer"
$payloadDirectory = Join-Path $installerRoot "payload"
$browserManifestDirectory = Join-Path $installerRoot "browser-manifests"
$customActionInputDirectory = Join-Path $installerRoot "custom-action"
$msiOutputDirectory = Join-Path $installerRoot "msi"
$bundleOutputDirectory = Join-Path $installerRoot "bundle"
$intermediateDirectory = Join-Path $installerRoot "obj"

foreach ($directory in @(
    $payloadDirectory,
    $browserManifestDirectory,
    $customActionInputDirectory,
    $msiOutputDirectory,
    $bundleOutputDirectory,
    $intermediateDirectory
)) {
    Reset-ArtifactDirectory `
        -Path $directory `
        -ArtifactRoot $artifactsRoot
}

$desktopOutput = Join-Path $repoRoot "$Platform\$Configuration\Librarian.Windows"
$vaultAgent = Join-Path $repoRoot (
    "target\x86_64-pc-windows-msvc\release\librarian-vault-agent.exe"
)
$nativeHost = Join-Path $repoRoot (
    "target\x86_64-pc-windows-msvc\release\librarian-chromium-native-host.exe"
)
$customActionProject = Join-Path $repoRoot (
    "packaging\windows\custom-actions\Librarian.Setup.CustomActions.vcxproj"
)
$customActionOutput = Join-Path $repoRoot (
    "artifacts\bin\$Platform\$Configuration\Librarian.Setup.CustomActions.dll"
)

foreach ($requiredPath in @(
    $desktopOutput,
    $vaultAgent,
    $nativeHost,
    $customActionProject
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required installer input is missing: $requiredPath"
    }
}

& (Join-Path $PSScriptRoot "build-identity-package.ps1") `
    -ProductVersion $ProductVersion
$identityPackageSource = Join-Path $repoRoot (
    "artifacts\package\Librarian.Identity_${ProductVersion}_neutral.msix"
)
if (-not (Test-Path -LiteralPath $identityPackageSource -PathType Leaf)) {
    throw "The identity package was not created at '$identityPackageSource'."
}

Invoke-CheckedProcess `
    -Label "Locked setup custom-action restore" `
    -FilePath $toolchain.MSBuild `
    -Arguments @(
        $customActionProject,
        "/t:Restore",
        "/m",
        "/nr:false",
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/p:RestoreLockedMode=true",
        "/verbosity:minimal"
    ) `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Setup custom-action build" `
    -FilePath $toolchain.MSBuild `
    -Arguments @(
        $customActionProject,
        "/t:Build",
        "/m",
        "/nr:false",
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/p:RestoreLockedMode=true",
        "/verbosity:minimal"
    ) `
    -WorkingDirectory $repoRoot

if (-not (Test-Path -LiteralPath $customActionOutput -PathType Leaf)) {
    throw "The setup custom-action DLL was not built at '$customActionOutput'."
}

Copy-RuntimeTree -Source $desktopOutput -Destination $payloadDirectory
Copy-Item `
    -LiteralPath $vaultAgent `
    -Destination (Join-Path $payloadDirectory "Librarian.VaultAgent.exe")
Copy-Item `
    -LiteralPath $nativeHost `
    -Destination (Join-Path $payloadDirectory "Librarian.ChromiumNativeHost.exe")
Copy-Item `
    -LiteralPath $identityPackageSource `
    -Destination (Join-Path $payloadDirectory "Librarian.Identity.msix")
Copy-Item `
    -LiteralPath $customActionOutput `
    -Destination (Join-Path $customActionInputDirectory "Librarian.Setup.CustomActions.dll")

$manifestTool = Join-Path $toolchain.WindowsSdkRoot (
    "bin\$($toolchain.Versions.WindowsSdk)\x64\mt.exe"
)
if (-not (Test-Path -LiteralPath $manifestTool -PathType Leaf)) {
    throw "The pinned mt.exe is missing at '$manifestTool'."
}
$manifestCases = @(
    [PSCustomObject]@{
        Source = Join-Path $repoRoot (
            "apps\windows\Librarian.Windows\app.manifest"
        )
        Rendered = Join-Path $intermediateDirectory "Librarian.Windows.manifest"
        Executable = Join-Path $payloadDirectory "Librarian.Windows.exe"
    },
    [PSCustomObject]@{
        Source = Join-Path $repoRoot "crates\vault-agent\app.manifest"
        Rendered = Join-Path $intermediateDirectory "Librarian.VaultAgent.manifest"
        Executable = Join-Path $payloadDirectory "Librarian.VaultAgent.exe"
    },
    [PSCustomObject]@{
        Source = Join-Path $repoRoot (
            "platform\chromium-native-host\app.manifest"
        )
        Rendered = Join-Path (
            $intermediateDirectory
        ) "Librarian.ChromiumNativeHost.manifest"
        Executable = Join-Path (
            $payloadDirectory
        ) "Librarian.ChromiumNativeHost.exe"
    }
)
foreach ($case in $manifestCases) {
    Set-EmbeddedManifestVersion `
        -ManifestSource $case.Source `
        -RenderedManifest $case.Rendered `
        -Executable $case.Executable `
        -Version $ProductVersion `
        -ManifestTool $manifestTool `
        -RepoRoot $repoRoot
}

$assetDirectory = Join-Path $payloadDirectory "Assets"
Copy-Item `
    -LiteralPath (Join-Path $assetDirectory "Square150x150Logo.scale-200.png") `
    -Destination (Join-Path $assetDirectory "Square150x150Logo.png")
Copy-Item `
    -LiteralPath (Join-Path $assetDirectory "Square44x44Logo.scale-200.png") `
    -Destination (Join-Path $assetDirectory "Square44x44Logo.png")

$nativeManifestTemplatePath = Join-Path $repoRoot (
    "packaging\windows\native-messaging\com.theundeadmonk.librarian.json.in"
)
$nativeManifestTemplate = Get-Content `
    -LiteralPath $nativeManifestTemplatePath `
    -Raw
if (-not $nativeManifestTemplate.Contains("@EXTENSION_ID@")) {
    throw "The native-messaging template is missing its extension-ID placeholder."
}
foreach ($browser in @(
    [PSCustomObject]@{ Name = "chrome"; Id = $ChromeExtensionId },
    [PSCustomObject]@{ Name = "edge"; Id = $EdgeExtensionId }
)) {
    $rendered = $nativeManifestTemplate.Replace(
        "@EXTENSION_ID@",
        $browser.Id
    )
    $manifestPath = Join-Path $browserManifestDirectory (
        "com.theundeadmonk.librarian.$($browser.Name).json"
    )
    [IO.File]::WriteAllText(
        $manifestPath,
        $rendered,
        (New-Object Text.UTF8Encoding($false))
    )
}

$nugetPackages = if ($env:NUGET_PACKAGES) {
    $env:NUGET_PACKAGES
} else {
    Join-Path $env:USERPROFILE ".nuget\packages"
}
$signTool = Join-Path $nugetPackages (
    "microsoft.windows.sdk.buildtools\$($toolchain.Versions.WindowsSdkBuildTools)" +
    "\bin\$($toolchain.Versions.WindowsSdk)\x64\SignTool.exe"
)
if (-not (Test-Path -LiteralPath $signTool -PathType Leaf)) {
    throw "The locked SignTool.exe was not restored at '$signTool'."
}

$signingIdentity = $null
$signingMode = "unsigned-fixture"
if ($DevelopmentCertificateThumbprint) {
    $signingIdentity = Resolve-DevelopmentCertificate `
        -Thumbprint $DevelopmentCertificateThumbprint
    $signingMode = "development"
    foreach ($path in @(
        (Join-Path $payloadDirectory "Librarian.Windows.exe"),
        (Join-Path $payloadDirectory "Librarian.VaultAgent.exe"),
        (Join-Path $payloadDirectory "Librarian.ChromiumNativeHost.exe"),
        (Join-Path $payloadDirectory "Librarian.Identity.msix"),
        (Join-Path $customActionInputDirectory "Librarian.Setup.CustomActions.dll")
    )) {
        Invoke-Sign `
            -SignTool $signTool `
            -SigningIdentity $signingIdentity `
            -Path $path `
            -RepoRoot $repoRoot
    }
}

$componentPaths = [ordered]@{
    Desktop = "Librarian.Windows.exe"
    VaultAgent = "Librarian.VaultAgent.exe"
    ChromiumNativeHost = "Librarian.ChromiumNativeHost.exe"
    IdentityPackage = "Librarian.Identity.msix"
}
$components = foreach ($entry in $componentPaths.GetEnumerator()) {
    $componentPath = Join-Path $payloadDirectory $entry.Value
    [ordered]@{
        role = $entry.Key
        path = $entry.Value
        sha256 = (Get-FileHash -LiteralPath $componentPath -Algorithm SHA256).Hash
    }
}
$releaseManifest = [ordered]@{
    schemaVersion = 1
    productVersion = $ProductVersion
    platform = $Platform
    signingMode = $signingMode
    components = @($components)
    browser = [ordered]@{
        hostName = "com.theundeadmonk.librarian"
        chromeOrigin = "chrome-extension://$ChromeExtensionId/"
        edgeOrigin = "chrome-extension://$EdgeExtensionId/"
    }
    passkeyProvider = [ordered]@{
        included = $false
        owner = "issue #18"
    }
}
[IO.File]::WriteAllText(
    (Join-Path $payloadDirectory "Librarian.Release.json"),
    (($releaseManifest | ConvertTo-Json -Depth 6) + [Environment]::NewLine),
    (New-Object Text.UTF8Encoding($false))
)

$packageProject = Join-Path $repoRoot "packaging\windows\Librarian.Package.wixproj"
$setupProject = Join-Path $repoRoot "packaging\windows\Librarian.Setup.wixproj"
$licenseRtf = Join-Path $repoRoot "packaging\windows\License.rtf"
$logo = Join-Path $repoRoot (
    "apps\windows\Librarian.Windows\Assets\Square150x150Logo.scale-200.png"
)
$splash = Join-Path $repoRoot (
    "apps\windows\Librarian.Windows\Assets\SplashScreen.scale-200.png"
)

$packageBuildArguments = @(
    "build",
    $packageProject,
    "--no-restore",
    "--configuration",
    $Configuration,
    "-p:ProductVersion=$ProductVersion",
    "-p:PayloadDir=$payloadDirectory",
    "-p:BrowserManifestDir=$browserManifestDirectory",
    (
        "-p:CustomActionPath=" +
        (Join-Path $customActionInputDirectory "Librarian.Setup.CustomActions.dll")
    ),
    "-p:LicenseRtfPath=$licenseRtf",
    "-p:OutputPath=$msiOutputDirectory\",
    "-p:IntermediateOutputPath=$intermediateDirectory\package\"
)
if ($SuppressMsiValidation) {
    Write-Host ""
    Write-Host (
        "WiX ICE validation is suppressed for this build. " +
        "scripts\test-installer.ps1 must either run ICE separately or record " +
        "that local App Control enforcement prevents it."
    )
    $packageBuildArguments += "-p:SuppressValidation=true"
}

Invoke-CheckedProcess `
    -Label "Locked WiX package restore" `
    -FilePath $dotnet `
    -Arguments @("restore", $packageProject, "--locked-mode") `
    -WorkingDirectory $repoRoot
Invoke-CheckedProcess `
    -Label "Librarian MSI build" `
    -FilePath $dotnet `
    -Arguments $packageBuildArguments `
    -WorkingDirectory $repoRoot

$msiPath = Join-Path $msiOutputDirectory "Librarian.Package.msi"
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw "The MSI was not created at '$msiPath'."
}
if ($signingIdentity) {
    Invoke-Sign `
        -SignTool $signTool `
        -SigningIdentity $signingIdentity `
        -Path $msiPath `
        -RepoRoot $repoRoot
}

Invoke-CheckedProcess `
    -Label "Locked WiX bundle restore" `
    -FilePath $dotnet `
    -Arguments @("restore", $setupProject, "--locked-mode") `
    -WorkingDirectory $repoRoot
Invoke-CheckedProcess `
    -Label "Librarian setup bundle build" `
    -FilePath $dotnet `
    -Arguments @(
        "build",
        $setupProject,
        "--no-restore",
        "--configuration",
        $Configuration,
        "-p:ProductVersion=$ProductVersion",
        "-p:MsiPath=$msiPath",
        "-p:LogoPath=$logo",
        "-p:SplashScreenPath=$splash",
        "-p:OutputPath=$bundleOutputDirectory\",
        "-p:IntermediateOutputPath=$intermediateDirectory\bundle\"
    ) `
    -WorkingDirectory $repoRoot

$setupPath = Join-Path $bundleOutputDirectory "LibrarianSetup.exe"
if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
    throw "The setup bundle was not created at '$setupPath'."
}
if ($signingIdentity) {
    Invoke-Sign `
        -SignTool $signTool `
        -SigningIdentity $signingIdentity `
        -Path $setupPath `
        -RepoRoot $repoRoot
}

Write-Host ""
Write-Host "Librarian installer artifacts created."
Write-Host "Setup: $setupPath"
Write-Host "MSI: $msiPath"
Write-Host "Identity MSIX: $(Join-Path $payloadDirectory 'Librarian.Identity.msix')"
Write-Host "Signing mode: $signingMode"
if (-not $signingIdentity) {
    Write-Host "Unsigned fixtures are for build validation only and must not be installed."
}
