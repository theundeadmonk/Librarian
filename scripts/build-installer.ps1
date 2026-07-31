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
. (Join-Path $PSScriptRoot "certificate-helpers.ps1")

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

function Get-WixExecutable {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot
    )

    [xml]$project = Get-Content -LiteralPath (
        Join-Path $RepoRoot "packaging\windows\Librarian.Package.wixproj"
    ) -Raw
    $sdk = $project.Project.Sdk
    $sdkMatch = [regex]::Match(
        $sdk,
        '^WixToolset\.Sdk/(?<version>\d+\.\d+\.\d+)$'
    )
    if (-not $sdkMatch.Success) {
        throw "The WiX project must pin an exact WixToolset.Sdk version."
    }

    $nugetPackages = if ($env:NUGET_PACKAGES) {
        $env:NUGET_PACKAGES
    } else {
        Join-Path $env:USERPROFILE ".nuget\packages"
    }
    $wix = Join-Path $nugetPackages (
        "wixtoolset.sdk\$($sdkMatch.Groups["version"].Value)" +
        "\tools\net472\x64\wix.exe"
    )
    if (-not (Test-Path -LiteralPath $wix -PathType Leaf)) {
        throw "The locked WiX executable is missing at '$wix'."
    }
    return $wix
}

function Release-ComReference {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -ne $Value -and
        [Runtime.InteropServices.Marshal]::IsComObject($Value)) {
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($Value) |
            Out-Null
    }
}

function Normalize-WindowsAppSdkMsiLanguages {
    param(
        [Parameter(Mandatory)]
        [string]$MsiPath
    )

    # Windows App SDK 2.3.1 ships valid modern resource cultures whose LCIDs
    # are not accepted by the legacy Windows Installer ICE language catalog.
    # Preserve the files and their paths, but mark only these pinned vendor
    # resources language-neutral in the MSI File table before validation.
    $legacyIceLanguageIds = @("1152", "1153", "1169")
    $expectedMuiFileNames = @(
        "Microsoft.UI.Xaml.Phone.dll.mui",
        "Microsoft.ui.xaml.dll.mui"
    )
    $expectedOverflowFileNames = @(
        "Microsoft.UI.Xaml.Phone.dll",
        "Microsoft.ui.xaml.dll"
    )
    $resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
    $installer = $null
    $database = $null
    $view = $null
    $record = $null
    $rows = @()

    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember(
            "OpenDatabase",
            "InvokeMethod",
            $null,
            $installer,
            [object[]]@($resolvedMsi, [int]1)
        )

        $query = (
            "SELECT ``File``, ``FileName``, ``Language`` FROM ``File`` " +
            "WHERE ``Language`` IS NOT NULL"
        )
        $view = $database.GetType().InvokeMember(
            "OpenView",
            "InvokeMethod",
            $null,
            $database,
            [object[]]@($query)
        )
        $view.GetType().InvokeMember(
            "Execute",
            "InvokeMethod",
            $null,
            $view,
            $null
        ) | Out-Null

        while ($true) {
            $record = $view.GetType().InvokeMember(
                "Fetch",
                "InvokeMethod",
                $null,
                $view,
                $null
            )
            if ($null -eq $record) {
                break
            }

            $fileId = [string]$record.GetType().InvokeMember(
                "StringData",
                "GetProperty",
                $null,
                $record,
                1
            )
            $fileName = [string]$record.GetType().InvokeMember(
                "StringData",
                "GetProperty",
                $null,
                $record,
                2
            )
            $language = [string]$record.GetType().InvokeMember(
                "StringData",
                "GetProperty",
                $null,
                $record,
                3
            )
            $rows += [PSCustomObject]@{
                FileId = $fileId
                FileName = ($fileName -split '\|', 2)[-1]
                Language = $language
            }
            Release-ComReference -Value $record
            $record = $null
        }
        Release-ComReference -Value $view
        $view = $null

        $legacyIceRows = @(
            $rows |
                Where-Object { $_.Language -in $legacyIceLanguageIds }
        )
        if ($legacyIceRows.Count -ne 6) {
            throw (
                "Expected exactly six pinned Windows App SDK MUI rows with " +
                "legacy ICE-incompatible LCIDs; found $($legacyIceRows.Count)."
            )
        }
        foreach ($languageId in $legacyIceLanguageIds) {
            $actualNames = @(
                $legacyIceRows |
                    Where-Object { $_.Language -eq $languageId } |
                    ForEach-Object { $_.FileName } |
                    Sort-Object
            )
            $expectedNames = @($expectedMuiFileNames | Sort-Object)
            if (($actualNames -join "`n") -ne ($expectedNames -join "`n")) {
                throw (
                    "Unexpected MSI files use legacy ICE-incompatible " +
                    "language '$languageId': " +
                    (($actualNames | ForEach-Object { "'$_'" }) -join ", ")
                )
            }
        }

        $overflowRows = @(
            $rows |
                Where-Object { $_.Language.Length -gt 20 }
        )
        $actualOverflowNames = @(
            $overflowRows |
                ForEach-Object { $_.FileName } |
                Sort-Object
        )
        $expectedOverflowNames = @($expectedOverflowFileNames | Sort-Object)
        if (($actualOverflowNames -join "`n") -ne
            ($expectedOverflowNames -join "`n")) {
            throw (
                "Unexpected MSI files exceed the File.Language limit: " +
                (($actualOverflowNames | ForEach-Object { "'$_'" }) -join ", ")
            )
        }
        foreach ($row in $overflowRows) {
            if ($row.Language -notmatch '^\d+(,\d+)+$') {
                throw (
                    "Unexpected language-list format for '$($row.FileName)'."
                )
            }
        }

        $normalizationRows = @($legacyIceRows) + @($overflowRows)
        if (@($normalizationRows.FileId | Sort-Object -Unique).Count -ne 8) {
            throw "Expected eight distinct Windows App SDK language rows."
        }
        foreach ($row in $normalizationRows) {
            if ($row.FileId -notmatch '^[A-Za-z0-9_.]+$') {
                throw "Unsafe MSI File identifier '$($row.FileId)'."
            }
            $query = (
                "UPDATE ``File`` SET ``Language`` = '0' " +
                "WHERE ``File`` = '$($row.FileId)'"
            )
            $view = $database.GetType().InvokeMember(
                "OpenView",
                "InvokeMethod",
                $null,
                $database,
                [object[]]@($query)
            )
            $view.GetType().InvokeMember(
                "Execute",
                "InvokeMethod",
                $null,
                $view,
                $null
            ) | Out-Null
            Release-ComReference -Value $view
            $view = $null
        }

        $database.GetType().InvokeMember(
            "Commit",
            "InvokeMethod",
            $null,
            $database,
            $null
        ) | Out-Null
    } finally {
        foreach ($value in @($record, $view, $database, $installer)) {
            Release-ComReference -Value $value
        }
    }

    Write-Host (
        "Normalized eight pinned Windows App SDK language rows for " +
        "legacy MSI ICE compatibility."
    )
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
    $hasCodeSigning = Test-CertificateEnhancedKeyUsage `
        -Certificate $certificate `
        -RequiredOid $codeSigningOid
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
$identityLauncherProject = Join-Path $repoRoot (
    "packaging\windows\identity-launcher\Librarian.IdentityLauncher.vcxproj"
)
$identityLauncherOutput = Join-Path $repoRoot (
    "artifacts\bin\$Platform\$Configuration\Librarian.IdentityLauncher.exe"
)

foreach ($requiredPath in @(
    $desktopOutput,
    $vaultAgent,
    $nativeHost,
    $customActionProject,
    $identityLauncherProject
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

Invoke-CheckedProcess `
    -Label "Locked identity-launcher restore" `
    -FilePath $toolchain.MSBuild `
    -Arguments @(
        $identityLauncherProject,
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
    -Label "Identity-launcher build" `
    -FilePath $toolchain.MSBuild `
    -Arguments @(
        $identityLauncherProject,
        "/t:Build",
        "/m",
        "/nr:false",
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/p:RestoreLockedMode=true",
        "/verbosity:minimal"
    ) `
    -WorkingDirectory $repoRoot

if (-not (Test-Path -LiteralPath $identityLauncherOutput -PathType Leaf)) {
    throw "The identity launcher was not built at '$identityLauncherOutput'."
}

Copy-RuntimeTree -Source $desktopOutput -Destination $payloadDirectory
Copy-Item `
    -LiteralPath $identityLauncherOutput `
    -Destination (Join-Path $payloadDirectory "Librarian.IdentityLauncher.exe")
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
        Source = Join-Path $repoRoot (
            "packaging\windows\identity-launcher\app.manifest"
        )
        Rendered = Join-Path (
            $intermediateDirectory
        ) "Librarian.IdentityLauncher.manifest"
        Executable = Join-Path (
            $payloadDirectory
        ) "Librarian.IdentityLauncher.exe"
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
        (Join-Path $payloadDirectory "Librarian.IdentityLauncher.exe"),
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
    IdentityLauncher = "Librarian.IdentityLauncher.exe"
    Desktop = "Librarian.Windows.exe"
    VaultAgent = "Librarian.VaultAgent.exe"
    ChromiumNativeHost = "Librarian.ChromiumNativeHost.exe"
    IdentityPackage = "Librarian.Identity.msix"
}
$componentHashes = [ordered]@{}
$components = foreach ($entry in $componentPaths.GetEnumerator()) {
    $componentPath = Join-Path $payloadDirectory $entry.Value
    $componentHash = (
        Get-FileHash -LiteralPath $componentPath -Algorithm SHA256
    ).Hash
    $componentHashes[$entry.Key] = $componentHash
    [ordered]@{
        role = $entry.Key
        path = $entry.Value
        sha256 = $componentHash
    }
}
$payloadHashManifestPath = Join-Path (
    $payloadDirectory
) "Librarian.PayloadHashes"
$payloadHashManifest = (
    "v2|$ProductVersion|" +
    (($componentPaths.Keys | ForEach-Object { $componentHashes[$_] }) -join "|")
)
[IO.File]::WriteAllText(
    $payloadHashManifestPath,
    $payloadHashManifest,
    (New-Object Text.UTF8Encoding($false))
)
$payloadHashManifestSha256 = (
    Get-FileHash -LiteralPath $payloadHashManifestPath -Algorithm SHA256
).Hash
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
    "-p:PayloadHashManifestSha256=$payloadHashManifestSha256",
    "-p:LicenseRtfPath=$licenseRtf",
    "-p:OutputPath=$msiOutputDirectory\",
    "-p:IntermediateOutputPath=$intermediateDirectory\package\"
)
$packageBuildArguments += "-p:SuppressValidation=true"
if ($SuppressMsiValidation) {
    Write-Host ""
    Write-Host (
        "WiX ICE validation is suppressed for this build. " +
        "scripts\test-installer.ps1 must either run ICE separately or record " +
        "that local App Control enforcement prevents it."
    )
} else {
    Write-Host ""
    Write-Host (
        "WiX ICE validation is deferred until pinned Windows App SDK language " +
        "metadata is normalized."
    )
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
Normalize-WindowsAppSdkMsiLanguages -MsiPath $msiPath
if (-not $SuppressMsiValidation) {
    $wix = Get-WixExecutable -RepoRoot $repoRoot
    Invoke-CheckedProcess `
        -Label "Librarian MSI ICE validation" `
        -FilePath $wix `
        -Arguments @(
            "msi",
            "validate",
            $msiPath,
            "--acceptEula",
            "wix7"
        ) `
        -WorkingDirectory $repoRoot
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
