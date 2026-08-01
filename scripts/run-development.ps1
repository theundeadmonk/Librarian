[CmdletBinding()]
param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [switch]$ValidateOnly,

    [switch]$SmokeTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($ValidateOnly -and $SmokeTest) {
    throw "ValidateOnly and SmokeTest cannot be used together."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$payloadDirectory = Join-Path $repoRoot "artifacts\installer\payload"
$releasePath = Join-Path $payloadDirectory "Librarian.Release.json"
$sourceLayout = Join-Path $repoRoot "$Platform\$Configuration\Librarian.Windows"
$sourceManifestPath = Join-Path $sourceLayout "AppxManifest.xml"
$developmentRoot = Join-Path $repoRoot "artifacts\development"
$layoutDirectory = Join-Path $developmentRoot "Librarian"
$manifestPath = Join-Path $layoutDirectory "AppxManifest.xml"
$packageName = "TheUndeadMonk.Librarian.Development"
$desktopPath = Join-Path $layoutDirectory "Librarian.Windows.exe"
$agentPath = Join-Path $layoutDirectory "Librarian.VaultAgent.exe"
$hostPath = Join-Path $layoutDirectory "Librarian.ChromiumNativeHost.exe"
$registeredByScript = $false
$layoutCreatedByScript = $false
$package = $null
$desktopProcess = $null
$agentProcess = $null
$registrationMutex = $null
$registrationMutexHeld = $false
$preserveLayoutForRecovery = $false

function Test-SamePath {
    param(
        [Parameter(Mandatory)]
        [string]$First,

        [Parameter(Mandatory)]
        [string]$Second
    )

    return [string]::Equals(
        [System.IO.Path]::GetFullPath($First).TrimEnd("\"),
        [System.IO.Path]::GetFullPath($Second).TrimEnd("\"),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-SafeDevelopmentLayoutPath {
    $resolvedRoot = [System.IO.Path]::GetFullPath($developmentRoot).TrimEnd("\")
    $resolvedLayout = [System.IO.Path]::GetFullPath($layoutDirectory).TrimEnd("\")
    if (
        (Split-Path -Parent $resolvedLayout) -ne $resolvedRoot -or
        (Split-Path -Leaf $resolvedLayout) -ne "Librarian"
    ) {
        throw "Refusing to mutate unexpected development layout '$layoutDirectory'."
    }
}

function Get-ManifestContext {
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest
    )

    $namespaceManager = [System.Xml.XmlNamespaceManager]::new(
        $Manifest.NameTable
    )
    $namespaceManager.AddNamespace(
        "foundation",
        "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
    )
    $namespaceManager.AddNamespace(
        "uap",
        "http://schemas.microsoft.com/appx/manifest/uap/windows10"
    )
    $namespaceManager.AddNamespace(
        "rescap",
        "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
    )
    return ,$namespaceManager
}

function Add-DevelopmentApplications {
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest
    )

    $namespaceManager = Get-ManifestContext -Manifest $Manifest
    $applications = $Manifest.SelectSingleNode(
        "/foundation:Package/foundation:Applications",
        $namespaceManager
    )
    $desktop = $Manifest.SelectSingleNode(
        (
            "/foundation:Package/foundation:Applications/" +
            "foundation:Application[@Id='Desktop']"
        ),
        $namespaceManager
    )
    if (
        $null -eq $applications -or
        $null -eq $desktop -or
        $desktop.Executable -ne "Librarian.Windows.exe" -or
        $desktop.EntryPoint -ne "Windows.FullTrustApplication"
    ) {
        throw "The generated Windows package layout has an unexpected desktop application."
    }
    $existingApplications = @($applications.SelectNodes(
        "foundation:Application",
        $namespaceManager
    ))
    if ($existingApplications.Count -ne 1) {
        throw "The generated Windows package layout contains an unexpected application entry."
    }

    foreach ($applicationSpec in @(
        @{
            Id = "VaultAgent"
            Executable = "Librarian.VaultAgent.exe"
            DisplayName = "Librarian vault agent"
        },
        @{
            Id = "ChromiumNativeHost"
            Executable = "Librarian.ChromiumNativeHost.exe"
            DisplayName = "Librarian browser bridge"
        }
    )) {
        if ($Manifest.SelectSingleNode(
            (
                "/foundation:Package/foundation:Applications/" +
                "foundation:Application[@Id='$($applicationSpec.Id)']"
            ),
            $namespaceManager
        )) {
            throw "The generated Windows layout already contains '$($applicationSpec.Id)'."
        }

        $application = $Manifest.CreateElement(
            "Application",
            $namespaceManager.LookupNamespace("foundation")
        )
        $application.SetAttribute("Id", $applicationSpec.Id)
        $application.SetAttribute("Executable", $applicationSpec.Executable)
        $application.SetAttribute("EntryPoint", "Windows.FullTrustApplication")

        $visualElements = $Manifest.CreateElement(
            "uap",
            "VisualElements",
            $namespaceManager.LookupNamespace("uap")
        )
        $visualElements.SetAttribute("AppListEntry", "none")
        $visualElements.SetAttribute("DisplayName", $applicationSpec.DisplayName)
        $visualElements.SetAttribute("Description", $applicationSpec.DisplayName)
        $visualElements.SetAttribute("BackgroundColor", "transparent")
        $visualElements.SetAttribute("Square150x150Logo", "Assets\Square150x150Logo.png")
        $visualElements.SetAttribute("Square44x44Logo", "Assets\Square44x44Logo.png")
        [void]$application.AppendChild($visualElements)
        [void]$applications.AppendChild($application)
    }

    $unvirtualizedResources = $Manifest.SelectSingleNode(
        (
            "/foundation:Package/foundation:Capabilities/" +
            "rescap:Capability[@Name='unvirtualizedResources']"
        ),
        $namespaceManager
    )
    if ($null -eq $unvirtualizedResources) {
        $capabilities = $Manifest.SelectSingleNode(
            "/foundation:Package/foundation:Capabilities",
            $namespaceManager
        )
        if ($null -eq $capabilities) {
            throw "The generated Windows package layout is missing Capabilities."
        }
        $capability = $Manifest.CreateElement(
            "rescap",
            "Capability",
            $namespaceManager.LookupNamespace("rescap")
        )
        $capability.SetAttribute("Name", "unvirtualizedResources")
        [void]$capabilities.AppendChild($capability)
    }
}

function Get-RegisteredApplications {
    param(
        [Parameter(Mandatory)]
        [string]$PackageFullName
    )

    [xml]$registeredManifest = Get-AppxPackageManifest -Package $PackageFullName
    $namespaceManager = Get-ManifestContext -Manifest $registeredManifest
    return @(
        $registeredManifest.SelectNodes(
            "/foundation:Package/foundation:Applications/foundation:Application",
            $namespaceManager
        ) |
            ForEach-Object {
                [pscustomobject]@{
                    Id = [string]$_.Id
                    Executable = [string]$_.Executable
                }
            }
    )
}

function Stop-ExpectedProcess {
    param(
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory)]
        [string]$ExpectedPath
    )

    if ($null -eq $Process) {
        return
    }

    try {
        $Process.Refresh()
        if ($Process.HasExited) {
            return
        }
        if (-not (Test-SamePath -First $Process.Path -Second $ExpectedPath)) {
            Write-Warning "Did not stop process $($Process.Id) from an unexpected path."
            return
        }
        Stop-Process -Id $Process.Id -Force
        Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    catch [System.InvalidOperationException] {
        # The process exited between the state and path checks.
    }
}

try {
    foreach ($requiredPath in @(
        $releasePath,
        $sourceManifestPath,
        (Join-Path $sourceLayout "Librarian.Windows.exe"),
        (Join-Path $payloadDirectory "Librarian.VaultAgent.exe"),
        (Join-Path $payloadDirectory "Librarian.ChromiumNativeHost.exe")
    )) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required development output is missing: $requiredPath. Run the Release|x64 build first."
        }
    }

    $release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
    if (
        $release.schemaVersion -ne 1 -or
        $release.platform -ne $Platform -or
        $release.signingMode -ne "unsigned-fixture" -or
        [string]$release.productVersion -notmatch "^\d+\.\d+\.\d+\.\d+$"
    ) {
        throw "The installer payload release manifest is not a valid x64 development fixture."
    }

    $requiredPayloadRoles = [ordered]@{
        IdentityLauncher = "Librarian.IdentityLauncher.exe"
        Desktop = "Librarian.Windows.exe"
        VaultAgent = "Librarian.VaultAgent.exe"
        ChromiumNativeHost = "Librarian.ChromiumNativeHost.exe"
        IdentityPackage = "Librarian.Identity.msix"
    }
    if (@($release.components).Count -ne $requiredPayloadRoles.Count) {
        throw "The payload release manifest contains an unexpected component entry."
    }
    foreach ($expected in $requiredPayloadRoles.GetEnumerator()) {
        $componentMatches = @($release.components | Where-Object {
            $_.role -eq $expected.Key
        })
        if (
            $componentMatches.Count -ne 1 -or
            [string]$componentMatches[0].path -ne $expected.Value -or
            [string]$componentMatches[0].sha256 -notmatch "^[0-9A-F]{64}$"
        ) {
            throw "The payload release manifest has an invalid '$($expected.Key)' component."
        }
        $componentPath = Join-Path $payloadDirectory $expected.Value
        if (
            (Get-FileHash -LiteralPath $componentPath -Algorithm SHA256).Hash -cne
            [string]$componentMatches[0].sha256
        ) {
            throw "The development payload hash does not match for '$($expected.Value)'."
        }
    }

    if (Test-Path -LiteralPath (
        Join-Path $payloadDirectory "Librarian.PasskeyProvider.exe"
    )) {
        throw "The development payload contains a passkey provider before issue #18."
    }

    [xml]$sourceManifest = Get-Content -LiteralPath $sourceManifestPath -Raw
    $sourceNamespaceManager = Get-ManifestContext -Manifest $sourceManifest
    $sourceIdentity = $sourceManifest.SelectSingleNode(
        "/foundation:Package/foundation:Identity",
        $sourceNamespaceManager
    )
    if (
        $null -eq $sourceIdentity -or
        $sourceIdentity.Name -ne $packageName -or
        $sourceIdentity.Publisher -ne "CN=Librarian Development" -or
        $sourceIdentity.Version -ne [string]$release.productVersion -or
        $sourceIdentity.ProcessorArchitecture -ne "x64"
    ) {
        throw "The generated Windows package identity does not match the Release payload."
    }
    Add-DevelopmentApplications -Manifest $sourceManifest

    if ($ValidateOnly) {
        Write-Host "Development package runner validation passed."
        Write-Host "Version: $($release.productVersion)"
        Write-Host "Applications: Desktop, VaultAgent, ChromiumNativeHost"
        return
    }

    if (-not [Environment]::UserInteractive) {
        throw "The development runner requires an interactive Windows desktop session."
    }
    if (
        -not [Environment]::Is64BitOperatingSystem -or
        [Environment]::OSVersion.Version.Build -lt 26100
    ) {
        throw "Librarian development requires x64 Windows 11 build 26100 or newer."
    }
    if ([uint32](Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) {
        throw "Librarian development requires a Windows workstation, not Windows Server."
    }

    $registrationMutex = [System.Threading.Mutex]::new(
        $false,
        "Local\Librarian.WindowsShellUi.PackageRegistration"
    )
    try {
        $registrationMutexHeld = $registrationMutex.WaitOne(
            [TimeSpan]::FromSeconds(30)
        )
    }
    catch [System.Threading.AbandonedMutexException] {
        $registrationMutexHeld = $true
    }
    if (-not $registrationMutexHeld) {
        throw "Timed out waiting for exclusive Librarian package registration ownership."
    }

    Assert-SafeDevelopmentLayoutPath
    if (Test-Path -LiteralPath $layoutDirectory -PathType Container) {
        foreach ($processSpec in @(
            @{ Name = "Librarian.Windows.exe"; Path = $desktopPath },
            @{ Name = "Librarian.VaultAgent.exe"; Path = $agentPath },
            @{ Name = "Librarian.ChromiumNativeHost.exe"; Path = $hostPath }
        )) {
            $matchingProcesses = @(
                Get-CimInstance Win32_Process -Filter "Name='$($processSpec.Name)'" |
                    Where-Object {
                        $null -ne $_.ExecutablePath -and
                        (Test-SamePath -First $_.ExecutablePath -Second $processSpec.Path)
                    }
            )
            if ($matchingProcesses.Count -ne 0) {
                throw "Close the existing $($processSpec.Name) development process and retry."
            }
        }
    }

    $existingPackages = @(Get-AppxPackage -Name $packageName)
    if ($existingPackages.Count -gt 1) {
        throw "More than one package is registered for the Librarian development identity."
    }
    if ($existingPackages.Count -eq 1) {
        $existingPackage = $existingPackages[0]
        if (
            -not $existingPackage.IsDevelopmentMode -or
            -not (Test-SamePath -First $existingPackage.InstallLocation -Second $layoutDirectory)
        ) {
            throw (
                "The Librarian development identity is registered from " +
                "'$($existingPackage.InstallLocation)'. Refusing to replace it."
            )
        }
        Remove-AppxPackage -Package $existingPackage.PackageFullName
    }

    if (Test-Path -LiteralPath $layoutDirectory) {
        Remove-Item -LiteralPath $layoutDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $developmentRoot -Force | Out-Null
    Copy-Item -LiteralPath $sourceLayout -Destination $layoutDirectory -Recurse
    $layoutCreatedByScript = $true
    Copy-Item `
        -LiteralPath (Join-Path $payloadDirectory "Librarian.VaultAgent.exe") `
        -Destination $agentPath
    Copy-Item `
        -LiteralPath (Join-Path $payloadDirectory "Librarian.ChromiumNativeHost.exe") `
        -Destination $hostPath

    [xml]$developmentManifest = Get-Content -LiteralPath $manifestPath -Raw
    Add-DevelopmentApplications -Manifest $developmentManifest
    $xmlSettings = [System.Xml.XmlWriterSettings]::new()
    $xmlSettings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $xmlSettings.Indent = $true
    $xmlSettings.NewLineChars = "`r`n"
    $xmlSettings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
    $writer = [System.Xml.XmlWriter]::Create($manifestPath, $xmlSettings)
    try {
        $developmentManifest.Save($writer)
    }
    finally {
        $writer.Dispose()
    }

    $registeredByScript = $true
    try {
        Add-AppxPackage -Register $manifestPath
    }
    catch {
        throw (
            "Unable to register the current-user development package. Verify " +
            "Developer Mode, then retry. $($_.Exception.Message)"
        )
    }
    $registeredPackages = @(Get-AppxPackage -Name $packageName)
    if ($registeredPackages.Count -ne 1) {
        throw "Expected one development registration; found $($registeredPackages.Count)."
    }
    $package = $registeredPackages[0]
    if (
        $package.Status -ne "Ok" -or
        -not $package.IsDevelopmentMode -or
        -not (Test-SamePath -First $package.InstallLocation -Second $layoutDirectory) -or
        [string]$package.Version -ne [string]$release.productVersion
    ) {
        throw "The current-user development package registration is stale or unhealthy."
    }

    $registeredApplications = @(Get-RegisteredApplications `
        -PackageFullName $package.PackageFullName)
    foreach ($expectedApplication in @(
        @{ Id = "Desktop"; Executable = "Librarian.Windows.exe" },
        @{ Id = "VaultAgent"; Executable = "Librarian.VaultAgent.exe" },
        @{ Id = "ChromiumNativeHost"; Executable = "Librarian.ChromiumNativeHost.exe" }
    )) {
        $applicationMatches = @($registeredApplications | Where-Object {
            $_.Id -eq $expectedApplication.Id -and
            $_.Executable -eq $expectedApplication.Executable
        })
        if ($applicationMatches.Count -ne 1) {
            throw "The loose package does not expose '$($expectedApplication.Id)' correctly."
        }
    }
    if ($registeredApplications.Count -ne 3) {
        throw "The loose package exposes an unexpected application entry."
    }

    if (-not ("LibrarianDevelopmentPackageActivator" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[Flags]
public enum LibrarianDevelopmentPackageActivateOptions { None = 0 }

[ComImport]
[Guid("2e941141-7f97-4756-ba1d-9decde894a3d")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ILibrarianDevelopmentApplicationActivationManager
{
    [PreserveSig]
    int ActivateApplication(
        [MarshalAs(UnmanagedType.LPWStr)] string applicationUserModelId,
        [MarshalAs(UnmanagedType.LPWStr)] string arguments,
        LibrarianDevelopmentPackageActivateOptions options,
        out uint processId);
}

[ComImport]
[Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
public class LibrarianDevelopmentApplicationActivationManager { }

public static class LibrarianDevelopmentPackageActivator
{
    public static uint Activate(string applicationUserModelId)
    {
        var manager =
            (ILibrarianDevelopmentApplicationActivationManager)
            new LibrarianDevelopmentApplicationActivationManager();
        try
        {
            uint processId;
            var result = manager.ActivateApplication(
                applicationUserModelId,
                null,
                LibrarianDevelopmentPackageActivateOptions.None,
                out processId);
            Marshal.ThrowExceptionForHR(result);
            return processId;
        }
        finally
        {
            Marshal.FinalReleaseComObject(manager);
        }
    }
}
"@
    }

    $agentProcessId = [LibrarianDevelopmentPackageActivator]::Activate(
        "$($package.PackageFamilyName)!VaultAgent"
    )
    $agentProcess = Get-Process -Id $agentProcessId -ErrorAction SilentlyContinue
    $desktopProcessId = [LibrarianDevelopmentPackageActivator]::Activate(
        "$($package.PackageFamilyName)!Desktop"
    )
    $desktopProcess = Get-Process -Id $desktopProcessId -ErrorAction Stop
    if (-not (Test-SamePath -First $desktopProcess.Path -Second $desktopPath)) {
        throw "Package activation started an unexpected desktop executable."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        $desktopProcess.Refresh()
        if ($desktopProcess.HasExited) {
            throw "Librarian exited before exposing its window."
        }
    } while (
        $desktopProcess.MainWindowTitle -ne "Librarian" -and
        [DateTime]::UtcNow -lt $deadline
    )
    if ($desktopProcess.MainWindowTitle -ne "Librarian") {
        throw "Librarian did not expose its window within 20 seconds."
    }

    if ($SmokeTest) {
        Write-Host "Development package registration and launch smoke test passed."
        return
    }

    Write-Host ""
    Write-Host "Librarian development session is running."
    Write-Host "Version: $($release.productVersion)"
    Write-Host "Close the Librarian window to end the session and clean up registration."
    Wait-Process -Id $desktopProcess.Id
    Write-Host "Librarian development session ended."
}
finally {
    try {
        try {
            Stop-ExpectedProcess -Process $desktopProcess -ExpectedPath $desktopPath
            Stop-ExpectedProcess -Process $agentProcess -ExpectedPath $agentPath
        }
        finally {
            if ($registeredByScript) {
                try {
                    $packageToRemove = Get-AppxPackage -Name $packageName |
                        Where-Object {
                            $_.IsDevelopmentMode -and
                            (Test-SamePath -First $_.InstallLocation -Second $layoutDirectory)
                        } |
                        Select-Object -First 1
                    if ($null -ne $packageToRemove) {
                        Remove-AppxPackage -Package $packageToRemove.PackageFullName
                    }
                    $remainingRegistration = Get-AppxPackage -Name $packageName |
                        Where-Object {
                            $_.IsDevelopmentMode -and
                            (Test-SamePath -First $_.InstallLocation -Second $layoutDirectory)
                        } |
                        Select-Object -First 1
                    if ($null -ne $remainingRegistration) {
                        throw "The temporary development package remains registered."
                    }
                }
                catch {
                    $preserveLayoutForRecovery = $true
                    throw
                }
            }
        }
    }
    finally {
        try {
            if ($layoutCreatedByScript -and -not $preserveLayoutForRecovery) {
                Assert-SafeDevelopmentLayoutPath
                Remove-Item -LiteralPath $layoutDirectory -Recurse -Force
                if (Test-Path -LiteralPath $layoutDirectory) {
                    throw "The temporary development layout could not be removed."
                }
            }
        }
        finally {
            if ($registrationMutexHeld) {
                $registrationMutex.ReleaseMutex()
            }
            if ($null -ne $registrationMutex) {
                $registrationMutex.Dispose()
            }
        }
    }
}
