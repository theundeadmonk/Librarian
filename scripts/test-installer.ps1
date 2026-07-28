[CmdletBinding()]
param(
    [string]$MsiPath,

    [string]$SetupPath,

    [ValidateSet("unsigned-fixture", "development")]
    [string]$ExpectedSigningMode = "unsigned-fixture",

    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$ExpectedProductVersion,

    [switch]$SkipIceValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "native-process-arguments.ps1")

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

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [string]$WorkingDirectory
    )

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
        throw "Could not start '$FilePath'."
    }

    try {
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [PSCustomObject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $standardOutput.Result
            StandardError = $standardError.Result
        }
    } finally {
        $process.Dispose()
    }
}

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

    Write-Host "==> $Label"
    $result = Invoke-CapturedProcess `
        -FilePath $FilePath `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory
    if ($result.StandardOutput) {
        Write-Host $result.StandardOutput.TrimEnd()
    }
    if ($result.StandardError) {
        Write-Host $result.StandardError.TrimEnd()
    }
    if ($result.ExitCode -ne 0) {
        throw "$Label failed with exit code $($result.ExitCode)."
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

function Get-WixExecutable {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot
    )

    [xml]$project = Get-Content -LiteralPath (
        Join-Path $RepoRoot "packaging\windows\Librarian.Package.wixproj"
    ) -Raw
    $sdk = $project.Project.Sdk
    $sdkMatch = [regex]::Match($sdk, '^WixToolset\.Sdk/(?<version>\d+\.\d+\.\d+)$')
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

function Get-ExtractedMsiFile {
    param(
        [Parameter(Mandatory)]
        [xml]$DecompiledMsi,

        [Parameter(Mandatory)]
        [string]$ExtractRoot,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $matches = @(
        $DecompiledMsi.SelectNodes("//*[local-name()='File']") |
            Where-Object { $_.GetAttribute("Name") -eq $Name }
    )
    if ($matches.Count -ne 1) {
        throw "Expected one '$Name' file in the MSI; found $($matches.Count)."
    }

    $source = $matches[0].GetAttribute("Source")
    $relativeSource = $source -replace '^SourceDir[\\/]', ""
    $path = Join-Path $ExtractRoot $relativeSource
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Extracted MSI file '$Name' is missing at '$path'."
    }
    return $path
}

function Get-MsiSequence {
    param(
        [Parameter(Mandatory)]
        [string]$DatabasePath,

        [Parameter(Mandatory)]
        [ValidatePattern("^[A-Za-z0-9_]+$")]
        [string]$Action
    )

    $installer = $null
    $database = $null
    $view = $null
    $record = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember(
            "OpenDatabase",
            "InvokeMethod",
            $null,
            $installer,
            @($DatabasePath, 0)
        )
        $query = (
            "SELECT ``Sequence`` FROM ``InstallExecuteSequence`` " +
            "WHERE ``Action`` = '$Action'"
        )
        $view = $database.GetType().InvokeMember(
            "OpenView",
            "InvokeMethod",
            $null,
            $database,
            @($query)
        )
        $view.GetType().InvokeMember(
            "Execute",
            "InvokeMethod",
            $null,
            $view,
            $null
        ) | Out-Null
        $record = $view.GetType().InvokeMember(
            "Fetch",
            "InvokeMethod",
            $null,
            $view,
            $null
        )
        if (-not $record) {
            throw "MSI action '$Action' is missing from InstallExecuteSequence."
        }
        return [int]$record.GetType().InvokeMember(
            "IntegerData",
            "GetProperty",
            $null,
            $record,
            1
        )
    } finally {
        foreach ($value in @($record, $view, $database, $installer)) {
            if ($null -ne $value) {
                [Runtime.InteropServices.Marshal]::FinalReleaseComObject($value) |
                    Out-Null
            }
        }
    }
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$artifactsRoot = Join-Path $repoRoot "artifacts"
$installerRoot = Join-Path $artifactsRoot "installer"
if (-not $MsiPath) {
    $MsiPath = Join-Path $installerRoot "msi\Librarian.Package.msi"
}
if (-not $SetupPath) {
    $SetupPath = Join-Path $installerRoot "bundle\LibrarianSetup.exe"
}

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$resolvedSetup = (Resolve-Path -LiteralPath $SetupPath).Path
$wix = Get-WixExecutable -RepoRoot $repoRoot
$toolchain = & (Join-Path $PSScriptRoot "bootstrap.ps1") -PassThru
if (-not $ExpectedProductVersion) {
    $ExpectedProductVersion = Get-WorkspaceVersion (
        Join-Path $repoRoot "Cargo.toml"
    )
}
$versionParts = @(
    $ExpectedProductVersion.Split(".") |
        ForEach-Object { [uint32]$_ }
)
if ($versionParts[0] -gt 255 -or $versionParts[1] -gt 255 -or
    $versionParts[2] -gt 65535 -or $versionParts[3] -gt 65535) {
    throw (
        "Expected installer version '$ExpectedProductVersion' exceeds " +
        "Windows Installer or MSIX field limits."
    )
}

$inspectionRoot = Join-Path $installerRoot (
    "test-inspect-" + [Guid]::NewGuid().ToString("N")
)
$resolvedInstallerRoot = [IO.Path]::GetFullPath($installerRoot).TrimEnd("\")
$resolvedInspectionRoot = [IO.Path]::GetFullPath($inspectionRoot).TrimEnd("\")
if (-not $resolvedInspectionRoot.StartsWith(
        "$resolvedInstallerRoot\test-inspect-",
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Refusing to create an inspection directory outside installer artifacts."
}

$msiExtractRoot = Join-Path $inspectionRoot "msi"
$decompiledPath = Join-Path $inspectionRoot "Librarian.Package.decompiled.wxs"
$bundleExtractRoot = Join-Path $inspectionRoot "bundle"
$bootstrapperApplicationRoot = Join-Path $inspectionRoot "ba"
$identityExtractRoot = Join-Path $inspectionRoot "identity"
New-Item -ItemType Directory -Path $inspectionRoot | Out-Null

try {
    if ($SkipIceValidation) {
        Write-Host (
            "==> MSI ICE validation skipped because enforced Windows App " +
            "Control blocks the validation engine's temporary MSI."
        )
    } else {
        Write-Host "==> Validate MSI with Windows Installer ICEs"
        $iceResult = Invoke-CapturedProcess `
            -FilePath $wix `
            -Arguments @(
                "msi",
                "validate",
                $resolvedMsi,
                "--acceptEula",
                "wix7"
            ) `
            -WorkingDirectory $repoRoot
        $iceDiagnostics = @(
            @(
                $iceResult.StandardOutput,
                $iceResult.StandardError
            ) | Where-Object { $_ }
        )
        if ($iceDiagnostics.Count -gt 0) {
            Write-Host ($iceDiagnostics -join [Environment]::NewLine).TrimEnd()
        }
        Assert-True (
            $iceResult.ExitCode -eq 0
        ) "Windows Installer ICE validation failed."
        Assert-True (
            ($iceDiagnostics -join [Environment]::NewLine) -notmatch "WIX1105"
        ) (
            "Windows Installer ICE validation did not run. Use " +
            "-SkipIceValidation only when enforced App Control is proven to " +
            "block the validation engine; CI must run ICE validation."
        )
    }

    Invoke-CheckedProcess `
        -Label "Decompile and extract MSI" `
        -FilePath $wix `
        -Arguments @(
            "msi",
            "decompile",
            $resolvedMsi,
            "-x",
            $msiExtractRoot,
            "-o",
            $decompiledPath,
            "--acceptEula",
            "wix7"
        ) `
        -WorkingDirectory $repoRoot

    Invoke-CheckedProcess `
        -Label "Extract setup bundle" `
        -FilePath $wix `
        -Arguments @(
            "burn",
            "extract",
            $resolvedSetup,
            "-o",
            $bundleExtractRoot,
            "-oba",
            $bootstrapperApplicationRoot,
            "--acceptEula",
            "wix7"
        ) `
        -WorkingDirectory $repoRoot

    [xml]$decompiled = Get-Content -LiteralPath $decompiledPath -Raw
    $package = $decompiled.SelectSingleNode("/*[local-name()='Wix']/*[local-name()='Package']")
    Assert-True ($null -ne $package) "The decompiled MSI has no Package element."
    Assert-True (
        $package.GetAttribute("Name") -eq "Librarian"
    ) "The MSI product name is not Librarian."
    Assert-True (
        $package.GetAttribute("Version") -eq $ExpectedProductVersion
    ) "The MSI version does not match the expected product version."
    Assert-True (
        $package.GetAttribute("UpgradeCode") -eq
            "{212A27C7-B2F4-4053-A80D-FCDAB5C2CEC1}"
    ) "The MSI upgrade code changed unexpectedly."

    $programFiles64 = $decompiled.SelectSingleNode(
        "//*[local-name()='StandardDirectory' and @Id='ProgramFiles64Folder']"
    )
    Assert-True ($null -ne $programFiles64) "The MSI is not rooted in ProgramFiles64."
    $arpSystemComponent = $decompiled.SelectSingleNode(
        "//*[local-name()='Property' and @Id='ARPSYSTEMCOMPONENT' and @Value='1']"
    )
    Assert-True (
        $null -ne $arpSystemComponent
    ) "The inner MSI must be hidden from Programs and Features."
    $startMenuShortcut = $decompiled.SelectSingleNode(
        "//*[local-name()='Shortcut' and @Id='LibrarianStartMenuShortcut']"
    )
    Assert-True (
        $null -ne $startMenuShortcut -and
        $startMenuShortcut.GetAttribute("Advertise") -eq "yes"
    ) "The per-machine Start menu shortcut must be advertised."

    $fileNodes = @($decompiled.SelectNodes("//*[local-name()='File']"))
    $executableNames = @(
        $fileNodes |
            ForEach-Object { $_.GetAttribute("Name") } |
            Where-Object { $_ -like "*.exe" } |
            Sort-Object
    )
    $productExecutableNames = @(
        $executableNames |
            Where-Object { $_ -like "Librarian.*.exe" }
    )
    $expectedProductExecutables = @(
        "Librarian.ChromiumNativeHost.exe",
        "Librarian.VaultAgent.exe",
        "Librarian.Windows.exe"
    )
    Assert-True (
        ($productExecutableNames -join "`n") -eq
            ($expectedProductExecutables -join "`n")
    ) (
        "The MSI must contain exactly the three implemented product executables. " +
        "Found: $($productExecutableNames -join ', ')."
    )
    $runtimeExecutableNames = @(
        $executableNames |
            Where-Object { $_ -notlike "Librarian.*.exe" }
    )
    Assert-True (
        ($runtimeExecutableNames -join "`n") -eq "RestartAgent.exe"
    ) (
        "The self-contained Windows App SDK executable scope changed. Found: " +
        "$($runtimeExecutableNames -join ', ')."
    )
    Assert-True (
        -not (($fileNodes | ForEach-Object {
            $_.GetAttribute("Name")
        }) -match "PasskeyProvider")
    ) "The MSI must not contain a passkey-provider placeholder."

    $coreFeature = $decompiled.SelectSingleNode(
        "//*[local-name()='Feature' and @Id='Core']"
    )
    Assert-True (
        $null -ne $coreFeature -and
        $coreFeature.GetAttribute("Level") -eq "1" -and
        $coreFeature.GetAttribute("Absent") -eq "disallow"
    ) "The core installer feature must be required."

    $browserFeatures = [ordered]@{
        ChromeIntegration = "CHROME_MACHINE OR CHROME_USER"
        EdgeIntegration = "EDGE_MACHINE OR EDGE_USER"
    }
    foreach ($entry in $browserFeatures.GetEnumerator()) {
        $feature = $decompiled.SelectSingleNode(
            "//*[local-name()='Feature' and @Id='$($entry.Key)']"
        )
        Assert-True (
            $null -ne $feature -and $feature.GetAttribute("Level") -eq "0"
        ) "Browser feature '$($entry.Key)' must be optional by default."
        $level = $feature.SelectSingleNode(
            "*[local-name()='Level' and @Level='2']"
        )
        Assert-True (
            $null -ne $level -and
            $level.GetAttribute("Condition") -eq $entry.Value
        ) "Browser feature '$($entry.Key)' has an unsafe detection condition."
    }

    $expectedRegistryKeys = [ordered]@{
        "SOFTWARE\Google\Chrome\NativeMessagingHosts\com.theundeadmonk.librarian" =
            "ChromeNativeHostManifest"
        "SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.theundeadmonk.librarian" =
            "EdgeNativeHostManifest"
    }
    foreach ($entry in $expectedRegistryKeys.GetEnumerator()) {
        $key = $entry.Key
        $registryValue = @(
            $decompiled.SelectNodes("//*[local-name()='RegistryValue']") |
                Where-Object {
                    $_.GetAttribute("Root") -eq "HKLM" -and
                    $_.GetAttribute("Key") -eq $key
                }
        )
        Assert-True (
            $registryValue.Count -eq 1
        ) "Expected one machine-level native-messaging registration for '$key'."
        $component = $registryValue[0].ParentNode
        $manifestFile = $component.SelectSingleNode(
            "*[local-name()='File' and @Id='$($entry.Value)']"
        )
        Assert-True (
            $registryValue[0].GetAttribute("KeyPath") -eq "yes" -and
            $null -ne $manifestFile
        ) (
            "Browser manifest and registration '$key' must share one " +
            "registry-keyed repair component."
        )
    }

    $expectedCustomActions = [ordered]@{
        SnapshotIdentity = [PSCustomObject]@{
            Execute = "deferred"; Impersonate = "no"
        }
        RollbackIdentitySnapshotCleanup = [PSCustomObject]@{
            Execute = "rollback"; Impersonate = "no"
        }
        RollbackCurrentUserIdentity = [PSCustomObject]@{
            Execute = "rollback"; Impersonate = "yes"
        }
        RollbackIdentity = [PSCustomObject]@{
            Execute = "rollback"; Impersonate = "no"
        }
        RegisterIdentity = [PSCustomObject]@{
            Execute = "deferred"; Impersonate = "no"
        }
        RegisterCurrentUserIdentity = [PSCustomObject]@{
            Execute = "deferred"; Impersonate = "yes"
        }
        SnapshotUnregisterIdentity = [PSCustomObject]@{
            Execute = "deferred"; Impersonate = "no"
        }
        RollbackUnregisterSnapshotCleanup = [PSCustomObject]@{
            Execute = "rollback"; Impersonate = "no"
        }
        RollbackUnregisterCurrentUserIdentity = [PSCustomObject]@{
            Execute = "rollback"; Impersonate = "yes"
        }
        RollbackUnregisterIdentity = [PSCustomObject]@{
            Execute = "rollback"; Impersonate = "no"
        }
        UnregisterIdentity = [PSCustomObject]@{
            Execute = "deferred"; Impersonate = "no"
        }
        CleanupIdentitySnapshot = [PSCustomObject]@{
            Execute = "commit"; Impersonate = "no"
        }
    }
    foreach ($entry in $expectedCustomActions.GetEnumerator()) {
        $action = $decompiled.SelectSingleNode(
            "//*[local-name()='CustomAction' and @Id='$($entry.Key)']"
        )
        Assert-True ($null -ne $action) "Custom action '$($entry.Key)' is missing."
        $actualImpersonate = $action.GetAttribute("Impersonate")
        $impersonationMatches = if ($entry.Value.Impersonate -eq "yes") {
            $actualImpersonate -in @("", "yes")
        } else {
            $actualImpersonate -eq "no"
        }
        Assert-True (
            $action.GetAttribute("BinaryRef") -eq "LibrarianSetupCustomActions" -and
            $action.GetAttribute("Execute") -eq $entry.Value.Execute -and
            $impersonationMatches -and
            $action.GetAttribute("HideTarget") -eq "yes"
        ) "Custom action '$($entry.Key)' has unsafe execution attributes."

        $scheduled = $decompiled.SelectSingleNode(
            (
                "//*[local-name()='InstallExecuteSequence']/" +
                "*[local-name()='Custom' and @Action='$($entry.Key)']"
            )
        )
        Assert-True (
            $null -ne $scheduled
        ) "Custom action '$($entry.Key)' is not transactionally scheduled."
    }

    foreach ($propertyActionId in @(
        "SetSnapshotIdentity",
        "SetRollbackIdentitySnapshotCleanup",
        "SetRollbackCurrentUserIdentity",
        "SetRollbackIdentity",
        "SetCleanupIdentitySnapshot",
        "SetSnapshotUnregisterIdentity",
        "SetRollbackUnregisterSnapshotCleanup",
        "SetRollbackUnregisterCurrentUserIdentity",
        "SetRollbackUnregisterIdentity"
    )) {
        $propertyAction = $decompiled.SelectSingleNode(
            "//*[local-name()='CustomAction' and @Id='$propertyActionId']"
        )
        Assert-True (
            $null -ne $propertyAction -and
            $propertyAction.GetAttribute("Value") -match
                '\[INSTALLFOLDER\]Librarian\.Identity\.msix\.state' -and
            $propertyAction.GetAttribute("Value") -notmatch
                '\[(?:TempFolder|LocalAppDataFolder|AppDataFolder)\]'
        ) (
            "Privileged rollback state must stay inside the protected " +
            "installer-owned directory."
        )
    }

    $unsafeCustomActions = @(
        $decompiled.SelectNodes("//*[local-name()='CustomAction']") |
            Where-Object {
                $_.HasAttribute("ExeCommand") -or
                $_.HasAttribute("Script") -or
                $_.HasAttribute("VBScriptCall") -or
                $_.HasAttribute("JScriptCall")
            }
    )
    Assert-True (
        $unsafeCustomActions.Count -eq 0
    ) "The MSI must not shell out or embed script custom actions."
    $restartManagerControl = $decompiled.SelectSingleNode(
        "//*[local-name()='Property' and @Id='MSIRESTARTMANAGERCONTROL']"
    )
    Assert-True (
        $null -eq $restartManagerControl -or
        $restartManagerControl.GetAttribute("Value") -ne "Disable"
    ) "Windows Installer Restart Manager must remain enabled."
    $coreCreateFolder = $decompiled.SelectSingleNode(
        (
            "//*[local-name()='Component' and @Id='CoreExecutables']/" +
            "*[local-name()='CreateFolder']"
        )
    )
    Assert-True (
        $null -ne $coreCreateFolder
    ) "The protected install directory must be created before identity snapshotting."
    $commitCleanup = $decompiled.SelectSingleNode(
        "//*[local-name()='CustomAction' and @Id='CleanupIdentitySnapshot']"
    )
    Assert-True (
        $null -ne $commitCleanup -and
        $commitCleanup.GetAttribute("Return") -eq "ignore"
    ) "Post-commit snapshot cleanup must not report a committed install as failed."
    $faultInjection = $decompiled.SelectSingleNode(
        (
            "//*[local-name()='InstallExecuteSequence']/" +
            "*[local-name()='Custom' and " +
            "contains(@Action,'FailWhenDeferred') and " +
            "contains(@Condition,'WIXFAILWHENDEFERRED=1')]"
        )
    )
    Assert-True (
        $null -ne $faultInjection
    ) "The transactional fault-injection hook is missing."

    $removeExistingProducts = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "RemoveExistingProducts"
    $installExecute = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "InstallExecute"
    $createFolders = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "CreateFolders"
    $snapshotIdentity = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "SnapshotIdentity"
    $rollbackSnapshotCleanup = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "RollbackIdentitySnapshotCleanup"
    $rollbackCurrentUserIdentity = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "RollbackCurrentUserIdentity"
    $rollbackIdentity = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "RollbackIdentity"
    $installFiles = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "InstallFiles"
    $installFinalize = Get-MsiSequence `
        -DatabasePath $resolvedMsi `
        -Action "InstallFinalize"
    Assert-True (
        $removeExistingProducts -gt $installExecute -and
        $removeExistingProducts -lt $installFinalize
    ) (
        "RemoveExistingProducts must run after InstallExecute and before " +
        "InstallFinalize so an upgrade can roll back."
    )
    Assert-True (
        $snapshotIdentity -gt $createFolders -and
        $rollbackSnapshotCleanup -gt $snapshotIdentity -and
        $rollbackCurrentUserIdentity -gt $rollbackSnapshotCleanup -and
        $rollbackIdentity -gt $rollbackCurrentUserIdentity -and
        $rollbackIdentity -lt $installFiles
    ) (
        "Identity snapshot and rollback actions must run in order after the " +
        "protected directory exists and before product files are installed."
    )

    $chromeManifestPath = Get-ExtractedMsiFile `
        -DecompiledMsi $decompiled `
        -ExtractRoot $msiExtractRoot `
        -Name "com.theundeadmonk.librarian.chrome.json"
    $edgeManifestPath = Get-ExtractedMsiFile `
        -DecompiledMsi $decompiled `
        -ExtractRoot $msiExtractRoot `
        -Name "com.theundeadmonk.librarian.edge.json"
    $releaseManifestPath = Get-ExtractedMsiFile `
        -DecompiledMsi $decompiled `
        -ExtractRoot $msiExtractRoot `
        -Name "Librarian.Release.json"
    $releaseManifest = Get-Content -LiteralPath $releaseManifestPath -Raw |
        ConvertFrom-Json
    Assert-True (
        $releaseManifest.signingMode -eq $ExpectedSigningMode
    ) "The release manifest has an unexpected signing mode."
    Assert-True (
        $releaseManifest.productVersion -eq $ExpectedProductVersion
    ) "The release manifest has an unexpected product version."
    Assert-True (
        $releaseManifest.passkeyProvider.included -eq $false
    ) "The release manifest must state that the passkey provider is absent."

    foreach ($manifestCase in @(
        [PSCustomObject]@{
            Path = $chromeManifestPath
            Origin = $releaseManifest.browser.chromeOrigin
        },
        [PSCustomObject]@{
            Path = $edgeManifestPath
            Origin = $releaseManifest.browser.edgeOrigin
        }
    )) {
        $browserManifest = Get-Content -LiteralPath $manifestCase.Path -Raw |
            ConvertFrom-Json
        Assert-True (
            $browserManifest.name -eq "com.theundeadmonk.librarian" -and
            $browserManifest.type -eq "stdio" -and
            $browserManifest.path -eq "Librarian.ChromiumNativeHost.exe"
        ) "A native-messaging manifest has an unsafe host definition."
        $origins = @($browserManifest.allowed_origins)
        Assert-True (
            $origins.Count -eq 1 -and
            $origins[0] -eq $manifestCase.Origin -and
            $origins[0] -match '^chrome-extension://[a-p]{32}/$' -and
            $origins[0] -notmatch '\*'
        ) "A native-messaging manifest must allow exactly one extension origin."
    }

    $expectedComponentRoles = @(
        "Desktop",
        "VaultAgent",
        "ChromiumNativeHost",
        "IdentityPackage"
    )
    $releaseHashes = [ordered]@{}
    foreach ($component in @($releaseManifest.components)) {
        Assert-True (
            $component.role -in $expectedComponentRoles -and
            -not $releaseHashes.Contains($component.role) -and
            $component.sha256 -match '^[0-9A-F]{64}$'
        ) "The release manifest has an invalid or duplicate component hash."
        $componentPath = Get-ExtractedMsiFile `
            -DecompiledMsi $decompiled `
            -ExtractRoot $msiExtractRoot `
            -Name $component.path
        $actualHash = (
            Get-FileHash -LiteralPath $componentPath -Algorithm SHA256
        ).Hash
        Assert-True (
            $actualHash -eq $component.sha256
        ) "Release hash mismatch for '$($component.path)'."
        $releaseHashes[$component.role] = $component.sha256
    }
    Assert-True (
        $releaseHashes.Count -eq $expectedComponentRoles.Count
    ) "The release manifest does not hash every identity-bound component."

    $expectedHashData = (
        $expectedComponentRoles |
            ForEach-Object { $releaseHashes[$_] }
    ) -join "|"
    foreach ($actionId in @(
        "SetRegisterIdentity",
        "SetRegisterCurrentUserIdentity"
    )) {
        $hashPropertyAction = $decompiled.SelectSingleNode(
            "//*[local-name()='CustomAction' and @Id='$actionId']"
        )
        Assert-True (
            $null -ne $hashPropertyAction -and
            $hashPropertyAction.GetAttribute("Value").EndsWith(
                "|$expectedHashData",
                [StringComparison]::Ordinal
            )
        ) (
            "Identity registration action '$actionId' is not bound to every " +
            "release payload hash."
        )
    }

    $desktopExecutablePath = Get-ExtractedMsiFile `
        -DecompiledMsi $decompiled `
        -ExtractRoot $msiExtractRoot `
        -Name "Librarian.Windows.exe"
    foreach ($runtimeFile in @(
        "Microsoft.WindowsAppRuntime.dll",
        "Microsoft.ui.xaml.dll"
    )) {
        [void](Get-ExtractedMsiFile `
            -DecompiledMsi $decompiled `
            -ExtractRoot $msiExtractRoot `
            -Name $runtimeFile)
    }

    $manifestTool = Join-Path $toolchain.WindowsSdkRoot (
        "bin\$($toolchain.Versions.WindowsSdk)\x64\mt.exe"
    )
    Assert-True (
        (Test-Path -LiteralPath $manifestTool -PathType Leaf)
    ) "The pinned mt.exe is missing."
    foreach ($manifestCase in @(
        [PSCustomObject]@{
            Executable = "Librarian.Windows.exe"
            ApplicationId = "Desktop"
        },
        [PSCustomObject]@{
            Executable = "Librarian.VaultAgent.exe"
            ApplicationId = "VaultAgent"
        },
        [PSCustomObject]@{
            Executable = "Librarian.ChromiumNativeHost.exe"
            ApplicationId = "ChromiumNativeHost"
        }
    )) {
        $executablePath = Get-ExtractedMsiFile `
            -DecompiledMsi $decompiled `
            -ExtractRoot $msiExtractRoot `
            -Name $manifestCase.Executable
        $embeddedManifestPath = Join-Path $inspectionRoot (
            "$($manifestCase.ApplicationId).manifest"
        )
        Invoke-CheckedProcess `
            -Label "Extract $($manifestCase.Executable) identity manifest" `
            -FilePath $manifestTool `
            -Arguments @(
                "-nologo",
                "-inputresource:$executablePath;#1",
                "-out:$embeddedManifestPath"
            ) `
            -WorkingDirectory $repoRoot

        [xml]$embeddedManifest = Get-Content `
            -LiteralPath $embeddedManifestPath `
            -Raw
        $embeddedNamespaces = New-Object Xml.XmlNamespaceManager(
            $embeddedManifest.NameTable
        )
        $embeddedNamespaces.AddNamespace(
            "assembly",
            "urn:schemas-microsoft-com:asm.v1"
        )
        $embeddedNamespaces.AddNamespace(
            "msix",
            "urn:schemas-microsoft-com:msix.v1"
        )
        $assemblyIdentity = $embeddedManifest.SelectSingleNode(
            "/assembly:assembly/assembly:assemblyIdentity",
            $embeddedNamespaces
        )
        Assert-True (
            $null -ne $assemblyIdentity -and
            $assemblyIdentity.GetAttribute("version") -eq $ExpectedProductVersion
        ) (
            "'$($manifestCase.Executable)' does not embed the expected " +
            "product version."
        )
        $msixIdentity = $embeddedManifest.SelectSingleNode(
            "/assembly:assembly/msix:msix",
            $embeddedNamespaces
        )
        Assert-True (
            $null -ne $msixIdentity -and
            $msixIdentity.GetAttribute("publisher") -eq
                "CN=Librarian Development" -and
            $msixIdentity.GetAttribute("packageName") -eq
                "TheUndeadMonk.Librarian.Development" -and
            $msixIdentity.GetAttribute("applicationId") -eq
                $manifestCase.ApplicationId
        ) (
            "'$($manifestCase.Executable)' does not embed the expected " +
            "external package identity."
        )
    }

    $identityPackage = Get-ExtractedMsiFile `
        -DecompiledMsi $decompiled `
        -ExtractRoot $msiExtractRoot `
        -Name "Librarian.Identity.msix"
    $makeAppx = Join-Path $toolchain.WindowsSdkRoot (
        "bin\$($toolchain.Versions.WindowsSdk)\x64\MakeAppx.exe"
    )
    Assert-True (
        (Test-Path -LiteralPath $makeAppx -PathType Leaf)
    ) "The pinned MakeAppx.exe is missing."
    Invoke-CheckedProcess `
        -Label "Unpack embedded identity package" `
        -FilePath $makeAppx `
        -Arguments @(
            "unpack",
            "/nv",
            "/p",
            $identityPackage,
            "/d",
            $identityExtractRoot,
            "/o"
        ) `
        -WorkingDirectory $repoRoot
    & (Join-Path $PSScriptRoot "test-identity-package.ps1") `
        -ManifestPath (Join-Path $identityExtractRoot "AppxManifest.xml") `
        -ExpectedVersion $ExpectedProductVersion

    $customActionBinary = Join-Path (
        Join-Path $msiExtractRoot "Binary"
    ) "LibrarianSetupCustomActions"
    Assert-True (
        (Test-Path -LiteralPath $customActionBinary -PathType Leaf)
    ) "The embedded setup custom-action DLL is missing."
    $vswhere = Join-Path ${env:ProgramFiles(x86)} (
        "Microsoft Visual Studio\Installer\vswhere.exe"
    )
    $dumpbinCandidates = @(
        & $vswhere `
            -latest `
            -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -find "VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe"
    )
    Assert-True (
        $dumpbinCandidates.Count -gt 0
    ) "Visual Studio dumpbin.exe could not be resolved."
    $desktopDependencies = Invoke-CapturedProcess `
        -FilePath $dumpbinCandidates[-1] `
        -Arguments @("/nologo", "/dependents", $desktopExecutablePath) `
        -WorkingDirectory $repoRoot
    Assert-True (
        $desktopDependencies.ExitCode -eq 0 -and
        $desktopDependencies.StandardOutput -notmatch
            '(?im)^\s*(MSVCP|VCRUNTIME)\d+(?:_\d+)?(?:D)?\.dll\s*$'
    ) (
        "The desktop executable must use the hybrid CRT instead of requiring " +
        "a separately installed Visual C++ runtime."
    )
    $dumpbinResult = Invoke-CapturedProcess `
        -FilePath $dumpbinCandidates[-1] `
        -Arguments @("/nologo", "/exports", $customActionBinary) `
        -WorkingDirectory $repoRoot
    Assert-True (
        $dumpbinResult.ExitCode -eq 0
    ) "dumpbin failed to inspect the embedded custom-action DLL."
    $expectedExports = @(
        "CleanupIdentitySnapshot",
        "RegisterCurrentUserIdentity",
        "RegisterIdentity",
        "RollbackCurrentUserIdentity",
        "RollbackIdentity",
        "SnapshotIdentity",
        "UnregisterIdentity"
    )
    foreach ($export in $expectedExports) {
        Assert-True (
            $dumpbinResult.StandardOutput -match (
                "(?m)^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+$export(?:\s|$)"
            )
        ) "The custom-action DLL does not export '$export'."
    }

    $baDataPath = Join-Path $bootstrapperApplicationRoot (
        "BootstrapperApplicationData.xml"
    )
    $burnManifestPath = Join-Path $bootstrapperApplicationRoot "manifest.xml"
    [xml]$baData = Get-Content -LiteralPath $baDataPath -Raw
    [xml]$burnManifest = Get-Content -LiteralPath $burnManifestPath -Raw
    $bundleProperties = $baData.SelectSingleNode(
        "/*[local-name()='BootstrapperApplicationData']/" +
        "*[local-name()='WixBundleProperties']"
    )
    Assert-True (
        $null -ne $bundleProperties -and
        $bundleProperties.GetAttribute("DisplayName") -eq "Librarian" -and
        $bundleProperties.GetAttribute("Compressed") -eq "yes" -and
        $bundleProperties.GetAttribute("Scope") -eq "perMachine" -and
        $bundleProperties.GetAttribute("UpgradeCode") -eq
            "{F2C20990-C7A5-4672-9046-E84427EFC9B6}"
    ) "The setup bundle has unexpected product metadata."

    $bundlePackages = @(
        $baData.SelectNodes(
            "/*[local-name()='BootstrapperApplicationData']/" +
            "*[local-name()='WixPackageProperties']"
        )
    )
    Assert-True (
        $bundlePackages.Count -eq 1 -and
        $bundlePackages[0].GetAttribute("PackageType") -eq "Msi" -and
        $bundlePackages[0].GetAttribute("Vital") -eq "yes" -and
        $bundlePackages[0].GetAttribute("Permanent") -eq "no" -and
        $bundlePackages[0].GetAttribute("Compressed") -eq "yes" -and
        $bundlePackages[0].GetAttribute("Version") -eq $ExpectedProductVersion
    ) "The bundle must contain one vital, removable, compressed MSI."
    $primaryPackage = $baData.SelectSingleNode(
        "//*[local-name()='WixBalPackageInfo' and " +
        "@PackageId='LibrarianPackage' and @PrimaryPackageType='default']"
    )
    Assert-True (
        $null -ne $primaryPackage
    ) "The bundle does not identify Librarian as its primary package."

    $burnRoot = $burnManifest.SelectSingleNode("/*[local-name()='BurnManifest']")
    Assert-True (
        $null -ne $burnRoot -and
        $burnRoot.GetAttribute("Win64") -eq "yes"
    ) "The setup bootstrapper is not x64."
    $registration = $burnManifest.SelectSingleNode(
        "/*[local-name()='BurnManifest']/*[local-name()='Registration']"
    )
    Assert-True (
        $null -ne $registration -and
        $registration.GetAttribute("Scope") -eq "perMachine" -and
        $registration.GetAttribute("Version") -eq $ExpectedProductVersion -and
        $null -ne $registration.SelectSingleNode("*[local-name()='Arp']")
    ) "Burn must own the single machine-wide ARP registration."
    $chainPackages = @(
        $burnManifest.SelectNodes(
            "/*[local-name()='BurnManifest']/" +
            "*[local-name()='Chain']/*[local-name()='MsiPackage']"
        )
    )
    Assert-True (
        $chainPackages.Count -eq 1 -and
        $chainPackages[0].GetAttribute("Id") -eq "LibrarianPackage" -and
        $chainPackages[0].GetAttribute("Vital") -eq "yes" -and
        $chainPackages[0].GetAttribute("Permanent") -eq "no"
    ) "The Burn chain must contain exactly the Librarian MSI."

    $embeddedMsi = Join-Path $bundleExtractRoot (
        "WixAttachedContainer\Librarian.Package.msi"
    )
    Assert-True (
        (Test-Path -LiteralPath $embeddedMsi -PathType Leaf)
    ) "The compressed setup bundle did not contain the Librarian MSI."
    Assert-True (
        (Get-FileHash -LiteralPath $embeddedMsi -Algorithm SHA256).Hash -eq
            (Get-FileHash -LiteralPath $resolvedMsi -Algorithm SHA256).Hash
    ) "The MSI embedded in the setup bundle differs from the built MSI."

    $nugetPackages = if ($env:NUGET_PACKAGES) {
        $env:NUGET_PACKAGES
    } else {
        Join-Path $env:USERPROFILE ".nuget\packages"
    }
    $signTool = Join-Path $nugetPackages (
        "microsoft.windows.sdk.buildtools\" +
        "$($toolchain.Versions.WindowsSdkBuildTools)\bin\" +
        "$($toolchain.Versions.WindowsSdk)\x64\SignTool.exe"
    )
    Assert-True (
        (Test-Path -LiteralPath $signTool -PathType Leaf)
    ) "The locked SignTool.exe is missing."
    foreach ($signedArtifact in @($resolvedMsi, $resolvedSetup)) {
        $verification = Invoke-CapturedProcess `
            -FilePath $signTool `
            -Arguments @("verify", "/pa", "/all", $signedArtifact) `
            -WorkingDirectory $repoRoot
        if ($ExpectedSigningMode -eq "development") {
            Assert-True (
                $verification.ExitCode -eq 0
            ) "Development artifact '$signedArtifact' is not signed."
        } else {
            Assert-True (
                $verification.ExitCode -ne 0
            ) "Unsigned fixture '$signedArtifact' unexpectedly has a trusted signature."
        }
    }

    Write-Host ""
    Write-Host "Installer structural validation passed."
    Write-Host "MSI: $resolvedMsi"
    Write-Host "Setup: $resolvedSetup"
    Write-Host "Version: $ExpectedProductVersion"
    Write-Host "Signing mode: $ExpectedSigningMode"
    Write-Host (
        "ICE validation: " +
        $(if ($SkipIceValidation) {
            "skipped locally due to enforced App Control"
        } else {
            "passed"
        })
    )
    Write-Host "Product executables: 3"
    Write-Host "Passkey provider: absent (owned by issue #18)"
} finally {
    if (Test-Path -LiteralPath $resolvedInspectionRoot) {
        Remove-Item -LiteralPath $resolvedInspectionRoot -Recurse -Force
    }
}
