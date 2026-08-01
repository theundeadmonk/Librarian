[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UnsignedSetupPath,

    [Parameter(Mandatory)]
    [string]$WrongSignerSetupPath,

    [Parameter(Mandatory)]
    [string]$MixedPayloadSetupPath,

    [Parameter(Mandatory)]
    [string]$SignedLowMsiPath,

    [Parameter(Mandatory)]
    [string]$SignedLowSetupPath,

    [Parameter(Mandatory)]
    [string]$SignedHighMsiPath,

    [Parameter(Mandatory)]
    [string]$SignedHighSetupPath,

    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$LowVersion = "0.1.0.0",

    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$HighVersion = "0.2.0.0",

    [Parameter(Mandatory)]
    [string]$LogDirectory,

    [switch]$SkipInteractiveDesktopLaunch,

    [switch]$ConfirmDisposableVm,

    [switch]$ConfirmDisposableWindows11Runner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "native-process-arguments.ps1")
. (Join-Path $PSScriptRoot "installer-runner-guard.ps1")

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
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    Write-Host ""
    Write-Host "==> $Label"
    $argumentText = Join-NativeProcessArguments -Arguments $Arguments

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $argumentText
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
        $result = [PSCustomObject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $standardOutput.Result
            StandardError = $standardError.Result
        }
    } finally {
        $process.Dispose()
    }

    if ($result.StandardOutput) {
        Write-Host $result.StandardOutput.TrimEnd()
    }
    if ($result.StandardError) {
        Write-Host $result.StandardError.TrimEnd()
    }
    Write-Host "$Label exit code: $($result.ExitCode)"
    return $result
}

function Invoke-SuccessfulProcess {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $result = Invoke-CapturedProcess `
        -Label $Label `
        -FilePath $FilePath `
        -Arguments $Arguments
    Assert-True (
        $result.ExitCode -eq 0
    ) "$Label failed with exit code $($result.ExitCode)."
}

function Invoke-FailingProcess {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $result = Invoke-CapturedProcess `
        -Label $Label `
        -FilePath $FilePath `
        -Arguments $Arguments
    Assert-True (
        $result.ExitCode -ne 0
    ) "$Label unexpectedly succeeded."
}

function Write-MsiFailureContext {
    param(
        [Parameter(Mandatory)]
        [IO.FileInfo]$Log
    )

    $lines = @(Get-Content -LiteralPath $Log.FullName -ErrorAction Continue)
    $failureIndex = $null
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match "Return value 3") {
            $failureIndex = $index
            break
        }
    }
    if ($null -eq $failureIndex) {
        return
    }

    $contextStart = [Math]::Max(0, $failureIndex - 40)
    $contextEnd = [Math]::Min($lines.Count - 1, $failureIndex + 15)
    Write-Host ""
    Write-Host "--- MSI failure context: $($Log.Name) ---"
    $lines[$contextStart..$contextEnd] | ForEach-Object { Write-Host $_ }
}

function Invoke-CurrentUserIdentityLauncher {
    param(
        [Parameter(Mandatory)]
        [string]$LauncherPath,

        [Parameter(Mandatory)]
        [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
        [string]$ExpectedVersion
    )

    Invoke-SuccessfulProcess `
        -Label "Register current-user identity $ExpectedVersion" `
        -FilePath $LauncherPath `
        -Arguments @("--register-only")
    $versions = @(
        Get-LibrarianCurrentUserPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $versions.Count -eq 1 -and $versions[0] -eq $ExpectedVersion
    ) (
        "The invoking user's identity launcher did not converge to version " +
        "'$ExpectedVersion'."
    )
}

function Invoke-CurrentUserNativeHostLauncher {
    param(
        [Parameter(Mandatory)]
        [string]$LauncherPath,

        [Parameter(Mandatory)]
        [ValidatePattern("^chrome-extension://[a-p]{32}/$")]
        [string]$Origin,

        [Parameter(Mandatory)]
        [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
        [string]$ExpectedVersion
    )

    Invoke-SuccessfulProcess `
        -Label "Converge identity through browser native-host activation" `
        -FilePath $LauncherPath `
        -Arguments @($Origin, "--parent-window=0")
    $versions = @(
        Get-LibrarianCurrentUserPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $versions.Count -eq 1 -and $versions[0] -eq $ExpectedVersion
    ) (
        "The browser native-host launcher did not converge the invoking " +
        "user's identity to version '$ExpectedVersion'."
    )
}

function Get-VisibleArpEntries {
    $entries = @()
    foreach ($root in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }
        foreach ($key in Get-ChildItem -LiteralPath $root) {
            $properties = Get-ItemProperty `
                -LiteralPath $key.PSPath `
                -ErrorAction SilentlyContinue
            if ($null -eq $properties) {
                continue
            }
            $displayName = $properties.PSObject.Properties["DisplayName"]
            $systemComponent = $properties.PSObject.Properties["SystemComponent"]
            if ($null -ne $displayName -and
                $displayName.Value -eq "Librarian" -and
                ($null -eq $systemComponent -or $systemComponent.Value -ne 1)) {
                $entries += $properties
            }
        }
    }
    return $entries
}

function Get-LibrarianPackages {
    return @(
        Get-AppxPackage `
            -AllUsers `
            -Name "TheUndeadMonk.Librarian.Development" `
            -ErrorAction Stop
    )
}

function Get-LibrarianCurrentUserPackages {
    return @(
        Get-AppxPackage `
            -Name "TheUndeadMonk.Librarian.Development" `
            -ErrorAction Stop
    )
}

function Get-LibrarianProvisionedPackages {
    return @(
        Get-AppxProvisionedPackage -Online |
            Where-Object {
                $_.DisplayName -eq "TheUndeadMonk.Librarian.Development"
            }
    )
}

function Get-RegistryDefaultValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return (Get-Item -LiteralPath $Path).GetValue($null)
}

function Assert-NoInstallerRollbackArtifacts {
    param(
        [Parameter(Mandatory)]
        [string]$InstallFolder
    )

    foreach ($name in @(
        "Librarian.Identity.msix.state",
        "Librarian.Identity.rollback.msix",
        "Librarian.Windows.rollback.exe",
        "Librarian.VaultAgent.rollback.exe",
        "Librarian.ChromiumNativeHost.rollback.exe"
    )) {
        Assert-True (
            -not (Test-Path -LiteralPath (Join-Path $InstallFolder $name))
        ) "Installer rollback artifact '$name' survived the transaction."
    }
}

function Assert-BrowserState {
    param(
        [Parameter(Mandatory)]
        [bool]$Expected,

        [Parameter(Mandatory)]
        [string]$InstallFolder,

        [Parameter(Mandatory)]
        [string]$ChromeRegistryPath,

        [Parameter(Mandatory)]
        [string]$EdgeRegistryPath
    )

    foreach ($browser in @(
        [PSCustomObject]@{
            Name = "Chrome"
            RegistryPath = $ChromeRegistryPath
            Manifest = "com.theundeadmonk.librarian.chrome.json"
            Origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        },
        [PSCustomObject]@{
            Name = "Edge"
            RegistryPath = $EdgeRegistryPath
            Manifest = "com.theundeadmonk.librarian.edge.json"
            Origin = "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/"
        }
    )) {
        $manifestPath = Join-Path $InstallFolder $browser.Manifest
        Assert-True (
            (Test-Path -LiteralPath $manifestPath -PathType Leaf)
        ) "$($browser.Name) native-messaging manifest is missing."
        $manifest = Get-Content -LiteralPath $manifestPath -Raw |
            ConvertFrom-Json
        Assert-True (
            $manifest.name -eq "com.theundeadmonk.librarian" -and
            $manifest.path -eq "Librarian.IdentityLauncher.exe" -and
            @($manifest.allowed_origins).Count -eq 1 -and
            @($manifest.allowed_origins)[0] -eq $browser.Origin
        ) "$($browser.Name) native-messaging manifest is unsafe."
        if ($Expected) {
            $actualRegistryValue = Get-RegistryDefaultValue `
                -Path $browser.RegistryPath
            Assert-True (
                $actualRegistryValue -eq $manifestPath
            ) (
                "$($browser.Name) native-messaging registration is incorrect. " +
                "Expected '$manifestPath'; found '$actualRegistryValue'."
            )
        } else {
            Assert-True (
                -not (Test-Path -LiteralPath $browser.RegistryPath)
            ) "$($browser.Name) integration was registered without opt-in."
        }
    }
}

function Assert-Installed {
    param(
        [Parameter(Mandatory)]
        [string]$ExpectedVersion,

        [Parameter(Mandatory)]
        [bool]$BrowsersExpected,

        [Parameter(Mandatory)]
        [string]$InstallFolder,

        [Parameter(Mandatory)]
        [string]$ChromeRegistryPath,

        [Parameter(Mandatory)]
        [string]$EdgeRegistryPath,

        [Parameter(Mandatory)]
        [string]$ProductRegistryPath,

        [AllowEmptyString()]
        [string]$ExpectedCurrentUserIdentityVersion = "__installed__"
    )

    if ($ExpectedCurrentUserIdentityVersion -eq "__installed__") {
        $ExpectedCurrentUserIdentityVersion = $ExpectedVersion
    }

    foreach ($name in @(
        "Librarian.IdentityLauncher.exe",
        "Librarian.Windows.exe",
        "Librarian.VaultAgent.exe",
        "Librarian.ChromiumNativeHost.exe",
        "Librarian.Identity.msix",
        "Librarian.PayloadHashes",
        "Librarian.Release.json",
        "com.theundeadmonk.librarian.chrome.json",
        "com.theundeadmonk.librarian.edge.json"
    )) {
        Assert-True (
            (Test-Path -LiteralPath (Join-Path $InstallFolder $name) -PathType Leaf)
        ) "Installed product file '$name' is missing."
    }
    Assert-True (
        -not (
            Test-Path -LiteralPath (
                Join-Path $InstallFolder "Librarian.PasskeyProvider.exe"
            )
        )
    ) "The installer introduced a passkey-provider placeholder."

    $release = Get-Content `
        -LiteralPath (Join-Path $InstallFolder "Librarian.Release.json") `
        -Raw |
        ConvertFrom-Json
    Assert-True (
        $release.productVersion -eq $ExpectedVersion -and
        $release.signingMode -eq "development" -and
        $release.passkeyProvider.included -eq $false
    ) "The installed release manifest does not match the expected fixture."

    foreach ($executable in @(
        "Librarian.IdentityLauncher.exe",
        "Librarian.Windows.exe",
        "Librarian.VaultAgent.exe",
        "Librarian.ChromiumNativeHost.exe"
    )) {
        $signature = Get-AuthenticodeSignature `
            -LiteralPath (Join-Path $InstallFolder $executable)
        Assert-True (
            $signature.Status -eq
                [System.Management.Automation.SignatureStatus]::Valid -and
            $null -ne $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -eq "CN=Librarian Development"
        ) "Installed executable '$executable' has an invalid development signature."
    }

    Assert-True (
        (Test-Path -LiteralPath $ProductRegistryPath) -and
        (Get-ItemProperty -LiteralPath $ProductRegistryPath).Version -eq
            $ExpectedVersion
    ) "The machine product-version registration is incorrect."
    Assert-True (
        @(Get-VisibleArpEntries).Count -eq 1
    ) "The install must expose exactly one visible Programs and Features entry."

    $currentUserVersions = @(
        Get-LibrarianCurrentUserPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    if ($ExpectedCurrentUserIdentityVersion) {
        Assert-True (
            $currentUserVersions.Count -eq 1 -and
            $currentUserVersions[0] -eq
                $ExpectedCurrentUserIdentityVersion
        ) (
            "The invoking user does not have identity version " +
            "'$ExpectedCurrentUserIdentityVersion'. Found: " +
            "$($currentUserVersions -join ', ')."
        )
    } else {
        Assert-True (
            $currentUserVersions.Count -eq 0
        ) (
            "Setup mutated current-user identity before user-context " +
            "activation. Found: $($currentUserVersions -join ', ')."
        )
    }
    $provisionedVersions = @(
        Get-LibrarianProvisionedPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $provisionedVersions.Count -eq 0
    ) (
        "The per-user installer must not provision package identity. Found: " +
        "$($provisionedVersions -join ', ')."
    )

    Assert-BrowserState `
        -Expected $BrowsersExpected `
        -InstallFolder $InstallFolder `
        -ChromeRegistryPath $ChromeRegistryPath `
        -EdgeRegistryPath $EdgeRegistryPath
    Assert-NoInstallerRollbackArtifacts -InstallFolder $InstallFolder
}

function Assert-ProductAbsent {
    param(
        [Parameter(Mandatory)]
        [string]$InstallFolder,

        [Parameter(Mandatory)]
        [string]$ChromeRegistryPath,

        [Parameter(Mandatory)]
        [string]$EdgeRegistryPath,

        [Parameter(Mandatory)]
        [string]$ProductRegistryPath
    )

    if (Test-Path -LiteralPath $InstallFolder) {
        $remaining = @(Get-ChildItem -LiteralPath $InstallFolder -Force -Recurse)
        Assert-True (
            $remaining.Count -eq 0
        ) (
            "Installer-owned files remain after rollback or uninstall: " +
            "$(($remaining | ForEach-Object FullName) -join ', ')."
        )
    }
    foreach ($registryPath in @(
        $ChromeRegistryPath,
        $EdgeRegistryPath,
        $ProductRegistryPath
    )) {
        Assert-True (
            -not (Test-Path -LiteralPath $registryPath)
        ) "Installer registration remains at '$registryPath'."
    }
    Assert-True (
        @(Get-VisibleArpEntries).Count -eq 0
    ) "A visible Librarian Programs and Features entry remains."
    Assert-True (
        @(Get-LibrarianPackages).Count -eq 0
    ) "A Librarian identity package remains installed."
    Assert-True (
        @(Get-LibrarianCurrentUserPackages).Count -eq 0
    ) "A Librarian identity package remains registered for the invoking user."
    Assert-True (
        @(Get-LibrarianProvisionedPackages).Count -eq 0
    ) "A Librarian identity package remains provisioned."
}

function Remove-ProductState {
    param(
        [Parameter(Mandatory)]
        [string[]]$SetupPaths,

        [Parameter(Mandatory)]
        [string[]]$MsiPaths,

        [Parameter(Mandatory)]
        [string]$InstallFolder,

        [Parameter(Mandatory)]
        [string]$ChromeRegistryPath,

        [Parameter(Mandatory)]
        [string]$EdgeRegistryPath,

        [Parameter(Mandatory)]
        [string]$ProductRegistryPath,

        [Parameter(Mandatory)]
        [string]$LogDirectory
    )

    $cleanupIndex = 0
    foreach ($setup in $SetupPaths) {
        if (Test-Path -LiteralPath $setup -PathType Leaf) {
            $cleanupIndex++
            [void](Invoke-CapturedProcess `
                -Label "Cleanup bundle $cleanupIndex" `
                -FilePath $setup `
                -Arguments @(
                    "/uninstall",
                    "/quiet",
                    "/norestart",
                    "/log",
                    (Join-Path $LogDirectory "cleanup-bundle-$cleanupIndex.log")
                ))
        }
    }
    foreach ($msi in $MsiPaths) {
        if (Test-Path -LiteralPath $msi -PathType Leaf) {
            $cleanupIndex++
            [void](Invoke-CapturedProcess `
                -Label "Cleanup MSI $cleanupIndex" `
                -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                -Arguments @(
                    "/x",
                    $msi,
                    "/qn",
                    "/norestart",
                    "/l*v",
                    (Join-Path $LogDirectory "cleanup-msi-$cleanupIndex.log")
                ))
        }
    }

    foreach ($package in @(Get-LibrarianCurrentUserPackages)) {
        Remove-AppxPackage `
            -Package $package.PackageFullName `
            -ErrorAction Continue
    }

    foreach ($registryPath in @(
        $ChromeRegistryPath,
        $EdgeRegistryPath,
        $ProductRegistryPath
    )) {
        if (Test-Path -LiteralPath $registryPath) {
            Remove-Item -LiteralPath $registryPath -Recurse -Force
        }
    }
    if (Test-Path -LiteralPath $InstallFolder) {
        $installDirectory = Get-Item -LiteralPath $InstallFolder -Force
        if (($installDirectory.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to clean a redirected installer test directory."
        }
        Remove-Item -LiteralPath $InstallFolder -Recurse -Force
    }
}

function Assert-Sentinel {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Expected
    )

    Assert-True (
        (Test-Path -LiteralPath $Path -PathType Leaf) -and
        (Get-Content -LiteralPath $Path -Raw) -eq $Expected
    ) "The disposable user-data sentinel was not preserved."
}

$runnerMode = Get-DisposableWindows11RunnerMode `
    -ConfirmSelfHosted:$ConfirmDisposableWindows11Runner
$isDisposableGitHubRunner = $null -ne $runnerMode
$isDisposableLocalVm = $false
if ($ConfirmDisposableVm) {
    $computerSystem = Get-CimInstance Win32_ComputerSystem
    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $isDisposableLocalVm = (
        ($computerSystem.Manufacturer -match "VMware" -or
            $computerSystem.Model -match "VMware") -and
        $operatingSystem.Caption -match "Windows 11 Enterprise Evaluation" -and
        $env:USERNAME -eq "librarian-test"
    )
}
if (-not $isDisposableGitHubRunner -and -not $isDisposableLocalVm) {
    throw (
        "The installer lifecycle suite is destructive and may run only on " +
        "a disposable Windows 11 GitHub Actions runner or an explicitly confirmed " +
        "Windows 11 Enterprise Evaluation VMware guest using the " +
        "'librarian-test' account."
    )
}
if ($isDisposableLocalVm) {
    Write-Host "Runner mode: disposable local VMware guest"
} else {
    Write-Host "Runner mode: $runnerMode"
}
Assert-True (
    [Environment]::Is64BitProcess
) "The installer lifecycle suite requires 64-bit PowerShell."
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
Assert-True (
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
) "The installer lifecycle suite requires an administrator runner."
$lowParts = @($LowVersion.Split(".") | ForEach-Object { [uint32]$_ })
$highParts = @($HighVersion.Split(".") | ForEach-Object { [uint32]$_ })
Assert-True (
    $lowParts[3] -eq 0 -and $highParts[3] -eq 0
) "Installer lifecycle fixtures must keep the ignored revision field at zero."
$lowMsiVersion = [version]"$($lowParts[0]).$($lowParts[1]).$($lowParts[2])"
$highMsiVersion = [version]"$($highParts[0]).$($highParts[1]).$($highParts[2])"
Assert-True (
    $highMsiVersion -gt $lowMsiVersion
) "The high fixture must change one of the three MSI version fields."

$resolvedUnsignedSetup = (Resolve-Path -LiteralPath $UnsignedSetupPath).Path
$resolvedWrongSignerSetup = (
    Resolve-Path -LiteralPath $WrongSignerSetupPath
).Path
$resolvedMixedPayloadSetup = (
    Resolve-Path -LiteralPath $MixedPayloadSetupPath
).Path
$resolvedSignedLowMsi = (Resolve-Path -LiteralPath $SignedLowMsiPath).Path
$resolvedSignedLowSetup = (Resolve-Path -LiteralPath $SignedLowSetupPath).Path
$resolvedSignedHighMsi = (Resolve-Path -LiteralPath $SignedHighMsiPath).Path
$resolvedSignedHighSetup = (Resolve-Path -LiteralPath $SignedHighSetupPath).Path
$resolvedLogDirectory = [IO.Path]::GetFullPath($LogDirectory)
New-Item -ItemType Directory -Path $resolvedLogDirectory -Force | Out-Null

$installFolder = Join-Path $env:ProgramFiles "Librarian"
$productRegistryPath = "HKLM:\SOFTWARE\TheUndeadMonk\Librarian"
$chromeRegistryPath = (
    "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\" +
    "com.theundeadmonk.librarian"
)
$edgeRegistryPath = (
    "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\" +
    "com.theundeadmonk.librarian"
)
$sentinelDirectory = Join-Path $env:LOCALAPPDATA "Librarian\installer-lifecycle"
$sentinelPath = Join-Path $sentinelDirectory "issue-19-ci-sentinel.txt"
$sentinelValue = "disposable-issue-19-user-data"
$msiexec = "$env:SystemRoot\System32\msiexec.exe"
$failure = $null

try {
    Assert-ProductAbsent `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-True (
        -not (Test-Path -LiteralPath $sentinelPath)
    ) "The disposable user-data sentinel already exists."
    Invoke-FailingProcess `
        -Label "Reject unsigned setup" `
        -FilePath $resolvedUnsignedSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "01-unsigned-rejected.log")
        )
    Assert-ProductAbsent `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath

    Invoke-FailingProcess `
        -Label "Reject validly signed wrong-signer payload" `
        -FilePath $resolvedWrongSignerSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "01b-wrong-signer-rejected.log")
        )
    Assert-ProductAbsent `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath

    Invoke-FailingProcess `
        -Label "Reject mixed-release payload" `
        -FilePath $resolvedMixedPayloadSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "01c-mixed-payload-rejected.log")
        )
    Assert-ProductAbsent `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath

    New-Item -ItemType Directory -Path $installFolder -Force | Out-Null
    $forbiddenProvider = Join-Path $installFolder "Librarian.PasskeyProvider.exe"
    [IO.File]::WriteAllText(
        $forbiddenProvider,
        "disposable issue 19 rejection marker",
        (New-Object Text.UTF8Encoding($false))
    )
    Invoke-FailingProcess `
        -Label "Reject unexpected passkey provider" `
        -FilePath $resolvedSignedLowSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "02-provider-rejected.log")
        )
    Assert-True (
        (Test-Path -LiteralPath $forbiddenProvider -PathType Leaf)
    ) "Rollback removed the pre-existing rejection marker."
    Remove-Item -LiteralPath $forbiddenProvider -Force
    if (@(Get-ChildItem -LiteralPath $installFolder -Force).Count -eq 0) {
        Remove-Item -LiteralPath $installFolder -Force
    }
    Assert-ProductAbsent `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath

    Invoke-SuccessfulProcess `
        -Label "Clean install low fixture" `
        -FilePath $resolvedSignedLowSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "03-clean-install-low.log")
        )
    Assert-Installed `
        -ExpectedVersion $LowVersion `
        -BrowsersExpected $false `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath `
        -ExpectedCurrentUserIdentityVersion ""
    $identityLauncher = Join-Path (
        $installFolder
    ) "Librarian.IdentityLauncher.exe"
    Invoke-CurrentUserIdentityLauncher `
        -LauncherPath $identityLauncher `
        -ExpectedVersion $LowVersion

    if (-not $SkipInteractiveDesktopLaunch) {
        if (-not [Environment]::UserInteractive) {
            throw (
                "Desktop launch validation requires an interactive Windows session. " +
                "Use -SkipInteractiveDesktopLaunch only when a separate interactive " +
                "Windows shell smoke test is required by the validation workflow."
            )
        }

        $launcherProcess = Start-Process `
            -FilePath $identityLauncher `
            -WorkingDirectory $installFolder `
            -PassThru
        $launchedDesktopProcesses = @()
        try {
            Start-Sleep -Seconds 3
            $launcherProcess.Refresh()
            Assert-True (
                $launcherProcess.HasExited -and
                $launcherProcess.ExitCode -eq 0
            ) "The installed identity launcher failed."
            $launchedDesktopProcesses = @(
                Get-Process `
                    -Name "Librarian.Windows" `
                    -ErrorAction SilentlyContinue
            )
            Assert-True (
                $launchedDesktopProcesses.Count -gt 0
            ) "The identity launcher did not start the desktop application."
        } finally {
            foreach ($launchedDesktop in @($launchedDesktopProcesses)) {
                Stop-Process `
                    -Id $launchedDesktop.Id `
                    -Force `
                    -ErrorAction SilentlyContinue
                Wait-Process `
                    -Id $launchedDesktop.Id `
                    -ErrorAction SilentlyContinue
            }
            if (-not $launcherProcess.HasExited) {
                Stop-Process -Id $launcherProcess.Id -Force
            }
            $launcherProcess.Dispose()
        }
    }

    New-Item -ItemType Directory -Path $sentinelDirectory -Force | Out-Null
    [IO.File]::WriteAllText(
        $sentinelPath,
        $sentinelValue,
        (New-Object Text.UTF8Encoding($false))
    )

    Invoke-SuccessfulProcess `
        -Label "Opt in Chrome and Edge features" `
        -FilePath $msiexec `
        -Arguments @(
            "/i",
            $resolvedSignedLowMsi,
            "ADDLOCAL=Core,ChromeIntegration,EdgeIntegration",
            "/qn",
            "/norestart",
            "/l*v",
            (Join-Path $resolvedLogDirectory "04-browser-opt-in.log")
        )
    Assert-Installed `
        -ExpectedVersion $LowVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath

    Remove-Item `
        -LiteralPath (Join-Path $installFolder "Librarian.VaultAgent.exe") `
        -Force
    Remove-Item `
        -LiteralPath (
            Join-Path $installFolder "com.theundeadmonk.librarian.chrome.json"
        ) `
        -Force
    Remove-Item -LiteralPath $chromeRegistryPath -Recurse -Force
    Invoke-SuccessfulProcess `
        -Label "Repair files and registrations" `
        -FilePath $msiexec `
        -Arguments @(
            "/i",
            $resolvedSignedLowMsi,
            "REINSTALL=ALL",
            "REINSTALLMODE=amus",
            "ADDLOCAL=Core,ChromeIntegration,EdgeIntegration",
            "/qn",
            "/norestart",
            "/l*v",
            (Join-Path $resolvedLogDirectory "05-repair.log")
        )
    Assert-Installed `
        -ExpectedVersion $LowVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-FailingProcess `
        -Label "Rollback interrupted same-version repair" `
        -FilePath $msiexec `
        -Arguments @(
            "/i",
            $resolvedSignedLowMsi,
            "REINSTALL=ALL",
            "REINSTALLMODE=amus",
            "ADDLOCAL=Core,ChromeIntegration,EdgeIntegration",
            "WIXFAILWHENDEFERRED=1",
            "/qn",
            "/norestart",
            "/l*v",
            (Join-Path $resolvedLogDirectory "05b-interrupted-repair.log")
        )
    Assert-Installed `
        -ExpectedVersion $LowVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-FailingProcess `
        -Label "Rollback interrupted upgrade" `
        -FilePath $msiexec `
        -Arguments @(
            "/i",
            $resolvedSignedHighMsi,
            "WIXFAILWHENDEFERRED=1",
            "/qn",
            "/norestart",
            "/l*v",
            (Join-Path $resolvedLogDirectory "06-interrupted-upgrade.log")
        )
    Assert-Installed `
        -ExpectedVersion $LowVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-SuccessfulProcess `
        -Label "Upgrade to high fixture" `
        -FilePath $resolvedSignedHighSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "07-upgrade-high.log")
        )
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath `
        -ExpectedCurrentUserIdentityVersion $LowVersion
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-CurrentUserNativeHostLauncher `
        -LauncherPath $identityLauncher `
        -Origin "chrome-extension://abcdefghijklmnopabcdefghijklmnop/" `
        -ExpectedVersion $HighVersion
    Invoke-SuccessfulProcess `
        -Label "Repair with current-user identity" `
        -FilePath $msiexec `
        -Arguments @(
            "/i",
            $resolvedSignedHighMsi,
            "REINSTALL=ALL",
            "REINSTALLMODE=amus",
            "ADDLOCAL=Core,ChromeIntegration,EdgeIntegration",
            "/qn",
            "/norestart",
            "/l*v",
            (Join-Path $resolvedLogDirectory "07a-current-user-repair.log")
        )
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-FailingProcess `
        -Label "Reject downgrade to low fixture" `
        -FilePath $resolvedSignedLowSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "08-downgrade-rejected.log")
        )
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-FailingProcess `
        -Label "Rollback interrupted uninstall" `
        -FilePath $msiexec `
        -Arguments @(
            "/x",
            $resolvedSignedHighMsi,
            "WIXFAILWHENDEFERRED=1",
            "/qn",
            "/norestart",
            "/l*v",
            (Join-Path $resolvedLogDirectory "09-interrupted-uninstall.log")
        )
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-SuccessfulProcess `
        -Label "Uninstall upgraded fixture" `
        -FilePath $resolvedSignedHighSetup `
        -Arguments @(
            "/uninstall",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "11-uninstall-high.log")
        )
    Assert-ProductAbsent `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-SuccessfulProcess `
        -Label "Reinstall high fixture" `
        -FilePath $resolvedSignedHighSetup `
        -Arguments @(
            "/install",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "12-reinstall-high.log")
        )
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $false `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath `
        -ExpectedCurrentUserIdentityVersion ""
    $identityLauncher = Join-Path (
        $installFolder
    ) "Librarian.IdentityLauncher.exe"
    Invoke-CurrentUserIdentityLauncher `
        -LauncherPath $identityLauncher `
        -ExpectedVersion $HighVersion
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $false `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-SuccessfulProcess `
        -Label "Final uninstall" `
        -FilePath $resolvedSignedHighSetup `
        -Arguments @(
            "/uninstall",
            "/quiet",
            "/norestart",
            "/log",
            (Join-Path $resolvedLogDirectory "13-final-uninstall.log")
        )
    Assert-ProductAbsent `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue
} catch {
    $failure = $_
    Write-Host ""
    Write-Host "Installer lifecycle failure: $($_.Exception.Message)"
    $diagnosticLogs = @(
        Get-ChildItem `
            -LiteralPath $resolvedLogDirectory `
            -Filter "*.log" `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne "lifecycle-console.log" }
    )
    foreach ($log in $diagnosticLogs) {
        if ($log.Name -match "LibrarianPackage\.log$") {
            Write-MsiFailureContext -Log $log
        }
        Write-Host ""
        Write-Host "--- Tail: $($log.Name) ---"
        Get-Content -LiteralPath $log.FullName -Tail 80 -ErrorAction Continue
        if ($log.Name -match "repair|upgrade|rollback|uninstall") {
            Write-Host ""
            Write-Host "--- Rollback actions: $($log.Name) ---"
            Select-String `
                -LiteralPath $log.FullName `
                -Pattern (
                    "Librarian setup:|" +
                    "Action (start|ended).*" +
                    "(ValidateIdentityPayload|" +
                    "UnregisterCurrentUserIdentity|" +
                    "WixFailWhenDeferred)"
                ) `
                -ErrorAction Continue |
                ForEach-Object { Write-Host $_.Line }
        }
    }
} finally {
    try {
        Remove-ProductState `
            -SetupPaths @(
                $resolvedSignedHighSetup,
                $resolvedSignedLowSetup
            ) `
            -MsiPaths @(
                $resolvedSignedHighMsi,
                $resolvedSignedLowMsi
            ) `
            -InstallFolder $installFolder `
            -ChromeRegistryPath $chromeRegistryPath `
            -EdgeRegistryPath $edgeRegistryPath `
            -ProductRegistryPath $productRegistryPath `
            -LogDirectory $resolvedLogDirectory
    } catch {
        if ($null -eq $failure) {
            $failure = $_
        } else {
            Write-Warning "Lifecycle cleanup also failed: $($_.Exception.Message)"
        }
    }
    if (Test-Path -LiteralPath $sentinelPath) {
        Remove-Item -LiteralPath $sentinelPath -Force
    }
    if (Test-Path -LiteralPath $sentinelDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $sentinelDirectory -Force).Count -eq 0) {
            Remove-Item -LiteralPath $sentinelDirectory -Force
        }
    }
}

if ($null -ne $failure) {
    throw $failure
}

Write-Host ""
Write-Host "Installer lifecycle validation passed."
Write-Host "Unsigned, wrong-signer, mixed, and unexpected-provider installs: rejected"
Write-Host "Clean install: passed"
if ($SkipInteractiveDesktopLaunch) {
    Write-Host "Interactive desktop launch: delegated to test-windows-shell-ui.ps1"
}
else {
    Write-Host "Interactive desktop launch: passed"
}
Write-Host "Browser opt-in and repair: passed"
Write-Host "Interrupted repair and upgrade rollback: passed"
Write-Host "Interactive current-user identity convergence: passed"
Write-Host "Downgrade rejection: passed"
Write-Host "Upgrade, uninstall, reinstall, and data retention: passed"
