[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UnsignedSetupPath,

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

    [switch]$SkipInteractiveDesktopLaunch
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

function Invoke-DisposableUserPowerShell {
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$Script
    )

    # CreateProcessWithLogonW limits its command line to 1,024 characters.
    # Keep the generated probe out of ArgumentList and remove it after use.
    $probeBase = Join-Path `
        ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData
        )) `
        ("LibrarianInstallerLifecycleProbe-{0}" -f [Guid]::NewGuid().ToString("N"))
    $probePath = "$probeBase.ps1"
    $standardOutputPath = "$probeBase.stdout.log"
    $standardErrorPath = "$probeBase.stderr.log"
    try {
        [IO.File]::WriteAllText(
            $probePath,
            $Script,
            (New-Object Text.UTF8Encoding($false))
        )
        $process = Start-Process `
            -FilePath (
                "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            ) `
            -ArgumentList @(
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                $probePath
            ) `
            -Credential $Credential `
            -LoadUserProfile `
            -UseNewEnvironment `
            -WorkingDirectory $env:SystemRoot `
            -WindowStyle Hidden `
            -RedirectStandardOutput $standardOutputPath `
            -RedirectStandardError $standardErrorPath `
            -Wait `
            -PassThru
        try {
            $standardOutput = [string](
                @(
                    Get-Content `
                        -LiteralPath $standardOutputPath `
                        -Raw `
                        -ErrorAction SilentlyContinue
                ) -join [Environment]::NewLine
            )
            $standardError = [string](
                @(
                    Get-Content `
                        -LiteralPath $standardErrorPath `
                        -Raw `
                        -ErrorAction SilentlyContinue
                ) -join [Environment]::NewLine
            )
            $diagnostic = @(
                $standardError.Trim(),
                $standardOutput.Trim()
            ) | Where-Object { $_ }
            $diagnostic = [string](
                $diagnostic -join [Environment]::NewLine
            )
            if ($diagnostic.Length -gt 2048) {
                $diagnostic = $diagnostic.Substring(0, 2048) + "..."
            }
            return [pscustomobject]@{
                ExitCode = $process.ExitCode
                Diagnostic = $diagnostic
            }
        } finally {
            $process.Dispose()
        }
    } finally {
        Remove-Item `
            -LiteralPath @(
                $probePath,
                $standardOutputPath,
                $standardErrorPath
            ) `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

function Invoke-DisposableUserIdentityProbe {
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
        [string]$ExpectedVersion
    )

    $probe = @"
`$ErrorActionPreference = "Stop"
`$deadline = [DateTime]::UtcNow.AddSeconds(20)
do {
    `$versions = @(
        Get-AppxPackage -Name "TheUndeadMonk.Librarian.Development" |
            ForEach-Object { `$_.Version.ToString() } |
            Sort-Object -Unique
    )
    if (`$versions.Count -eq 1 -and `$versions[0] -eq "$ExpectedVersion") {
        exit 0
    }
    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt `$deadline)
exit 1
"@
    $result = Invoke-DisposableUserPowerShell `
        -Credential $Credential `
        -Script $probe
    Assert-True (
        $result.ExitCode -eq 0
    ) (
        "The disposable secondary user did not receive Librarian identity " +
        "version '$ExpectedVersion'. Probe error: " +
        $result.Diagnostic
    )
}

function Register-DisposableUserIdentity {
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$PackagePath,

        [Parameter(Mandatory)]
        [string]$ExternalLocation,

        [Parameter(Mandatory)]
        [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
        [string]$ExpectedVersion
    )

    $stagedPackagePath = Join-Path `
        ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData
        )) `
        ("LibrarianInstallerLifecycle-{0}.msix" -f [Guid]::NewGuid().ToString("N"))
    try {
        Copy-Item `
            -LiteralPath $PackagePath `
            -Destination $stagedPackagePath `
            -Force
        $escapedPackagePath = $stagedPackagePath.Replace("'", "''")
        $escapedExternalLocation = $ExternalLocation.Replace("'", "''")
        $probe = @"
`$ErrorActionPreference = "Stop"
Add-AppxPackage -Path '$escapedPackagePath' -ExternalLocation '$escapedExternalLocation' -ForceUpdateFromAnyVersion
`$versions = @(
    Get-AppxPackage -Name "TheUndeadMonk.Librarian.Development" |
        ForEach-Object { `$_.Version.ToString() } |
        Sort-Object -Unique
)
if (`$versions.Count -ne 1 -or `$versions[0] -ne "$ExpectedVersion") {
    exit 1
}
exit 0
"@
        $result = Invoke-DisposableUserPowerShell `
            -Credential $Credential `
            -Script $probe
        Assert-True (
            $result.ExitCode -eq 0
        ) (
            "The disposable secondary user could not register Librarian " +
            "identity version '$ExpectedVersion'. Probe error: " +
            $result.Diagnostic
        )
    } finally {
        Remove-Item `
            -LiteralPath $stagedPackagePath `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

function Register-CurrentUserIdentity {
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,

        [Parameter(Mandatory)]
        [string]$ExternalLocation,

        [Parameter(Mandatory)]
        [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
        [string]$ExpectedVersion
    )

    Add-AppxPackage `
        -Path $PackagePath `
        -ExternalLocation $ExternalLocation `
        -ForceUpdateFromAnyVersion
    $versions = @(
        Get-LibrarianCurrentUserPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $versions.Count -eq 1 -and $versions[0] -eq $ExpectedVersion
    ) (
        "The invoking user could not register Librarian identity version " +
        "'$ExpectedVersion'."
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
        if ($Expected) {
            $actualRegistryValue = Get-RegistryDefaultValue `
                -Path $browser.RegistryPath
            Assert-True (
                $actualRegistryValue -eq $manifestPath
            ) (
                "$($browser.Name) native-messaging registration is incorrect. " +
                "Expected '$manifestPath'; found '$actualRegistryValue'."
            )
            Assert-True (
                (Test-Path -LiteralPath $manifestPath -PathType Leaf)
            ) "$($browser.Name) native-messaging manifest is missing."
            $manifest = Get-Content -LiteralPath $manifestPath -Raw |
                ConvertFrom-Json
            Assert-True (
                $manifest.name -eq "com.theundeadmonk.librarian" -and
                $manifest.path -eq "Librarian.ChromiumNativeHost.exe" -and
                @($manifest.allowed_origins).Count -eq 1 -and
                @($manifest.allowed_origins)[0] -eq $browser.Origin
            ) "$($browser.Name) native-messaging manifest is unsafe."
        } else {
            Assert-True (
                -not (Test-Path -LiteralPath $browser.RegistryPath)
            ) "$($browser.Name) integration was registered without opt-in."
            Assert-True (
                -not (Test-Path -LiteralPath $manifestPath)
            ) "$($browser.Name) manifest was installed without opt-in."
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
        [string]$ProductRegistryPath
    )

    foreach ($name in @(
        "Librarian.Windows.exe",
        "Librarian.VaultAgent.exe",
        "Librarian.ChromiumNativeHost.exe",
        "Librarian.Identity.msix",
        "Librarian.Release.json"
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

    $packageVersions = @(
        Get-LibrarianPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $packageVersions.Count -eq 1 -and
        $packageVersions[0] -eq $ExpectedVersion
    ) (
        "The staged identity package is missing, stale, or duplicated. Found: " +
        "$($packageVersions -join ', ')."
    )
    $currentUserVersions = @(
        Get-LibrarianCurrentUserPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $currentUserVersions.Count -eq 1 -and
        $currentUserVersions[0] -eq $ExpectedVersion
    ) (
        "The invoking user does not have the expected package identity. Found: " +
        "$($currentUserVersions -join ', ')."
    )
    $provisionedVersions = @(
        Get-LibrarianProvisionedPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $provisionedVersions.Count -eq 1 -and
        $provisionedVersions[0] -eq $ExpectedVersion
    ) (
        "The provisioned identity package is missing, stale, or duplicated. Found: " +
        "$($provisionedVersions -join ', ')."
    )

    Assert-BrowserState `
        -Expected $BrowsersExpected `
        -InstallFolder $InstallFolder `
        -ChromeRegistryPath $ChromeRegistryPath `
        -EdgeRegistryPath $EdgeRegistryPath
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
            "$($remaining.FullName -join ', ')."
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

function Assert-InstalledWithoutIdentity {
    param(
        [Parameter(Mandatory)]
        [string]$ExpectedVersion,

        [Parameter(Mandatory)]
        [string]$InstallFolder,

        [Parameter(Mandatory)]
        [string]$ChromeRegistryPath,

        [Parameter(Mandatory)]
        [string]$EdgeRegistryPath,

        [Parameter(Mandatory)]
        [string]$ProductRegistryPath
    )

    foreach ($name in @(
        "Librarian.Windows.exe",
        "Librarian.VaultAgent.exe",
        "Librarian.ChromiumNativeHost.exe",
        "Librarian.Identity.msix",
        "Librarian.Release.json"
    )) {
        Assert-True (
            Test-Path -LiteralPath (Join-Path $InstallFolder $name) -PathType Leaf
        ) "Uninstall rollback did not restore installer-owned file '$name'."
    }
    Assert-True (
        (Get-ItemProperty -LiteralPath $ProductRegistryPath).Version -eq
            $ExpectedVersion
    ) "Uninstall rollback did not restore the product registration."
    Assert-True (
        @(Get-VisibleArpEntries).Count -eq 1
    ) "Uninstall rollback did not restore the Programs and Features entry."
    Assert-BrowserState `
        -Expected $true `
        -InstallFolder $InstallFolder `
        -ChromeRegistryPath $ChromeRegistryPath `
        -EdgeRegistryPath $EdgeRegistryPath
    Assert-True (
        @(Get-LibrarianPackages).Count -eq 0 -and
        @(Get-LibrarianCurrentUserPackages).Count -eq 0 -and
        @(Get-LibrarianProvisionedPackages).Count -eq 0
    ) "Uninstall rollback created identity state that was absent beforehand."
}

function Remove-LibrarianIdentityState {
    foreach ($package in Get-LibrarianProvisionedPackages) {
        $null = Remove-AppxProvisionedPackage `
            -Online `
            -AllUsers `
            -PackageName $package.PackageName
    }
    foreach ($package in Get-LibrarianPackages) {
        Remove-AppxPackage `
            -AllUsers `
            -Package $package.PackageFullName
    }
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

    foreach ($provisioned in @(Get-LibrarianProvisionedPackages)) {
        Remove-AppxProvisionedPackage `
            -Online `
            -AllUsers `
            -PackageName $provisioned.PackageName `
            -ErrorAction Continue |
            Out-Null
    }
    foreach ($package in @(Get-LibrarianPackages)) {
        Remove-AppxPackage `
            -AllUsers `
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

if ($env:GITHUB_ACTIONS -ne "true" -or
    $env:CI -ne "true" -or
    $env:RUNNER_ENVIRONMENT -ne "github-hosted" -or
    $env:RUNNER_OS -ne "Windows" -or
    $env:RUNNER_ARCH -ne "X64" -or
    $env:GITHUB_REPOSITORY -ne "theundeadmonk/Librarian") {
    throw (
        "The installer lifecycle suite is destructive and may run only on a " +
        "disposable GitHub Actions runner."
    )
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
$resolvedSignedLowMsi = (Resolve-Path -LiteralPath $SignedLowMsiPath).Path
$resolvedSignedLowSetup = (Resolve-Path -LiteralPath $SignedLowSetupPath).Path
$resolvedSignedLowIdentity = (
    Resolve-Path -LiteralPath (
        Join-Path (
            Split-Path $resolvedSignedLowMsi -Parent
        ) "Librarian.Identity.msix"
    )
).Path
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
$disposableUserName = "LibrarianCiUser"
$disposableUser = $null
$disposableUserCredential = $null
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
    Assert-True (
        $null -eq (
            Get-LocalUser -Name $disposableUserName -ErrorAction SilentlyContinue
        )
    ) "The disposable secondary installer-test user already exists."
    $disposablePassword = ConvertTo-SecureString `
        -String ("L1brarian-CI-only!" + [Guid]::NewGuid().ToString("N")) `
        -AsPlainText `
        -Force
    $disposableUser = New-LocalUser `
        -Name $disposableUserName `
        -Password $disposablePassword `
        -AccountNeverExpires `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -Description "Disposable Librarian installer test user"
    $disposableUserCredential = [PSCredential]::new(
        "$env:COMPUTERNAME\$disposableUserName",
        $disposablePassword
    )

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
        -ProductRegistryPath $productRegistryPath
    Register-DisposableUserIdentity `
        -Credential $disposableUserCredential `
        -PackagePath $resolvedSignedLowIdentity `
        -ExternalLocation $installFolder `
        -ExpectedVersion $LowVersion

    if (-not $SkipInteractiveDesktopLaunch) {
        if (-not [Environment]::UserInteractive) {
            throw (
                "Desktop launch validation requires an interactive Windows session. " +
                "Use -SkipInteractiveDesktopLaunch only when a separate interactive " +
                "Windows shell smoke test is required by the validation workflow."
            )
        }

        $desktopProcess = Start-Process `
            -FilePath (Join-Path $installFolder "Librarian.Windows.exe") `
            -WorkingDirectory $installFolder `
            -PassThru
        try {
            Start-Sleep -Seconds 3
            $desktopProcess.Refresh()
            if ($desktopProcess.HasExited) {
                $desktopExitCode = $desktopProcess.ExitCode
                $desktopExitCodeHex = "0x{0:X8}" -f (
                    [int64]$desktopExitCode -band 0xFFFFFFFFL
                )
                Assert-True (
                    $desktopExitCode -eq 0
                ) (
                    "The installed desktop executable exited with code " +
                    "$desktopExitCode ($desktopExitCodeHex)."
                )
            }
        } finally {
            if (-not $desktopProcess.HasExited) {
                Stop-Process -Id $desktopProcess.Id -Force
                Wait-Process -Id $desktopProcess.Id -ErrorAction SilentlyContinue
            }
            $desktopProcess.Dispose()
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
        -ProductRegistryPath $productRegistryPath
    Invoke-DisposableUserIdentityProbe `
        -Credential $disposableUserCredential `
        -ExpectedVersion $HighVersion
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Register-CurrentUserIdentity `
        -PackagePath $resolvedSignedLowIdentity `
        -ExternalLocation $installFolder `
        -ExpectedVersion $LowVersion
    $highProvisioning = @(Get-LibrarianProvisionedPackages)
    Assert-True (
        $highProvisioning.Count -eq 1 -and
        $highProvisioning[0].Version.ToString() -eq $HighVersion
    ) "The retained-user fixture did not begin with high provisioning."
    $null = Remove-AppxProvisionedPackage `
        -Online `
        -AllUsers `
        -PackageName $highProvisioning[0].PackageName
    Assert-True (
        @(Get-LibrarianProvisionedPackages).Count -eq 0
    ) "The retained-user fixture could not remove package provisioning."
    Invoke-DisposableUserIdentityProbe `
        -Credential $disposableUserCredential `
        -ExpectedVersion $HighVersion
    Invoke-FailingProcess `
        -Label "Reject repair over another user's incoming identity" `
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
            (Join-Path $resolvedLogDirectory "07a-other-user-state-rejected.log")
        )
    $currentUserAfterOtherUserRejection = @(
        Get-LibrarianCurrentUserPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $currentUserAfterOtherUserRejection.Count -eq 1 -and
        $currentUserAfterOtherUserRejection[0] -eq $LowVersion -and
        @(Get-LibrarianProvisionedPackages).Count -eq 0
    ) "The rejected retained-user repair changed identity state."
    Invoke-DisposableUserIdentityProbe `
        -Credential $disposableUserCredential `
        -ExpectedVersion $HighVersion
    Register-CurrentUserIdentity `
        -PackagePath (Join-Path $installFolder "Librarian.Identity.msix") `
        -ExternalLocation $installFolder `
        -ExpectedVersion $HighVersion
    Invoke-SuccessfulProcess `
        -Label "Restore provisioning after retained-user rejection" `
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
            (Join-Path $resolvedLogDirectory "07b-restored-provisioning.log")
        )
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Invoke-DisposableUserIdentityProbe `
        -Credential $disposableUserCredential `
        -ExpectedVersion $HighVersion

    Register-DisposableUserIdentity `
        -Credential $disposableUserCredential `
        -PackagePath $resolvedSignedLowIdentity `
        -ExternalLocation $installFolder `
        -ExpectedVersion $LowVersion
    $coexistingVersions = @(
        Get-LibrarianPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $coexistingVersions.Count -eq 2 -and
        $coexistingVersions -contains $LowVersion -and
        $coexistingVersions -contains $HighVersion
    ) "The secondary-user fixture did not create two package versions."
    Register-CurrentUserIdentity `
        -PackagePath $resolvedSignedLowIdentity `
        -ExternalLocation $installFolder `
        -ExpectedVersion $LowVersion
    $provisionedBeforeRejectedRepair = @(
        Get-LibrarianProvisionedPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $provisionedBeforeRejectedRepair.Count -eq 1 -and
        $provisionedBeforeRejectedRepair[0] -eq $HighVersion
    ) "The divergent-state fixture did not preserve high provisioning."
    Invoke-FailingProcess `
        -Label "Reject repair from divergent identity state" `
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
            (Join-Path $resolvedLogDirectory "07a-divergent-state-rejected.log")
        )
    $currentUserAfterRejectedRepair = @(
        Get-LibrarianCurrentUserPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    $provisionedAfterRejectedRepair = @(
        Get-LibrarianProvisionedPackages |
            ForEach-Object { $_.Version.ToString() } |
            Sort-Object -Unique
    )
    Assert-True (
        $currentUserAfterRejectedRepair.Count -eq 1 -and
        $currentUserAfterRejectedRepair[0] -eq $LowVersion -and
        $provisionedAfterRejectedRepair.Count -eq 1 -and
        $provisionedAfterRejectedRepair[0] -eq $HighVersion
    ) "The rejected divergent-state repair changed identity state."
    Register-CurrentUserIdentity `
        -PackagePath (Join-Path $installFolder "Librarian.Identity.msix") `
        -ExternalLocation $installFolder `
        -ExpectedVersion $HighVersion
    Invoke-SuccessfulProcess `
        -Label "Repair with a retained secondary-user identity" `
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
            (Join-Path $resolvedLogDirectory "07b-secondary-user-repair.log")
        )
    Assert-Installed `
        -ExpectedVersion $HighVersion `
        -BrowsersExpected $true `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Invoke-DisposableUserIdentityProbe `
        -Credential $disposableUserCredential `
        -ExpectedVersion $HighVersion
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

    Remove-LibrarianIdentityState
    Assert-InstalledWithoutIdentity `
        -ExpectedVersion $HighVersion `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Invoke-FailingProcess `
        -Label "Preserve absent identity through uninstall rollback" `
        -FilePath $msiexec `
        -Arguments @(
            "/x",
            $resolvedSignedHighMsi,
            "WIXFAILWHENDEFERRED=1",
            "/qn",
            "/norestart",
            "/l*v",
            (Join-Path $resolvedLogDirectory "09-absent-identity-rollback.log")
        )
    Assert-InstalledWithoutIdentity `
        -ExpectedVersion $HighVersion `
        -InstallFolder $installFolder `
        -ChromeRegistryPath $chromeRegistryPath `
        -EdgeRegistryPath $edgeRegistryPath `
        -ProductRegistryPath $productRegistryPath
    Assert-Sentinel -Path $sentinelPath -Expected $sentinelValue

    Invoke-SuccessfulProcess `
        -Label "Repair identity after external package-state damage" `
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
            (Join-Path $resolvedLogDirectory "10-repair-identity.log")
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
    foreach ($log in Get-ChildItem `
        -LiteralPath $resolvedLogDirectory `
        -Filter "*.log" `
        -ErrorAction SilentlyContinue) {
        Write-Host ""
        Write-Host "--- Tail: $($log.Name) ---"
        Get-Content -LiteralPath $log.FullName -Tail 80 -ErrorAction Continue
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
    if ($null -ne $disposableUser) {
        $userProfile = Get-CimInstance `
            -ClassName Win32_UserProfile `
            -Filter "SID = '$($disposableUser.SID.Value)'" `
            -ErrorAction SilentlyContinue
        if ($null -ne $userProfile -and -not $userProfile.Loaded) {
            Remove-CimInstance -InputObject $userProfile -ErrorAction Continue
        }
        Remove-LocalUser `
            -Name $disposableUserName `
            -ErrorAction Continue
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
Write-Host "Unsigned and unexpected-provider installs: rejected"
Write-Host "Clean install: passed"
if ($SkipInteractiveDesktopLaunch) {
    Write-Host "Interactive desktop launch: delegated to test-windows-shell-ui.ps1"
}
else {
    Write-Host "Interactive desktop launch: passed"
}
Write-Host "Browser opt-in and repair: passed"
Write-Host "Interrupted repair and upgrade rollback: passed"
Write-Host "Secondary-user identity upgrade retirement: passed"
Write-Host "Downgrade rejection: passed"
Write-Host "Upgrade, uninstall, reinstall, and data retention: passed"
