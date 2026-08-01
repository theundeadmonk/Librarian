[CmdletBinding()]
param(
    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$LowVersion,

    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$HighVersion,

    [switch]$ConfirmDisposableWindows11Runner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Get-HigherFixtureVersion {
    param(
        [Parameter(Mandatory)]
        [string]$Version
    )

    $parts = @($Version.Split(".") | ForEach-Object { [uint32]$_ })
    if ($parts[2] -lt 65535) {
        $parts[2]++
    } elseif ($parts[1] -lt 255) {
        $parts[1]++
        $parts[2] = 0
    } elseif ($parts[0] -lt 255) {
        $parts[0]++
        $parts[1] = 0
        $parts[2] = 0
    } else {
        throw "The workspace version cannot produce a higher MSI fixture."
    }
    $parts[3] = 0
    return $parts -join "."
}

function Reset-GeneratedDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$ExpectedParent,

        [Parameter(Mandatory)]
        [string]$ExpectedLeaf
    )

    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd("\")
    $resolvedParent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd("\")
    Assert-True (
        (Split-Path $resolvedPath -Parent) -eq $resolvedParent -and
        (Split-Path $resolvedPath -Leaf) -eq $ExpectedLeaf
    ) "Refusing to reset unexpected generated directory '$resolvedPath'."
    if (Test-Path -LiteralPath $resolvedPath) {
        Remove-Item -LiteralPath $resolvedPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $resolvedPath | Out-Null
    return $resolvedPath
}

function Copy-InstallerFixture {
    param(
        [Parameter(Mandatory)]
        [string]$SourceRoot,

        [Parameter(Mandatory)]
        [string]$DestinationRoot
    )

    New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null
    $sourceMsi = Join-Path $SourceRoot "msi\Librarian.Package.msi"
    $sourceSetup = Join-Path $SourceRoot "bundle\LibrarianSetup.exe"
    $sourceIdentity = Join-Path $SourceRoot "payload\Librarian.Identity.msix"
    foreach ($source in @($sourceMsi, $sourceSetup, $sourceIdentity)) {
        Assert-True (
            (Test-Path -LiteralPath $source -PathType Leaf)
        ) "Installer fixture input is missing at '$source'."
    }
    Copy-Item `
        -LiteralPath $sourceMsi `
        -Destination (Join-Path $DestinationRoot "Librarian.Package.msi")
    Copy-Item `
        -LiteralPath $sourceSetup `
        -Destination (Join-Path $DestinationRoot "LibrarianSetup.exe")
    Copy-Item `
        -LiteralPath $sourceIdentity `
        -Destination (Join-Path $DestinationRoot "Librarian.Identity.msix")
}

function Assert-CertificateSubjectAbsent {
    param(
        [Parameter(Mandatory)]
        [string]$Subject
    )

    foreach ($store in @(
        "Cert:\CurrentUser\My",
        "Cert:\LocalMachine\TrustedPeople",
        "Cert:\LocalMachine\Root"
    )) {
        $matches = @(
            Get-ChildItem -LiteralPath $store |
                Where-Object { $_.Subject -eq $Subject }
        )
        Assert-True (
            $matches.Count -eq 0
        ) "The disposable runner already contains '$Subject' in '$store'."
    }
}

function New-TrustedDisposableCodeSigningCertificate {
    param(
        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [string]$FriendlyName,

        [Parameter(Mandatory)]
        [string]$CertificatePath
    )

    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -FriendlyName $FriendlyName `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotBefore (Get-Date).AddMinutes(-5) `
        -NotAfter (Get-Date).AddHours(8)
    if ($null -ne $certificate) {
        $script:createdCertificates += $certificate
    }
    Assert-True (
        $null -ne $certificate -and
        $certificate.Subject -eq $Subject -and
        $certificate.HasPrivateKey
    ) "The disposable code-signing certificate was not created correctly."
    Export-Certificate `
        -Cert $certificate `
        -FilePath $CertificatePath `
        -Type CERT |
        Out-Null
    $trustedCertificate = Import-Certificate `
        -FilePath $CertificatePath `
        -CertStoreLocation "Cert:\LocalMachine\TrustedPeople"
    Assert-True (
        $trustedCertificate.Thumbprint -eq $certificate.Thumbprint
    ) "The disposable certificate was not trusted correctly."
    $rootCertificate = Import-Certificate `
        -FilePath $CertificatePath `
        -CertStoreLocation "Cert:\LocalMachine\Root"
    Assert-True (
        $rootCertificate.Thumbprint -eq $certificate.Thumbprint
    ) "The disposable certificate was not rooted correctly."
    return $certificate
}

$runnerMode = Get-DisposableWindows11RunnerMode `
    -ConfirmSelfHosted:$ConfirmDisposableWindows11Runner
if ($null -eq $runnerMode) {
    throw (
        "Development-certificate creation and installer execution are allowed " +
        "only on a disposable Windows 11 GitHub Actions runner. A self-hosted " +
        "runner also requires -ConfirmDisposableWindows11Runner and the " +
        "provisioner-set LIBRARIAN_DISPOSABLE_WINDOWS11_RUNNER=true marker " +
        "and a runner name beginning with 'librarian-disposable-win11-'."
    )
}
Assert-True (
    [Environment]::Is64BitProcess
) "Installer CI requires 64-bit PowerShell."
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
Assert-True (
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
) "Installer CI requires an administrator runner."

$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $LowVersion) {
    $LowVersion = Get-WorkspaceVersion (Join-Path $repoRoot "Cargo.toml")
}
if (-not $HighVersion) {
    $HighVersion = Get-HigherFixtureVersion -Version $LowVersion
}
$lowParts = @($LowVersion.Split(".") | ForEach-Object { [uint32]$_ })
$highParts = @($HighVersion.Split(".") | ForEach-Object { [uint32]$_ })
foreach ($parts in @($lowParts, $highParts)) {
    Assert-True (
        $parts[0] -le 255 -and $parts[1] -le 255 -and
        $parts[2] -le 65535 -and $parts[3] -le 65535
    ) "A lifecycle fixture version exceeds MSI or MSIX field limits."
}
$lowMsiVersion = [version]"$($lowParts[0]).$($lowParts[1]).$($lowParts[2])"
$highMsiVersion = [version]"$($highParts[0]).$($highParts[1]).$($highParts[2])"
Assert-True (
    $highMsiVersion -gt $lowMsiVersion
) "The high fixture must change one of the three MSI version fields."
$artifactsRoot = Join-Path $repoRoot "artifacts"
$installerRoot = Join-Path $artifactsRoot "installer"
$ciRoot = Reset-GeneratedDirectory `
    -Path (Join-Path $artifactsRoot "installer-ci") `
    -ExpectedParent $artifactsRoot `
    -ExpectedLeaf "installer-ci"
$fixtureRoot = Join-Path $ciRoot "fixtures"
$logRoot = Join-Path $ciRoot "logs"
New-Item -ItemType Directory -Path $fixtureRoot, $logRoot | Out-Null

$unsignedRoot = Join-Path $fixtureRoot "unsigned-$LowVersion"
$signedLowRoot = Join-Path $fixtureRoot "signed-$LowVersion"
$signedHighRoot = Join-Path $fixtureRoot "signed-$HighVersion"
$wrongSignerRoot = Join-Path $fixtureRoot "wrong-signer-$LowVersion"
$mixedPayloadRoot = Join-Path $fixtureRoot "mixed-$LowVersion-$HighVersion"
$overrideRoot = Join-Path $ciRoot "payload-overrides"
New-Item -ItemType Directory -Path $overrideRoot | Out-Null
$signedLowLauncher = Join-Path $overrideRoot "accepted-low-launcher.exe"
$signedHighLauncher = Join-Path $overrideRoot "accepted-high-launcher.exe"
$wrongSignerLauncher = Join-Path $overrideRoot "wrong-signer-low-launcher.exe"
$certificatePath = Join-Path $ciRoot "Librarian.Development.cer"
$wrongCertificatePath = Join-Path $ciRoot "Librarian.WrongSigner.cer"
$certificate = $null
$wrongCertificate = $null
$createdCertificates = @()
$failure = $null
$previousRunnerMode = $env:LIBRARIAN_INSTALLER_LIFECYCLE_RUNNER_MODE
$env:LIBRARIAN_INSTALLER_LIFECYCLE_RUNNER_MODE = $runnerMode

try {
    Write-Host "==> Preserve and revalidate unsigned build fixture"
    & (Join-Path $PSScriptRoot "test-installer.ps1") `
        -MsiPath (Join-Path $installerRoot "msi\Librarian.Package.msi") `
        -SetupPath (Join-Path $installerRoot "bundle\LibrarianSetup.exe") `
        -ExpectedSigningMode "unsigned-fixture" `
        -ExpectedProductVersion $LowVersion
    Copy-InstallerFixture `
        -SourceRoot $installerRoot `
        -DestinationRoot $unsignedRoot

    $subject = "CN=Librarian Development"
    $wrongSubject = "CN=Librarian Wrong Signer"
    Assert-CertificateSubjectAbsent -Subject $subject
    Assert-CertificateSubjectAbsent -Subject $wrongSubject

    Write-Host ""
    Write-Host "==> Create ephemeral non-exportable development certificate"
    $certificate = New-TrustedDisposableCodeSigningCertificate `
        -Subject $subject `
        -FriendlyName "Librarian issue 19 CI only" `
        -CertificatePath $certificatePath

    Write-Host ""
    Write-Host "==> Build and validate signed low fixture"
    & (Join-Path $PSScriptRoot "build-installer.ps1") `
        -Configuration Release `
        -Platform x64 `
        -ProductVersion $LowVersion `
        -DevelopmentCertificateThumbprint $certificate.Thumbprint
    & (Join-Path $PSScriptRoot "test-installer.ps1") `
        -ExpectedSigningMode development `
        -ExpectedProductVersion $LowVersion
    Copy-InstallerFixture `
        -SourceRoot $installerRoot `
        -DestinationRoot $signedLowRoot
    Copy-Item `
        -LiteralPath (
            Join-Path $installerRoot "payload\Librarian.IdentityLauncher.exe"
        ) `
        -Destination $signedLowLauncher

    Write-Host ""
    Write-Host "==> Build and validate signed high fixture"
    & (Join-Path $PSScriptRoot "build-installer.ps1") `
        -Configuration Release `
        -Platform x64 `
        -ProductVersion $HighVersion `
        -DevelopmentCertificateThumbprint $certificate.Thumbprint
    & (Join-Path $PSScriptRoot "test-installer.ps1") `
        -ExpectedSigningMode development `
        -ExpectedProductVersion $HighVersion
    Copy-InstallerFixture `
        -SourceRoot $installerRoot `
        -DestinationRoot $signedHighRoot
    Copy-Item `
        -LiteralPath (
            Join-Path $installerRoot "payload\Librarian.IdentityLauncher.exe"
        ) `
        -Destination $signedHighLauncher

    Write-Host ""
    Write-Host "==> Create validly signed wrong-signer payload"
    $wrongCertificate = New-TrustedDisposableCodeSigningCertificate `
        -Subject $wrongSubject `
        -FriendlyName "Librarian issue 19 wrong-signer fixture" `
        -CertificatePath $wrongCertificatePath
    Copy-Item `
        -LiteralPath $signedLowLauncher `
        -Destination $wrongSignerLauncher
    $wrongSignature = Set-AuthenticodeSignature `
        -FilePath $wrongSignerLauncher `
        -Certificate $wrongCertificate `
        -HashAlgorithm SHA256
    Assert-True (
        $wrongSignature.Status -eq
            [System.Management.Automation.SignatureStatus]::Valid -and
        $wrongSignature.SignerCertificate.Thumbprint -eq
            $wrongCertificate.Thumbprint
    ) "The deliberately wrong-signer launcher is not validly signed."

    Write-Host ""
    Write-Host "==> Build validly signed wrong-signer rejection fixture"
    & (Join-Path $PSScriptRoot "build-installer.ps1") `
        -Configuration Release `
        -Platform x64 `
        -ProductVersion $LowVersion `
        -DevelopmentCertificateThumbprint $certificate.Thumbprint `
        -CiOnlyPayloadOverrideRole IdentityLauncher `
        -CiOnlyPayloadOverridePath $wrongSignerLauncher
    Copy-InstallerFixture `
        -SourceRoot $installerRoot `
        -DestinationRoot $wrongSignerRoot

    Write-Host ""
    Write-Host "==> Build accepted-signer mixed-release rejection fixture"
    & (Join-Path $PSScriptRoot "build-installer.ps1") `
        -Configuration Release `
        -Platform x64 `
        -ProductVersion $LowVersion `
        -DevelopmentCertificateThumbprint $certificate.Thumbprint `
        -CiOnlyPayloadOverrideRole IdentityLauncher `
        -CiOnlyPayloadOverridePath $signedHighLauncher
    Copy-InstallerFixture `
        -SourceRoot $installerRoot `
        -DestinationRoot $mixedPayloadRoot

    Write-Host ""
    Write-Host "==> Exercise disposable signed installer lifecycle"
    & (Join-Path $PSScriptRoot "test-installer-lifecycle.ps1") `
        -UnsignedSetupPath (
            Join-Path $unsignedRoot "LibrarianSetup.exe"
        ) `
        -WrongSignerSetupPath (
            Join-Path $wrongSignerRoot "LibrarianSetup.exe"
        ) `
        -MixedPayloadSetupPath (
            Join-Path $mixedPayloadRoot "LibrarianSetup.exe"
        ) `
        -SignedLowMsiPath (
            Join-Path $signedLowRoot "Librarian.Package.msi"
        ) `
        -SignedLowSetupPath (
            Join-Path $signedLowRoot "LibrarianSetup.exe"
        ) `
        -SignedHighMsiPath (
            Join-Path $signedHighRoot "Librarian.Package.msi"
        ) `
        -SignedHighSetupPath (
            Join-Path $signedHighRoot "LibrarianSetup.exe"
        ) `
        -LowVersion $LowVersion `
        -HighVersion $HighVersion `
        -LogDirectory $logRoot `
        -SkipInteractiveDesktopLaunch `
        -ConfirmDisposableWindows11Runner:($runnerMode -eq "self-hosted-windows11")
} catch {
    $failure = $_
} finally {
    $env:LIBRARIAN_INSTALLER_LIFECYCLE_RUNNER_MODE = $previousRunnerMode
    $cleanupFailures = @()
    foreach ($createdCertificate in $createdCertificates) {
        $certificatePaths = @(
            "Cert:\LocalMachine\TrustedPeople\$($createdCertificate.Thumbprint)",
            "Cert:\LocalMachine\Root\$($createdCertificate.Thumbprint)",
            "Cert:\CurrentUser\My\$($createdCertificate.Thumbprint)"
        )
        foreach ($certificatePathToRemove in $certificatePaths) {
            try {
                if (Test-Path -LiteralPath $certificatePathToRemove) {
                    Remove-Item `
                        -LiteralPath $certificatePathToRemove `
                        -Force `
                        -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $certificatePathToRemove) {
                    throw (
                        "Certificate entry remains after removal: " +
                        $certificatePathToRemove
                    )
                }
            } catch {
                $cleanupFailures += (
                    "Failed to remove '$certificatePathToRemove': " +
                    $_.Exception.Message
                )
            }
        }
    }
    if ($cleanupFailures.Count -gt 0) {
        $cleanupMessage = (
            "Ephemeral code-signing certificate cleanup failed: " +
            ($cleanupFailures -join " ")
        )
        if ($null -eq $failure) {
            $failure = [RuntimeException]::new($cleanupMessage)
        } else {
            $failure = [RuntimeException]::new(
                "$($failure.Exception.Message) $cleanupMessage",
                $failure.Exception
            )
        }
    }
}

if ($null -ne $failure) {
    throw $failure
}

Write-Host ""
Write-Host "CI-only signed installer validation passed."
Write-Host "All ephemeral certificate-store entries were removed."
