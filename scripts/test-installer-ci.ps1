[CmdletBinding()]
param(
    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$LowVersion,

    [ValidatePattern("^\d+\.\d+\.\d+\.\d+$")]
    [string]$HighVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

if ($env:GITHUB_ACTIONS -ne "true" -or
    $env:CI -ne "true" -or
    $env:RUNNER_ENVIRONMENT -ne "github-hosted" -or
    $env:RUNNER_OS -ne "Windows" -or
    $env:RUNNER_ARCH -ne "X64" -or
    $env:GITHUB_REPOSITORY -ne "theundeadmonk/Librarian") {
    throw (
        "Development-certificate creation and installer execution are allowed " +
        "only on a disposable GitHub Actions runner."
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
$certificatePath = Join-Path $ciRoot "Librarian.Development.cer"
$certificate = $null
$trustedCertificate = $null
$failure = $null

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
    $preexistingPersonal = @(
        Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $subject }
    )
    $preexistingTrusted = @(
        Get-ChildItem Cert:\LocalMachine\TrustedPeople |
            Where-Object { $_.Subject -eq $subject }
    )
    Assert-True (
        $preexistingPersonal.Count -eq 0 -and
        $preexistingTrusted.Count -eq 0
    ) "The disposable runner already contains a Librarian development certificate."

    Write-Host ""
    Write-Host "==> Create ephemeral non-exportable development certificate"
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -FriendlyName "Librarian issue 19 CI only" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotBefore (Get-Date).AddMinutes(-5) `
        -NotAfter (Get-Date).AddHours(8)
    Assert-True (
        $null -ne $certificate -and
        $certificate.Subject -eq $subject -and
        $certificate.HasPrivateKey
    ) "The ephemeral development certificate was not created correctly."
    Export-Certificate `
        -Cert $certificate `
        -FilePath $certificatePath `
        -Type CERT |
        Out-Null
    $trustedCertificate = Import-Certificate `
        -FilePath $certificatePath `
        -CertStoreLocation "Cert:\LocalMachine\TrustedPeople"
    Assert-True (
        $trustedCertificate.Thumbprint -eq $certificate.Thumbprint
    ) "The public development certificate was not trusted correctly."

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

    Write-Host ""
    Write-Host "==> Exercise disposable signed installer lifecycle"
    & (Join-Path $PSScriptRoot "test-installer-lifecycle.ps1") `
        -UnsignedSetupPath (
            Join-Path $unsignedRoot "LibrarianSetup.exe"
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
        -LogDirectory $logRoot
} catch {
    $failure = $_
} finally {
    if ($null -ne $trustedCertificate) {
        $trustedPath = (
            "Cert:\LocalMachine\TrustedPeople\" +
            $trustedCertificate.Thumbprint
        )
        if (Test-Path -LiteralPath $trustedPath) {
            Remove-Item -LiteralPath $trustedPath -Force
        }
    }
    if ($null -ne $certificate) {
        $personalPath = "Cert:\CurrentUser\My\$($certificate.Thumbprint)"
        if (Test-Path -LiteralPath $personalPath) {
            Remove-Item -LiteralPath $personalPath -Force
        }
    }
}

if ($null -ne $failure) {
    throw $failure
}

Write-Host ""
Write-Host "CI-only signed installer validation passed."
Write-Host "The ephemeral certificate and both trust-store entries were removed."
