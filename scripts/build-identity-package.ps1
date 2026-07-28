[CmdletBinding()]
param(
    [string]$Version,

    [string]$MakeAppxPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path $PSScriptRoot -Parent
$cargoManifestPath = Join-Path $repoRoot "Cargo.toml"
$templatePath = Join-Path $repoRoot "packaging\msix\identity\AppxManifest.xml.in"
$packageRoot = Join-Path $repoRoot "artifacts\package"
$layoutName = "identity-layout-$PID-$([Guid]::NewGuid().ToString('N'))"
$layoutPath = Join-Path $packageRoot $layoutName
$renderedManifestPath = Join-Path $layoutPath "AppxManifest.xml"

if (-not $Version) {
    $cargoManifest = Get-Content -LiteralPath $cargoManifestPath -Raw
    $workspaceVersionMatch = [regex]::Match(
        $cargoManifest,
        '(?ms)^\[workspace\.package\].*?^version\s*=\s*"(?<version>\d+\.\d+\.\d+)"'
    )
    if (-not $workspaceVersionMatch.Success) {
        throw "Could not read the workspace package version from '$cargoManifestPath'."
    }
    $Version = "$($workspaceVersionMatch.Groups["version"].Value).0"
}

if ($Version -notmatch "^\d+\.\d+\.\d+\.\d+$") {
    throw "Identity package version '$Version' must contain four numeric parts."
}
foreach ($part in $Version.Split(".")) {
    if ([uint32]$part -gt 65535) {
        throw "Identity package version part '$part' exceeds 65535."
    }
}

if (-not $MakeAppxPath) {
    $toolchain = & (Join-Path $PSScriptRoot "bootstrap.ps1") -PassThru
    $MakeAppxPath = Join-Path (
        Join-Path $toolchain.WindowsSdkRoot "bin\$($toolchain.Versions.WindowsSdk)\x64"
    ) "MakeAppx.exe"
}
if (-not (Test-Path -LiteralPath $MakeAppxPath -PathType Leaf)) {
    throw "MakeAppx.exe was not found at '$MakeAppxPath'."
}

$packagePath = Join-Path $packageRoot "Librarian.Identity_${Version}_neutral.msix"
try {
    New-Item -ItemType Directory -Path $layoutPath | Out-Null
    $template = [IO.File]::ReadAllText($templatePath)
    if (-not $template.Contains("@PACKAGE_VERSION@")) {
        throw "Identity manifest template does not contain its version placeholder."
    }
    $rendered = $template.Replace("@PACKAGE_VERSION@", $Version)
    [IO.File]::WriteAllText(
        $renderedManifestPath,
        $rendered,
        (New-Object Text.UTF8Encoding($false))
    )

    & (Join-Path $PSScriptRoot "test-identity-package.ps1") `
        -ManifestPath $renderedManifestPath

    & $MakeAppxPath pack /o /d $layoutPath /nv /p $packagePath
    if ($LASTEXITCODE -ne 0) {
        throw "MakeAppx.exe failed with exit code $LASTEXITCODE."
    }
}
finally {
    $resolvedPackageRoot = [IO.Path]::GetFullPath($packageRoot).TrimEnd("\")
    $resolvedLayoutPath = [IO.Path]::GetFullPath($layoutPath)
    if ((Split-Path $resolvedLayoutPath -Parent) -ne $resolvedPackageRoot -or
        (Split-Path $resolvedLayoutPath -Leaf) -notlike "identity-layout-*") {
        throw "Refusing to clean unexpected identity package staging path '$layoutPath'."
    }
    if (Test-Path -LiteralPath $resolvedLayoutPath) {
        Remove-Item -LiteralPath $resolvedLayoutPath -Recurse -Force
    }
}

Write-Host ""
Write-Host "Unsigned development identity package created."
Write-Host "Package: $packagePath"
Write-Host "This script did not sign, install, or register the package."
