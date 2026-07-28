[CmdletBinding()]
param(
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "native-process-arguments.ps1")

$expected = [ordered]@{
    Node = "24.18.0"
    Npm = "11.16.0"
    Rust = "1.97.1"
    DotNetSdk = "10.0.302"
    Wix = "7.0.0"
    WindowsSdk = "10.0.28000.0"
    WindowsSdkBuildTools = "10.0.28000.2270"
    WindowsAppSdk = "2.3.1"
    CppWinRt = "3.0.260715.1"
    Wil = "1.0.260126.7"
}

function Normalize-ProcessPathEnvironment {
    # Windows environment names are case-insensitive, but some process launchers
    # can supply both Path and PATH. .NET Framework then throws while copying the
    # inherited block for a child process. Rewrite only this process's entry.
    $activePath = [Environment]::GetEnvironmentVariable("Path", "Process")
    if ($null -eq $activePath) {
        throw "The current process does not have a Path environment variable."
    }

    [Environment]::SetEnvironmentVariable("PATH", $null, "Process")
    [Environment]::SetEnvironmentVariable("Path", $activePath, "Process")
}

function Add-KnownToolDirectories {
    $directories = @()

    if (-not (Get-Command "node.exe" -ErrorAction SilentlyContinue)) {
        $directories += Join-Path $env:ProgramFiles "nodejs"
    }

    if (-not (Get-Command "cargo.exe" -ErrorAction SilentlyContinue)) {
        $directories += Join-Path $env:USERPROFILE ".cargo\bin"
    }

    if (-not (Get-Command "git.exe" -ErrorAction SilentlyContinue)) {
        $directories += Join-Path $env:ProgramFiles "Git\cmd"
    }

    $directories = @($directories | Where-Object { Test-Path $_ })

    if ($directories.Count -gt 0) {
        $env:Path = (($directories + ($env:Path -split ";")) | Select-Object -Unique) -join ";"
    }
}

function Resolve-Tool {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string[]]$KnownPaths = @()
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    foreach ($candidate in $KnownPaths) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "Required tool '$Name' was not found. See DEVELOPMENT.md for the supported setup."
}

function Get-ToolOutput {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $argumentText = Join-NativeProcessArguments -Arguments $Arguments

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $argumentText
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Could not start '$FilePath'."
    }

    try {
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()

        $output = $standardOutput.Result
        $errorOutput = $standardError.Result
        if ($process.ExitCode -ne 0) {
            $diagnostics = (@($output, $errorOutput) | Where-Object { $_ }) -join [Environment]::NewLine
            throw "'$FilePath $($Arguments -join ' ')' failed with exit code $($process.ExitCode): $($diagnostics.Trim())"
        }

        return $output.Trim()
    } finally {
        $process.Dispose()
    }
}

function Assert-ExactVersion {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Actual,

        [Parameter(Mandatory)]
        [string]$Required
    )

    if ($Actual -ne $Required) {
        throw "$Name $Required is required, but $Actual is active."
    }

    if ($Actual -match "(?i)(alpha|beta|preview|rc|experimental)") {
        throw "$Name must be a stable release, but '$Actual' is active."
    }
}

function Resolve-MSBuild {
    $knownPaths = @(
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe")
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe")
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe")
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe")
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe")
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe")
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe")
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe")
    )

    foreach ($candidate in $knownPaths) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    $vsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $discovered = & $vsWhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe"
        if ($LASTEXITCODE -eq 0 -and $discovered) {
            return (Resolve-Path ($discovered | Select-Object -First 1)).Path
        }
    }

    return Resolve-Tool -Name "MSBuild.exe"
}

function Assert-FileContains {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$ExpectedText
    )

    if (-not (Test-Path $Path)) {
        throw "Required file is missing: $Path"
    }

    $contents = Get-Content -Raw $Path
    if (-not $contents.Contains($ExpectedText)) {
        throw "'$Path' does not contain the required pin '$ExpectedText'."
    }
}

$isWindowsPlatform = if (Get-Variable IsWindows -ErrorAction SilentlyContinue) {
    $IsWindows
} else {
    $env:OS -eq "Windows_NT"
}

if (-not $isWindowsPlatform) {
    throw "Librarian's MVP bootstrap must run on Windows 11."
}

$minimumWindowsBuild = 26100
$windowsVersion = [Environment]::OSVersion.Version
if ($windowsVersion.Build -lt $minimumWindowsBuild) {
    throw "Windows 11 build $minimumWindowsBuild or newer is required; build $($windowsVersion.Build) is active."
}

Normalize-ProcessPathEnvironment
Add-KnownToolDirectories

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$node = Resolve-Tool -Name "node.exe" -KnownPaths @(
    (Join-Path $env:ProgramFiles "nodejs\node.exe")
)
$npm = Resolve-Tool -Name "npm.cmd" -KnownPaths @(
    (Join-Path $env:ProgramFiles "nodejs\npm.cmd")
)
$rustc = Resolve-Tool -Name "rustc.exe" -KnownPaths @(
    (Join-Path $env:USERPROFILE ".cargo\bin\rustc.exe")
)
$cargo = Resolve-Tool -Name "cargo.exe" -KnownPaths @(
    (Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe")
)
$git = Resolve-Tool -Name "git.exe" -KnownPaths @(
    (Join-Path $env:ProgramFiles "Git\cmd\git.exe")
)
$dotnet = Resolve-Tool -Name "dotnet.exe" -KnownPaths @(
    (Join-Path $env:ProgramFiles "dotnet\dotnet.exe")
)
$msbuild = Resolve-MSBuild

$nodeVersion = (Get-ToolOutput -FilePath $node -Arguments @("--version")).TrimStart("v")
$npmVersion = Get-ToolOutput -FilePath $npm -Arguments @("--version")
$rustOutput = Get-ToolOutput -FilePath $rustc -Arguments @("--version")
$cargoOutput = Get-ToolOutput -FilePath $cargo -Arguments @("--version")
$gitVersion = Get-ToolOutput -FilePath $git -Arguments @("--version")
$dotnetVersion = Get-ToolOutput -FilePath $dotnet -Arguments @("--version")

if ($rustOutput -notmatch "^rustc ([^\s]+)") {
    throw "Could not parse rustc version from '$rustOutput'."
}
$rustVersion = $Matches[1]

Assert-ExactVersion -Name "Node.js" -Actual $nodeVersion -Required $expected.Node
Assert-ExactVersion -Name "npm" -Actual $npmVersion -Required $expected.Npm
Assert-ExactVersion -Name "Rust" -Actual $rustVersion -Required $expected.Rust
Assert-ExactVersion `
    -Name ".NET SDK" `
    -Actual $dotnetVersion `
    -Required $expected.DotNetSdk

if ($cargoOutput -match "(?i)(alpha|beta|preview|rc|experimental)") {
    throw "Cargo must be from a stable Rust toolchain, but '$cargoOutput' is active."
}

$msbuildFileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($msbuild).FileVersion
$msbuildVersion = [Version]$msbuildFileVersion
if ($msbuildVersion.Major -lt 17 -or ($msbuildVersion.Major -eq 17 -and $msbuildVersion.Minor -lt 12)) {
    throw "Visual Studio 2022 17.12 or newer is required; MSBuild $msbuildFileVersion is active."
}

$windowsSdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$windowsSdkHeader = Join-Path $windowsSdkRoot "Include\$($expected.WindowsSdk)\um\Windows.h"
if (-not (Test-Path $windowsSdkHeader)) {
    throw (
        "Windows SDK $($expected.WindowsSdk) is required. " +
        "Install it with 'winget install Microsoft.WindowsSDK.10.0.28000' and run bootstrap again."
    )
}
$windowsSdkSource = "installed SDK and locked NuGet Build Tools"

$windowsProject = Join-Path $repoRoot "apps\windows\Librarian.Windows\Librarian.Windows.vcxproj"
Assert-FileContains -Path $windowsProject -ExpectedText ('Include="Microsoft.WindowsAppSDK" Version="' + $expected.WindowsAppSdk + '"')
Assert-FileContains -Path $windowsProject -ExpectedText ('Include="Microsoft.Windows.CppWinRT" Version="' + $expected.CppWinRt + '"')
Assert-FileContains -Path $windowsProject -ExpectedText ('Include="Microsoft.Windows.SDK.BuildTools" Version="' + $expected.WindowsSdkBuildTools + '"')
Assert-FileContains -Path $windowsProject -ExpectedText ('Include="Microsoft.Windows.ImplementationLibrary" Version="' + $expected.Wil + '"')
Assert-FileContains -Path $windowsProject -ExpectedText "<WindowsAppSDKSelfContained>true</WindowsAppSDKSelfContained>"
Assert-FileContains -Path $windowsProject -ExpectedText "<UseCrtSDKReferenceStaticWarning>false</UseCrtSDKReferenceStaticWarning>"
Assert-FileContains `
    -Path (Join-Path $repoRoot "apps\windows\Librarian.Windows\Directory.Build.props") `
    -ExpectedText '<Import Project="$(MSBuildThisFileDirectory)HybridCRT.props" />'
Assert-FileContains `
    -Path (Join-Path $repoRoot "apps\windows\Librarian.Windows\HybridCRT.props") `
    -ExpectedText "<RuntimeLibrary>MultiThreaded</RuntimeLibrary>"
Assert-FileContains `
    -Path (Join-Path $repoRoot "scripts\build-installer.ps1") `
    -ExpectedText "Test-CertificateEnhancedKeyUsage"

$globalJsonPath = Join-Path $repoRoot "global.json"
if (-not (Test-Path -LiteralPath $globalJsonPath -PathType Leaf)) {
    throw "Required .NET SDK pin is missing: $globalJsonPath"
}
$globalJson = Get-Content -LiteralPath $globalJsonPath -Raw | ConvertFrom-Json
if ($globalJson.sdk.version -ne $expected.DotNetSdk -or
    $globalJson.sdk.rollForward -ne "disable" -or
    $globalJson.sdk.allowPrerelease -ne $false) {
    throw (
        "global.json must pin .NET SDK $($expected.DotNetSdk), disable " +
        "roll-forward, and disallow prerelease SDKs."
    )
}

$customActionProject = Join-Path $repoRoot (
    "packaging\windows\custom-actions\Librarian.Setup.CustomActions.vcxproj"
)
Assert-FileContains `
    -Path $customActionProject `
    -ExpectedText (
        'Include="Microsoft.Windows.CppWinRT" Version="' +
        $expected.CppWinRt +
        '"'
    )
Assert-FileContains `
    -Path $customActionProject `
    -ExpectedText (
        'Include="Microsoft.Windows.SDK.BuildTools" Version="' +
        $expected.WindowsSdkBuildTools +
        '"'
    )

foreach ($wixProject in @(
    (Join-Path $repoRoot "packaging\windows\Librarian.Package.wixproj")
    (Join-Path $repoRoot "packaging\windows\Librarian.Setup.wixproj")
)) {
    Assert-FileContains `
        -Path $wixProject `
        -ExpectedText ('Project Sdk="WixToolset.Sdk/' + $expected.Wix + '"')
    Assert-FileContains `
        -Path $wixProject `
        -ExpectedText "<AcceptEula>wix7</AcceptEula>"
}

foreach ($lockfile in @(
    (Join-Path $repoRoot "Cargo.lock")
    (Join-Path $repoRoot "package-lock.json")
    (Join-Path $repoRoot "apps\windows\Librarian.Windows\packages.lock.json")
    (Join-Path $repoRoot "packaging\windows\custom-actions\packages.lock.json")
    (Join-Path $repoRoot "packaging\windows\Librarian.Package.packages.lock.json")
    (Join-Path $repoRoot "packaging\windows\Librarian.Setup.packages.lock.json")
)) {
    if (-not (Test-Path $lockfile)) {
        throw "Required dependency lockfile is missing: $lockfile"
    }
}

$result = [PSCustomObject]@{
    RepoRoot = $repoRoot
    Node = $node
    Npm = $npm
    Rustc = $rustc
    Cargo = $cargo
    Git = $git
    DotNet = $dotnet
    MSBuild = $msbuild
    WindowsSdkRoot = $windowsSdkRoot
    Versions = [PSCustomObject]@{
        Windows = $windowsVersion.ToString()
        MSBuild = $msbuildFileVersion
        WindowsSdk = $expected.WindowsSdk
        WindowsSdkSource = $windowsSdkSource
        WindowsSdkBuildTools = $expected.WindowsSdkBuildTools
        WindowsAppSdk = $expected.WindowsAppSdk
        CppWinRt = $expected.CppWinRt
        Wil = $expected.Wil
        Rust = $rustVersion
        Cargo = $cargoOutput
        Node = $nodeVersion
        Npm = $npmVersion
        Git = $gitVersion
        DotNetSdk = $dotnetVersion
        Wix = $expected.Wix
    }
}

if ($PassThru) {
    return $result
}

Write-Host "Librarian Windows development environment is ready."
$result.Versions | Format-List
