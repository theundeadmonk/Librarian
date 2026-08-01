[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [string]$DiffBase = $env:LIBRARIAN_DIFF_BASE
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:PATHEXT = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"

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
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables["Path"] = $env:Path
    $startInfo.EnvironmentVariables["PATHEXT"] = $env:PATHEXT

    if ([IO.Path]::GetExtension($FilePath) -eq ".cmd") {
        $startInfo.FileName = $env:ComSpec
        $startInfo.Arguments = '/d /s /c ""' + $FilePath + '" ' + $argumentText + '"'
    } else {
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = $argumentText
    }

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "$Label could not start '$FilePath'."
    }

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

    $process.Dispose()
}

function Test-SmartAppControlEnforced {
    $policyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
    try {
        $state = (
            Get-ItemProperty `
                -LiteralPath $policyPath `
                -Name "VerifiedAndReputablePolicyState" `
                -ErrorAction Stop
        ).VerifiedAndReputablePolicyState
        return $state -eq 1
    } catch {
        return $false
    }
}

$toolchain = & (Join-Path $PSScriptRoot "bootstrap.ps1") -PassThru
$repoRoot = $toolchain.RepoRoot
$artifacts = Join-Path $repoRoot "artifacts"
$logs = Join-Path $artifacts "logs"
$powerShellHost = (Get-Process -Id $PID).Path
if (-not $powerShellHost -or -not (Test-Path -LiteralPath $powerShellHost -PathType Leaf)) {
    throw "The current PowerShell host executable could not be resolved."
}
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$env:Path = "$(Split-Path $toolchain.Node -Parent);$env:Path"

$windowsSdkBin = Join-Path $toolchain.WindowsSdkRoot "bin\$($toolchain.Versions.WindowsSdk)\x64"
if (Test-Path $windowsSdkBin) {
    $env:Path = "$windowsSdkBin;$env:Path"
}

Invoke-CheckedProcess `
    -Label "Native process argument tests" `
    -FilePath $powerShellHost `
    -Arguments @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "scripts\test-native-process-arguments.ps1"
    ) `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Certificate helper tests" `
    -FilePath $powerShellHost `
    -Arguments @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "scripts\test-certificate-helpers.ps1"
    ) `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Rust formatting" `
    -FilePath $toolchain.Cargo `
    -Arguments @("fmt", "--all", "--", "--check") `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Rust linting" `
    -FilePath $toolchain.Cargo `
    -Arguments @(
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--target",
        "x86_64-pc-windows-msvc",
        "--",
        "-D",
        "warnings"
    ) `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Rust unit tests" `
    -FilePath $toolchain.Cargo `
    -Arguments @(
        "test",
        "--workspace",
        "--all-targets",
        "--locked",
        "--target",
        "x86_64-pc-windows-msvc"
    ) `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Rust documentation tests" `
    -FilePath $toolchain.Cargo `
    -Arguments @(
        "test",
        "--workspace",
        "--doc",
        "--locked",
        "--target",
        "x86_64-pc-windows-msvc"
    ) `
    -WorkingDirectory $repoRoot

$cargoBuildArguments = @(
    "build",
    "--workspace",
    "--locked",
    "--target",
    "x86_64-pc-windows-msvc"
)
if ($Configuration -eq "Release") {
    $cargoBuildArguments += "--release"
}

Invoke-CheckedProcess `
    -Label "Rust workspace build" `
    -FilePath $toolchain.Cargo `
    -Arguments $cargoBuildArguments `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Extension dependency restore" `
    -FilePath $toolchain.Npm `
    -Arguments @("ci", "--ignore-scripts") `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Cross-platform Rust test parity checker tests" `
    -FilePath $toolchain.Npm `
    -Arguments @("run", "check:test-parity") `
    -WorkingDirectory $repoRoot

$typeScript = Join-Path $repoRoot "node_modules\typescript\bin\tsc"
if (-not (Test-Path $typeScript)) {
    throw "The locked TypeScript compiler was not restored at '$typeScript'."
}

Invoke-CheckedProcess `
    -Label "Extension type check" `
    -FilePath $toolchain.Node `
    -Arguments @(
        $typeScript,
        "--project",
        "apps\browser-extension\tsconfig.json",
        "--noEmit"
    ) `
    -WorkingDirectory $repoRoot

Invoke-CheckedProcess `
    -Label "Extension build" `
    -FilePath $toolchain.Node `
    -Arguments @(
        $typeScript,
        "--project",
        "apps\browser-extension\tsconfig.json"
    ) `
    -WorkingDirectory $repoRoot

$solution = Join-Path $repoRoot "Librarian.sln"
$msbuildRestoreLog = Join-Path $logs "msbuild-restore-$Configuration-$Platform.log"
$msbuildLog = Join-Path $logs "msbuild-$Configuration-$Platform.log"
$msbuildRestoreArguments = @(
    $solution
    "/t:Restore"
    "/m"
    "/nr:false"
    "/p:Configuration=$Configuration"
    "/p:Platform=$Platform"
    "/p:RestoreLockedMode=true"
    "/verbosity:minimal"
    "/fileLogger"
    ("/fileLoggerParameters:LogFile=" + $msbuildRestoreLog + ";Verbosity=diagnostic")
)

Invoke-CheckedProcess `
    -Label "Locked native dependency restore" `
    -FilePath $toolchain.MSBuild `
    -Arguments $msbuildRestoreArguments `
    -WorkingDirectory $repoRoot

$nugetPackages = if ($env:NUGET_PACKAGES) {
    $env:NUGET_PACKAGES
} else {
    Join-Path $env:USERPROFILE ".nuget\packages"
}
$nugetWindowsSdkBin = Join-Path $nugetPackages (
    "microsoft.windows.sdk.buildtools\$($toolchain.Versions.WindowsSdkBuildTools)" +
    "\bin\$($toolchain.Versions.WindowsSdk)\x64"
)
if (-not (Test-Path (Join-Path $nugetWindowsSdkBin "mdmerge.exe"))) {
    throw "The locked Windows SDK tools were not restored at '$nugetWindowsSdkBin'."
}
$env:Path = "$nugetWindowsSdkBin;$env:Path"

$msbuildArguments = @(
    $solution
    "/t:Build"
    "/m"
    "/nr:false"
    "/p:AppxBundle=Never"
    "/p:AppxPackageSigningEnabled=false"
    "/p:Configuration=$Configuration"
    "/p:Platform=$Platform"
    "/p:RestoreLockedMode=true"
    "/verbosity:minimal"
    "/fileLogger"
    ("/fileLoggerParameters:LogFile=" + $msbuildLog + ";Verbosity=diagnostic")
)

Invoke-CheckedProcess `
    -Label "Windows native boundaries build" `
    -FilePath $toolchain.MSBuild `
    -Arguments $msbuildArguments `
    -WorkingDirectory $repoRoot

if ($Configuration -eq "Release") {
    $manifestTool = Join-Path $windowsSdkBin "mt.exe"
    Invoke-CheckedProcess `
        -Label "Release binary package-identity validation" `
        -FilePath $powerShellHost `
        -Arguments @(
            "-NoProfile"
            "-ExecutionPolicy"
            "Bypass"
            "-File"
            "scripts\test-embedded-identity.ps1"
            "-MtPath"
            $manifestTool
            "-Configuration"
            $Configuration
            "-Platform"
            $Platform
        ) `
        -WorkingDirectory $repoRoot
}

$makeAppx = Join-Path $nugetWindowsSdkBin "MakeAppx.exe"
if (-not (Test-Path $makeAppx)) {
    throw "The locked MakeAppx.exe was not restored at '$makeAppx'."
}

Invoke-CheckedProcess `
    -Label "Unsigned identity package fixture" `
    -FilePath $powerShellHost `
    -Arguments @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        "scripts\build-identity-package.ps1"
        "-MakeAppxPath"
        $makeAppx
    ) `
    -WorkingDirectory $repoRoot

$ipcProbe = Join-Path $repoRoot (
    "artifacts\bin\$Platform\$Configuration\Librarian.WindowsIpcProbe.exe"
)
if (-not (Test-Path $ipcProbe)) {
    throw "The Windows local IPC security probe was not built at '$ipcProbe'."
}

Invoke-CheckedProcess `
    -Label "Windows local IPC peer-verification probe" `
    -FilePath $ipcProbe `
    -Arguments @("--self-test") `
    -WorkingDirectory $repoRoot

$windowsHelloTests = Join-Path $repoRoot (
    "artifacts\bin\$Platform\$Configuration\Librarian.WindowsHelloTests.exe"
)
if (-not (Test-Path $windowsHelloTests)) {
    throw "The Windows Hello security tests were not built at '$windowsHelloTests'."
}

Invoke-CheckedProcess `
    -Label "Windows Hello production-boundary security tests" `
    -FilePath $windowsHelloTests `
    -Arguments @("--self-test") `
    -WorkingDirectory $repoRoot

$windowsShellTests = Join-Path $repoRoot (
    "artifacts\bin\$Platform\$Configuration\Librarian.WindowsShellTests.exe"
)
if (-not (Test-Path $windowsShellTests)) {
    throw "The Windows shell tests were not built at '$windowsShellTests'."
}

Invoke-CheckedProcess `
    -Label "Windows shell model and XAML smoke tests" `
    -FilePath $windowsShellTests `
    -Arguments @(
        "--xaml"
        "apps\windows\Librarian.Windows\MainWindow.xaml"
        "--source"
        "apps\windows\Librarian.Windows\MainWindow.xaml.cpp"
    ) `
    -WorkingDirectory $repoRoot

if ($Configuration -eq "Release") {
    $installerBuildArguments = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        "scripts\build-installer.ps1"
        "-Configuration"
        $Configuration
        "-Platform"
        $Platform
    )
    $installerTestArguments = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        "scripts\test-installer.ps1"
        "-ExpectedSigningMode"
        "unsigned-fixture"
    )

    if (Test-SmartAppControlEnforced) {
        Write-Host ""
        Write-Host (
            "Smart App Control is enforced. The local build will suppress WiX " +
            "ICE execution because Windows blocks its temporary unsigned MSI; " +
            "the structural suite still runs, and CI must run ICE validation."
        )
        $installerBuildArguments += "-SuppressMsiValidation"
        $installerTestArguments += "-SkipIceValidation"
    }

    Invoke-CheckedProcess `
        -Label "Unsigned single-installer fixture" `
        -FilePath $powerShellHost `
        -Arguments $installerBuildArguments `
        -WorkingDirectory $repoRoot

    Invoke-CheckedProcess `
        -Label "Installer lifecycle structural and ICE validation" `
        -FilePath $powerShellHost `
        -Arguments $installerTestArguments `
        -WorkingDirectory $repoRoot

    Invoke-CheckedProcess `
        -Label "Current-user development runner validation" `
        -FilePath $powerShellHost `
        -Arguments @(
            "-NoProfile"
            "-ExecutionPolicy"
            "Bypass"
            "-File"
            "scripts\run-development.ps1"
            "-Configuration"
            $Configuration
            "-Platform"
            $Platform
            "-ValidateOnly"
        ) `
        -WorkingDirectory $repoRoot
}

$gitMetadata = Join-Path $repoRoot ".git"
$usesWslWorktreeMetadata = (Test-Path $gitMetadata -PathType Leaf) -and
    ((Get-Content -Raw $gitMetadata) -match "^gitdir:\s+/")

if ($usesWslWorktreeMetadata) {
    Write-Host ""
    Write-Host "==> Git whitespace validation"
    Write-Host "Skipped for this WSL-attached worktree; Windows Git cannot resolve its /mnt gitdir pointer."
} else {
    $committedDiffBase = if ($DiffBase -and $DiffBase -notmatch "^0+$") {
        $DiffBase
    } else {
        "origin/main"
    }

    Invoke-CheckedProcess `
        -Label "Committed diff whitespace validation" `
        -FilePath $toolchain.Git `
        -Arguments @("diff", "--check", "$committedDiffBase...HEAD") `
        -WorkingDirectory $repoRoot

    Invoke-CheckedProcess `
        -Label "Staged diff whitespace validation" `
        -FilePath $toolchain.Git `
        -Arguments @("diff", "--cached", "--check") `
        -WorkingDirectory $repoRoot

    Invoke-CheckedProcess `
        -Label "Working-tree diff whitespace validation" `
        -FilePath $toolchain.Git `
        -Arguments @("diff", "--check") `
        -WorkingDirectory $repoRoot
}

Write-Host ""
Write-Host "Librarian foundation build completed successfully."
Write-Host "Configuration: $Configuration|$Platform"
Write-Host "MSBuild log: $msbuildLog"
