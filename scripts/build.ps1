[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:PATHEXT = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"

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

    $argumentText = ($Arguments | ForEach-Object {
        if ($_ -match '^".*"$' -or $_ -notmatch '\s') {
            $_
        } else {
            '"' + $_.Replace('"', '\"') + '"'
        }
    }) -join " "

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

$toolchain = & (Join-Path $PSScriptRoot "bootstrap.ps1") -PassThru
$repoRoot = $toolchain.RepoRoot
$artifacts = Join-Path $repoRoot "artifacts"
$logs = Join-Path $artifacts "logs"
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$env:Path = "$(Split-Path $toolchain.Node -Parent);$env:Path"

$windowsSdkBin = Join-Path $toolchain.WindowsSdkRoot "bin\$($toolchain.Versions.WindowsSdk)\x64"
if (Test-Path $windowsSdkBin) {
    $env:Path = "$windowsSdkBin;$env:Path"
}

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
    ('"' + $solution + '"')
    "/t:Restore"
    "/m"
    "/nr:false"
    "/p:Configuration=$Configuration"
    "/p:Platform=$Platform"
    "/p:RestoreLockedMode=true"
    "/verbosity:minimal"
    "/fileLogger"
    ('"/fileLoggerParameters:LogFile=' + $msbuildRestoreLog + ';Verbosity=diagnostic"')
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
    ('"' + $solution + '"')
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
    ('"/fileLoggerParameters:LogFile=' + $msbuildLog + ';Verbosity=diagnostic"')
)

Invoke-CheckedProcess `
    -Label "WinUI and Windows passkey boundary build" `
    -FilePath $toolchain.MSBuild `
    -Arguments $msbuildArguments `
    -WorkingDirectory $repoRoot

$gitMetadata = Join-Path $repoRoot ".git"
$usesWslWorktreeMetadata = (Test-Path $gitMetadata -PathType Leaf) -and
    ((Get-Content -Raw $gitMetadata) -match "^gitdir:\s+/")

if ($usesWslWorktreeMetadata) {
    Write-Host ""
    Write-Host "==> Git whitespace validation"
    Write-Host "Skipped for this WSL-attached worktree; Windows Git cannot resolve its /mnt gitdir pointer."
} else {
    Invoke-CheckedProcess `
        -Label "Git whitespace validation" `
        -FilePath $toolchain.Git `
        -Arguments @("diff", "--check") `
        -WorkingDirectory $repoRoot
}

Write-Host ""
Write-Host "Librarian foundation build completed successfully."
Write-Host "Configuration: $Configuration|$Platform"
Write-Host "MSBuild log: $msbuildLog"
