[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "installer-runner-guard.ps1")

function Assert-Equal {
    param(
        $Actual,

        $Expected,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected'; found '$Actual'."
    }
}

$environmentNames = @(
    "GITHUB_ACTIONS",
    "CI",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "RUNNER_ARCH",
    "RUNNER_NAME",
    "GITHUB_REPOSITORY",
    "LIBRARIAN_DISPOSABLE_WINDOWS11_RUNNER"
)
$originalEnvironment = @{}
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable(
        $name,
        [EnvironmentVariableTarget]::Process
    )
}

$windows11 = [pscustomobject]@{
    ProductType = 1
    Caption = "Microsoft Windows 11 Enterprise Evaluation"
    BuildNumber = "26100"
}
$windowsServer = [pscustomobject]@{
    ProductType = 3
    Caption = "Microsoft Windows Server 2025 Standard"
    BuildNumber = "26100"
}
$oldWindows = [pscustomobject]@{
    ProductType = 1
    Caption = "Microsoft Windows 11 Pro"
    BuildNumber = "26000"
}

try {
    $env:GITHUB_ACTIONS = "true"
    $env:CI = "true"
    $env:RUNNER_OS = "Windows"
    $env:RUNNER_ARCH = "X64"
    $env:GITHUB_REPOSITORY = "theundeadmonk/Librarian"
    $env:RUNNER_ENVIRONMENT = "github-hosted"
    $env:RUNNER_NAME = "GitHub Actions 1"
    $env:LIBRARIAN_DISPOSABLE_WINDOWS11_RUNNER = $null

    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode -OperatingSystem $windows11) `
        -Expected "github-hosted-windows11" `
        -Message "A disposable hosted Windows 11 runner must be accepted."
    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode -OperatingSystem $windowsServer) `
        -Expected $null `
        -Message "Windows Server must be rejected."
    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode -OperatingSystem $oldWindows) `
        -Expected $null `
        -Message "An older Windows workstation build must be rejected."

    $env:RUNNER_ENVIRONMENT = "self-hosted"
    $env:RUNNER_NAME = "librarian-disposable-win11-1"
    $env:LIBRARIAN_DISPOSABLE_WINDOWS11_RUNNER = "true"
    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode -OperatingSystem $windows11) `
        -Expected $null `
        -Message "A self-hosted runner without explicit confirmation must be rejected."
    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode `
            -ConfirmSelfHosted `
            -OperatingSystem $windows11) `
        -Expected "self-hosted-windows11" `
        -Message "An explicitly confirmed disposable self-hosted runner must be accepted."
    Assert-Equal `
        -Actual (Test-InstallerLifecycleRunnerMode `
            -ExpectedMode "self-hosted-windows11" `
            -OperatingSystem $windows11) `
        -Expected $true `
        -Message "Nested lifecycle steps must recognize the inherited runner mode."

    $env:RUNNER_NAME = "general-purpose-windows-runner"
    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode `
            -ConfirmSelfHosted `
            -OperatingSystem $windows11) `
        -Expected $null `
        -Message "A general-purpose self-hosted runner name must be rejected."

    $env:RUNNER_NAME = "librarian-disposable-win11-1"
    $env:LIBRARIAN_DISPOSABLE_WINDOWS11_RUNNER = $null
    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode `
            -ConfirmSelfHosted `
            -OperatingSystem $windows11) `
        -Expected $null `
        -Message "A self-hosted runner without the provisioner marker must be rejected."

    $env:LIBRARIAN_DISPOSABLE_WINDOWS11_RUNNER = "true"
    $env:GITHUB_REPOSITORY = "another/repository"
    Assert-Equal `
        -Actual (Get-DisposableWindows11RunnerMode `
            -ConfirmSelfHosted `
            -OperatingSystem $windows11) `
        -Expected $null `
        -Message "A runner job for another repository must be rejected."
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $originalEnvironment[$name],
            [EnvironmentVariableTarget]::Process
        )
    }
}

Write-Host "Installer runner guard tests passed."
