Set-StrictMode -Version Latest

function Get-DisposableWindows11RunnerMode {
    param(
        [switch]$ConfirmSelfHosted,

        [psobject]$OperatingSystem
    )

    if (
        $env:GITHUB_ACTIONS -ne "true" -or
        $env:CI -ne "true" -or
        $env:RUNNER_OS -ne "Windows" -or
        $env:RUNNER_ARCH -ne "X64" -or
        $env:GITHUB_REPOSITORY -ne "theundeadmonk/Librarian"
    ) {
        return $null
    }

    if ($null -eq $OperatingSystem) {
        $OperatingSystem = Get-CimInstance Win32_OperatingSystem
    }
    if (
        [uint32]$operatingSystem.ProductType -ne 1 -or
        $operatingSystem.Caption -notmatch "Windows 11" -or
        [uint32]$operatingSystem.BuildNumber -lt 26100
    ) {
        return $null
    }

    if ($env:RUNNER_ENVIRONMENT -eq "github-hosted") {
        return "github-hosted-windows11"
    }

    if (
        $env:RUNNER_ENVIRONMENT -eq "self-hosted" -and
        $ConfirmSelfHosted -and
        $env:LIBRARIAN_DISPOSABLE_WINDOWS11_RUNNER -eq "true" -and
        $env:RUNNER_NAME -like "librarian-disposable-win11-*"
    ) {
        return "self-hosted-windows11"
    }

    return $null
}

function Test-InstallerLifecycleRunnerMode {
    param(
        [Parameter(Mandatory)]
        [string]$ExpectedMode,

        [psobject]$OperatingSystem
    )

    $confirmSelfHosted = $ExpectedMode -eq "self-hosted-windows11"
    $actualMode = Get-DisposableWindows11RunnerMode `
        -ConfirmSelfHosted:$confirmSelfHosted `
        -OperatingSystem $OperatingSystem
    return $actualMode -eq $ExpectedMode
}
