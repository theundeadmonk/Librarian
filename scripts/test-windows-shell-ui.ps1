[CmdletBinding()]
param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$developmentRunner = Join-Path $PSScriptRoot "run-development.ps1"
$developmentLayout = Join-Path $repoRoot "artifacts\development\Librarian"
$desktopPath = Join-Path $developmentLayout "Librarian.Windows.exe"
$logDirectory = Join-Path $repoRoot "artifacts\logs"
$runId = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss-ffff")
$runnerOutput = Join-Path $logDirectory "windows-shell-ui-$runId.out.log"
$runnerError = Join-Path $logDirectory "windows-shell-ui-$runId.err.log"
$runnerProcess = $null
$desktopProcess = $null

if (-not (Test-Path -LiteralPath $developmentRunner -PathType Leaf)) {
    throw "The development package runner is missing: $developmentRunner"
}
if (-not [Environment]::UserInteractive) {
    throw "The Windows shell UI smoke test requires an interactive desktop session."
}
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

function Test-SamePath {
    param(
        [Parameter(Mandatory)]
        [string]$First,

        [Parameter(Mandatory)]
        [string]$Second
    )

    return [string]::Equals(
        [System.IO.Path]::GetFullPath($First).TrimEnd("\"),
        [System.IO.Path]::GetFullPath($Second).TrimEnd("\"),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Get-ExpectedDesktopProcess {
    if (-not (Test-Path -LiteralPath $desktopPath -PathType Leaf)) {
        return $null
    }

    return Get-Process -Name "Librarian.Windows" -ErrorAction SilentlyContinue |
        Where-Object {
            try {
                Test-SamePath -First $_.Path -Second $desktopPath
            }
            catch {
                $false
            }
        } |
        Select-Object -First 1
}

function Close-ExpectedDesktop {
    param([System.Diagnostics.Process]$Process)

    if ($null -eq $Process) {
        return
    }
    try {
        $Process.Refresh()
        if ($Process.HasExited) {
            return
        }
        if ($Process.CloseMainWindow()) {
            try {
                Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction Stop
                return
            }
            catch {
                # Fall through to the bounded expected-process cleanup.
            }
        }
        $current = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
        if (
            $null -ne $current -and
            (Test-SamePath -First $current.Path -Second $desktopPath)
        ) {
            Stop-Process -Id $current.Id -Force
        }
    }
    catch {
        # The development runner performs its own final process cleanup.
    }
}

try {
    $runnerArguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        ('"{0}"' -f $developmentRunner),
        "-Configuration",
        $Configuration,
        "-Platform",
        $Platform
    )
    $runnerProcess = Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList $runnerArguments `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $runnerOutput `
        -RedirectStandardError $runnerError

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 100
        $runnerProcess.Refresh()
        if ($runnerProcess.HasExited) {
            $runnerProcess.WaitForExit()
            throw (
                "The development package runner exited before Librarian started. " +
                "Logs: $runnerOutput, $runnerError"
            )
        }
        $desktopProcess = Get-ExpectedDesktopProcess
    } while ($null -eq $desktopProcess -and [DateTime]::UtcNow -lt $deadline)

    if ($null -eq $desktopProcess) {
        throw "Librarian did not start within 30 seconds. Runner logs: $runnerOutput, $runnerError"
    }

    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes

    $window = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $desktopProcess.Refresh()
        if ($desktopProcess.HasExited) {
            throw "Librarian exited before exposing an accessibility window."
        }
        $processCondition = [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty,
            $desktopProcess.Id
        )
        $window = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [System.Windows.Automation.TreeScope]::Children,
            $processCondition
        )
    } while ($null -eq $window -and [DateTime]::UtcNow -lt $deadline)

    if ($null -eq $window) {
        throw "Librarian did not expose a top-level accessibility window within 20 seconds."
    }

    $nativeWindowTitle = ""
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $desktopProcess.Refresh()
        $nativeWindowTitle = $desktopProcess.MainWindowTitle
        if ($nativeWindowTitle -eq "Librarian") {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)

    $accessibleNames = @()
    $firstRun = $false
    $locked = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $elements = $window.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.Condition]::TrueCondition
        )
        $accessibleNames = @($window.Current.Name)
        foreach ($element in $elements) {
            if (-not [string]::IsNullOrWhiteSpace($element.Current.Name)) {
                $accessibleNames += $element.Current.Name
            }
        }
        $firstRun = (
            $accessibleNames -contains "First-run setup" -and
            $accessibleNames -contains "Create local vault"
        )
        $locked = (
            $accessibleNames -contains "Vault locked" -and
            $accessibleNames -contains "Unlock with Windows Hello"
        )
        if ($firstRun -or $locked) {
            break
        }
        Start-Sleep -Milliseconds 100
        $desktopProcess.Refresh()
        if ($desktopProcess.HasExited) {
            throw "Librarian exited before reaching its agent-backed UI state."
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    if (-not $firstRun -and -not $locked) {
        $knownStateLabels = @(
            "First-run setup",
            "Vault locked",
            "Accounts",
            "Librarian needs attention",
            "Vault agent unavailable"
        )
        $observedStateLabels = @(
            $knownStateLabels | Where-Object { $accessibleNames -contains $_ }
        )
        $observedState = if ($observedStateLabels.Count -eq 0) {
            "none"
        }
        else {
            $observedStateLabels -join ", "
        }
        throw (
            "Librarian did not reach the first-run or locked agent-backed UI state. " +
            "Observed shell state: $observedState."
        )
    }

    $expectedFocusName = if ($firstRun) {
        "New master password"
    }
    else {
        "Unlock with Windows Hello"
    }
    $focusElement = $window.FindFirst(
        [System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            $expectedFocusName
        )
    )
    if ($null -eq $focusElement) {
        throw "The expected initial control could not be resolved as an automation element."
    }

    $initialControlHasKeyboardFocus = $false
    $focusedDetail = "No global focused automation element was reported."
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        Start-Sleep -Milliseconds 100
        $initialControlHasKeyboardFocus = $focusElement.Current.HasKeyboardFocus
        $focusedElement = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($null -ne $focusedElement) {
            $focusedDetail = (
                "Focused process: $($focusedElement.Current.ProcessId); " +
                "name: '$($focusedElement.Current.Name)'; " +
                "automation id: '$($focusedElement.Current.AutomationId)'; " +
                "control type: '$($focusedElement.Current.ControlType.ProgrammaticName)'."
            )
        }
    } while (
        -not $initialControlHasKeyboardFocus -and
        [DateTime]::UtcNow -lt $deadline
    )

    $checks = [ordered]@{
        "Window title" = $nativeWindowTitle -eq "Librarian"
        "Agent-backed state" = $firstRun -or $locked
        "Master-password fallback" = (
            $accessibleNames -contains "New master password" -or
            $accessibleNames -contains "Master password"
        )
        "Initial keyboard focus" = $initialControlHasKeyboardFocus
    }
    $failedChecks = @($checks.GetEnumerator() | Where-Object { -not $_.Value })
    if ($failedChecks.Count -ne 0) {
        $failedNames = ($failedChecks | ForEach-Object { $_.Key }) -join ", "
        throw "Windows shell UI smoke checks failed: $failedNames. $focusedDetail"
    }

    Close-ExpectedDesktop -Process $desktopProcess
    $desktopProcess = $null
    if (-not $runnerProcess.WaitForExit(30000)) {
        throw "The development runner did not finish cleanup within 30 seconds."
    }
    $runnerProcess.WaitForExit()
    $runnerProcess.Refresh()
    $runnerOutputText = Get-Content -LiteralPath $runnerOutput -Raw
    $runnerErrorText = Get-Content -LiteralPath $runnerError -Raw
    if (
        -not [string]::IsNullOrWhiteSpace($runnerErrorText) -or
        $runnerOutputText -notmatch "Librarian development session ended\."
    ) {
        throw (
            "The development runner did not report successful cleanup. " +
            "Logs: $runnerOutput, $runnerError"
        )
    }

    Write-Host "Windows shell UI smoke test passed."
    Write-Host "State: $(if ($firstRun) { 'First run' } else { 'Locked' })"
    Write-Host "Initial focus: $expectedFocusName"
}
finally {
    Close-ExpectedDesktop -Process $desktopProcess
    if ($null -ne $runnerProcess) {
        try {
            $runnerProcess.Refresh()
            if (-not $runnerProcess.HasExited) {
                Wait-Process -Id $runnerProcess.Id -Timeout 30 -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Preserve the runner so it can finish its own package cleanup.
        }
    }
}
