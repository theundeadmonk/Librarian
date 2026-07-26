[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$layoutDirectory = Join-Path $repoRoot "$Platform\$Configuration\Librarian.Windows"
$manifestPath = Join-Path $layoutDirectory "AppxManifest.xml"
$executablePath = Join-Path $layoutDirectory "Librarian.Windows.exe"

foreach ($requiredPath in @($manifestPath, $executablePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required Windows shell output is missing: $requiredPath. Run the Release|x64 build first."
    }
}

if (-not [Environment]::UserInteractive) {
    throw "The Windows shell UI smoke test requires an interactive desktop session."
}

[xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
$namespaceManager = [System.Xml.XmlNamespaceManager]::new($manifest.NameTable)
$namespaceManager.AddNamespace(
    "foundation",
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
)

$identity = $manifest.SelectSingleNode(
    "/foundation:Package/foundation:Identity",
    $namespaceManager
)
$application = $manifest.SelectSingleNode(
    "/foundation:Package/foundation:Applications/foundation:Application",
    $namespaceManager
)
if ($null -eq $identity -or $null -eq $application) {
    throw "The generated package manifest does not contain one package identity and application."
}

$packageName = [string]$identity.Name
$applicationId = [string]$application.Id
$registeredByScript = $false
$package = $null
$process = $null

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

try {
    $existingPackages = @(Get-AppxPackage -Name $packageName)
    if ($existingPackages.Count -gt 1) {
        throw "More than one package is registered for the development identity '$packageName'."
    }

    if ($existingPackages.Count -eq 1) {
        $package = $existingPackages[0]
        if (-not (Test-SamePath -First $package.InstallLocation -Second $layoutDirectory)) {
            throw (
                "The development identity '$packageName' is already registered from " +
                "'$($package.InstallLocation)'. Refusing to replace it with '$layoutDirectory'."
            )
        }
        if ($package.Status -ne "Ok") {
            throw "The existing development package is not healthy: $($package.Status)."
        }
        if (-not $package.IsDevelopmentMode) {
            throw "The existing package uses the development identity but is not development-mode."
        }
    }
    else {
        try {
            Add-AppxPackage -Register $manifestPath
        }
        catch {
            throw (
                "Unable to register the loose Windows shell layout. Verify Developer Mode and " +
                "Windows App Runtime 2.3.1, then retry. $($_.Exception.Message)"
            )
        }

        $registeredByScript = $true
        $package = Get-AppxPackage -Name $packageName
        if ($null -eq $package -or $package.Status -ne "Ok") {
            throw "The development package was not healthy after loose registration."
        }
    }

    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes

    $knownProcessIds = @(
        Get-CimInstance Win32_Process -Filter "Name='Librarian.Windows.exe'" |
            Where-Object {
                $null -ne $_.ExecutablePath -and
                (Test-SamePath -First $_.ExecutablePath -Second $executablePath)
            } |
            Select-Object -ExpandProperty ProcessId
    )

    $applicationUserModelId = "$($package.PackageFamilyName)!$applicationId"
    Start-Process -FilePath "explorer.exe" -ArgumentList (
        "shell:AppsFolder\$applicationUserModelId"
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $candidate = Get-CimInstance Win32_Process -Filter "Name='Librarian.Windows.exe'" |
            Where-Object {
                $null -ne $_.ExecutablePath -and
                (Test-SamePath -First $_.ExecutablePath -Second $executablePath) -and
                $_.ProcessId -notin $knownProcessIds
            } |
            Select-Object -First 1
        if ($null -ne $candidate) {
            $process = Get-Process -Id $candidate.ProcessId -ErrorAction Stop
        }
    } while ($null -eq $process -and [DateTime]::UtcNow -lt $deadline)

    if ($null -eq $process) {
        throw "Package activation did not start the expected Librarian process within 20 seconds."
    }

    $window = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $process.Refresh()
        if ($process.HasExited) {
            throw "Librarian exited before exposing a window. Exit code: $($process.ExitCode)."
        }

        $processCondition = [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty,
            $process.Id
        )
        $window = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [System.Windows.Automation.TreeScope]::Children,
            $processCondition
        )
    } while ($null -eq $window -and [DateTime]::UtcNow -lt $deadline)

    if ($null -eq $window) {
        throw "Librarian did not expose a top-level accessibility window within 20 seconds."
    }

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

    $focusedName = ""
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        Start-Sleep -Milliseconds 100
        $focusedElement = [System.Windows.Automation.AutomationElement]::FocusedElement
        if (
            $null -ne $focusedElement -and
            $focusedElement.Current.ProcessId -eq $process.Id
        ) {
            $focusedName = $focusedElement.Current.Name
        }
    } while (
        $focusedName -ne "Retry vault agent connection" -and
        [DateTime]::UtcNow -lt $deadline
    )

    $checks = [ordered]@{
        "Window title" = $window.Current.Name -eq "Librarian"
        "Fail-closed state" = $accessibleNames -contains "Vault agent unavailable"
        "Retry action" = $accessibleNames -contains "Retry vault agent connection"
        "Initial keyboard focus" = $focusedName -eq "Retry vault agent connection"
    }

    foreach ($check in $checks.GetEnumerator()) {
        if (-not $check.Value) {
            throw "Windows shell UI smoke check failed: $($check.Key)."
        }
        Write-Host "[PASS] $($check.Key)"
    }

    Write-Host "Windows shell packaged UI smoke test passed."
}
finally {
    if ($null -ne $process) {
        $process.Refresh()
        if (-not $process.HasExited) {
            $actualPath = $process.Path
            if (Test-SamePath -First $actualPath -Second $executablePath) {
                Stop-Process -Id $process.Id -Force
                Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
            }
            else {
                Write-Warning (
                    "Did not stop process $($process.Id) because its executable path changed to " +
                    "'$actualPath'."
                )
            }
        }
    }

    if ($registeredByScript) {
        try {
            $packageToRemove = $package
            if ($null -eq $packageToRemove) {
                $packageToRemove = Get-AppxPackage -Name $packageName |
                    Where-Object {
                        $_.IsDevelopmentMode -and
                        (Test-SamePath -First $_.InstallLocation -Second $layoutDirectory)
                    } |
                    Select-Object -First 1
            }

            if (
                $null -ne $packageToRemove -and
                $packageToRemove.IsDevelopmentMode -and
                (Test-SamePath -First $packageToRemove.InstallLocation -Second $layoutDirectory)
            ) {
                Remove-AppxPackage -Package $packageToRemove.PackageFullName
            }

            $remainingRegistration = Get-AppxPackage -Name $packageName |
                Where-Object {
                    $_.IsDevelopmentMode -and
                    (Test-SamePath -First $_.InstallLocation -Second $layoutDirectory)
                } |
                Select-Object -First 1
            if ($null -ne $remainingRegistration) {
                throw (
                    "The temporary development package remains registered as " +
                    "'$($remainingRegistration.PackageFullName)'."
                )
            }
        }
        catch {
            throw (
                "The UI smoke test could not remove the development package registration it " +
                "created: $($_.Exception.Message)"
            )
        }
    }
}
