[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sdkVersion = "10.0.28000.0"
$sdkServicingVersion = "10.0.28000.2270"
$installerUri = "https://download.microsoft.com/download/78b533c3-6724-4e28-a984-b9fa93265781/KIT_BUNDLE_WINDOWSSDK_MEDIACREATION/winsdksetup.exe"
$installerSha256 = "E9F1BDE566381355E594E2F90DAF4F714EB5C7EF2C45C501CE236AFE2ABEA300"

$sdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$requiredFiles = @(
    (Join-Path $sdkRoot "Include\$sdkVersion\um\Windows.h")
    (Join-Path $sdkRoot "Lib\$sdkVersion\um\x64\kernel32.lib")
)
$missingFiles = @($requiredFiles | Where-Object { -not (Test-Path $_) })

if ($missingFiles.Count -eq 0) {
    Write-Host "Windows SDK $sdkServicingVersion is already installed."
    exit 0
}

$temporaryDirectory = if ($env:RUNNER_TEMP) {
    $env:RUNNER_TEMP
} else {
    [IO.Path]::GetTempPath()
}
$installer = Join-Path $temporaryDirectory "winsdksetup-$sdkServicingVersion.exe"

Write-Host "Downloading Windows SDK $sdkServicingVersion from Microsoft."
Invoke-WebRequest -Uri $installerUri -OutFile $installer

$actualSha256 = (Get-FileHash -Path $installer -Algorithm SHA256).Hash
if ($actualSha256 -ne $installerSha256) {
    throw "Windows SDK installer checksum mismatch. Expected $installerSha256 but received $actualSha256."
}

$signature = Get-AuthenticodeSignature -FilePath $installer
if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $signature.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
    throw "Windows SDK installer does not have a valid Microsoft signature."
}

$process = Start-Process `
    -FilePath $installer `
    -ArgumentList @(
        "/features"
        "OptionId.DesktopCPPx64"
        "OptionId.UWPCPP"
        "/quiet"
        "/norestart"
    ) `
    -Wait `
    -PassThru `
    -NoNewWindow

if ($process.ExitCode -notin @(0, 3010)) {
    throw "Windows SDK installer failed with exit code $($process.ExitCode)."
}

$missingFiles = @($requiredFiles | Where-Object { -not (Test-Path $_) })
if ($missingFiles.Count -gt 0) {
    throw "Windows SDK installation completed without the required files: $($missingFiles -join ', ')"
}

Write-Host "Windows SDK $sdkServicingVersion is installed."
