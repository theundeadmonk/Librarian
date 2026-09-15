# Local helper, invoked only by disposable PowerShell build/check processes.
# It does not change the user's or machine's persisted environment or SDK install.
$ErrorActionPreference = 'Stop'
$issue17SdkRoot = Join-Path $PSScriptRoot 'artifacts\toolchains\dotnet-sdk-10.0.302-win-x64'
$issue17DotNet = Join-Path $issue17SdkRoot 'dotnet.exe'
if (-not (Test-Path -LiteralPath $issue17DotNet -PathType Leaf)) {
    throw "The verified project-local SDK is missing: $issue17DotNet"
}
$issue17Signature = Get-AuthenticodeSignature -LiteralPath $issue17DotNet
if ($issue17Signature.Status -ne 'Valid' -or $issue17Signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'The project-local .NET host does not have a valid Microsoft signature.'
}
Set-Location -LiteralPath $PSScriptRoot
# bootstrap also launches tools through ProcessStartInfo without WorkingDirectory.
[Environment]::CurrentDirectory = $PSScriptRoot
$env:Path = $issue17SdkRoot + ';' + $env:Path
$env:DOTNET_ROOT = $issue17SdkRoot
$env:DOTNET_ROOT_X64 = $issue17SdkRoot
$issue17ActualSdk = & $issue17DotNet --version
if ($LASTEXITCODE -ne 0 -or $issue17ActualSdk -cne '10.0.302') {
    throw "Expected project-local SDK 10.0.302, got '$issue17ActualSdk'."
}
Write-Host "Project-local .NET SDK: $issue17ActualSdk ($issue17DotNet)"
