[CmdletBinding()]
param(
    [string]$NodePath = 'node',
    [string]$CargoPath = 'cargo',
    [string]$NpmPath = 'npm'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'issue17-fixture-helpers.ps1')
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Assert-Issue17PlainDirectory $repo
Assert-Issue17PlainDirectory (Join-Path $repo 'artifacts')
$originalLocation = Get-Location
try {
    Set-Location -LiteralPath $repo
    $metadata = (& $CargoPath metadata --locked --no-deps --format-version 1 | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $package = @($metadata.packages | Where-Object name -CEQ 'librarian-chromium-native-host')
    $target = @($package.targets | Where-Object name -CEQ 'issue17-stdio')
    if ($package.Count -ne 1 -or $target.Count -ne 1 -or
        @($target[0].kind).Count -ne 1 -or $target[0].kind[0] -cne 'example' -or -not $target[0].test) {
        throw 'Stdio fixture must remain an explicitly tested example, never a product binary.'
    }
    & $CargoPath build --release --locked -p librarian-chromium-native-host --example issue17-stdio --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Stdio fixture build failed.' }
    # Rebuild instead of accidentally testing stale generated extension modules.
    & $NpmPath run build:extension
    if ($LASTEXITCODE -ne 0) { throw 'Extension build failed.' }
    $executable = Join-Path $repo 'target\x86_64-pc-windows-msvc\release\examples\issue17-stdio.exe'
    & $NodePath (Join-Path $repo 'apps\browser-extension\tests\native-runtime.mjs') $executable
    if ($LASTEXITCODE -ne 0) { throw 'Native/runtime component integration failed; isolated evidence retained.' }
} finally { Set-Location -LiteralPath $originalLocation.Path }
