[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'issue17-fixture-helpers.ps1')
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Assert-Issue17PlainDirectory $repo
$originalLocation = Get-Location
try {
    Set-Location -LiteralPath $repo
    # An example target is deliberately excluded from the default product build.
    $metadata = (& cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $package = @($metadata.packages | Where-Object name -CEQ 'librarian-vault-agent')
    $target = @($package.targets | Where-Object name -CEQ 'issue17-fixture')
    if ($package.Count -ne 1 -or $target.Count -ne 1 -or
        @($target[0].kind).Count -ne 1 -or $target[0].kind[0] -cne 'example' -or -not $target[0].test) {
        throw 'Fixture must remain an explicitly tested example, never a product binary.'
    }
    & cargo test --locked -p librarian-vault-agent --example issue17-fixture --target x86_64-pc-windows-msvc -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'Fixture safety/runtime tests failed.' }
    & cargo build --release --locked -p librarian-vault-agent --example issue17-fixture --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Fixture build failed.' }
    $executable = Join-Path $repo 'target\x86_64-pc-windows-msvc\release\examples\issue17-fixture.exe'
    $artifacts = Join-Path $repo 'artifacts'
    Assert-Issue17PlainDirectory $artifacts
    $runId = 'issue17-synthetic-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
    $output = Join-Path $artifacts $runId
    # Tool creates this exact NEW directory; no overwrite, installer, or trust.
    $stdout = @(& $executable --new-directory $output)
    $fixtureExit = $LASTEXITCODE
    if ($fixtureExit -ne 0) { throw "Isolated fixture failed (exit $fixtureExit). Partial evidence retained in $output." }
    $reportPath = Join-Path $output 'report.json'
    if ((Get-Item -LiteralPath $reportPath).Length -gt 65536) { throw 'Fixture report exceeds its bound.' }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    Assert-Issue17FixtureReport $report
    $stdoutReport = ($stdout -join "`n") | ConvertFrom-Json
    Assert-Issue17FixtureReport $stdoutReport
    if (($stdout -join "`n").Trim() -cne (Get-Content -LiteralPath $reportPath -Raw).Trim()) {
        throw 'Fixture stdout and saved report disagree.'
    }
    [pscustomobject]@{
        outcome='Passed'; runId=$runId; resultsPath=$output; reportPath=$reportPath
        executable=$executable; sha256=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
        checks=@($report.checks).Count; createdAccounts=$report.createdAccounts
        evidenceScope=$report.evidenceScope; installedBrowserAcceptance='NotRun'; uiAcceptance='NotRun'
    }
} finally { Set-Location -LiteralPath $originalLocation.Path }
