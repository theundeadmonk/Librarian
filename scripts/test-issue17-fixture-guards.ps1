[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'issue17-fixture-helpers.ps1')
$sample = [ordered]@{
    schemaVersion=1; testOnly=$true; outcome='Passed'; failure=$null
    evidenceScope='isolated in-process production runtime'; expectedAccountCount=5; createdAccounts=5
    vaultFile='vault.sqlite3'; existingVaultAccessed=$false
    installedBrowserAcceptance='NotRun'; uiAcceptance='NotRun'; osPeerAuthentication='NotRun'
    checks=@(Get-Issue17FixtureCheckNames | ForEach-Object { @{name=$_;passed=$true} })
}
$json = $sample | ConvertTo-Json -Depth 6
Assert-Issue17FixtureReport ($json | ConvertFrom-Json)
foreach ($mutation in @('missing','substituted','failed','string-boolean','wrong-count','false-ui-pass','false-installed-pass','existing-vault','partial')) {
    $report = $json | ConvertFrom-Json
    switch ($mutation) {
        'missing' { $report.checks = @($report.checks | Select-Object -Skip 1) }
        'substituted' { $report.checks[1].name = $report.checks[0].name }
        'failed' { $report.checks[0].passed = $false }
        'string-boolean' { $report.checks[0].passed = 'true' }
        'wrong-count' { $report.createdAccounts = 4 }
        'false-ui-pass' { $report.uiAcceptance = 'Passed' }
        'false-installed-pass' { $report.installedBrowserAcceptance = 'Passed' }
        'existing-vault' { $report.existingVaultAccessed = $true }
        'partial' { $report.outcome = 'Failed'; $report.failure = 'fixture failure' }
    }
    $rejected = $false
    try { Assert-Issue17FixtureReport $report } catch { $rejected = $true }
    if (-not $rejected) { throw "Accepted invalid fixture report: $mutation" }
}
foreach ($name in @('issue17-fixture-helpers.ps1','test-issue17-fixture.ps1','test-issue17-fixture-guards.ps1','test-issue17-native-runtime.ps1',
    'issue17-auth-lab-config.ps1','test-issue17-auth-lab-config.ps1','build-issue17-lab-launcher.ps1')) {
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "PowerShell syntax failed: $name" }
}
Write-Host 'PASS: exact 43-check result, account counts, boolean outcomes, evidence scope, and script syntax.'
& (Join-Path $PSScriptRoot 'test-issue17-auth-lab-config.ps1')
