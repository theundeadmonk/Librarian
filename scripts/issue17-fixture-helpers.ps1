Set-StrictMode -Version Latest

function Get-Issue17FixtureCheckNames {
    $origins = @(
        'baseline exact origin and single-use disclosure',
        'non-default port exact match and single-use disclosure',
        'Unicode stored account matches canonical IDN wire origin',
        'omitted non-default port refuses', 'different non-default port refuses',
        'IDN ASCII lookalike refuses', 'IDN subdomain refuses', 'IDN different port refuses',
        'two known accounts at exact origin refuse', 'duplicate account different port refuses',
        'baseline hostname suffix refuses', 'raw HTTP native origin rejected',
        'raw Unicode native origin rejected', 'zero-padded native port rejected',
        'explicit default native port rejected', 'native origin containing path rejected'
    )
    @('fresh encrypted vault created', 'five synthetic accounts created via runtime') + $origins + @(
        'explicit lock changes runtime state', 'selected credential unavailable after lock',
        'locked vault refuses new origin request', 'exactly five accounts persist on disk',
        'all synthetic fields and duplicate setup verified', 'restart begins locked',
        'synthetic fixture unlocks after restart'
    ) + $origins + @(
        'fixture runtime shut down with keys discarded',
        'bounded database and sidecar plaintext-canary scan'
    )
}

function Assert-Issue17FixtureReport {
    param([Parameter(Mandatory)]$Report)
    if ($Report.schemaVersion -ne 1 -or $Report.testOnly -isnot [bool] -or -not $Report.testOnly -or
        $Report.outcome -cne 'Passed' -or $null -ne $Report.failure -or
        $Report.evidenceScope -cne 'isolated in-process production runtime' -or
        $Report.expectedAccountCount -ne 5 -or $Report.createdAccounts -ne 5 -or
        $Report.vaultFile -cne 'vault.sqlite3' -or
        $Report.existingVaultAccessed -isnot [bool] -or $Report.existingVaultAccessed -or
        $Report.installedBrowserAcceptance -cne 'NotRun' -or $Report.uiAcceptance -cne 'NotRun' -or
        $Report.osPeerAuthentication -cne 'NotRun') {
        throw 'Fixture result has an invalid outcome, account count, or evidence scope.'
    }
    $expected = @(Get-Issue17FixtureCheckNames)
    if (@($Report.checks).Count -ne $expected.Count) { throw 'Fixture result omitted required checks.' }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($Report.checks[$index].name -cne $expected[$index] -or
            $Report.checks[$index].passed -isnot [bool] -or -not $Report.checks[$index].passed) {
            throw 'Fixture result has a failed, missing, reordered, or substituted check.'
        }
    }
}

function Assert-Issue17PlainDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -notmatch '^[A-Za-z]:\\' -or $resolved -match ':.*:') {
        throw 'Fixture directories must be local absolute paths without streams.'
    }
    for ($cursor = $resolved; $cursor; $cursor = [IO.Path]::GetDirectoryName($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Fixture directory ancestors must be plain directories, not reparse points.'
        }
    }
}
