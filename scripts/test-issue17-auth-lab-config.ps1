[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'issue17-auth-lab-config.ps1')
$fixtures=Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\.codex-issue17-fill-fixtures.json') -Raw | ConvertFrom-Json
$name='Librarian.I17.R0123456789abcdef01234567'
$stage='C:\LibrarianTest\authlab-'+$name
foreach($browser in @('chrome','edge')){
    foreach($batch in @('Initial','Extended')){
        $config=New-Issue17LabBrowserConfiguration -Stage $stage -PackageName $name -Browser $browser -Batch $batch -Fixtures $fixtures
        $decoded=$config | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        $expected=$(if($batch -ceq 'Extended'){4}else{0})
        if(-not($decoded.additionalAccounts -is [Array]) -or $decoded.additionalAccounts.Count -ne $expected){throw 'Serialized fixture list must be a real array of the expected size.'}
        if($decoded.account.origin -cne 'https://librarian.test' -or $decoded.labPackage -cne $name -or $decoded.browser -cne $browser -or $decoded.batch -cne $batch){throw 'Serialized fixture identity changed.'}
        if($decoded.reportPath -cne ($stage+'\results\'+$browser+'-'+$batch+'\fill-'+$browser+'.json')){throw 'Report path escaped the exact test batch.'}
        Write-Output ('PASS '+$browser+' '+$batch+' serialized lab configuration')
    }
}
$refused=$false
try{[void](New-Issue17LabBrowserConfiguration -Stage $stage -PackageName 'TheUndeadMonk.Librarian.Development' -Browser chrome -Batch Initial -Fixtures $fixtures)}catch{$refused=$true}
if(-not $refused){throw 'Ordinary product configuration was not refused.'}
Write-Output 'PASS ordinary product configuration refused'
foreach($case in @(
    @{Package='TheUndeadMonk.Librarian.Development';Stage=$stage},
    @{Package=$name;Stage='C:\Program Files\Librarian'},
    @{Package=$name;Stage=(Join-Path $PSScriptRoot '..\artifacts\wrong-stage')}
)){
    $refused=$false
    try{& (Join-Path $PSScriptRoot 'build-issue17-lab-launcher.ps1') -Stage $case.Stage -PackageName $case.Package -MSBuild 'must-not-launch'}
    catch{$refused=$_.Exception.Message -ceq 'Unexpected launcher lab scope.'}
    if(-not $refused){throw 'Lab launcher accepted an ordinary or mismatched scope.'}
}
Write-Output 'PASS launcher rejects ordinary identities and mismatched staging paths before writing or building'
