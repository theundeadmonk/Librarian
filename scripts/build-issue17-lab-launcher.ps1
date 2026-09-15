[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Stage,
    [Parameter(Mandatory)][string]$PackageName,
    [Parameter(Mandatory)][string]$MSBuild
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'issue17-fixture-helpers.ps1')
$Stage=[IO.Path]::GetFullPath($Stage)
if($PackageName -cnotmatch '^Librarian\.I17\.R[0-9a-f]{24}$' -or
    $Stage -cne (Join-Path $repo ('artifacts\authlab-'+$PackageName))){throw 'Unexpected launcher lab scope.'}
Assert-Issue17PlainDirectory $Stage
$sourceRoot=Join-Path $repo 'packaging\windows\identity-launcher'
$buildRoot=Join-Path $Stage 'launcher-source'
if(Test-Path -LiteralPath $buildRoot){throw 'Launcher build must be fresh.'}
New-Item -ItemType Directory -Path (Join-Path $buildRoot 'src') | Out-Null
foreach($file in @('Librarian.IdentityLauncher.vcxproj','packages.lock.json','app.manifest',
    'src\main.cpp','src\LaunchOperation.h','src\NativeHostStartup.h','src\RegistrationFailure.h')){
    Copy-Item -LiteralPath (Join-Path $sourceRoot $file) -Destination (Join-Path $buildRoot $file)
}
# Generate a test-only translation unit. No product source, validation branch,
# timeout, signature/identity policy, or native stdio behavior is changed.
$path=Join-Path $buildRoot 'src\main.cpp'
$original=[IO.File]::ReadAllText($path)
$registration=(Join-Path $repo 'platform\windows-passkey\include\librarian\windows_passkey\registration.h').Replace('\','/')
$edits=@(
    @('L"TheUndeadMonk.Librarian.Development"',('L"'+$PackageName+'"')),
    @('L"CN=Librarian Development"','L"CN=Librarian Issue17 Test Only"'),
    @('(program_files / L"Librarian").lexically_normal()',('(program_files / L"LibrarianIssue17Lab" / L"'+$PackageName+'").lexically_normal()')),
    @('#include "../../../../platform/windows-passkey/include/librarian/windows_passkey/registration.h"',('#include "'+$registration+'"'))
)
$generated=$original
foreach($edit in $edits){
    if(([regex]::Matches($generated,[regex]::Escape($edit[0]))).Count -ne 1){throw 'Production launcher substitution was not unique.'}
    $generated=$generated.Replace($edit[0],$edit[1])
}
$roundTrip=$generated
for($i=$edits.Count-1;$i -ge 0;$i--){$roundTrip=$roundTrip.Replace($edits[$i][1],$edits[$i][0])}
if($roundTrip -cne $original){throw 'Launcher source changed outside the four declared test substitutions.'}
[IO.File]::WriteAllText($path,$generated,[Text.UTF8Encoding]::new($false))
$arguments=@((Join-Path $buildRoot 'Librarian.IdentityLauncher.vcxproj'),'/restore','/t:Build','/nr:false',
    '/p:Configuration=Release','/p:Platform=x64','/p:RestoreLockedMode=true',('/p:RepoRoot='+$repo),
    ('/p:OutDir='+(Join-Path $buildRoot 'bin').Replace('\','/')+'/'),('/p:IntDir='+(Join-Path $buildRoot 'obj').Replace('\','/')+'/'),'/verbosity:minimal')
& $MSBuild @arguments
if($LASTEXITCODE){throw 'Production-logic lab launcher build failed.'}
Copy-Item -LiteralPath (Join-Path $buildRoot 'bin\Librarian.IdentityLauncher.exe') -Destination (Join-Path $Stage 'payload\Librarian.IdentityLauncher.exe')
@{testOnly=$true;sourceSha256=(Get-FileHash -LiteralPath (Join-Path $sourceRoot 'src\main.cpp')).Hash;
  generatedSha256=(Get-FileHash -LiteralPath $path).Hash;sourceRoundTrip='Passed';
  substitutions=@('package name','publisher','protected install subdirectory','absolute unchanged header include');
  validationLogic='unchanged production launcher source';productionInstallAcceptance=$false} |
    ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Stage 'launcher-evidence.json') -Encoding UTF8
