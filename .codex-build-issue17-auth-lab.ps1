[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '.codex-use-issue17-toolchain.ps1')
. (Join-Path $PSScriptRoot 'scripts\issue17-fixture-helpers.ps1')
Assert-Issue17PlainDirectory $PSScriptRoot
$tools = & (Join-Path $PSScriptRoot 'scripts\bootstrap.ps1') -PassThru
& (Join-Path $PSScriptRoot 'scripts\test-issue17-auth-lab-config.ps1')
& cargo test --locked -p librarian-vault-agent --example issue17-auth-client
if($LASTEXITCODE){throw 'Authenticated lab client tests failed.'}
& cargo build --locked --release --target x86_64-pc-windows-msvc -p librarian-vault-agent -p librarian-chromium-native-host
if($LASTEXITCODE){throw 'Production components failed to build.'}
& cargo build --locked --release --target x86_64-pc-windows-msvc -p librarian-vault-agent --example issue17-auth-client
if($LASTEXITCODE){throw 'Authenticated lab client build failed.'}
& $tools.Npm run build:extension
if($LASTEXITCODE){throw 'Extension build failed.'}
$name='Librarian.I17.R'+[guid]::NewGuid().ToString('N').Substring(0,24)
$stage=Join-Path $PSScriptRoot ('artifacts\authlab-'+$name)
$payload=Join-Path $stage 'payload'
$layout=Join-Path $stage 'identity'
$extension=Join-Path $stage 'extension'
New-Item -ItemType Directory -Path $stage,$payload,$layout,$extension | Out-Null
$sdk=Join-Path $tools.WindowsSdkRoot ('bin\'+$tools.Versions.WindowsSdk+'\x64')
$mt=Join-Path $sdk 'mt.exe'
$makeappx=Join-Path $sdk 'makeappx.exe'
$sign=Join-Path $sdk 'signtool.exe'
foreach($tool in @($mt,$makeappx,$sign)){if(-not(Test-Path -LiteralPath $tool -PathType Leaf)){throw 'Pinned SDK tool missing.'}}
$release=Join-Path $PSScriptRoot 'target\x86_64-pc-windows-msvc\release'
foreach($item in @(
    @{Source='librarian-vault-agent.exe';Name='Librarian.VaultAgent.exe';Role='VaultAgent'},
    @{Source='librarian-chromium-native-host.exe';Name='Librarian.ChromiumNativeHost.exe';Role='ChromiumNativeHost'},
    @{Source='examples\issue17-auth-client.exe';Name='Librarian.Windows.exe';Role='Desktop'}
)){
    $dest=Join-Path $payload $item.Name
    Copy-Item -LiteralPath (Join-Path $release $item.Source) -Destination $dest
    [xml]$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'platform\chromium-native-host\app.manifest')
    $msix=$manifest.assembly.msix
    if($item.Role){$msix.SetAttribute('packageName',$name);$msix.SetAttribute('publisher','CN=Librarian Issue17 Test Only');$msix.SetAttribute('applicationId',$item.Role)}
    else{[void]$manifest.assembly.RemoveChild($msix)}
    $manifestPath=Join-Path $stage ($item.Name+'.manifest')
    $manifest.Save($manifestPath)
    & $mt '-nologo' '-manifest' $manifestPath ('-outputresource:'+ $dest + ';#1')
    if($LASTEXITCODE){throw 'Lab identity resource stamping failed.'}
}
& (Join-Path $PSScriptRoot 'scripts\build-issue17-lab-launcher.ps1') -Stage $stage -PackageName $name -MSBuild $tools.MSBuild
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'artifacts\installer\payload\Librarian.PasskeyProvider.exe') -Destination $payload
@{testOnly=$true;packageName=$name;version='0.1.0.0'} | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $payload 'Librarian.Release.json') -Encoding UTF8
[xml]$package=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'packaging\msix\identity\AppxManifest.xml.in') -Raw).Replace('@PACKAGE_VERSION@','0.1.0.0')
$package.Package.Identity.SetAttribute('Name',$name)
$package.Package.Identity.SetAttribute('Publisher','CN=Librarian Issue17 Test Only')
$package.Package.Properties.DisplayName='Librarian Issue17 TEST ONLY'
$package.Package.Properties.PublisherDisplayName='Librarian Issue17 TEST ONLY'
$provider=@($package.Package.Applications.Application | Where-Object Id -eq 'PasskeyProvider')[0]
[void]$package.Package.Applications.RemoveChild($provider)
$package.Save((Join-Path $layout 'AppxManifest.xml'))
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'artifacts\installer\payload\Assets') -Destination $payload -Recurse
& $makeappx pack /o /nv /d $layout /p (Join-Path $payload 'Librarian.Identity.msix')
if($LASTEXITCODE){throw 'Lab identity package build failed.'}
$hostName='com.theundeadmonk.librarian.issue17r'+$name.Substring('Librarian.I17.R'.Length)
$extensionId='jiifjoajanfeoabbkmpodkgfmabhikkh'
$install='C:\Program Files\LibrarianIssue17Lab\'+$name
foreach($browser in @('chrome','edge')){
    $json=@{name='com.theundeadmonk.librarian';description='Librarian browser bridge';path='Librarian.IdentityLauncher.exe';type='stdio';allowed_origins=@("chrome-extension://$extensionId/")} | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $payload "com.theundeadmonk.librarian.$browser.json"),$json,[Text.UTF8Encoding]::new($false))
}
$json=@{name=$hostName;description='Librarian isolated Issue17 TEST ONLY';path=($install+'\Librarian.IdentityLauncher.exe');type='stdio';allowed_origins=@("chrome-extension://$extensionId/")} | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $payload 'lab-native-host.json'),$json,[Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'apps\browser-extension\manifest.json') -Destination $extension
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'apps\browser-extension\dist') -Destination $extension -Recurse
$backgroundPath=Join-Path $extension 'dist\background.js'
$background=[IO.File]::ReadAllText($backgroundPath)
if(([regex]::Matches($background,'"com\.theundeadmonk\.librarian"')).Count -ne 1){throw 'Expected exactly one native host configuration constant.'}
[IO.File]::WriteAllText($backgroundPath,$background.Replace('"com.theundeadmonk.librarian"',('"'+$hostName+'"')),[Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath $tools.Node -Destination (Join-Path $stage 'node.exe')
Copy-Item -LiteralPath $sign -Destination (Join-Path $stage 'signtool.exe')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'scripts\issue17-auth-lab-config.ps1') -Destination $stage
foreach($file in @('.codex-issue17-fill-probe.mjs','.codex-issue17-extended-cases.mjs','.codex-issue17-fill-fixtures.json','.codex-exercise-issue17-auth-lab.ps1')){
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $stage
}
$inventory=@(Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object {
    @{path=$_.FullName.Substring($stage.Length+1);sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
$sourceState=if(@(& git status --porcelain --untracked-files=no).Count){'uncommitted tracked changes; exact staged-file hashes recorded'}else{'clean tracked files; exact staged-file hashes recorded'}
$metadata=[ordered]@{testOnly=$true;packageName=$name;publisher='CN=Librarian Issue17 Test Only';hostName=$hostName;installRoot=$install;launcher='production source with four documented test-only substitutions';sourceCommit=(& git rev-parse HEAD);sourceState=$sourceState;files=$inventory}
$metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'lab.json') -Encoding UTF8
[pscustomobject]@{stage=$stage;packageName=$name;hostName=$hostName}
