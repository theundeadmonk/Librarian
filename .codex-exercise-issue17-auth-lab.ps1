[CmdletBinding()]
param([Parameter(Mandatory)][string]$Stage)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:COMPUTERNAME -cne 'LIBRARIAN-TEST' -or $Stage -cnotmatch '^C:\\LibrarianTest\\authlab-Librarian\.I17\.R[0-9a-f]{24}$'){throw 'Wrong authenticated lab scope.'}
$lab=Get-Content -LiteralPath (Join-Path $Stage 'lab.json') -Raw | ConvertFrom-Json
if($lab.packageName -cnotmatch '^Librarian\.I17\.R[0-9a-f]{24}$' -or $lab.installRoot -cne ('C:\Program Files\LibrarianIssue17Lab\'+$lab.packageName)){throw 'Invalid lab identity.'}
. (Join-Path $Stage 'issue17-auth-lab-config.ps1')
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Lab tests must run non-elevated.'}
$output=Join-Path $Stage 'results'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$result=[ordered]@{outcome='Failed';stage='Start';testOnly=$true;packageName=$lab.packageName;userVaultAccessed=$false;osPeerAuthentication='NotRun';browsers=@();failure=$null;cleanup='NotRun'}
$agent=$null;$registered=$false
function Save-State([string]$name){$result.stage=$name;$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'status.json') -Encoding UTF8}
function Invoke-Client([string]$operation){
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=Join-Path $lab.installRoot 'Librarian.Windows.exe'
    $info.Arguments=$operation;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    if(-not $process.Start()){throw 'Lab client launch failed.'}
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(90000)){$process.Kill();throw 'Owned lab client timed out.'}
    $text=$stdout.GetAwaiter().GetResult();$errorText=$stderr.GetAwaiter().GetResult()
    if($text.Length -gt 65536 -or $errorText.Length -gt 4096){throw 'Lab client diagnostic bound exceeded.'}
    if($process.ExitCode -ne 0){throw ('Lab client failed: '+$errorText.Trim())}
    $value=$text | ConvertFrom-Json
    if($value.testOnly -ne $true -or $value.outcome -cne 'Passed' -or $value.authenticatedWindowsIpc -ne $true){throw 'Lab client returned invalid evidence.'}
    return $value
}
try {
    if(@(Get-Process -Name 'Librarian.VaultAgent','Librarian.Windows' -ErrorAction SilentlyContinue | Where-Object SessionId -eq ([Diagnostics.Process]::GetCurrentProcess().SessionId)).Count){throw 'Another Librarian instance owns this Windows session; close it before starting the lab.'}
    Save-State 'Register isolated package'
    if(@(Get-AppxPackage -Name $lab.packageName).Count){throw 'Lab package already registered; refusing implicit reuse.'}
    Add-AppxPackage -Path (Join-Path $lab.installRoot 'Librarian.Identity.msix') -ExternalLocation $lab.installRoot
    $registered=$true
    $package=Get-AppxPackage -Name $lab.packageName
    if(@($package).Count -ne 1 -or $package.Publisher -cne $lab.publisher){throw 'Registered lab package mismatch.'}
    $result.packageFullName=$package.PackageFullName
    Save-State 'Start actual vault agent'
    $agent=Start-Process -FilePath (Join-Path $lab.installRoot 'Librarian.VaultAgent.exe') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $output 'agent.stdout') -RedirectStandardError (Join-Path $output 'agent.stderr')
    $ready=$false
    for($attempt=0;$attempt -lt 20;$attempt++){
        Start-Sleep -Milliseconds 250
        if($agent.HasExited){
            $result.agentExitCode=$agent.ExitCode
            $diagnostic=Get-Content -LiteralPath (Join-Path $output 'agent.stderr') -Raw
            if($diagnostic -and $diagnostic.Length -le 4096){$result.agentDiagnostic=$diagnostic.Trim()}
            throw 'Actual lab vault agent exited during startup.'
        }
        try{$state=Invoke-Client '--status';if($state.state -ceq 'NoVault'){$ready=$true;break}}catch{if($attempt -eq 19){throw}}
    }
    if(-not $ready){throw 'Expected a fresh authenticated NoVault agent.'}
    $result.osPeerAuthentication='Passed (real Desktop-role handshake)'
    Save-State 'Create fixed accounts through authenticated Windows IPC'
    $seed=Invoke-Client '--seed'
    if($seed.state -cne 'Unlocked'){throw 'Authenticated seeding failed.'}
    $result.osPeerAuthentication='Passed';$result.createdAccounts=5
    $seed | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'seed.json') -Encoding UTF8
    # A repeated seed must fail, never overwrite or add duplicate fixture data.
    $refused=$false
    try{[void](Invoke-Client '--seed')}catch{$refused=$_.Exception.Message -like '*existing lab vault refused*'}
    if(-not $refused){throw 'Repeated seed was not explicitly refused.'}
    $result.seedReuseRefused=$true
    Save-State 'Verify authenticated lock and fixed-fixture unlock'
    if((Invoke-Client '--lock').state -cne 'Locked'){throw 'Authenticated lock failed.'}
    if((Invoke-Client '--unlock-fixture').state -cne 'Unlocked'){throw 'Authenticated fixture unlock failed.'}
    $result.lockUnlock='Passed'
    $fixtures=Get-Content -LiteralPath (Join-Path $Stage '.codex-issue17-fill-fixtures.json') -Raw | ConvertFrom-Json
    foreach($browser in @('chrome','edge')){
        foreach($batch in @('Initial','Extended')){
            Save-State ($browser+' '+$batch+' authenticated browser batch')
            $batchOutput=Join-Path $output ($browser+'-'+$batch)
            New-Item -ItemType Directory -Path $batchOutput | Out-Null
            $config=New-Issue17LabBrowserConfiguration -Stage $Stage -PackageName $lab.packageName -Browser $browser -Batch $batch -Fixtures $fixtures
            $configPath=Join-Path $batchOutput 'config.json'
            $config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding UTF8
            $runner=[Diagnostics.ProcessStartInfo]::new()
            $runner.FileName=Join-Path $Stage 'node.exe'
            $runner.Arguments='"'+(Join-Path $Stage '.codex-issue17-fill-probe.mjs')+'" "'+$configPath+'"'
            $runner.UseShellExecute=$false;$runner.CreateNoWindow=$true
            $runner.RedirectStandardOutput=$true;$runner.RedirectStandardError=$true
            $browserProcess=[Diagnostics.Process]::new();$browserProcess.StartInfo=$runner
            if(-not $browserProcess.Start()){throw 'Owned browser runner failed to start.'}
            $browserStdout=$browserProcess.StandardOutput.ReadToEndAsync();$browserStderr=$browserProcess.StandardError.ReadToEndAsync()
            # Leave room for the probe's three-minute suite deadline plus its
            # startup and bounded browser cleanup.
            if(-not $browserProcess.WaitForExit(240000)){$browserProcess.Kill();throw 'Owned browser runner timed out.'}
            $runnerOutput=$browserStdout.GetAwaiter().GetResult();$runnerError=$browserStderr.GetAwaiter().GetResult()
            if($runnerOutput.Length -gt 131072 -or $runnerError.Length -gt 131072){throw 'Browser runner diagnostic limit exceeded.'}
            # Raw test-runner diagnostics remain in this isolated guest stage.
            [IO.File]::WriteAllText((Join-Path $batchOutput 'runner.log'),$runnerOutput+$runnerError,[Text.UTF8Encoding]::new($false))
            $exitCode=$browserProcess.ExitCode
            if($exitCode -ne 0){throw ('Authenticated browser batch failed: '+$browser+' '+$batch)}
            $browserResult=Get-Content -LiteralPath $config.reportPath -Raw | ConvertFrom-Json
            if($browserResult.outcome -cne 'Passed'){throw 'Browser result did not pass.'}
            $result.browsers+=@{browser=$browser;batch=$batch;checks=@($browserResult.tests).Count;notRun=$browserResult.notRun}
        }
    }
    $result.outcome='Passed';Save-State 'Passed'
}catch{
    $result.failure=$_.Exception.Message
    Save-State $result.stage
}finally{
    $cleanup=@()
    if($agent -and -not $agent.HasExited){
        try{[void](Invoke-Client '--lock')}catch{$cleanup+='lab lock did not complete'}
        try{
            $current=Get-Process -Id $agent.Id -ErrorAction Stop
            if($current.StartTime -ne $agent.StartTime -or $current.Path -cne (Join-Path $lab.installRoot 'Librarian.VaultAgent.exe')){throw 'Lab agent identity changed.'}
            Stop-Process -Id $agent.Id -Force
        }catch{$cleanup+='owned agent cleanup failed'}
    }
    # Keep the isolated lab package and encrypted vault for diagnosis, not the
    # signing private key. Host runner removes this run's temporary trust/key.
    $result.cleanup=$(if($cleanup.Count){$result.outcome='Failed';$cleanup -join '; '}else{'Owned lab processes stopped; isolated package and encrypted fixture retained'})
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'status.json') -Encoding UTF8
}
