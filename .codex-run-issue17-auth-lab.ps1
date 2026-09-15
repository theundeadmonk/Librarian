[CmdletBinding()]
param([Parameter(Mandatory)][string]$Stage)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '.codex-hyperv-access.ps1')
. (Join-Path $PSScriptRoot 'scripts\issue17-fixture-helpers.ps1')
Assert-LibrarianHyperVHostAccess
if($env:COMPUTERNAME -cne 'ADITYA-DESKTOP' -or $PSScriptRoot -cne 'C:\Users\adity\Documents\ChatGPT\Librarian 3'){throw 'Unexpected host/workspace.'}
$Stage=[IO.Path]::GetFullPath($Stage)
if((Split-Path $Stage -Parent) -cne (Join-Path $PSScriptRoot 'artifacts') -or (Split-Path $Stage -Leaf) -cnotmatch '^authlab-Librarian\.I17\.R[0-9a-f]{24}$'){throw 'Unexpected lab staging path.'}
Assert-Issue17PlainDirectory $Stage
$lab=Get-Content -LiteralPath (Join-Path $Stage 'lab.json') -Raw | ConvertFrom-Json
if((Split-Path $Stage -Leaf) -cne ('authlab-'+$lab.packageName)){throw 'Lab staging identity mismatch.'}
$vmId='1c727738-cf97-494f-ae16-486bfa7a2ea4'
if((Get-VM -Id $vmId).State -ne 'Running'){throw 'The exact lab VM must be running.'}
$credential=[Management.Automation.PSCredential]::new('LibrarianTest',(ConvertTo-SecureString 'LibrarianTest!2026' -AsPlainText -Force))
$session=New-PSSession -VMId $vmId -Credential $credential
$guestStage='C:\LibrarianTest\'+(Split-Path $Stage -Leaf)
$taskName='Librarian-AuthLab-'+$lab.packageName
$hostOutput=Join-Path $Stage 'vm-results'
New-Item -ItemType Directory -Path $hostOutput | Out-Null
$prepared=$false;$taskCreated=$false
try {
    Invoke-Command -Session $session -ArgumentList $guestStage -ScriptBlock {
        param($stage)
        if($env:COMPUTERNAME -cne 'LIBRARIAN-TEST' -or (Test-Path -LiteralPath $stage)){throw 'Unexpected guest or existing stage.'}
        if(-not(Get-Process explorer -ErrorAction SilentlyContinue)){throw 'No interactive test session is available.'}
    }
    $archive=$Stage+'.zip'
    if(Test-Path -LiteralPath $archive){throw 'Lab transfer archive already exists.'}
    Compress-Archive -LiteralPath $Stage -DestinationPath $archive -CompressionLevel Fastest
    $archiveHash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    $guestArchive=$guestStage+'.zip'
    try{Copy-Item -ToSession $session -LiteralPath $archive -Destination $guestArchive}catch{
        # PowerShell Direct may finish writing then fail setting a timestamp
        # while Windows scans the file. Only a full independent hash match can
        # make such a transfer usable; no partial copy is accepted.
        Write-Host 'Archive copy reported an error; checking its complete hash before continuing.'
    }
    Invoke-Command -Session $session -ArgumentList $guestArchive,$archiveHash,$guestStage -ScriptBlock {
        param($archive,$expectedHash,$stage)
        $ErrorActionPreference='Stop'
        if(Test-Path -LiteralPath $stage){throw 'Lab extraction destination already exists.'}
        if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -cne $expectedHash){throw 'Lab archive hash mismatch.'}
        Expand-Archive -LiteralPath $archive -DestinationPath 'C:\LibrarianTest'
    }
    # All authority-changing actions are confined to this disposable guest and
    # new package/key names. No host trust or installed product mutation.
    $prepared=$true
    Invoke-Command -Session $session -ArgumentList $guestStage -ScriptBlock {
        param($stage)
        $ErrorActionPreference='Stop'
        $lab=Get-Content -LiteralPath (Join-Path $stage 'lab.json') -Raw | ConvertFrom-Json
        if($env:COMPUTERNAME -cne 'LIBRARIAN-TEST' -or $lab.testOnly -ne $true -or $lab.packageName -cnotmatch '^Librarian\.I17\.R[0-9a-f]{24}$' -or
            $stage -cne ('C:\LibrarianTest\authlab-'+$lab.packageName) -or $lab.installRoot -cne ('C:\Program Files\LibrarianIssue17Lab\'+$lab.packageName) -or
            $lab.hostName -cne ('com.theundeadmonk.librarian.issue17r'+$lab.packageName.Substring('Librarian.I17.R'.Length))){throw 'Guest lab scope mismatch.'}
        foreach($file in $lab.files){
            $path=[IO.Path]::GetFullPath((Join-Path $stage $file.path))
            if(-not $path.StartsWith($stage+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Inventory path escaped lab stage.'}
            for($cursorPath=$path;$cursorPath;$cursorPath=Split-Path $cursorPath -Parent){if((Get-Item -LiteralPath $cursorPath).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Redirected lab inventory.'}}
            if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $file.sha256){throw 'Lab transfer hash mismatch.'}
        }
        if(Test-Path -LiteralPath $lab.installRoot){throw 'Lab install path already exists.'}
        $parent=Split-Path $lab.installRoot -Parent
        if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent | Out-Null}
        for($cursor=Get-Item -LiteralPath $parent;$null -ne $cursor;$cursor=$cursor.Parent){if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Redirected lab install parent.'}}
        Copy-Item -LiteralPath (Join-Path $stage 'payload') -Destination $lab.installRoot -Recurse
        $certificate=New-SelfSignedCertificate -Type CodeSigningCert -Subject $lab.publisher -FriendlyName $lab.packageName -CertStoreLocation 'Cert:\LocalMachine\My' `
            -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotBefore (Get-Date).AddMinutes(-5) -NotAfter (Get-Date).AddHours(8)
        @{thumbprint=$certificate.Thumbprint;expires=$certificate.NotAfter.ToUniversalTime().ToString('o');packageName=$lab.packageName} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'signer.json') -Encoding UTF8
        $public=Join-Path $stage 'Lab.Development.cer'
        Export-Certificate -Cert $certificate -FilePath $public | Out-Null
        Import-Certificate -FilePath $public -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Import-Certificate -FilePath $public -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
        foreach($name in @('Librarian.Windows.exe','Librarian.IdentityLauncher.exe','Librarian.VaultAgent.exe','Librarian.ChromiumNativeHost.exe','Librarian.PasskeyProvider.exe','Librarian.Identity.msix')){
            $path=Join-Path $lab.installRoot $name
            & (Join-Path $stage 'signtool.exe') sign /fd SHA256 /sm /s My /sha1 $certificate.Thumbprint $path
            if($LASTEXITCODE){throw 'Guest lab signature failed.'}
            $signature=Get-AuthenticodeSignature -LiteralPath $path
            if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $certificate.Thumbprint){throw 'Guest lab signature validation failed.'}
        }
        # Same v4 hash contract consumed by the unchanged production launcher.
        # Hash after signing, and never weaken required payload coverage.
        $payloadFiles=@(Get-ChildItem -LiteralPath $lab.installRoot -File -Recurse | Sort-Object FullName)
        $fields=@('v4','0.1.0.0',[string]$payloadFiles.Count)
        foreach($file in $payloadFiles){
            $fields+=@($file.FullName.Substring($lab.installRoot.Length+1),(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash)
        }
        [IO.File]::WriteAllText((Join-Path $lab.installRoot 'Librarian.PayloadHashes'),($fields -join '|'),[Text.UTF8Encoding]::new($false))
        foreach($browserKey in @('HKCU:\Software\Google\Chrome\NativeMessagingHosts','HKCU:\Software\Microsoft\Edge\NativeMessagingHosts')){
            $key=Join-Path $browserKey $lab.hostName
            if(Test-Path -LiteralPath $key){throw 'Lab native registry key already exists.'}
            New-Item -Path $key -Force | Out-Null
            Set-Item -LiteralPath $key -Value (Join-Path $lab.installRoot 'lab-native-host.json')
        }
        [pscustomobject]@{packageName=$lab.packageName;signatures='Passed';transferHashes='Passed';expires=$certificate.NotAfter.ToUniversalTime().ToString('o')}
    }
    Invoke-Command -Session $session -ArgumentList $guestStage,$taskName -ScriptBlock {
        param($stage,$taskName)
        $ErrorActionPreference='Stop'
        if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Lab task already exists.'}
        $script=Join-Path $stage '.codex-exercise-issue17-auth-lab.ps1'
        $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$script+'" -Stage "'+$stage+'"') -WorkingDirectory $stage
        $principal=New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME+'\LibrarianTest') -LogonType Interactive -RunLevel Limited
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 12) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        Start-ScheduledTask -TaskName $taskName
    }
    $taskCreated=$true
    $deadline=(Get-Date).AddMinutes(13);$lastStage=''
    do {
        Start-Sleep -Seconds 3
        $snapshot=Invoke-Command -Session $session -ArgumentList $guestStage,$taskName -ScriptBlock {
            param($stage,$taskName)
            $path=Join-Path $stage 'results\status.json'
            [pscustomobject]@{taskState=[string](Get-ScheduledTask -TaskName $taskName).State;taskResult=(Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult;
                result=$(if(Test-Path -LiteralPath $path){Get-Content -LiteralPath $path -Raw | ConvertFrom-Json}else{$null})}
        }
        if($snapshot.result -and $snapshot.result.stage -cne $lastStage){$lastStage=$snapshot.result.stage;Write-Host $lastStage}
        if($snapshot.taskState -eq 'Ready'){break}
    }while((Get-Date) -lt $deadline)
    if($snapshot.taskState -ne 'Ready'){throw 'Authenticated lab task exceeded its limit.'}
    foreach($relative in @('results\status.json','results\seed.json','signer.json','results\chrome-Initial\fill-chrome.json','results\chrome-Extended\fill-chrome.json','results\edge-Initial\fill-edge.json','results\edge-Extended\fill-edge.json')){
        $guestPath=Join-Path $guestStage $relative
        $exists=Invoke-Command -Session $session -ArgumentList $guestPath -ScriptBlock {param($path) (Test-Path -LiteralPath $path -PathType Leaf) -and (Get-Item -LiteralPath $path).Length -lt 131072}
        if($exists){Copy-Item -FromSession $session -LiteralPath $guestPath -Destination (Join-Path $hostOutput ($relative.Replace('\','-')))}
    }
    if(-not $snapshot.result -or $snapshot.result.outcome -cne 'Passed'){throw ('Authenticated lab run failed: '+$snapshot.result.failure)}
    Write-Host ('Authenticated lab browser run passed: '+$hostOutput)
}finally{
    if($prepared){
        $cleanup=Invoke-Command -Session $session -ArgumentList $guestStage,$taskName -ScriptBlock {
            param($stage,$taskName)
            $ErrorActionPreference='Stop'
            $lab=Get-Content -LiteralPath (Join-Path $stage 'lab.json') -Raw | ConvertFrom-Json
            $errors=@()
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if($task){if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName};Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
            foreach($base in @('HKCU:\Software\Google\Chrome\NativeMessagingHosts','HKCU:\Software\Microsoft\Edge\NativeMessagingHosts')){
                $key=Join-Path $base $lab.hostName
                try{if(Test-Path -LiteralPath $key){if((Get-Item -LiteralPath $key).GetValue('') -cne (Join-Path $lab.installRoot 'lab-native-host.json')){throw 'Lab registry key changed.'};Remove-Item -LiteralPath $key -Force}}catch{$errors+='registry cleanup failed'}
            }
            $signerPath=Join-Path $stage 'signer.json'
            if(Test-Path -LiteralPath $signerPath){
                $signer=Get-Content -LiteralPath $signerPath -Raw | ConvertFrom-Json
                if($signer.thumbprint -cnotmatch '^[A-F0-9]{40}$' -or $signer.packageName -cne $lab.packageName){throw 'Unsafe signer cleanup identity.'}
                foreach($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPeople','Cert:\LocalMachine\My')){
                    $path=Join-Path $store $signer.thumbprint
                    try{if(Test-Path -LiteralPath $path){if((Get-Item -LiteralPath $path).FriendlyName -cne $lab.packageName -and $store -eq 'Cert:\LocalMachine\My'){throw 'Signer identity changed.'};if($store -eq 'Cert:\LocalMachine\My'){Remove-Item -LiteralPath $path -DeleteKey -Force}else{Remove-Item -LiteralPath $path -Force}};if(Test-Path -LiteralPath $path){throw 'Signer remains.'}}catch{$errors+='signer cleanup failed'}
                }
            }
            [pscustomobject]@{outcome=$(if($errors.Count){'Failed'}else{'Passed'});errors=$errors;temporaryTrustAndKeyRemoved=($errors.Count -eq 0);testPackageRetained=$true}
        }
        $cleanup | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $hostOutput 'cleanup.json') -Encoding UTF8
        if($cleanup.outcome -cne 'Passed'){throw 'Lab trust cleanup failed; see cleanup.json. This run must not be counted Passed.'}
    }
    Remove-PSSession $session
}
