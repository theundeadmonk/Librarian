# Pure test configuration construction; importing this file performs no VM,
# registry, certificate, process, or vault operations.
function New-Issue17LabBrowserConfiguration {
    param(
        [Parameter(Mandatory)][string]$Stage,
        [Parameter(Mandatory)][string]$PackageName,
        [Parameter(Mandatory)][ValidateSet('chrome','edge')][string]$Browser,
        [Parameter(Mandatory)][ValidateSet('Initial','Extended')][string]$Batch,
        [Parameter(Mandatory)]$Fixtures
    )
    if($PackageName -cnotmatch '^Librarian\.I17\.R[0-9a-f]{24}$' -or $Stage -cne ('C:\LibrarianTest\authlab-'+$PackageName)){
        throw 'Unexpected authenticated lab configuration scope.'
    }
    $batchOutput=Join-Path $Stage ('results\'+$Browser+'-'+$Batch)
    return [ordered]@{
        browser=$Browser;batch=$Batch;labPackage=$PackageName;outputDirectory=$batchOutput
        reportPath=(Join-Path $batchOutput ('fill-'+$Browser+'.json'))
        extensionDirectory=(Join-Path $Stage 'extension')
        executable=$(if($Browser -ceq 'chrome'){'C:\LibrarianTest\tools\chrome-win64\chrome.exe'}else{'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'})
        account=$Fixtures.accounts[0]
        # An empty PowerShell subexpression can serialize as {}, not [].
        # Retain an actual array for both batches, including the empty case.
        additionalAccounts=@(if($Batch -ceq 'Extended'){$Fixtures.extended.accounts})
    }
}
