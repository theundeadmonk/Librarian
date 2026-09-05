[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$sourceRoot = Join-Path $repoRoot "apps\browser-extension"
$outputRoot = Join-Path $repoRoot "artifacts\browser-extension"
$unpackedRoot = Join-Path $outputRoot "unpacked"
$archivePath = Join-Path $outputRoot "Librarian.BrowserExtension.zip"
$expectedOutput = [IO.Path]::GetFullPath(
    (Join-Path $repoRoot "artifacts\browser-extension")
)
if ([IO.Path]::GetFullPath($outputRoot) -cne $expectedOutput) {
    throw "The browser-extension output escaped its expected artifact root."
}

$manifestPath = Join-Path $sourceRoot "manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$permissions = @($manifest.permissions)
if ($manifest.manifest_version -ne 3 -or
    $manifest.background.service_worker -cne "dist/background.js" -or
    $manifest.background.type -cne "module" -or
    $permissions.Count -ne 1 -or
    $permissions[0] -cne "nativeMessaging") {
    throw "The browser-extension manifest has an unexpected privilege surface."
}

$publicKey = [Convert]::FromBase64String($manifest.key)
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $digest = $sha256.ComputeHash($publicKey)
} finally {
    $sha256.Dispose()
}
$alphabet = "abcdefghijklmnop"
$extensionId = -join ($digest[0..15] | ForEach-Object {
    $alphabet[$_ -shr 4]
    $alphabet[$_ -band 15]
})
if ($extensionId -cne "jiifjoajanfeoabbkmpodkgfmabhikkh") {
    throw "The browser-extension development identity changed unexpectedly."
}

$packageFiles = @(
    [PSCustomObject]@{
        Source = $manifestPath
        Relative = "manifest.json"
    },
    [PSCustomObject]@{
        Source = Join-Path $sourceRoot "dist\background.js"
        Relative = "dist\background.js"
    },
    [PSCustomObject]@{
        Source = Join-Path $sourceRoot "dist\native.js"
        Relative = "dist\native.js"
    }
)
foreach ($file in $packageFiles) {
    if (-not (Test-Path -LiteralPath $file.Source -PathType Leaf)) {
        throw "The browser-extension package input '$($file.Source)' is missing."
    }
}

if (Test-Path -LiteralPath $outputRoot) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}
[void](New-Item -ItemType Directory -Path $unpackedRoot -Force)
foreach ($file in $packageFiles) {
    $destination = Join-Path $unpackedRoot $file.Relative
    [void](New-Item -ItemType Directory -Path (Split-Path $destination) -Force)
    Copy-Item -LiteralPath $file.Source -Destination $destination
}

Add-Type -AssemblyName System.IO.Compression
$archiveStream = [IO.File]::Open(
    $archivePath,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::None
)
try {
    $archive = [IO.Compression.ZipArchive]::new(
        $archiveStream,
        [IO.Compression.ZipArchiveMode]::Create,
        $false
    )
    try {
        foreach ($file in $packageFiles) {
            $entryName = $file.Relative.Replace('\', '/')
            $entry = $archive.CreateEntry(
                $entryName,
                [IO.Compression.CompressionLevel]::Optimal
            )
            $source = [IO.File]::OpenRead($file.Source)
            $destination = $entry.Open()
            try {
                $source.CopyTo($destination)
            } finally {
                $destination.Dispose()
                $source.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
} finally {
    $archiveStream.Dispose()
}

$packaged = @(
    Get-ChildItem -LiteralPath $unpackedRoot -Recurse -File |
        ForEach-Object {
            $_.FullName.Substring($unpackedRoot.Length + 1)
        } |
        Sort-Object
)
$expected = @($packageFiles.Relative | Sort-Object)
if (($packaged -join "`n") -cne ($expected -join "`n")) {
    throw "The browser-extension package contains an unexpected file set."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $entries = @($archive.Entries.FullName | Sort-Object)
} finally {
    $archive.Dispose()
}
$expectedEntries = @(
    $packageFiles.Relative |
        ForEach-Object { $_.Replace('\', '/') } |
        Sort-Object
)
if (($entries -join "`n") -cne ($expectedEntries -join "`n")) {
    throw "The browser-extension archive contains an unexpected entry set."
}

Write-Host "Browser extension package completed successfully."
Write-Host "Development extension ID: $extensionId"
Write-Host "Unpacked: $unpackedRoot"
Write-Host "Archive: $archivePath"
