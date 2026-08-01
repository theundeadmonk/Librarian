[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "native-process-arguments.ps1")

function Assert-Equal {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Actual,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Expected,

        [Parameter(Mandatory)]
        [string]$Label
    )

    if ($Actual -cne $Expected) {
        throw (
            "$Label failed. Expected '$Expected', received '$Actual'."
        )
    }
}

$quote = [char]34
$slash = [char]92

Assert-Equal `
    -Actual (ConvertTo-NativeProcessArgument -Argument "plain") `
    -Expected "plain" `
    -Label "Unquoted argument"
Assert-Equal `
    -Actual (ConvertTo-NativeProcessArgument -Argument "") `
    -Expected "$quote$quote" `
    -Label "Empty argument"
Assert-Equal `
    -Actual (
        ConvertTo-NativeProcessArgument `
            -Argument "-p:OutputPath=C:${slash}My Repo${slash}"
    ) `
    -Expected (
        "$quote-p:OutputPath=C:${slash}My Repo${slash}${slash}$quote"
    ) `
    -Label "Quoted trailing backslash"
Assert-Equal `
    -Actual (ConvertTo-NativeProcessArgument -Argument "a${quote}b") `
    -Expected ("$quote" + "a${slash}${quote}b" + "$quote") `
    -Label "Embedded quote"
Assert-Equal `
    -Actual (
        Join-NativeProcessArguments -Arguments @(
            "alpha",
            "C:${slash}Space Path${slash}",
            ""
        )
    ) `
    -Expected (
        "alpha " +
        "$quote" + "C:${slash}Space Path${slash}${slash}" + "$quote " +
        "$quote$quote"
    ) `
    -Label "Argument list"

Write-Host "Native process argument tests passed."
