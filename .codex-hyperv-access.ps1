# Local lab helper. Importing this file never changes permissions or VM state.
function Test-LibrarianHyperVRole {
    param(
        [bool]$IsAdministrator,
        [bool]$IsHyperVAdministrator
    )
    return $IsAdministrator -or $IsHyperVAdministrator
}

function Assert-LibrarianHyperVHostAccess {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $hyperVSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-578')
    if (-not (Test-LibrarianHyperVRole `
        -IsAdministrator $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) `
        -IsHyperVAdministrator $principal.IsInRole($hyperVSid))) {
        throw 'Host Hyper-V administrator access is required. Use the approved Hyper-V Administrators account or Terminal (Admin).'
    }
}
