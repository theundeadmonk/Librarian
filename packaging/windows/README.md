# Windows installer

Issue [#19](https://github.com/theundeadmonk/Librarian/issues/19) owns
Librarian's single Windows setup lifecycle. The implementation follows
[[../../ADRs/0007 Windows Setup and Package Identity]].

## Product boundary

`LibrarianSetup.exe` is the only user-facing installer. Its compressed WiX Burn
bundle owns one per-machine MSI and one Programs and Features entry. The MSI
installs exactly the three product executables that currently exist:

- `Librarian.Windows.exe`
- `Librarian.VaultAgent.exe`
- `Librarian.ChromiumNativeHost.exe`

The passkey-provider role is reserved for issue
[#18](https://github.com/theundeadmonk/Librarian/issues/18). This installer
does not add a placeholder executable, application identity, or registration.

Chrome and Edge native-messaging registrations are separate optional MSI
features. They are offered only when the corresponding browser is detected.
Each manifest allows one exact extension origin. Setup never bundles,
force-installs, or trusts a browser extension; issue
[#16](https://github.com/theundeadmonk/Librarian/issues/16) owns the real store
IDs and browser connection.

The host executable path remains relative to each colocated manifest. Chrome
and Edge both explicitly support a path relative to the manifest directory on
Windows; this avoids baking one machine's Program Files drive into the MSI.
The registry default value remains the required absolute manifest path.

## Tooling and license

The projects pin WiX Toolset 7.0.0 and accept the `wix7` Open Source Maintenance
Fee EULA required by the official binaries. The WiX source license and the
maintenance-fee terms are separate obligations; see the
[WiX license](https://github.com/wixtoolset/wix/blob/main/LICENSE.TXT) and
[OSMF terms](https://docs.firegiant.com/wix/osmf/).

## Build-only fixture

The authoritative Release build creates and structurally validates an unsigned
fixture:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Configuration Release -Platform x64
```

The installer-specific commands are:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-installer.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-installer.ps1 -ExpectedSigningMode unsigned-fixture
```

The setup bundle, MSI, identity package, and embedded executable manifests use
one four-part product version. The fourth field must remain zero because
Windows Installer compares only the first three fields during major-upgrade
detection; every installer upgrade must increment one of those fields.

Outputs are written below `artifacts\installer\`:

- `bundle\LibrarianSetup.exe`
- `msi\Librarian.Package.msi`
- `payload\Librarian.Identity.msix`
- `payload\Librarian.Release.json`

The default Chrome and Edge extension IDs are disposable `[a-p]{32}` fixture
values. They are not published extension identities. An unsigned fixture must
never be installed.

The structural suite decompiles the MSI, extracts the Burn bundle, checks the
three-component scope, feature conditions, registry ownership, custom-action
transaction modes and exports, package identity, hashes, native-messaging
origins, signing mode, and upgrade sequence. It does not execute setup.

Windows Installer ICE validation also runs unless the caller explicitly passes
`-SkipIceValidation`. Smart App Control can block ICE's temporary unsigned MSI
even from an elevated process. On such a development machine, the authoritative
build detects enforcement, records the local skip, and still runs the structural
suite. GitHub's Windows build must run ICE validation and fails if WiX reports
that validation did not start.

The same disposable Windows runner then executes
`scripts\test-installer-ci.ps1`. That entry point refuses to run anywhere
except GitHub Actions, creates a short-lived non-exportable development
certificate, trusts only its public certificate for the duration of the test,
builds two signed versions, and removes both certificate-store entries in a
`finally` block. It does not export a PFX or private key.

The lifecycle suite rejects unsigned and unexpected-provider installs, launches
a clean installation, opts into and repairs both browser registrations, rolls
back an injected upgrade failure, upgrades in place, rejects a downgrade,
uninstalls, reinstalls, and confirms that a disposable per-user data sentinel
survives every repair, update, and removal. The suite may mutate Program Files,
HKLM, package provisioning, and the test profile, so its CI guard must not be
removed or bypassed for developer machines.

## Development signing

`build-installer.ps1 -DevelopmentCertificateThumbprint <SHA1>` accepts only one
currently valid code-signing certificate with:

- exact subject `CN=Librarian Development`;
- a private key in `CurrentUser\My` or `LocalMachine\My`; and
- the code-signing enhanced key usage.

The script resolves the exact thumbprint once, signs copied build artifacts,
and verifies every signature. It accepts no PFX path or password. It never
creates a certificate and never modifies a trust store.

Production signing remains a separate release-controlled operation. Do not
commit certificates, private keys, passwords, tokens, or generated artifacts.

## Transaction boundary

The identity-only MSIX is registered through an embedded native C++ custom
action that calls the Windows package-management API. It does not invoke
PowerShell. Deferred, rollback, and commit actions run without user
impersonation and hide `CustomActionData` from logs. Install and uninstall
rollback markers are disposable and contain version/state only.

The MSI owns Librarian files and registrations beneath `Program Files` and
machine-level native-messaging keys. Vaults and backups remain outside the
installation directory and are not deleted by repair or normal uninstall.
