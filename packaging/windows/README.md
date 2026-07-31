# Windows installer

Issue [#19](https://github.com/theundeadmonk/Librarian/issues/19) owns
Librarian's single Windows setup lifecycle. The implementation follows
[[../../ADRs/0007 Windows Setup and Package Identity]].

## Product boundary

`LibrarianSetup.exe` is the only user-facing installer. Its compressed WiX Burn
bundle owns one per-machine MSI and one Programs and Features entry. The MSI
installs the three product-role executables that currently exist:

- `Librarian.Windows.exe`
- `Librarian.VaultAgent.exe`
- `Librarian.ChromiumNativeHost.exe`

It also installs the narrow support executable
`Librarian.IdentityLauncher.exe`. The one Start-menu shortcut and setup's
optional post-install launch target this executable. It is not a fourth product
role or separate user-facing application: it validates the installed payload,
reconciles external-location package identity for the current user, and then
opens `Librarian.Windows.exe`.

The passkey-provider role is reserved for issue
[#18](https://github.com/theundeadmonk/Librarian/issues/18). This installer
does not add a placeholder executable, application identity, or registration.

The WinUI app is built with the Windows App SDK self-contained deployment mode
and Microsoft's hybrid CRT configuration. Its required Windows App SDK runtime
files are installed beside the executable, so the one setup does not require a
separate Windows App SDK or Visual C++ Redistributable installation. The pinned
runtime currently contributes Microsoft's `RestartAgent.exe`; it is a runtime
helper, not a fourth Librarian product role or package identity.

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
three product roles and launcher boundary, feature conditions, registry
ownership, custom-action modes and exports, package identity, hashes,
native-messaging origins, signing mode, self-contained Windows App SDK payload,
hybrid CRT linkage, and upgrade sequence. It does not execute setup.

Windows Installer ICE validation also runs unless the caller explicitly passes
`-SkipIceValidation`. Smart App Control can block ICE's temporary unsigned MSI
even from an elevated process. On such a development machine, the authoritative
build detects enforcement, records the local skip, and still runs the structural
suite. GitHub's Windows build must run ICE validation and fails if WiX reports
that validation did not start.

Windows App SDK 2.3.1 includes valid `gd-GB`, `mi-NZ`, and `ug-CN` WinUI MUI
resources whose modern LCIDs are rejected by the legacy MSI ICE language
catalog. Its two base WinUI DLLs also carry comma-separated language lists that
exceed the MSI `File.Language` field. Installer authoring preserves every
localized file and fail-closed normalizes only these eight pinned Microsoft
`File.Language` cells to language-neutral before running the complete ICE
suite. Structural validation requires all eight normalized rows, rejects the
original LCIDs and overlong values, and never globally suppresses ICE03.

The five security-critical payload hashes (launcher, desktop, vault agent,
native host, and identity package) live in a fixed-format manifest installed
beside the binaries. Only that manifest's SHA-256 is passed through bounded
deferred custom-action data. The System-context custom action first uses
Windows `WinVerifyTrust` to require its own module and all five payloads to
have a valid chain, the expected code-signing publisher, and one matching
signer certificate. It then validates the protected manifest path, rejects
reparse points, verifies the manifest hash, and verifies every identity-bound
payload hash. It does not stage, provision, register, or remove package
identity.

The signed launcher repeats the path and hash checks in the interactive user's
context. It rejects a newer identity and otherwise uses the documented
`PackageManager.AddPackageByUriAsync` external-location flow to register the
installed version for that user before it opens the desktop. The desktop also
checks that its current package version matches the installed release. Users
therefore converge independently on first launch after install or upgrade;
repair restores the machine payload without attempting to inspect or mutate
another Windows user's package projection.

The same disposable Windows runner then executes
`scripts\test-installer-ci.ps1`. That entry point refuses to run anywhere
except GitHub Actions, creates a short-lived non-exportable development
certificate plus an independent wrong-signer certificate, and trusts only
their public certificates for the duration of the test. It builds two valid
signed versions and two deliberately invalid bundles: one replaces the low
launcher with a validly signed wrong-signer copy, while the other replaces it
with the accepted-signer high-version copy after the low manifest hashes are
bound. The invalid-payload build hook refuses to run outside the exact
GitHub-hosted lifecycle guard. The entry point verifies removal of all six
`TrustedPeople`, `Root`, and personal certificate-store entries in a `finally`
block. It does not export a PFX or private key.

The lifecycle suite rejects unsigned, validly signed wrong-signer,
accepted-signer mixed-release, and unexpected-provider installs without
leaving product state. It then validates a clean installation, registers the
invoking and disposable secondary users through the launcher, opts into and
repairs both browser registrations, and rolls back injected repair and upgrade
failures. It proves an upgraded MSI can be repaired while a dormant secondary
user retains the old identity, then proves each user converges independently
through the launcher. It also rejects a downgrade, verifies invoking-user
uninstall cleanup and inert retained secondary-user identity, reinstalls, and
confirms that a disposable per-user data sentinel survives every repair,
update, and removal. The hosted runner deliberately delegates the interactive
WinUI launch assertion to
`scripts\test-windows-shell-ui.ps1`, which must run in an interactive Windows
desktop after the Release build. The suite may mutate Program Files, HKLM,
local accounts, package registrations, and test profiles, so its CI guard must
not be removed or bypassed for developer machines.

For bounded local lifecycle diagnosis, the lower-level suite additionally
accepts `-ConfirmDisposableVm` only inside the dedicated VMware guest whose
operating system is Windows 11 Enterprise Evaluation and whose user is
`librarian-test`. This exception does not permit execution on the development
host, a general-purpose VM, or a self-hosted CI runner. Certificate creation
and trust remain owned by the GitHub-hosted entry point above.

Windows Installer Restart Manager remains enabled so repair and upgrade can
coordinate processes that hold product files. The lifecycle suite requires a
zero exit code; it does not treat a restart-required result as a completed
replacement. Identity registration independently rejects any retained
identity-bearing file whose hash does not match the MSI-bound manifest.

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

The identity-only MSIX is not mutated from the MSI service transaction.
Installation, repair, upgrade, and rollback remain ordinary per-machine MSI
file and registry operations. A deferred, non-impersonated native C++ custom
action only verifies the canonical protected path and the MSI-bound SHA-256
manifest after files are installed; it calls no package-management API and
invokes no PowerShell.

The signed, unpackaged launcher owns current-user registration outside the MSI
transaction, following Microsoft's external-location C++ setup sample. It
repeats the canonical path, reparse-point, version, and hash validation before
calling the supported package-management API. A stale or mixed-release
identity-bearing file therefore fails closed before desktop launch.

Final uninstall schedules one checked impersonated native commit action after
file removal succeeds, so a transaction that rolls back cannot unregister the
invoking user. The commit action removes only matching registrations belonging
to that user and leaves newer versions untouched. If more than one removable
version is present for that user, it fails closed before changing any
registration rather than risk partial cleanup. It never enumerates or mutates
another profile. Registrations retained by other users become inert once
Program Files is removed and can converge after reinstall and next launch.
Deterministic all-user cleanup is intentionally deferred to
[issue #39](https://github.com/theundeadmonk/Librarian/issues/39).

The MSI owns Librarian files and registrations beneath `Program Files` and
machine-level native-messaging keys. Vaults and backups remain outside the
installation directory and are not deleted by repair or normal uninstall.
