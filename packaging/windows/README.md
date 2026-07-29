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
three-component scope, feature conditions, registry ownership, custom-action
transaction modes and exports, package identity, hashes, native-messaging
origins, signing mode, self-contained Windows App SDK payload, hybrid CRT
linkage, and upgrade sequence. It does not execute setup.

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

The four security-critical payload hashes live in a fixed-format manifest
installed beside the binaries. Only that manifest's SHA-256 is passed through
the bounded deferred custom-action data. Each identity action validates the
protected manifest path, rejects reparse points, verifies the manifest hash,
and then verifies every identity-bound payload before changing package state.
After an upgrade commits and provisions the incoming identity, setup retires
superseded all-user registrations so a later repair never encounters multiple
versions of the same package family. Users who were not running setup receive
the already-provisioned incoming version at their next sign-in.

The same disposable Windows runner then executes
`scripts\test-installer-ci.ps1`. That entry point refuses to run anywhere
except GitHub Actions, creates a short-lived non-exportable development
certificate, trusts only its public certificate for the duration of the test,
builds two signed versions, and removes both certificate-store entries in a
`finally` block. It does not export a PFX or private key.

The lifecycle suite rejects unsigned and unexpected-provider installs, validates
a clean installation, opts into and repairs both browser registrations, rolls
back injected repair and upgrade failures, upgrades a disposable secondary
Windows account's provisioned identity, proves divergent registered and
provisioned versions fail closed without state loss, rejects a downgrade,
uninstalls, reinstalls, and confirms that a disposable per-user data sentinel
survives every repair, update, and removal. The hosted runner deliberately
delegates the interactive WinUI launch assertion to
`scripts\test-windows-shell-ui.ps1`, which must run in an interactive Windows
desktop after the Release build. The suite may mutate Program Files, HKLM,
local accounts, package provisioning, and test profiles, so its CI guard must
not be removed or bypassed for developer machines.

Windows Installer Restart Manager remains enabled so repair and upgrade can
coordinate processes that hold product files. The lifecycle suite requires a
zero exit code; it does not treat a restart-required result as a completed
replacement. Identity registration independently rejects any retained
identity-bearing file whose hash does not match the incoming MSI.

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

The rollback-capable script stages identity and registers only the invoking
user. Device provisioning is a checked commit action. Uninstall similarly
defers all-user package removal to its checked commit action, after MSI file
removal has succeeded; only best-effort marker cleanup follows it. A failed
transaction therefore does not remove another existing user's registration,
and rollback does not clean-reprovision identity when the prior provisioning
is already intact. Snapshotting fails closed before mutation if the invoking
user's registered identity version differs from the device-provisioned
version, because a single-version rollback marker cannot safely restore both
states. It also fails closed if a different incoming version already exists
for another user or as staged state, because rollback must not remove state
that predates the transaction.

Before either machine staging or invoking-user registration, the custom action
requires exact SHA-256 matches for the installed desktop, vault-agent,
native-host, and identity-package files. The expected values are generated
from the release payload and embedded in the signed MSI; a stale or
mixed-release identity-bearing file fails closed.

The MSI creates the protected installation directory before taking its
identity-state snapshot on a clean install. Snapshot removal after transaction
commit is best-effort: a temporary scanner lock may leave only a disposable
version/state marker, but cannot turn an already committed product transaction
into a reported rollback.

The MSI owns Librarian files and registrations beneath `Program Files` and
machine-level native-messaging keys. Vaults and backups remain outside the
installation directory and are not deleted by repair or normal uninstall.
