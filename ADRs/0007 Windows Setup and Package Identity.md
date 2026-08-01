# ADR 0007: Windows Setup and Package Identity

**Status:** Accepted
**Date:** 2026-07-27
**Scope:** Windows installation, package identity, browser integration, and servicing
**Decision issue:** [#19](https://github.com/theundeadmonk/Librarian/issues/19)

## Context

Librarian must install several cooperating native executables, give each one a
verifiable Windows package identity, register browser native-messaging hosts,
and service the product as one compatible release. The supported audience
includes Windows 11 Home users, who should not need enterprise browser policy
or several separate installers.

A conventional packaged MSIX is not a complete lifecycle owner for this
product. Chrome and Edge native-messaging registrations live outside the
package, browser extensions must remain user-consented store installations,
and the product needs explicit repair, downgrade, rollback, and data-retention
behavior. Conversely, abandoning package identity would weaken the authenticated
client boundary accepted by
[[ADRs/0006 Authenticated Local IPC and Client Authorization]].

## 2026-07-30 amendment: user-context identity ownership

The original issue #19 design staged and provisioned identity machine-wide,
then attempted to snapshot and roll back AppX state across Windows users from
the MSI service context. Disposable multi-user VM testing proved that the
supported package APIs do not always expose a verifiable external path for
another user's retained registration in that context. Failing open would
weaken the IPC trust boundary, while relying on private package-database state
would create an unsupported security dependency.

This amendment replaces Slice 1's provisioning and all-user package mutation
with the documented per-user `PackageManager` registration model below.
[Issue #39](https://github.com/theundeadmonk/Librarian/issues/39) preserves the
evidence and owns any future return to an ideal all-user lifecycle.

## 2026-07-31 amendment: user-session validation boundary

Issue #19 validates identity registration and servicing in the established
invoking user's Windows session. Its GitHub-hosted gate does not simulate
another user's first launch by starting a credential-only, noninteractive
process. That process does not provide the same supported package-deployment
projection as a user who signs in and launches Librarian, so making it a release
gate would expand the product contract beyond the user-context ownership model
accepted above.

The hosted lifecycle still proves that setup never provisions identity for all
users or mutates another user's package state, and it exercises current-user
registration, upgrade convergence, repair, uninstall cleanup, and reinstall.
Disposable multi-user activation, dormant-user retention, and independent
convergence remain explicit VM coverage owned by
[issue #39](https://github.com/theundeadmonk/Librarian/issues/39). This boundary
does not weaken publisher, signature, path, ACL, payload-hash, version, or
fail-closed validation.

## 2026-07-31 amendment: Windows 11 lifecycle execution boundary

GitHub-hosted Windows jobs run Windows Server 2025. Librarian supports Windows
11 workstations, and its production MSI must reject Server by requiring
`MsiNTProductType = 1` for a new installation. The destructive signed-fixture
lifecycle therefore cannot execute on the hosted runner without weakening the
same product boundary that the installer is required to enforce.

Hosted pull-request CI remains blocking for bootstrap, builds, lint, unit and
integration tests, installer structural validation, WiX ICE, and Rust parity.
Current-user product development uses a loose development package rather than
installing the unsigned MSI fixture. Issue
[#40](https://github.com/theundeadmonk/Librarian/issues/40) owns automated
destructive lifecycle execution on an actual disposable Windows 11 workstation
and makes it a required installer-release gate. No public MSI property or
runtime override may bypass the production workstation condition.

## Decision

### One user-facing setup

Release one open-source, signed `LibrarianSetup.exe`. Its bundled MSI is the
single owner of installation, repair, upgrade, rollback, and uninstall.
Installer source and deterministic packaging inputs live in this repository.

The MSI installs the native product binaries beneath a protected per-machine
`Program Files` location using the role names fixed by ADR 0006:

- `Librarian.VaultAgent.exe`
- `Librarian.Windows.exe`
- `Librarian.ChromiumNativeHost.exe`

The `Librarian.PasskeyProvider.exe` role remains reserved by ADR 0006, but it
is not installed or registered until issue #18 supplies the real provider.
Issue #19 must fail closed rather than add a placeholder executable or identity.
Issue #18 will extend this same setup lifecycle with the fourth component.

The setup executable, MSI, identity package, and native binaries carry one
compatible product version. Installation must validate the complete required
payload before enabling registrations. An interrupted or invalid installation
rolls back instead of leaving a partially authorized product.

The WinUI desktop output is self-contained for the Windows App SDK and uses
Microsoft's hybrid CRT configuration. The MSI therefore carries the native
Windows App SDK runtime beside the application and does not require a separate
Windows App SDK or Visual C++ Redistributable installation. Windows system UCRT
API-set dependencies remain operating-system components.

WiX Toolset 7.0.0 authors the setup bundle and MSI. The source is available
under the Microsoft Reciprocal License; the project accepts the Open Source
Maintenance Fee EULA v1.1 that governs the official WiX binaries, including
its maintenance-fee obligation if the applicable annual-revenue threshold is
reached. The exact SDK and extension package versions are pinned in source.

### Identity-only MSIX

Bundle an MSIX package that grants package identity by using an external
location. The identity package declares one application identity for each
native executable but does not contain or service those executables. It is not
a second user-facing application and does not create a second Apps & Features
entry.

The MSI owns the protected machine-wide payload and validates it before commit.
Librarian owns package registration in the interactive user's context by using
the Windows `PackageManager` API with the installed external location; it does
not shell out to PowerShell. Every identity-bearing executable embeds matching
side-by-side MSIX identity metadata. Package name, publisher, and application
identifiers must match exactly. The identity-only MSIX remains
architecture-neutral as required by Microsoft's external-location guidance;
the external production executables and installer payload remain x64-only.
Setup separately validates the fixed executable paths and requires every
payload component to carry the same product version.

The Start-menu shortcut targets a narrow, unpackaged
`Librarian.IdentityLauncher.exe`, following Microsoft's external-location C++
sample boundary. Before opening the product UI or connecting to the vault
agent, that launcher accepts only the canonical, non-redirected
`Program Files\Librarian` payload, verifies its MSI-bound hashes, registers the
installed identity MSIX for the current user with `AddPackageByUriAsync` and
`ExternalLocationUri`, and starts the identity-bearing desktop. Registration,
path validation, or launch failure is fail closed. The desktop separately
refuses to open if its current package version does not match the installed
payload version. The first successful desktop launch therefore registers all
application identities declared by the package without a second download, an
administrator prompt, PowerShell, or manual package-management step.

The browser manifests also target `Librarian.IdentityLauncher.exe`. A
browser-first activation uses a narrow headless mode that accepts only the
documented Chromium origin and parent-window argument shapes, performs the same
payload validation and current-user identity convergence, and then starts
`Librarian.ChromiumNativeHost.exe` with the inherited standard-input/output
channel and original browser arguments. Browser use therefore cannot bypass the
first-launch or post-upgrade identity boundary.

The MSI deliberately does not provision the package for all users or ask a
System-context custom action to inspect another user's package projection.
Each user converges independently at first launch. An upgrade leaves dormant
users' old registrations untouched until their next launch, when the newer
side-by-side executable identity causes the same current-user registration
path to converge them to the installed version. Repair restores the protected
payload; current-user registration is repaired at the next launch.

A final uninstall removes the invoking user's matching package registration in
that user's impersonated Windows Installer context before deleting the
machine-wide payload. Registrations belonging to other Windows users are not
mutated by Slice 1. They become inert when the protected executable path is
removed and converge on reinstall and next launch. Complete deterministic
all-user cleanup, including dormant and deleted profiles, is deferred to
[issue #39](https://github.com/theundeadmonk/Librarian/issues/39). That issue
must use a supported Windows ownership model; private AppRepository state,
arbitrary user-hive manipulation, and weaker path validation remain forbidden.

Before accepting the installed payload, the elevated validation action uses
Windows `WinVerifyTrust` to require its own custom-action module and all five
identity-bound payload files to have a valid code-signing chain, the exact
development publisher, and one matching signer certificate. It then hashes the
launcher, three identity-bearing executables, and fixed identity-package path.
Those SHA-256 values must match the values embedded in the signed MSI at build
time. Unsigned, wrong-signer, stale, or mixed-version files at the protected
installation path therefore fail closed before a user can register them.

The existing package-enabled WinUI development target may continue to produce a
full MSIX for isolated UI smoke tests. It is not the production product
lifecycle described by this ADR.

### Browser integration remains optional

Chrome and Edge are optional integrations, not prerequisites. Setup detects
installed supported browsers and offers only the applicable integrations. The
user can decline them and can add or remove them later through Librarian
settings or setup maintenance mode.

The MSI always installs both inert native-messaging manifests as hash-bound core
payload files. For a selected browser, its optional feature publishes only the
machine registry value that lets the browser discover the corresponding
manifest. The extension itself is acquired from that browser's official
extension store through the browser's user-confirmed installation flow.
Librarian does not bundle a CRX, silently install an extension, or use
enterprise force-install policy on consumer devices. Removing Librarian removes
its native-host registrations but does not override the user's independent
browser-extension choices.

### Security and servicing rules

- Production setup, MSI, identity MSIX, and every shipped PE are signed by
  approved release identities. Signing keys and credentials never enter the
  repository, command line, logs, or package payload.
- A developer may use a clearly non-production self-signed certificate for
  local validation. Setup must never add a certificate to a trust store
  silently.
- Setup verifies expected signatures, identities, versions, and payload hashes
  before registration. Downgrades and mixed release sets fail closed.
- The shared four-part version keeps its revision field at zero because Windows
  Installer major-upgrade comparison uses only the first three fields.
- Windows Installer Restart Manager remains enabled to coordinate running
  product processes before update or repair replaces files. Setup does not
  accept a restart-required result as a completed lifecycle test, and
  hash-bound identity registration fails closed if any old executable remains.
  Clients from a partial or incompatible release cannot receive the incoming
  package identity.
- The MSI uses transactional installation and Windows Installer repair. Native
  binaries and machine-wide registrations are removed together. Current-user
  package identity is reconciled at launch and removed for the invoking user
  during final uninstall; ideal all-user removal is owned by issue #39.
- User vaults and encrypted backups live outside the installation directory.
  Uninstall retains encrypted user data by default. Deletion is a separate,
  explicit, warned action; repair never replaces user data.
- Supported production installation is x64 on supported Windows 11 editions,
  including Windows 11 Home. Browser absence is not an installation error.

The production signing service remains a separate release decision. Local
development uses only an explicitly supplied non-production certificate;
setup never creates or trusts one.

## Consequences

- Users see one setup executable and one installed product while native
  processes retain package identities suitable for local client authorization.
- The MSI can transactionally own external native-host registrations and
  preserve encrypted user data during servicing.
- Package deployment stays in the interactive user's supported Windows API
  projection instead of coupling MSI service rollback to cross-user AppX state.
- Browser vendors retain control of extension distribution and consent.
- External native binaries do not receive the full container and block-map
  protections of a conventional MSIX. Librarian compensates with protected
  installation ACLs, Authenticode on every executable, signed MSI and MSIX
  artifacts, payload verification, transactional repair, and fail-closed
  version checks.
- The packaging implementation must test install, invoking-user first-launch
  registration and upgrade convergence, repair, downgrade, interruption, wrong
  signer, mixed versions, browser opt-in/out, invoking-user uninstall cleanup,
  reinstall, and retained data. Issue #39 owns signed-in multi-user activation,
  dormant-user retention, and independent convergence coverage.

## Validation

Issue #19 must produce and validate the identity package, setup/MSI payload, and
registration fixtures with disposable values. A production-credential release
remains blocked until the release gates in [[Threat Model]] pass, including a
clean-profile install and independent security review.

The Release pipeline decompiles and inspects the built MSI and Burn bundle; it
does not treat source review as proof of the bound installer. Windows Installer
ICE validation is also mandatory in CI. A local Windows 11 development machine
with Smart App Control enforcement may explicitly skip ICE because Windows
blocks the validator's temporary unsigned MSI even when WiX is elevated. That
exception does not suppress the structural suite, does not weaken Smart App
Control, and is not permitted on the clean Windows CI runner.

The destructive Windows 11 lifecycle runner creates a short-lived,
non-exportable development code-signing certificate, trusts only its public
certificate in `TrustedPeople` and `Root` for that job, and removes both
trust entries plus the personal certificate in a verified `finally` cleanup.
CI builds a workspace-version fixture and a strictly higher
fixture whose first three Windows Installer version fields differ. It then
executes unsigned and wrong-component rejection, clean install and
current-user registration, browser opt-in, repair, interrupted-upgrade
rollback, browser-first current-user upgrade convergence, downgrade rejection,
invoking-user uninstall cleanup, reinstall, and retained disposable user-data
checks. The multi-user lifecycle remains a disposable interactive-VM boundary
under issue #39. Issue #40 owns the isolated Windows 11 runner for this
current-user lifecycle. The harness refuses to run on a developer machine and
never exports a PFX or private key.
