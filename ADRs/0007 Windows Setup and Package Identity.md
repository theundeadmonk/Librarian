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

The MSI owns registration and removal of the identity package. Production setup
uses the Windows `PackageManager` API with the installed external location; it
does not shell out to PowerShell. Every identity-bearing executable embeds
matching side-by-side MSIX identity metadata. Package name, publisher, and
application identifiers must match exactly. The identity-only MSIX remains
architecture-neutral as required by Microsoft's external-location guidance;
the external production executables and installer payload remain x64-only.
Setup separately validates the fixed executable paths and requires every
payload component to carry the same product version.

Setup stages and provisions the identity package for future profiles and also
registers it immediately in the invoking user's impersonated Windows Installer
context before any optional launch. Transaction rollback records the prior
package version, provisioning state, and invoking-user registration in the
protected installation directory. It restores that exact state after a failed
install, repair, upgrade, or uninstall, including preserving pre-existing
absence.

The existing package-enabled WinUI development target may continue to produce a
full MSIX for isolated UI smoke tests. It is not the production product
lifecycle described by this ADR.

### Browser integration remains optional

Chrome and Edge are optional integrations, not prerequisites. Setup detects
installed supported browsers and offers only the applicable integrations. The
user can decline them and can add or remove them later through Librarian
settings or setup maintenance mode.

For a selected browser, the MSI owns only Librarian's native-messaging host
manifest and registry registration. The extension itself is acquired from that
browser's official extension store through the browser's user-confirmed
installation flow. Librarian does not bundle a CRX, silently install an
extension, or use enterprise force-install policy on consumer devices.
Removing Librarian removes its native-host registrations but does not override
the user's independent browser-extension choices.

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
- Update and repair lock the agent and disconnect clients before replacing
  product files or registrations. Clients from a partial or incompatible
  release cannot connect to an unlocked agent.
- The MSI uses transactional installation and Windows Installer repair. Native
  binaries and registrations are removed together.
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
- Browser vendors retain control of extension distribution and consent.
- External native binaries do not receive the full container and block-map
  protections of a conventional MSIX. Librarian compensates with protected
  installation ACLs, Authenticode on every executable, signed MSI and MSIX
  artifacts, payload verification, transactional repair, and fail-closed
  version checks.
- The packaging implementation must test install, repair, upgrade, downgrade,
  interruption, wrong signer, mixed versions, browser opt-in/out, uninstall,
  retained data, and complete removal of Librarian-owned registrations.

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

The disposable GitHub-hosted Windows runner also creates a short-lived,
non-exportable development code-signing certificate, trusts only its public
certificate for that job, and removes both certificate-store entries in a
`finally` block. CI builds a workspace-version fixture and a strictly higher
fixture whose first three Windows Installer version fields differ. It then
executes unsigned and wrong-component rejection, clean install and launch,
browser opt-in, repair, interrupted-upgrade rollback, successful upgrade,
downgrade rejection, uninstall, reinstall, registration cleanup, and retained
disposable user-data checks. The harness refuses to run on a developer or
self-hosted machine and never exports a PFX or private key.
