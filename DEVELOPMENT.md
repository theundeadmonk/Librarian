# Windows development

The active Librarian MVP builds only on x64 Windows 11. The repository does not contain Android, Apple-platform, Linux, or cross-platform user-interface projects.

## Supported toolchain

The foundation is pinned to stable releases verified on 2026-07-28:

| Area | Required version |
|---|---|
| Operating system | Windows 11 build 26100 or newer |
| Visual Studio | Visual Studio 2022 17.12 or newer with Desktop development with C++ and Windows application development; Visual Studio 2026 is supported |
| Windows SDK target | 10.0.28000.0 |
| Windows SDK Build Tools | 10.0.28000.2270, supplied by the locked NuGet package |
| Windows App SDK | 2.3.1 |
| C++/WinRT | 3.0.260715.1 |
| Windows Implementation Library | 1.0.260126.7 |
| .NET SDK | 10.0.302 |
| WiX Toolset | 7.0.0 with accepted `wix7` OSMF EULA |
| Rust | 1.97.1, x86_64-pc-windows-msvc |
| Node.js | 24.18.0 LTS |
| npm | 11.16.0 |
| TypeScript | 7.0.2 |
| Extension bundler | esbuild 0.28.2, added and verified for issue #17 on 2026-09-04 |

The manifests and lockfiles in source control are authoritative. Preview, release-candidate, beta, experimental, and floating dependency versions are not accepted by the foundation.

## First-time setup

Install Git for Windows, the required Visual Studio workloads, .NET SDK
10.0.302, Node.js 24.18.0, Rustup, and the Windows SDK:

```powershell
winget install Microsoft.WindowsSDK.10.0.28000
```

Visual Studio's C++ workload does not install SDK 10.0.28000. The build uses its installed platform headers and libraries together with the exact 10.0.28000.2270 Build Tools from the locked NuGet package. From a PowerShell terminal at the repository root, let the pinned `rust-toolchain.toml` install Rust and then validate the complete environment:

```powershell
powershell.exe -NoProfile -File .\scripts\bootstrap.ps1
```

The bootstrap command only validates the machine. It does not change system settings or install software. It reports every active version and stops on a missing tool, mismatched pin, preview release, missing lockfile, or unsupported Windows build.

## Build and test

One command formats-checks, lints, tests, restores locked dependencies, builds
the Rust workspace, Chromium extension, WinUI app, Windows passkey boundary,
and Windows local-IPC security probe, then builds and inspects the unsigned
single-installer fixture:

```powershell
powershell.exe -NoProfile -File .\scripts\build.ps1 -Configuration Release -Platform x64
```

Build outputs and diagnostic logs are written beneath `artifacts/` or the
component-specific ignored output directories. The setup, MSI, identity MSIX,
and native binaries produced by this command are unsigned test fixtures and
must not be installed. See
[`packaging/windows/README.md`](packaging/windows/README.md) for installer
outputs, structural validation, development signing, and Smart App Control
behavior. Production signing credentials are never part of the repository or
local build command.
On a normal Windows checkout, the build also checks whitespace in the committed branch diff, the index, and the working tree. GitHub Actions supplies the pull request or push base commit explicitly.

Rust tests use optimized test code with debug assertions and overflow checks
enabled. This keeps the vault-agent integration suite's production request
deadlines representative without relaxing those deadlines.

Windows Rust commands use `--target x86_64-pc-windows-msvc`. The corresponding
`.cargo/config.toml` setting statically links the CRT into the Rust executables
and their C/C++ dependencies so a clean Windows PC needs no separate Visual C++
Redistributable. Linux linkage is unchanged. Installer validation checks the
actual shipped executable imports, not just the build configuration.

## Run the current Windows product

After a successful Release build, start a development session without
installing the unsigned MSI fixture:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-development.ps1
```

The command verifies the Release payload and its hashes, registers a loose
development package only for the current Windows user, starts the vault-agent
entry point and desktop under their package identity, and leaves the desktop
open for manual testing. Close the Librarian window to stop the session. If the
command created the package registration, it removes that registration before
exiting.

The generated Release manifest also binds the exact WinUI loose-layout desktop
hash. Rebuilding or modifying only the app layout or only the installer fixture
therefore fails validation instead of launching a mixed development set.

This workflow does not install the MSI, write machine-wide browser integration,
or exercise install, upgrade, repair, rollback, or uninstall transactions. It
refuses to replace a development identity registered from another directory.
Developer Mode is required. The packaged desktop and vault agent communicate
over the authenticated local transport. The desktop can create or unlock the
local vault, manage the current website-account subset, and enroll, use, or
remove the optional Windows Hello convenience unlock. Use disposable test
values only; the product remains development-only.

## Test the browser connection

The Release build produces the same minimal Manifest V3 development package
for Chrome and Edge at:

- `artifacts\browser-extension\unpacked`
- `artifacts\browser-extension\Librarian.BrowserExtension.zip`

The package has the stable development ID
`jiifjoajanfeoabbkmpodkgfmabhikkh`. Its public manifest key is not signing or
credential material. A store release can receive different Chrome and Edge
IDs, which must be supplied to the signed installer build.

The unsigned installer fixture must not be installed. To test a
development-signed setup, select the optional Chrome and/or Edge integration,
start the installed Librarian desktop app, then use **Load unpacked** on
`chrome://extensions` or `edge://extensions` and select the unpacked artifact
directory. Verify the displayed extension ID before continuing. Use only a
disposable browser profile and test vault. The extension asks for website
access once for all HTTPS sites; there is no separate per-site enablement step.
Installation/startup and toolbar clicks outside supported HTTPS documents
perform a status probe:

- `ON` means the native app is connected and unlocked.
- `LOCK` means it is connected and must be unlocked in the desktop app.
- `SET` means first-run vault setup is incomplete.
- `...` means the agent is temporarily changing state.
- `!` or `UP` gives a non-secret install, repair, timeout, or compatibility
  instruction in the action title.

On an eligible HTTPS sign-in page, the issue #17 development implementation
automatically requests one exact-origin account once per document. A toolbar
click requests an explicit second fill. The vault must already be unlocked in
the desktop app; the extension cannot unlock it. Changed fields, changed pages,
expired requests, and locking suppress pending fills. Filling never submits.
Zero or multiple matching accounts produce no fill, not a multi-account menu.

The [ADR 0008 amendment](ADRs/0008%20Chromium%20Native%20Messaging%20Boundary.md#issue-17-amendment-exact-origin-fill-development-implementation)
documents the closed schemas and disclosure rules. Chrome/Edge 106 or later
is required. HTTP pages, all embedded frames, shadow-DOM fields, registration
and ambiguous forms are unsupported. Username-only steps are not filled;
password-only steps require `current-password`. Later steps in the same
document and back-navigation restores require the toolbar action.

Run the focused checks with:

```powershell
npm run test:extension
cargo test --locked -p librarian-vault-core browser_origin
cargo test --locked -p librarian-agent-protocol --test browser_fill
cargo test --locked -p librarian-vault-agent browser_
cargo test --locked -p librarian-chromium-native-host
npm run test:browser-dom --workspace @librarian/browser-extension -- edge
npm run test:browser-dom --workspace @librarian/browser-extension -- chrome
```

The opt-in DOM suite uses the standard Windows browser install paths for the
`edge` and `chrome` aliases. A direct invocation of
`node apps/browser-extension/tests/browser-dom.mjs <executable-path>` also works
after building the extension. It creates and removes its own temporary profile,
intercepts fixture requests without changing certificate trust, and injects
fake messaging alongside the real bundled content script. No real credentials
or native host are used. Browser versions are printed with the test results.

The full Release build and these local tests pass on the issue #17 development
branch. The installed signed extension-to-agent Chrome/Edge acceptance matrix
and independent review are still outstanding; do not treat this as production
credential approval or close #17 based only on the local checks.

Local verification on 2026-09-04: 93 extension unit/controller tests and 22 DOM
scenarios per browser, using Chrome 152.0.7977.76 and Edge 152.0.4191.62.
The DOM results include a real back-navigation restore, validation errors,
dynamic forms, pending edits/replacement, and explicit second filling. Rust
verification additionally covers six browser protocol tests, five agent
integration tests, two terminal-publication/lease-expiry tests, and the native
host suite. This is uncommitted development-tree evidence, not a signed release
or a substitute for the outstanding installed-chain matrix.

Windows Home VM verification on 2026-09-05: the signed 0.1.7.0-to-0.1.8.0
upgrade completed with setup exit code zero and exactly one visible product
entry. The installed connection smoke stopped at passkey-provider registration
with `0x80090027` (`NTE_INVALID_PARAMETER`), before any browser fill checks.
Inspection of the same `webauthn.dll` version (10.0.26100.8117) found that both
registration paths reject a null plugin RP ID. The candidate 0.1.9.0 change
supplies the reserved `librarian.invalid` identifier; its regression test fails
with the previous null value and passes with the correction. The subsequent
signed 0.1.9.0 upgrade, provider registration, and hidden registration-state
probe passed in the same Home VM. Its connection smoke stopped because the
vault agent was not detected after desktop startup; the signed browser-fill
acceptance matrix remains unrun. This does not relax the registration failure
policy or authorize real credentials.

A bounded startup diagnostic then confirmed that an old 0.1.6.0 discovery file
prevented the 0.1.9.0 desktop from activating its agent. Direct activation of
the registered current agent succeeded and refreshed the file. The candidate
0.1.10.0 desktop recovers only from a fully valid descriptor for a strictly
older version of its exact package identity: activate the trusted current
agent, reload discovery, then apply all existing connection authentication.
Malformed or foreign descriptors still fail closed. Production-decoder and
retry regression tests fail before the correction and pass after it. Signed
installed upgrade/startup verification passed in the same Home VM with
0.1.10.0: setup exit zero, no reboot, one visible product entry, healthy package,
normal desktop/agent startup, and real native-host status connections from
Edge 152.0.4191.62 and Chrome for Testing 152.0.7977.82. Both browsers reported
`SET` (connected, vault not yet created). Actual credential filling and the
independent issue #17 review remain outstanding; status success is not a fill
acceptance pass. Do not repeat the completed 0.1.9.0-to-0.1.10.0 upgrade.

After the user created the synthetic test account, the initial installed Edge
fill batch connected with `ON` but failed its first fill. A live browser-only
diagnostic found that Chromium supplied a compact uppercase document token,
which the extension incorrectly rejected as not a lowercase dashed UUID.
The extension now preserves that raw token for browser identity and delivery,
converting only its native-wire spelling without changing the 128-bit value.
All 98 extension tests and 22 DOM scenarios in each host browser pass; those
are local checks, not installed acceptance. The corrected extension is ready
to be staged separately against the existing signed native installation.
Installed rerun `desktop-20260905-212242` subsequently passed all 22 required
Edge checks but stopped in Chrome's test-controller preflight with a worker
evaluation timeout. After switching the harness to a direct worker endpoint,
`desktop-20260905-212851` passed all 22 required checks in both Edge
152.0.4191.62 and Chrome for Testing 152.0.7977.82 through the actual
extension/native-host/agent chain. Both began connected/unlocked, shut down
their isolated test browsers cleanly, and passed bounded browser-log canary
scans. Report collection also passed. This is a passed initial fill batch,
with overall Issue #17 acceptance still Partial. Both real-toolbar checks
were explicitly NotRun in both browsers because the action test API was
unavailable; duplicate-account, positive port/IDN, worker-restart, lock-race,
and independent-review coverage also remain outstanding. No further rerun
of this completed initial batch or the completed upgrade is needed.

As of 2026-09-14, that development signer has expired. Local preparation for a
fresh 0.1.11.0 VM-only fixture and a second 15-check-per-browser origin batch
has passed the Release pipeline and harness self-tests. The second batch adds
positive custom-port/Unicode/punycode accounts and duplicate-account refusal;
it requires user-created synthetic accounts and explicit setup confirmation.
It has not yet run against an installed fresh fixture. Worker restart,
supervised real-toolbar actions, deterministic installed lock-race evidence,
and independent review remain separate outstanding gates. The owner-run
0.1.10.0-to-0.1.11.0 upgrade subsequently passed, with no reboot and one visible
product entry. Connection smoke `desktop-20260914-112250` verified healthy
0.1.11.0 identity/desktop/agent startup and real LOCK status in Edge
152.0.4191.66 and Chrome for Testing 152.0.7977.82. Signing cleanup and evidence
collection passed. The four extra synthetic accounts still require user setup;
the 0.1.11.0 extended fill batch remains NotRun. Do not repeat the upgrade.

## Unattended synthetic account fixtures

For development without manual account entry, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-issue17-fixture.ps1
```

This builds a test-only Cargo example (not a product executable), creates a
new encrypted vault in a unique artifact directory, and automatically creates
the five public dummy accounts from `tests/fixtures/issue17-accounts.tsv`.
It cannot open an existing output directory, accepts no arbitrary credentials
or existing-vault input, and never contacts the installed agent or UI. Its
compiled-in synthetic master password is intentionally public and must never
be used for real data. No production authorization, signature, identity, or
credential-storage readiness gate is changed.

The tool runs 43 checks through production runtime/storage APIs: durable seed
and readback, exact-origin and duplicate matching, rejection of noncanonical
native requests, single-use selections, lock revocation, restart persistence,
and bounded database/sidecar canary scanning. It leaves the fixture on disk
locked, and emits only named check outcomes, counts, and evidence-scope labels.
It retains partial outputs on failure and refuses to overwrite or recursively
delete anything. Native errors never log credential response bodies.

The example's safety tests run with the ordinary `cargo test --all-targets`
pipeline. Report-validator negative tests run in `scripts/build.ps1` too.
In this lab, `.codex-run-issue17-synthetic.ps1` runs the same executable inside
the exact Home VM, with hash-checked transfer and sanitized-report-only collection.
Host and VM runs passed 43 checks each on 2026-09-14. This is the current default
route following the user's request for no manual testing at this stage.

These checks use synthetic in-process connections, not OS-authenticated peers.
They are NOT installed browser, UI, Windows Hello, or browser canonicalization
acceptance. The existing user's vault is untouched; the generated accounts do
not appear in that vault's Add Account UI. The interactive checklist below is
deferred, not passed, and must not block this automatic setup route.

### Extension/native/runtime component integration

The normal Windows build also runs `scripts/test-issue17-native-runtime.ps1`.
To run this suite alone after toolchain bootstrap:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-issue17-native-runtime.ps1
```

It rebuilds the extension and the separate `issue17-stdio` Cargo example,
then connects production `requestCredential`/`probeNativeStatus` JavaScript
to the production native JSON framing/parser and a real encrypted runtime.
Two fresh vaults are automatically seeded with the five public dummy accounts;
one is locked before requests begin. The 29 checks cover browser-origin and
document-token normalization, unique/duplicate/absent credentials, exact ports,
IDNs and lookalikes, malformed native contexts, lock refusal, and discarding a
late response after cancellation. Product request timeouts are unchanged.

Only the Chrome port and Windows IPC bridge are replaced by test adapters.
This suite does NOT exercise actual browser registration, permissions/DOM,
process-per-port lifetime, authenticated named pipes, or agent event transport.
In particular cancellation here verifies extension-side late-response discard,
not cancellation propagation across the Windows pipe. The existing runtime
tests separately cover lock/cancel/disconnect publication ordering.
Installed browser acceptance, OS peer authentication, and UI acceptance are
explicitly `NotRun` in its sanitized report. This is not a shortcut around
production identity/trust checks or a reason to close issue #17.

The helper is an explicitly tested example, not a production executable or
installer file. It accepts only a new absolute directory (local drive on
Windows), refuses existing directories and redirected ancestors, and retains
encrypted fixture artifacts plus a boolean-only report under
`artifacts/issue17-native-runtime-*`. No existing vault, registry entry,
installed product process, or trust store is modified.

### Isolated authenticated Windows lab

The opt-in `issue17-auth-client` example exercises actual Windows peer
authentication and framed IPC using only fixed dummy operations. It refuses
the normal product identity and any installation outside the unique lab
package in the disposable `LIBRARIAN-TEST` VM. It is not an installer payload.

`.codex-build-issue17-auth-lab.ps1` stages a new sparse package plus production
agent/native-host binaries. `.codex-run-issue17-auth-lab.ps1 -Stage <stage>`
signs and registers it only in the VM, runs the limited-user guest exercise,
and removes its temporary signing trust/key and unique native-host registry
keys. The normal installed vault is never the target. The lab uses its own
Desktop client/native launcher and changes only the extension's native-host
name, so it is not production installer/launcher acceptance.

Close other Librarian instances first: the production singleton is scoped to
the Windows session. That session must also be unlocked and recently active.
The test client uses the production inactivity monitor before seeding/unlocking;
it does not synthesize input, bypass an authentication dialog, or relax the
15-minute timeout. If idle, interact with the ordinary VM desktop before
retrying a fresh stage. No existing vault password or manual account entry is
needed. Reports distinguish authenticated setup, browser batches, remaining
NotRun cases, and independent review. See `.codex-issue17-next-tests.md` for
the latest evidence; do not infer completion from setup. On 2026-09-15 the
authenticated lab passed 74 Chrome/Edge checks plus five-account creation and
lock/unlock. Toolbar actions, worker restart, in-flight lock races, production
launcher acceptance, CI, and independent review remain outstanding; detailed
scope is in `.codex-issue17-auth-lab-evidence.md`.

## Interactive Windows shell smoke test

### Add Account page persistence regression

The 2026-09-14 VM report identified account-entry loss after pasting and clicking
elsewhere. Source diagnosis found that window reactivation unconditionally
closed the editor and cleared its controls during status refresh. The local fix
keeps Add Account as a separate, persistent page while checking status. It
temporarily disables vault-action buttons but keeps draft fields editable for
clipboard delivery, retains existing controls in memory without copying draft
secrets, and preserves field focus after verified unlocked status.
Blank-space clicks and field focus changes have no navigation/dismiss handler.
Save, Cancel, and Lock are explicit controls; a lock or failed access check
clears the draft. Inactivity locking is unchanged.

Regression tests cover repeated activation, request serialization, explicit
cancel/lock, refresh failures, and nonfatal passkey-list cancellation. They do
not substitute for installed pointer/keyboard acceptance. The complete local
Release pipeline passed on 2026-09-14 after this fix, including the native UI
build, shell regressions, Rust/extension tests, and installer structural/ICE
checks. The signed 0.1.12.0 fixture now contains this fix: VM upgrade
`issue17-vm-20260914-125120-dc3d1c07` and installed connection smoke
`desktop-20260914-125646` passed on 2026-09-14. Setup returned zero without a
reboot; identity, desktop/agent stability, and real native LOCK presentation
passed in Edge and Chrome. Temporary host signer trust/private key and evidence
cleanup passed. Do not repeat either completed 0.1.11.0/0.1.12.0 upgrade.
Installed shell acceptance is Partial: the user reported a generic request
failure followed by successfully adding a test account on 2026-09-14. The
failure's triggering action/cause and the click-away/paste behavior are not yet
confirmed; do not mark the transient error fixed. New credential-fill acceptance
remains NotRun, and the exact synthetic account setup is still unconfirmed.
Complete the remaining manual checks with synthetic fields:

1. Open Add Account and enter all four fields. Click blank space, the heading,
   border, and each other field; the same page and entered values must remain.
2. Tab and Shift+Tab between fields; copy/paste through VMConnect, switch away
   and return, and repeat. Verify all values and keyboard focus are preserved.
3. Cancel must return to the overview; reopening starts with empty fields.
   Save must store exactly one synthetic account and return to the overview.
4. Lock while editing, then manually unlock. The old draft must not reappear.
   Do not collect or automate master-password/Hello input.

### Packaged shell startup smoke

After a successful Release build, run the packaged WinUI shell smoke test from
an interactive Windows desktop:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-windows-shell-ui.ps1 -Configuration Release -Platform x64
```

The smoke test uses the generated loose package layout, starts Librarian
through its package application ID, and verifies an agent-backed first-run or
locked state, the master-password fallback, accessibility tree, and initial
keyboard focus. It refuses to replace a development package registered from
another location. If it creates the loose registration, it removes that
registration when the test finishes; an existing
registration for the same build layout is preserved.

This interactive test is the authoritative desktop-launch check. GitHub-hosted
Windows jobs run on Windows Server 2025, so the production MSI's Windows 11
workstation condition deliberately prevents them from executing the destructive
installer lifecycle. Hosted CI remains blocking for the complete build, tests,
installer structural validation, WiX ICE validation, and Rust parity. Issue
[#40](https://github.com/theundeadmonk/Librarian/issues/40) owns automated
install, upgrade, repair, rollback, and removal coverage on an actual disposable
Windows 11 workstation and the required release gate.

Developer Mode and the matching Windows App Runtime are required. The official
runtime installer is available from the
[Windows App SDK downloads](https://learn.microsoft.com/windows/apps/windows-app-sdk/downloads)
page. Loose registration is for development testing only and does not replace
the production installer. The destructive lifecycle remains in the repository
but is deferred to issue #40 rather than running on an unsupported Server host.

Windows is the authoritative MVP build and remains responsible for the native
application, passkey provider, packaging boundary, and Windows-specific
filesystem behavior. CI also formats, lints, and tests every Rust workspace
target and documentation test on Linux. This second platform catches
accidental portability gaps in the security core; it does not make Linux a
supported Librarian product.

After both jobs pass, CI compares each Rust test's package, Cargo target,
harness type, name, and active or ignored status. All platform-neutral tests
must appear and execute under the same status on both systems. An intentional
operating-system-specific test must be listed in
`tests/rust-test-parity.json` with a concrete rationale. The comparison fails
for an undocumented difference and for a stale policy entry, so removing,
renaming, ignoring, or accidentally excluding a Windows-only test is also
visible. Aggregate test counts are not used as a substitute for test identity.
The inventory compiles the complete workspace test graph once and lists the
exact test executables Cargo selected. This preserves workspace-wide dependency
feature unification and naturally excludes disabled targets. Documentation
tests are listed through the corresponding workspace-wide Cargo command, and
platform-specific path separators are normalized before comparison. Cargo's
stable metadata does not expose the `harness` manifest setting. A selected
target declared with `harness = false` must therefore also be named in
`harnessFreeTargets` in `tests/rust-test-parity.json`; CI compares that
executable at the target level without passing libtest arguments and rejects
duplicate, inactive, or stale declarations.

The trusted Rust path now includes the vault lifecycle, encrypted key
hierarchy, master-password unlock, guarded local SQLite ownership, and the
single website-account CRUD subset from issues #10 and #11. Each mutation
commits one opaque record envelope and the next encrypted manifest generation
in the same immediate transaction. Account origins use the pinned WHATWG URL
parser and are stored as exact normalized HTTP(S) origins. Native messaging is
limited to the issue #16 status protocol; browser site access and credential
operations remain disabled until their security gates and implementation
issues are complete. Vault-backed passkey storage and the
packaged Windows provider are available only for disposable development testing
until their review and real relying-party validation gates complete. Each
private-key operation binds the Windows Hello approval to the selected
credential and to a fresh authenticated agent connection; the agent accepts it
only as that connection's first request, so a captured proof cannot be replayed
with a new idempotency key or after a process restart. The packaged desktop now
reaches the vault agent through the authenticated issue #13 transport. The
Windows Hello native component owns platform-credential enrollment, PRF
evaluation, strict authenticator-response validation, and credential removal
inside the trusted agent; raw PRF results never cross desktop-controlled IPC.
Its build-time test executable uses synthetic responses and invalid-argument
paths only; it never displays a prompt or creates a credential. Interactive
development sessions may display the real Windows-owned prompt and create a
disposable development credential only after explicit user consent. Tests use
uniquely identifiable disposable values; do not use the current build with real
credentials.

## Dependency updates

Dependency updates are deliberate maintenance changes:

1. Verify the new version is a stable upstream release.
2. Review release notes and security advisories.
3. Update the manifest pin and regenerate the corresponding lockfile.
4. Run the complete Windows build.
5. Record changes to architectural assumptions in the relevant ADR.

Do not hand-edit integrity hashes in a lockfile and do not commit package caches, downloaded installers, signing material, or generated build output.
