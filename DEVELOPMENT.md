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

This workflow does not install the MSI, write machine-wide browser integration,
or exercise install, upgrade, repair, rollback, or uninstall transactions. It
refuses to replace a development identity registered from another directory.
Developer Mode is required. At the current foundation stage, the vault-agent
executable exits after its bounded startup status and the desktop therefore
shows its intentional fail-closed agent-unavailable state; later product issues
will connect the already implemented agent protocol and UI surfaces.

## Interactive Windows shell smoke test

After a successful Release build, run the packaged WinUI shell smoke test from
an interactive Windows desktop:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-windows-shell-ui.ps1 -Configuration Release -Platform x64
```

The smoke test uses the generated loose package layout, starts Librarian
through its package application ID, and verifies the fail-closed state, retry
action, accessibility tree, and initial keyboard focus. It refuses to replace a
development package registered from another location. If it creates the loose
registration, it removes that registration when the test finishes; an existing
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
parser and are stored as exact normalized HTTP(S) origins. Browser site access,
production authenticated IPC, native messaging, Windows Hello, and production
passkey storage remain disabled until their security gates and implementation
issues are complete. The Windows local-IPC probe validates operating-system
assumptions with disposable marker bytes; it is not the issue #13 production
transport. The Windows Hello native component owns platform-credential
enrollment, PRF evaluation, strict authenticator-response validation, and
credential removal. Its build-time test executable uses synthetic responses
and invalid-argument paths only; it never displays a prompt or creates a
credential. The WinUI-to-agent enrollment and unlock path remains disabled
until the native ceremony runs inside the trusted agent; raw PRF results must
never cross desktop-controlled IPC. Tests use uniquely identifiable disposable
values; do not use the current build with real credentials.

## Dependency updates

Dependency updates are deliberate maintenance changes:

1. Verify the new version is a stable upstream release.
2. Review release notes and security advisories.
3. Update the manifest pin and regenerate the corresponding lockfile.
4. Run the complete Windows build.
5. Record changes to architectural assumptions in the relevant ADR.

Do not hand-edit integrity hashes in a lockfile and do not commit package caches, downloaded installers, signing material, or generated build output.
