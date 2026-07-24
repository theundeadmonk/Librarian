# Windows development

The active Librarian MVP builds only on x64 Windows 11. The repository does not contain Android, Apple-platform, Linux, or cross-platform user-interface projects.

## Supported toolchain

The foundation is pinned to stable releases verified on 2026-07-22:

| Area | Required version |
|---|---|
| Operating system | Windows 11 build 26100 or newer |
| Visual Studio | Visual Studio 2022 17.12 or newer with Desktop development with C++ and Windows application development; Visual Studio 2026 is supported |
| Windows SDK target | 10.0.28000.0 |
| Windows SDK Build Tools | 10.0.28000.2270, supplied by the locked NuGet package |
| Windows App SDK | 2.3.1 |
| C++/WinRT | 3.0.260715.1 |
| Windows Implementation Library | 1.0.260126.7 |
| Rust | 1.97.1, x86_64-pc-windows-msvc |
| Node.js | 24.18.0 LTS |
| npm | 11.16.0 |
| TypeScript | 7.0.2 |

The manifests and lockfiles in source control are authoritative. Preview, release-candidate, beta, experimental, and floating dependency versions are not accepted by the foundation.

## First-time setup

Install Git for Windows, the required Visual Studio workloads, Node.js 24.18.0, Rustup, and the Windows SDK:

```powershell
winget install Microsoft.WindowsSDK.10.0.28000
```

Visual Studio's C++ workload does not install SDK 10.0.28000. The build uses its installed platform headers and libraries together with the exact 10.0.28000.2270 Build Tools from the locked NuGet package. From a PowerShell terminal at the repository root, let the pinned `rust-toolchain.toml` install Rust and then validate the complete environment:

```powershell
powershell.exe -NoProfile -File .\scripts\bootstrap.ps1
```

The bootstrap command only validates the machine. It does not change system settings or install software. It reports every active version and stops on a missing tool, mismatched pin, preview release, missing lockfile, or unsupported Windows build.

## Build and test

One command formats-checks, lints, tests, restores locked dependencies, and builds the Rust workspace, Chromium extension, WinUI app, and Windows passkey boundary:

```powershell
powershell.exe -NoProfile -File .\scripts\build.ps1 -Configuration Release -Platform x64
```

Build outputs and diagnostic logs are written beneath `artifacts/` or the component-specific ignored output directories. Native artifacts are unsigned; production MSIX generation and signing are deferred to issue #19.
On a normal Windows checkout, the build also checks whitespace in the committed branch diff, the index, and the working tree. GitHub Actions supplies the pull request or push base commit explicitly.

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

The foundation now includes the empty-vault lifecycle, encrypted key hierarchy,
master-password unlock, and guarded local SQLite ownership described by issue
#10. Credential records, browser site access, authenticated IPC, native
messaging, Windows Hello, and production passkey storage remain disabled until
their security gates and implementation issues are complete. Do not use the
current build with real credentials.

## Dependency updates

Dependency updates are deliberate maintenance changes:

1. Verify the new version is a stable upstream release.
2. Review release notes and security advisories.
3. Update the manifest pin and regenerate the corresponding lockfile.
4. Run the complete Windows build.
5. Record changes to architectural assumptions in the relevant ADR.

Do not hand-edit integrity hashes in a lockfile and do not commit package caches, downloaded installers, signing material, or generated build output.
