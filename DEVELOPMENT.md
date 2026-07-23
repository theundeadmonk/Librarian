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

Install Git for Windows, the required Visual Studio workloads, Node.js 24.18.0, and Rustup. Visual Studio may install a Windows SDK, but the build obtains the exact 10.0.28000.2270 Build Tools from the locked NuGet package. From a PowerShell terminal at the repository root, let the pinned `rust-toolchain.toml` install Rust and then validate the complete environment:

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

The foundation contains no functional vault, cryptography, credential storage, browser site access, native-messaging protocol, agent IPC, or passkey implementation. Do not use it with real credentials.

## Dependency updates

Dependency updates are deliberate maintenance changes:

1. Verify the new version is a stable upstream release.
2. Review release notes and security advisories.
3. Update the manifest pin and regenerate the corresponding lockfile.
4. Run the complete Windows build.
5. Record changes to architectural assumptions in the relevant ADR.

Do not hand-edit integrity hashes in a lockfile and do not commit package caches, downloaded installers, signing material, or generated build output.
