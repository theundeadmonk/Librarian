# ADR 0004: Windows MVP Technology Baseline

**Status:** Proposed
**Date:** 2026-07-22
**Scope:** Initial implementation toolchain

## Context

The MVP needs direct Windows passkey and Hello integration, a small portable security core, a Chromium extension, transactional local storage, and one coherent Windows package. The project should begin on current stable software rather than obsolete or preview toolchains.

## Proposed decision

Start the repository with the following baseline, then pin exact versions and lockfiles in source control:

| Area | Baseline |
|---|---|
| Windows UI | C++/WinRT with WinUI 3 and Windows App SDK 2.2, the current stable release at the time of this decision. |
| Windows APIs | Windows SDK 10.0.28000.0, already proven by the local passkey feasibility spike. |
| Portable core and agent | Stable Rust 1.97.1 at the time of this decision, pinned with `rust-toolchain.toml`. |
| Browser extension | TypeScript targeting Chromium Manifest V3, with checked-in package-manager lockfile. |
| Native browser bridge | Chromium native messaging through a small Rust host. |
| Local database | SQLite used transactionally beneath vault-layer authenticated encryption; the encryption construction is a separate security decision. |
| Windows packaging | MSIX for the native product components and registration manifests. |

Use the latest stable patch versions available when the repository is scaffolded and record them in the first build manifest. Preview SDKs, experimental browser APIs, and unpinned dependencies require an explicit exception and rollback plan.

## Consequences

- The chosen baseline aligns the product with the current supported Windows application platform and the successful passkey spike.
- Rust and Node dependencies remain reproducible through pinned toolchains and lockfiles.
- Updating to newer stable releases is an intentional maintenance change with release-note review, build verification, and regression testing.
- Exact cryptographic crates, SQLite binding, test framework, package manager, local IPC transport, and signing service remain undecided; this ADR must not be read as approving them.

## Exit criteria

Accept this baseline only after a clean Windows developer environment can bootstrap, build, test, package, install, upgrade, and uninstall the Slice 1 skeleton using documented commands.
