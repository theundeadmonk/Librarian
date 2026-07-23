# ADR 0004: Windows MVP Technology Baseline

**Status:** Accepted
**Date:** 2026-07-22
**Scope:** Initial implementation toolchain
**Decision issue:** [#6](https://github.com/theundeadmonk/Librarian/issues/6)

## Context

The MVP needs direct Windows passkey and Hello integration, a small portable security core, a Chromium extension, transactional local storage, and one coherent Windows package. The project should begin on current stable software rather than obsolete or preview toolchains.

## Decision

Start the repository with the following baseline. These exact stable versions were verified and pinned when the repository was scaffolded on 2026-07-22:

| Area | Baseline |
|---|---|
| Windows UI | C++/WinRT with WinUI 3 and Windows App SDK 2.3.1. |
| Windows APIs | Windows SDK target 10.0.28000.0 with Build Tools 10.0.28000.2270, already proven by the local passkey feasibility spike. |
| Windows C++ support | C++/WinRT 3.0.260715.1 and Windows Implementation Library 1.0.260126.7. |
| Portable core and agent | Rust 1.97.1 for `x86_64-pc-windows-msvc`, pinned with `rust-toolchain.toml`. |
| Browser extension | Node.js 24.18.0 LTS, npm 11.16.0, and TypeScript 7.0.2 targeting Chromium Manifest V3. |
| Native browser bridge | Chromium native messaging through a small Rust host. |
| Local database | SQLite used transactionally beneath vault-layer authenticated encryption; the encryption construction is a separate security decision. |
| Windows packaging | MSIX for the native product components and registration manifests. |

The version evidence is the official [Windows App SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/downloads), [Windows SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads), [Rust release announcement](https://blog.rust-lang.org/releases/latest/), and [Node.js release schedule](https://nodejs.org/en/about/previous-releases). Package manifests and checked-in lockfiles are the reproducibility boundary.

Use the latest stable patch versions available when an intentional maintenance update is approved. Preview SDKs, experimental browser APIs, and unpinned dependencies require an explicit exception and rollback plan.

## Consequences

- The chosen baseline aligns the product with the current supported Windows application platform and the successful passkey spike.
- Rust and Node dependencies remain reproducible through pinned toolchains and lockfiles.
- Updating to newer stable releases is an intentional maintenance change with release-note review, build verification, and regression testing.
- Exact cryptographic crates, SQLite binding, test framework, package manager, local IPC transport, and signing service remain undecided; this ADR must not be read as approving them.

## Validation and follow-up

[Issue #7](https://github.com/theundeadmonk/Librarian/issues/7) must verify the exact stable versions available at scaffolding time and prove that a clean Windows developer environment can bootstrap, build, and test the Slice 1 skeleton using documented commands. Packaging, installation, upgrade, repair, and removal are validated by [issue #19](https://github.com/theundeadmonk/Librarian/issues/19).

If the accepted baseline cannot pass those checks, amend or supersede this ADR before dependent implementation proceeds. Acceptance records the technology direction; it does not waive implementation validation.
