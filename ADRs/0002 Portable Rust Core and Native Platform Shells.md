# ADR 0002: Portable Rust Core and Native Platform Shells

**Status:** Accepted
**Date:** 2026-07-22
**Scope:** Security core and platform application strategy
**Decision issue:** [#6](https://github.com/theundeadmonk/Librarian/issues/6)

## Context

The MVP must integrate deeply with Windows WebAuthn, Windows Hello, Chromium native messaging, and Windows packaging. Later products are expected on Android, macOS, iPhone, and iPad. Vault formats, key management, passkey handling, and recovery rules should not be independently reimplemented for each operating system, but platform credential providers and user interfaces must behave like native applications.

## Decision

Implement the portable vault, cryptographic, record-format, and policy core in stable, repository-pinned Rust. Keep its public interface narrow and free of Windows or UI concepts.

Use native platform shells and adapters:

- Windows MVP: C++/WinRT and WinUI 3 for the desktop application and Windows passkey-provider surface.
- Android later: Kotlin/Compose and Android Credential Manager provider APIs.
- Apple platforms later: Swift/SwiftUI and Authentication Services extensions.

Do not build a shared cross-platform UI. C++ should remain limited to Windows integration code. Rust owns portable security rules; platform code owns lifecycle, presentation, accessibility, and operating-system APIs.

For the Windows MVP, the C++/WinRT app and passkey provider communicate with the Rust vault agent through the accepted process boundary and the authenticated IPC design owned by [issue #12](https://github.com/theundeadmonk/Librarian/issues/12). Do not introduce an in-process C++/Rust FFI boundary unless measured evidence demonstrates that IPC cannot satisfy a required Windows transaction.

For future Kotlin and Swift bindings, evaluate UniFFI in a bounded spike. Do not adopt it until cancellation, errors, concurrency, binary size, versioning, and secret-memory behavior have been measured and the version is pinned.

## 2026-07-27 amendment: agent-internal Windows Hello bridge

Issue #15 requires the Rust vault agent to own the Windows Hello ceremony.
Sending a WebAuthn PRF result through desktop-controlled IPC was rejected
because a modified desktop could choose those bytes and bypass the
Windows-owned verification prompt. Running the existing reviewed native
WebAuthn component out of process would recreate the same secret-bearing IPC
problem, while independently redeclaring the evolving WebAuthn API-v8 ABI in
Rust would duplicate a security-critical Windows boundary.

The agent may therefore statically link one narrow C ABI adapter around
`platform/windows-hello` as a measured exception to the general prohibition on
in-process C++/Rust FFI. This exception is part of the trusted agent process;
it is not available to the desktop, passkey provider, native-messaging host,
extension, or website.

The exception is limited to:

- capability discovery, enrollment, PRF evaluation, cancellation, and removal
  for the fixed Librarian relying party;
- one nonzero parent-window value that the Rust agent validates belongs to the
  authenticated desktop peer before calling native code;
- bounded public metadata: a credential ID of at most 1,024 bytes and one
  32-byte PRF salt;
- exactly one 32-byte transient PRF result written into caller-owned,
  zeroizing Rust storage; and
- integer status codes with no exception, allocator, object, string, or
  ownership transfer across the ABI.

The adapter catches every C++ exception, initializes outputs before work,
clears native and caller-visible secret buffers on every unsuccessful path,
and never receives a password, installation key, VRK, protector ciphertext,
vault record, or database handle. Rust remains the only owner of cryptography,
protector construction, local protected-state parsing, vault state, and
authorization. ABI size/offset assertions, canaries, cancellation and cleanup
tests, and independent review are required before production readiness.
This amendment does not authorize a general binding layer or any other
secret-bearing FFI.

## Consequences

### Benefits

- Security-critical behavior and test vectors have one implementation.
- Native platform surfaces preserve expected accessibility, lifecycle, and credential-provider behavior.
- The Windows MVP does not wait for mobile UI or build-system decisions.
- Rust's ownership model reduces common memory-safety defects in the most sensitive portable code.

### Costs and controls

- Cross-language and process boundaries add failure modes; make protocols small, versioned, fail-closed, and covered by integration tests.
- C++/Rust diagnostics and packaging require deliberate tooling, compatible symbols, and version management.
- Native UIs require separate implementations; share behavior specifications and tests rather than UI code.
- Rust does not make cryptography automatically safe; use vetted libraries, explicit formats, test vectors, and external review.

## Alternatives considered

- **C++ for the entire product:** strong Windows access, but a weaker long-term portability and memory-safety tradeoff for the shared security core.
- **C#/.NET for the entire product:** productive for Windows UI, but the third-party passkey provider still requires careful native integration and the core would not naturally serve Kotlin and Swift clients.
- **Kotlin Multiplatform core:** credible for Android and Apple business logic, but it duplicates the role of a Rust security core and does not improve the Windows-first native boundary enough to justify two portable runtimes.
- **Electron or a web UI:** broader UI reuse, but adds a browser runtime and a less direct native security surface to a Windows-only MVP.
- **Tauri:** useful for some desktop products, but the MVP still needs native Windows passkey-provider and lifecycle work; defer UI framework convenience until the trusted boundaries are proven.
