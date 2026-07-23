# ADR 0002: Portable Rust Core and Native Platform Shells

**Status:** Proposed
**Date:** 2026-07-22
**Scope:** Security core and platform application strategy

## Context

The MVP must integrate deeply with Windows WebAuthn, Windows Hello, Chromium native messaging, and Windows packaging. Later products are expected on Android, macOS, iPhone, and iPad. Vault formats, key management, passkey handling, and recovery rules should not be independently reimplemented for each operating system, but platform credential providers and user interfaces must behave like native applications.

## Proposed decision

Implement the portable vault, cryptographic, record-format, and policy core in stable, repository-pinned Rust. Keep its public interface narrow and free of Windows or UI concepts.

Use native platform shells and adapters:

- Windows MVP: C++/WinRT and WinUI 3 for the desktop application and Windows passkey-provider surface.
- Android later: Kotlin/Compose and Android Credential Manager provider APIs.
- Apple platforms later: Swift/SwiftUI and Authentication Services extensions.

Do not build a shared cross-platform UI. C++ should remain limited to Windows integration code. Rust owns portable security rules; platform code owns lifecycle, presentation, accessibility, and operating-system APIs.

For future Kotlin and Swift bindings, evaluate UniFFI in a bounded spike. Do not adopt it until cancellation, errors, concurrency, binary size, versioning, and secret-memory behavior have been measured and the version is pinned.

## Consequences

### Benefits

- Security-critical behavior and test vectors have one implementation.
- Native platform surfaces preserve expected accessibility, lifecycle, and credential-provider behavior.
- The Windows MVP does not wait for mobile UI or build-system decisions.
- Rust's ownership model reduces common memory-safety defects in the most sensitive portable code.

### Costs and controls

- Foreign-function boundaries add failure modes; make them small, synchronous where practical, versioned, and covered by integration tests.
- C++/Rust debugging and packaging require deliberate tooling and symbol management.
- Native UIs require separate implementations; share behavior specifications and tests rather than UI code.
- Rust does not make cryptography automatically safe; use vetted libraries, explicit formats, test vectors, and external review.

## Alternatives considered

- **C++ for the entire product:** strong Windows access, but a weaker long-term portability and memory-safety tradeoff for the shared security core.
- **C#/.NET for the entire product:** productive for Windows UI, but the third-party passkey provider still requires careful native integration and the core would not naturally serve Kotlin and Swift clients.
- **Kotlin Multiplatform core:** credible for Android and Apple business logic, but it duplicates the role of a Rust security core and does not improve the Windows-first native boundary enough to justify two portable runtimes.
- **Electron or a web UI:** broader UI reuse, but adds a browser runtime and a less direct native security surface to a Windows-only MVP.
- **Tauri:** useful for some desktop products, but the MVP still needs native Windows passkey-provider and lifecycle work; defer UI framework convenience until the trusted boundaries are proven.
