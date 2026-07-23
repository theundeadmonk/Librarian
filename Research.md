# Research

This is the initial evidence index behind the MVP direction and proposed [[Architecture]]. Sources were reviewed on 2026-07-22. They inform the design; they do not substitute for the formal threat model, architecture decisions, implementation validation, or independent review still listed in [[Open Questions]].

## Usability

- [The more accounts I use, the less I have to think: A Longitudinal Study on the Usability of Password Managers for Novice Users — SOUPS 2025](https://www.usenix.org/conference/soups2025/presentation/cabarcos)
  - First-impression usability strongly affects adoption.
  - Primary-password management is a major novice hurdle.
  - The product must reduce decisions rather than rely on security dashboards.

## Browser-extension trust boundary

- [Phishing Attacks against Password Manager Browser Extensions — USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-anliker.pdf)
  - Web content can imitate extension-style unlock surfaces.
  - The MVP therefore keeps master-password entry in a recognizable native Windows surface.

- [Native Messaging — Chrome for Developers](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
  - Defines the supported channel between a Chromium extension and registered native application.

- [Manifest V3 overview — Chrome for Developers](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3)
  - Establishes the current Chromium extension platform and its service-worker-based execution model.

- [The activeTab permission — Chrome for Developers](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab)
  - Supports temporary page access after an explicit user gesture, useful for authentication QR capture.

## Passkeys on Windows

- [Windows App SDK release channels — Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/get-started/versioning-overview)
  - Identifies Windows App SDK 2.2 as the current stable release when this note was reviewed.

- [Build desktop Windows apps with the Windows App SDK — Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/)
  - Recommends WinUI 3 and the Windows App SDK for new Windows desktop applications.

- [Plugin passkey manager support — Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/develop/security/third-party)
  - Windows 11 supports third-party passkey-manager plugins and Windows Hello verification.
  - Microsoft's public sample is for testing rather than production, making an early feasibility spike mandatory.

- [Passkey Manager sample — Microsoft Learn](https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/passkeymanager/)
  - Demonstrates the Windows WebAuthn plugin APIs and native application responsibilities.

- [Local Windows passkey-provider feasibility spike](<../Password Manager/README.md>)
  - Passed on 2026-07-22 using Windows 11 build 26200.8875, Windows SDK 10.0.28000.0, Google Chrome, and webauthn.io.
  - Verified provider registration and enablement plus passkey creation, authentication, and deletion.

## Shared core and native platform boundaries

- [Rust 1.97.1 release — The Rust Programming Language](https://blog.rust-lang.org/releases/latest/)
  - Records the current stable Rust release used for the proposed initial toolchain baseline when this note was reviewed.

- [Rust for Windows — Microsoft](https://github.com/microsoft/windows-rs)
  - Provides official Rust language projections for Windows APIs and demonstrates an actively supported Rust/Windows boundary.

- [UniFFI — Mozilla](https://github.com/mozilla/uniffi-rs)
  - Generates Kotlin and Swift bindings for Rust libraries and is used in production, but remains pre-1.0; the architecture therefore treats it as a future spike, not an accepted dependency.

## Authentication codes

- [RFC 6238: TOTP](https://www.rfc-editor.org/info/rfc6238)
  - Defines interoperable time-based one-time passwords.

- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
  - Documents the common `otpauth://` provisioning payload encoded by authenticator QR codes.

## Backup and key recovery

- [NIST SP 800-63B-4: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)
  - Defines current authenticator guidance, including verifier-name binding for phishing-resistant WebAuthn authenticators, local activation secrets, and protection requirements for exportable authentication keys.

- [FIDO Credential Exchange Specifications](https://fidoalliance.org/specifications-credential-exchange-specifications/)
  - Establishes an emerging standard direction for secure credential exchange, including passkeys and passwords; future import and portability work should evaluate it before inventing a private exchange format.

- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
  - Long-lived encrypted data needs secure key backup because lost decryption keys make it permanently unrecoverable.

- [NCSC Password Manager Buyers Guide](https://www.ncsc.gov.uk/collection/passwords/password-manager-buyers-guide)
  - Recovery must deliberately balance unauthorized recovery risk against permanent loss of vault access.

## Future platforms — evidence only, outside the MVP

- [Credential Manager provider integration — Android Developers](https://developer.android.com/identity/sign-in/credential-provider)
  - Android exposes provider APIs for passwords and passkeys. A future Android application should integrate through these native APIs rather than reproduce browser-only autofill behavior.

- [Credential-provider extension context — Apple Developer Documentation](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderextensioncontext)
  - Apple Authentication Services exposes credential-provider operations for passwords, passkey registration and assertion, and one-time codes.

- [Providing one-time passcodes to AutoFill — Apple Developer Documentation](https://developer.apple.com/documentation/authenticationservices/providing-one-time-passcodes-to-autofill)
  - A future Apple-platform application can provide authentication codes through the operating system's native credential-provider experience.

These platform APIs influence the proposed portable-core boundary only. They do not authorize Android, macOS, iPhone, or iPad implementation during the Windows MVP.
