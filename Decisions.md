# Decisions

This note records settled product choices. Proposed ideas belong in [[Open Questions]], not here.

| Date | Decision | Reason |
|---|---|---|
| 2026-07-22 | The working product name is **Librarian**. | It suggests a calm, trustworthy guide that organizes and safeguards credentials for the user. |
| 2026-07-22 | The MVP is for one user on Windows 11. | Prove the central experience before adding family and multi-device complexity. |
| 2026-07-22 | The MVP implementation and acceptance boundary is Windows 11 only. | Future Android and Apple support may shape stable formats and narrow interfaces, but it must not add code or delay the four Windows slices. |
| 2026-07-22 | Passkeys are a defining MVP feature. | Passkeys are the primary reason for building the product. |
| 2026-07-22 | The MVP includes a Windows desktop app and Chromium extension. | Windows owns native passkey and Hello integration; the extension owns website context and forms. |
| 2026-07-22 | Chrome and Edge are the first tested browsers. | Both use Chromium while covering the user's immediate environment. |
| 2026-07-22 | The live MVP vault is local-only and works offline. | Avoid account, server, and synchronization complexity while proving the core. |
| 2026-07-22 | Unlock supports a master password and Windows Hello. | The password is dependable; Hello provides the everyday low-friction experience. |
| 2026-07-22 | The extension never asks for the master password. | A native unlock surface is harder for a website to imitate and keeps the trust boundary recognizable. |
| 2026-07-22 | Automatic fill happens once, while the dropdown stays available. | Avoid fighting user edits while preserving an explicit refill escape hatch. |
| 2026-07-22 | Generated passwords are preserved before form submission and confirmed after success. | A generated password must not be lost during navigation or a failed website workflow. |
| 2026-07-22 | Manually entered credentials require a one-action save prompt. | Saving should be easy without silently capturing an unintended secret. |
| 2026-07-22 | Password changes preserve history and require account-aware confirmation. | Prevent ambiguous or incorrect overwrites. |
| 2026-07-22 | Time-based authentication codes are part of the MVP. | Users should not need a separate authenticator app for standard codes. |
| 2026-07-22 | Authentication setup is detected automatically, then saved with one user action. | Minimize friction without silently storing unrelated QR codes. |
| 2026-07-22 | Encrypted backups live in a user-selected OneDrive or Google Drive synchronized folder. | Reuse existing desktop sync without adding cloud APIs or exposing plaintext. |
| 2026-07-22 | The backup must restore the vault after device loss. | Opaque cloud storage is useful only if the user retains an independent decryption path. |
| 2026-07-22 | 1Password and LastPass import is a fast follow, not MVP scope. | Manual entry and native capture prove the product before importer complexity is added. |
| 2026-07-22 | Extension-only access is post-MVP. | Public and managed computers require a different security and recovery architecture. |
| 2026-07-22 | Windows third-party passkey-provider feasibility is proven. | The local spike registered and enabled a provider, then created, authenticated with, and deleted a test passkey through Chrome. |
| 2026-07-25 | Trusted local clients use mutually authenticated, logon-scoped Windows named pipes with exact per-role authorization. | Endpoint discovery and same-user access are not proof of identity; both peers must validate the connected packaged process before a bounded operation may cross the vault boundary. |
| 2026-08-01 | Librarian locks after 15 minutes without Windows keyboard, mouse, or touch input, and immediately on sleep, session lock, or sign-out. | A predictable app-owned timeout limits exposed key material even when the user has not configured a Windows inactivity policy. |
