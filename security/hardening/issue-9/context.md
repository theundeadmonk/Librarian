# Issue 9 hardening context

This analysis supports the proposed vault cryptography decision. It is derived
design material, not evidence that credential storage is implemented or safe.

## Source identity

- Repository revision: `6416e0bfb72f3d02c2676ba09483eff1822fa087`
- Source drift at analysis start: none
- Evidence collection digest:
  `39dbfa6b7ab66a8af7bbd846e8d5a232066543fd0d61c1aae865cf648fe4779d`
- Digest construction: SHA-256 of the ordered `sha256sum` output for the five
  repository artifacts below as stored at the source revision. The current
  working tree also contains the derived ADR and navigation changes produced
  by this analysis.

## Evidence inventory

| ID | Kind | Title | Source | What it establishes |
|---|---|---|---|---|
| `E-01` | Threat model | Slice 1 threat model | `Threat Model.md` | Hostile-file, rollback, offline-password, Windows Hello, recovery, diagnostics, and agent-ownership invariants. |
| `E-02` | Architecture | Windows MVP architecture | `Architecture.md` | The agent owns long-lived keys; SQLite sits beneath vault-layer authenticated encryption; exact cryptography is blocked on issue #9. |
| `E-03` | Architecture decision | Windows MVP component boundaries | `ADRs/0003 Windows MVP Component Boundaries.md` | Clients cannot write ciphertext or own the vault; incompatible and malformed operations fail closed. |
| `E-04` | Source | Vault-format scaffold | `crates/vault-format/src/lib.rs` | No credential schema or cryptographic construction is currently approved. |
| `E-05` | Source | Vault-core scaffold | `crates/vault-core/src/lib.rs` | Credential storage remains disabled while format readiness is scaffold-only. |
| `E-06` | Standard | RFC 9106 | https://www.rfc-editor.org/rfc/rfc9106.html | Argon2id version 19, salt guidance, recommended profiles, and vectors. |
| `E-07` | Standard | RFC 5869 | https://www.rfc-editor.org/rfc/rfc5869.html | HKDF extract/expand semantics and purpose-binding through `info`. |
| `E-08` | Standard | RFC 8439 | https://www.rfc-editor.org/rfc/rfc8439.html | ChaCha20-Poly1305 construction and authoritative vectors. |
| `E-09` | Standard | RFC 8452 | https://www.rfc-editor.org/rfc/rfc8452.html | AES-GCM-SIV misuse resistance and authoritative vectors. |
| `E-10` | Standard | RFC 8949 | https://www.rfc-editor.org/rfc/rfc8949.html | Deterministic CBOR encoding rules. |
| `E-11` | Platform guidance | Windows Hello | https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello | Windows Hello user-verification APIs; the reviewed page does not establish the complete symmetric wrapping boundary needed by Librarian. |
| `E-12` | Library evidence | RustCrypto XChaCha20-Poly1305 | https://docs.rs/crate/chacha20poly1305/0.11.0 | Current stable Rust implementation and its NCC Group audit statement. |
| `E-13` | Library evidence | RustCrypto AES-GCM-SIV | https://docs.rs/aes-gcm-siv/0.11.1/aes_gcm_siv/#security-warning | The current stable crate states that it has never received a security audit. |
| `E-14` | Independent implementation | libsodium XChaCha20-Poly1305 | https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction | Independent implementation, 192-bit random-nonce guidance, and interoperability path. |
| `E-15` | Inference from source | Dispersed cryptographic ownership risk | `crates/vault-format/src/lib.rs`, `Architecture.md` | Without a single versioned specification, later unlock, record, backup, and migration paths could independently own the same security invariants. |

## Limits

- No production vault exists to benchmark or attack.
- No Windows Hello wrapper or rollback anchor has been implemented; issue #15
  must prove that boundary.
- KDF, full-vault verification, migration, and backup performance are
  unmeasured.
- The standards and crate metadata were reviewed on 2026-07-23. Dependency
  state is time-sensitive and must be refreshed when implementation begins.
