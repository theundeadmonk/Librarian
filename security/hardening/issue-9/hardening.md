# Security Hardening Review: Librarian Vault Cryptographic Boundary

## Evidence Basis

This review turns the accepted Slice 1 threat model and the deliberately
disabled vault scaffold into a decision-ready cryptographic boundary. I
inspected the architecture, threat model, format/core readiness guards, current
standards, current stable Rust crate metadata, and the published audit posture
of the serious AEAD candidates. The evidence inventory and limitations are in
[context.md](context.md).

This is proposed design, not proof of remediation. No production vault exists,
and Windows Hello release, rollback-anchor protection, performance, and the
complete composition still require implementation and independent review.

## Constraints

- Windows 11 is the only MVP implementation and acceptance platform.
- The Rust vault agent remains the only long-lived plaintext and key owner.
- Either a master password or a high-entropy recovery key must restore a
  portable backup without the original device.
- Windows Hello is convenience unlock, never the only recovery path.
- Cloud providers receive one opaque authenticated backup payload.
- Hostile files, unknown versions, corruption, and migration failure fail
  closed.
- No production credential handling is enabled by this analysis.
- Performance and memory effects are not measured; the profile is balanced and
  requires explicit benchmark gates.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
|---|---|---|---|---|
| Establish one versioned cryptographic ownership boundary | Slice 1 hostile-file and key-ownership invariants; disabled vault-format and vault-core guards; current AEAD audit evidence | 1. AES-256-GCM with durable counters; 2. XChaCha20-Poly1305 envelopes and encrypted manifest; 3. AES-256-GCM-SIV envelopes | Choose Option 2 for the MVP, conditioned on vectors, #15, benchmarks, and independent review. | [Vault cryptographic boundary](proposals/vault-cryptographic-boundary.md) |

## Recommendation Summary

I recommend Option 2 under the MVP's current constraints. Its 192-bit nonce
lets every write use operating-system randomness without making a crash-safe
global counter part of the security boundary. The current Rust implementation
has a published third-party audit statement, and libsodium gives us a genuinely
independent interoperability path. Record-level envelopes preserve the agent's
ownership boundary, while an encrypted manifest prevents SQLite row deletion,
substitution, or partial replay from looking like a valid smaller vault.

Option 1 becomes preferable only if a standards or compliance requirement
forces AES-GCM and we are prepared to treat nonce allocation as durable
security-critical state. Option 3 becomes preferable if the selected
AES-GCM-SIV implementation and Librarian composition receive independent
review at least as strong as the XChaCha path; it offers attractive resilience
to accidental nonce reuse, but the current stable Rust crate's own warning
gives me pause for the first credential-bearing format.

## Next Decisions

- Review and accept, amend, or reject
  [ADR 0005](../../../ADRs/0005%20Vault%20Key%20Hierarchy%20and%20Encrypted%20Record%20Format.md).
- Prove the Windows Hello protector and rollback-anchor boundary in issue #15.
- Benchmark Argon2id and full-vault verification on the minimum supported
  Windows hardware before implementation acceptance.
- Produce independent deterministic vectors and fuzz the strict parser.
- Keep `FormatReadiness::ScaffoldOnly` until the named independent review gate
  is recorded.
