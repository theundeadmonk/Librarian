# Implementation Plan: XChaCha20-Poly1305 Envelopes and Encrypted Manifest

## Selected Design And Constraints

Implement Option 2 from the
[vault cryptographic boundary proposal](../proposals/vault-cryptographic-boundary.md)
and the exact bytes and failure rules in
[ADR 0005](../../../../ADRs/0005%20Vault%20Key%20Hierarchy%20and%20Encrypted%20Record%20Format.md).

The implementation must preserve the agent as the only long-lived plaintext
owner, keep all browser-facing components away from unlock material, support
master-password-only and recovery-key-only clean-device restore, and leave
credential storage disabled until the final independent review gate.

Evidence collection digest:
`39dbfa6b7ab66a8af7bbd846e8d5a232066543fd0d61c1aae865cf648fe4779d`.

## Source Revision And Drift Check

- Design source revision:
  `6416e0bfb72f3d02c2676ba09483eff1822fa087`.
- Before implementation, refresh `main`, re-read `Threat Model.md`, ADRs 0003
  and 0005, and the current `vault-core`, `vault-format`, and agent boundaries.
- Recompute the evidence digest and record source drift in the implementation
  PR. If another change gives a client direct database access, changes recovery
  semantics, or introduces credential handling, return to design review.

## Affected Components

- `crates/vault-format`: private versioned wire types, deterministic CBOR,
  strict decoders, bounds, test-vector reader.
- `crates/vault-core`: secret types, key generation/schedule, wrappers, record
  and manifest operations, migration orchestration.
- `crates/vault-agent`: lifecycle, SQLite ownership, transactions, rollback
  anchor, lock/cancellation, backup/restore coordination.
- `tests/test-vectors`: primitive, complete-format, negative, and independent
  verifier fixtures.
- Windows integration from #15: device-local Hello protector and anchor
  protection.
- CI/security policy: dependency audit, fuzz targets, canary scans, review
  evidence, and the final readiness gate.

## Ordered Work Packages

1. **Land dependency and type boundaries.** Pin the ADR versions; add secret
   wrappers that cannot format, serialize, or clone; keep all public
   credential APIs disabled.
2. **Implement deterministic formats.** Add fixed-array encoders and strict,
   bounded decoders for header, wrapper AAD, record AAD/envelope/plaintext,
   manifest, and backup. Re-encode and compare on decode.
3. **Add primitive conformance.** Implement Argon2id and HKDF labels, OS
   randomness, XChaCha seal/open, zeroization, and authoritative vectors.
4. **Implement root creation and portable unlock.** Generate VRK/RUK, create
   independent master and recovery wrappers, and prove both restore the same
   empty vault. Do not implement Hello yet.
5. **Implement SQLite ownership.** Create the two-table strict schema, configure
   limits/defensive mode, and deny database handles outside the agent storage
   module.
6. **Implement record and manifest transactions.** Authenticate the complete
   row set, increment generation once, use fresh nonces, commit atomically, and
   make lock/cancellation win before success is released.
7. **Implement hostile-file behavior.** Add full authenticated open,
   quarantine, uniform authentication failure, resource limits, mutation
   tests, fuzzing, and post-open file-change handling.
8. **Implement backup and restore.** Use SQLite's backup API, outer encryption,
   safe temporary writes, full readback verification, quarantine restore, and
   independent master/recovery paths.
9. **Implement copy-on-write migration.** Start with a no-op v1-to-v1 fixture
   and synthetic unsupported versions; exercise crash points and application
   downgrade behavior before a real v2 exists.
10. **Integrate #15.** Add the proven Hello device protector and rollback
    anchor without changing the portable format. Test session, cancellation,
    restart, same-user, wrapper corruption, and clean-device behavior.
11. **Measure and review.** Benchmark the accepted Windows baseline, run all
    independent vectors and canary scans, refresh dependency evidence, and
    commission the named independent review.
12. **Enable in a separate gate.** Only after every acceptance item passes,
    change the readiness enum and its negative test in a dedicated pull
    request. The first enabled capability stores only disposable test records
    until end-to-end security acceptance.

## Compatibility And Migration

- On-disk numeric identifiers are explicit and independent of Rust enum layout.
- A version 1 writer emits only canonical version 1.
- Unknown suite or schema identifiers fail with an update-required error.
- Parameter changes rewrap the VRK after authenticated unlock.
- Record, cipher, schedule, or root-key changes write and verify a complete
  separate database before atomic replacement.
- Retain the encrypted pre-migration file until the new format survives
  authenticated open after restart.

## Tactical Protections During Migration

- Preserve `FormatReadiness::ScaffoldOnly` and the core negative test.
- Keep cryptographic modules private to the agent/core crates.
- Continue prohibiting real credentials, recovery material, and passkey private
  keys in issues, fixtures, logs, or manual testing.
- Reject partial schemas and unknown versions rather than adding permissive
  compatibility shortcuts.
- Retain old encrypted artifacts; never test migration with the only copy.

## Tests And Security Validation

- Primitive known-answer tests from RFC 9106, RFC 5869, RFC 8439, and published
  XChaCha vectors.
- Independent libsodium XChaCha verification.
- Golden bytes for every version 1 structure and a separately implemented
  strict verifier.
- Property tests for encode/decode stability, sorted unique manifests, bounds,
  generation monotonicity, and cross-vault rejection.
- Mutation and truncation tests for every field and representative byte.
- Fuzz targets with allocation, time, and nesting limits.
- Crash/cancellation tests at every transaction, backup, restore, and migration
  durability boundary.
- Wrong key, wrong AAD, rollback-anchor, file replacement, WAL recovery, disk
  full, and application downgrade tests.
- Disposable canary scans of logs, events, temporary files, and crash artifacts.

## Performance And Resource Benchmarks

Measure on the minimum supported Windows hardware and a representative current
device:

| Workload | Metrics | Required decision |
|---|---|---|
| Argon2id exact v1 profile | median, p95 wall time, peak working set | Accept profile or amend ADR; never silently weaken |
| Authenticated open at 1, 1k, 10k, and 100k small records | median, p95, bytes/s, peak memory | Confirm full verification preserves unlock UX or return to design |
| One record create/update/delete | p95 latency, fsync count | Confirm transaction cost is acceptable |
| 10 MiB and 512 MiB backup/restore | wall time, throughput, peak memory, temporary disk | Confirm bounded streaming and product progress behavior |
| Interrupted migration | recovery time and surviving artifacts | Prove one complete authoritative vault remains |

No threshold is invented in this document. Product and engineering must record
the user-facing unlock budget before the benchmark gate can pass.

## Rollout And Rollback

The implementation lands behind the readiness guard in the ordered packages
above. Every package can be reverted before enablement without a production
data migration. After enablement, a rollback-compatible release can read but
must not write a newer format. A format rollback restores the retained
pre-migration encrypted artifact through an explicit recovery flow and warns
about lost post-migration changes.

If a primitive or composition problem is found, disable new writes first,
preserve source ciphertext, ship a reviewed read-and-migrate path under a new
suite/version, and never decrypt into an unauthenticated salvage format.

## Acceptance Criteria

- ADR 0005 is accepted for the exact implementation revision.
- All pinned dependencies and advisories are refreshed and reviewed.
- Master-password and recovery-key clean-device restores both pass.
- Windows Hello and rollback anchor pass #15's accepted threat tests.
- Every supported structure has stable golden bytes and independent verification.
- All negative, corruption, rollback, crash, migration, fuzz, and canary tests pass.
- Benchmarks meet the separately recorded Windows UX/resource thresholds.
- A reviewer who did not author the implementation records approval with scope
  and residual risks.
- `FormatReadiness` changes only in the final dedicated gate; before that,
  credential storage remains impossible.

## Open Decisions

- Named independent reviewer and review artifact location.
- Product-owned unlock latency and peak-memory thresholds.
- Exact #15 Windows protector and rollback-anchor primitives.
- Recovery-kit human encoding and confirmation UX for Slice 4.
