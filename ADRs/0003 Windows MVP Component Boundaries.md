# ADR 0003: Windows MVP Component Boundaries

**Status:** Proposed
**Date:** 2026-07-22
**Scope:** Local processes, vault ownership, and browser integration

## Context

Librarian must connect three different trust environments: untrusted websites and extension content scripts, Windows credential-provider APIs, and an unlocked local vault. Letting every component open the database or hold the vault key would multiply the secret-bearing attack surface and make locking, upgrades, and crash behavior inconsistent.

## Proposed decision

Use a local vault agent as the only long-lived owner of unlocked keys, decrypted records, database writes, and backup operations.

- The WinUI desktop app is a native user-interface client.
- The Windows passkey provider is a thin, request-scoped native client.
- The Chromium extension communicates only with a small registered native-messaging host.
- The native host validates the extension protocol and relays authorized requests to the agent.
- Only the agent opens the encrypted SQLite vault.

All boundaries use explicit protocol versions, schemas, size limits, timeouts, cancellation, and least-privilege operations. The exact local IPC transport and client-authentication mechanism require a follow-up ADR and threat-model validation.

## Required invariants

- The master password and recovery material never enter the extension, native host, or website process.
- A website cannot select credentials for a different parsed origin.
- A locked agent releases no credentials or passkey operations.
- The provider cannot request arbitrary vault records; it can perform only the passkey transaction authorized by Windows and the user.
- Clients cannot bypass record validation or write ciphertext directly.
- No secret-bearing request or response is logged.
- Protocol incompatibility fails closed and directs the user to update the product.

## Consequences

### Benefits

- One process enforces locking, key lifetime, authorization, storage, and backup consistency.
- Browser compromise does not directly expose the vault database or unlock material.
- UI and operating-system integrations can be restarted or updated without becoming alternative vault implementations.
- Future native clients can reuse a documented protocol or core boundary without duplicating policy.

### Costs and controls

- Agent startup, shutdown, upgrade, and crash recovery become product-critical and require end-to-end tests.
- Local IPC is a security boundary, not an implementation detail; peer verification and authorization need focused review.
- Multiple processes complicate diagnostics; use redacted structured events and correlation identifiers, never secret values.
- Packaging must keep app, provider, host, agent, and registered manifests version-compatible.

## Validation required

Before storing real credentials, test a locked agent, stale clients, malformed and oversized messages, cancellation, concurrent requests, process crashes, Windows sign-out, app upgrade, and uninstall. Threat modeling must include a malicious website, compromised extension context, unprivileged local process, and corrupted vault file.
