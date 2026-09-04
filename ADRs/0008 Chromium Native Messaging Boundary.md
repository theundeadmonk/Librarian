# ADR 0008: Chromium Native Messaging Boundary

**Status:** Proposed
**Date:** 2026-08-02
**Scope:** Chrome and Edge extension identity, native-messaging framing, status protocol, cancellation, and failure behavior
**Decision issue:** [#16](https://github.com/theundeadmonk/Librarian/issues/16)
**Security baseline:** [[Threat Model]] and [[ADRs/0006 Authenticated Local IPC and Client Authorization]]

## Context

Chrome and Edge must reach the vault agent without making a website, content
script, arbitrary same-user process, or unregistered extension a trusted local
client. Chromium already supplies an extension-ID allowlist, launches a
separate native process, and frames JSON over standard input and output. The
Librarian host must narrow that browser boundary again before authenticating as
the `NativeHost` role on the accepted local named-pipe protocol.

Issue #16 needs only compatibility and lock status. Website-origin credential
selection and fill remain issue #17. Adding those operations before their
origin and response schemas are reviewed would turn a connection test into an
unrestricted credential API.

## Research basis

This proposal was checked against primary browser documentation current on
2026-08-02:

- [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
  requires the `nativeMessaging` permission, uses a native-endian 32-bit byte
  length followed by UTF-8 JSON, limits messages from the host to 1 MiB, and
  supplies the caller extension origin to the Windows host process.
- [Chrome's extension service-worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
  documents that `runtime.connectNative()` keeps an MV3 worker alive while the
  native port remains connected and that the port closes when the host exits.
- [Chrome's manifest key guidance](https://developer.chrome.com/docs/extensions/reference/manifest/key)
  defines the public manifest key used to keep an unpacked development
  extension ID stable.
- [Microsoft Edge native messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging)
  uses the Chromium manifest and framing model, browser-specific Windows
  registration, and exact allowed extension origins. Chrome Web Store and
  Edge Add-ons listings can receive different IDs, so release packaging keeps
  separate Chrome and Edge ID inputs.

## Decision

### Browser identity and package

- One Manifest V3 source package is built for Chrome and Edge. It requests only
  `nativeMessaging`; issue #16 adds no website host permissions or content
  script.
- The unpacked development package contains a public-only key with the stable
  ID `jiifjoajanfeoabbkmpodkgfmabhikkh`. No private extension key is stored.
- The installer renders separate Chrome and Edge host manifests. Each allows
  exactly one extension origin. Development fixtures use the stable ID in both;
  release builds must supply the IDs assigned by the two official stores.
- Chromium's `allowed_origins` check is the browser-side authorization gate.
  The launched host also requires the caller-origin argument to exactly match
  one of its two integrity-bound installed manifests. That origin is not
  delegated to the vault agent as process identity.

### Version 1 browser protocol

Each native port carries exactly one request and one terminal response. The
host accepts at most 16 KiB, well below Chromium's host-output bound, and never
logs a message body.

The only version-1 request is:

```json
{
  "protocolVersion": 1,
  "requestId": "00112233445566778899aabbccddeeff",
  "operation": "status",
  "context": { "kind": "none" },
  "timeoutMs": 2000
}
```

The request is a closed object. The ID is a nonzero random 128-bit lowercase
hex value, the timeout is 100 through 5000 milliseconds, and status requires
an explicit context with no website origin. Unknown fields, operations,
context kinds, versions, identifiers, timeouts, truncated frames, and
oversized frames fail before agent connection.

A successful response contains only the protocol version, matching request ID,
and one public agent state: `starting`, `noVault`, `locked`, `unlocking`,
`unlocked`, `updating`, or `shuttingDown`. A failure contains only one closed
category: `invalidRequest`, `incompatible`, `agentUnavailable`, or
`operationFailed`. It contains no exception text, path, browser message,
account metadata, or credential data.

### Agent authentication and lifecycle

- The agent accepts the host only when Windows observes the same user, logon
  session, package full name and family, exact package version, medium-or-lower
  integrity, `ChromiumNativeHost` application ID, and installed executable
  path specified by ADR 0006.
- The host independently authenticates the agent with the same package,
  session, user, application ID, path, process, and discovery checks before
  reporting status. It negotiates no credential feature.
- The host creates no vault, cache, queue, log, or persistent state. It opens a
  fresh authenticated agent connection for the single request and exits after
  one response.
- Closing the native port is cancellation. An incomplete frame or a disconnect
  before a complete request causes no agent connection. If the browser closes
  after the request is sent, Chromium terminates the host and the agent's
  retained peer-liveness check prevents a dead host from gaining new
  admission. Version 1 status is non-mutating and is never retried within a
  request.
- The extension uses a fresh random request ID after browser or service-worker
  restart. It probes on install, browser startup, or explicit toolbar click,
  and does not persist or replay a request.

### Deterministic user-visible states

| Condition | Extension result |
|---|---|
| Agent reports unlocked | Connected and unlocked |
| Agent reports locked | Connected; unlock in the native desktop app |
| No vault | Connected; finish setup in the native desktop app |
| Starting, unlocking, updating, or shutting down | Temporarily busy; try again |
| App, registration, agent, or host unavailable; host crash | App unavailable; install, start, or repair |
| Browser/host protocol mismatch | Components incompatible; update or repair |
| Deadline expires | Timed out; explicit retry only |
| Malformed authenticated response | Connection verification failed; repair |

The toolbar badge and title show these non-secret categories. Raw browser
`lastError` text and native error details are not retained or displayed.

## Consequences

- The first browser slice proves the complete extension-to-agent trust chain
  without exposing credentials or creating a broad native API.
- One request per process costs a process launch for each explicit status
  probe, but makes cancellation, crashes, worker suspension, and stale state
  easier to reason about.
- Missing application and crashed/unavailable native components intentionally
  share one public category because browser error strings are not a stable or
  security-relevant API.
- Issue #17 must amend this ADR before adding exact HTTPS website context,
  credential selection, or fill responses. It must preserve closed schemas,
  agent-side origin parsing, per-role authorization, bounded responses, and
  disconnect-before-admission behavior.

## Validation

- Rust protocol tests cover malformed, truncated, oversized, stale-version,
  invalid-ID, context, timeout, error-mapping, and pre-request cancellation
  cases without invoking the agent.
- TypeScript tests cover request construction, random IDs, exact response
  parsing, missing/crashed host, timeout disconnect, non-retry behavior, and
  development-ID consistency.
- Installer structural and lifecycle suites verify exact Chrome and Edge
  manifests, optional registrations, payload integrity, repair, and removal.
- Real Chrome and Edge acceptance loads the same unpacked artifact, verifies
  the development ID, checks locked/unlocked and missing-component states, and
  confirms an unapproved extension cannot open the host. Issue #20 retains the
  broader release-level end-to-end browser matrix.
