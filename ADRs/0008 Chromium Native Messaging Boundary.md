# ADR 0008: Chromium Native Messaging Boundary

**Status:** Proposed
**Date:** 2026-08-02
**Scope:** Chrome and Edge extension identity, native-messaging framing, status protocol, cancellation, failure behavior, and the proposed issue #17 fill boundary
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

- One Manifest V3 source package is built for Chrome and Edge. The issue #16
  baseline requested only `nativeMessaging`. The issue #17 amendment below adds
  the narrowly defined website/content-script surface to the development build.
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

## Issue #17 amendment: exact-origin fill (development implementation)

This amendment starts [issue #17](https://github.com/theundeadmonk/Librarian/issues/17)
on 2026-09-04. It preserves the status-only version-1 wire contract and adds a
version-2 credential path in development builds. It does not approve production
credential use; independent review and installed-browser acceptance remain gates.
The owner confirmed the website-access
decision: ask for browser consent once for all HTTPS sites, with no Librarian
per-site enablement step. Browser consent does not authorize credential release
without the exact-origin and unlocked-state checks below. The manifest requests
`nativeMessaging`, `webNavigation`, and host access to `https://*/*`, with one
top-level isolated-world content script. It requests no storage, cookies,
external messaging, or page-accessible extension resources.

### Exact origin and browser document

- Fill only HTTPS origins. Existing saved HTTP accounts remain valid records
  but are ineligible for browser filling, including on loopback addresses.
- Extract the WHATWG origin from browser API URLs. Discard path, query, and
  fragment before sending a native request. Host and agent independently parse
  the canonical ASCII origin, bounded to 2048 UTF-8 bytes. Reject full URLs,
  opaque origins, userinfo, malformed inputs, and noncanonical wire spellings.
- Compare exact canonical scheme, host, and effective port. HTTPS `:443` and an
  omitted port normalize to the same origin before sending. Nondefault ports,
  subdomains, suffix lookalikes, and trailing-dot hosts remain distinct. IDNs
  compare by ASCII serialization; visual resemblance never grants a match.
  An explicitly saved IDN may match itself.
- Support only the top-level frame (`frameId = 0`), including for explicit
  filling. Reject all embedded frames, even same-origin ones, and inherited or
  opaque `about:blank`, `srcdoc`, `blob:`, and `data:` contexts. No suffix,
  registrable-domain, or inherited-origin fallback is permitted.
- Derive context from the extension's own `runtime.MessageSender` and a fresh
  `webNavigation.getFrame({tabId, frameId: 0})` result. Require the expected
  extension ID, a real tab, matching browser document IDs, an active outermost
  document, and agreement between sender origin, sender URL, tab URL, and
  current frame URL. Message-body URLs and DOM attributes cannot supply identity.
- Preserve the browser's exact document-ID spelling for comparisons, grants,
  and document-targeted messages. Accept nonzero lowercase dashed UUIDs and
  the nonzero 32-character uppercase hexadecimal token observed in Chromium.
  Convert the latter to the same 128-bit value in lowercase dashed form only
  when encoding the native request; never normalize browser identity comparisons.
- Re-query and compare the complete binding before delivery. Target the original
  `documentId`, not merely the tab/frame, and recheck the live document and fields
  immediately before writing. Even same-origin navigation invalidates old work
  when the document ID changes. Browser navigation and DOM writing are not
  atomic; document-targeted delivery prevents routing to a replacement document.

The manifest minimum browser version is 106. Chrome documents sender document
IDs/lifecycle from version 106 and warns that lifecycle snapshots can become
stale. See
[runtime MessageSender](https://developer.chrome.com/docs/extensions/reference/api/runtime#type-MessageSender),
[webNavigation](https://developer.chrome.com/docs/extensions/reference/api/webNavigation),
and [document-targeted messaging](https://developer.chrome.com/docs/extensions/reference/api/tabs#method-sendMessage).

### One account and bounded disclosure

Preserve one browser request and one terminal response per native port. The
browser protocol version 2 adds only `fillSingle`; version 1 stays status-only.
Within that transaction, the host performs two agent requests on the same fresh
authenticated connection:

1. `ExactOriginMatches` (20) independently validates both origins and selects
   only when exactly one live account matches. Return one opaque selection lease
   with the record ID/revision to the host, or a uniform no-selection result for
   zero or multiple matches. No username list, count, or unrelated metadata.
2. `GetSelectedCredential` (21) consumes the lease once for that context, record
   ID/revision, connection, and unlock epoch. Return only the selected username
   and password. Changed/deleted records and expired leases require a fresh
   explicit request, never automatic reselection.

The unique exact-origin account is this slice's selection rule; multiple-account
choice remains Slice 2. The browser receives neither the internal record ID nor
the lease. The host retains no transaction state after its response.

The closed browser request is:

```json
{
  "protocolVersion": 2,
  "requestId": "00112233445566778899aabbccddeeff",
  "operation": "fillSingle",
  "context": {
    "kind": "exactHttps",
    "tabId": 7,
    "frameId": 0,
    "documentId": "12345678-1234-4234-8234-123456789abc",
    "topLevelOrigin": "https://example.com",
    "frameOrigin": "https://example.com"
  },
  "timeoutMs": 2000
}
```

Keep the 16 KiB request bound, nonzero random 128-bit request ID, and 100–5000 ms
timeout rules. Tab IDs are nonnegative signed 32-bit values; document IDs are
nonzero lowercase UUID strings. Both canonical origins must match. The host
forwards these fields and the browser request ID as context, not as independent
attestation of the website or user action.

The version-2 response contains only `protocolVersion`, the matching
`requestId`, `status`, and fields permitted by that status:

| Status | Additional fields |
|---|---|
| `credential` | `username` (at most 1024 UTF-8 bytes), `password` (at most 16384 UTF-8 bytes) |
| `noCredential` | None; zero and multiple matches are indistinguishable |
| `error` | One `error`: `invalidRequest`, `incompatible`, `agentUnavailable`, `locked`, `cancelled`, `timedOut`, or `operationFailed` |

Bound the complete serialized response to 128 KiB, including worst-case JSON
escaping; never truncate. Reject unknown fields or invalid variants. No master
password, vault key, passkey material, recovery data, history, free-form error,
or unrelated record is permitted. Do not normalize or log credential bytes.

Agent protocol 1.3 and explicit browser-fill feature ID 3 gate these two
operations. Versions 1.0–1.2 still reject their bodies. Only an
authenticated `NativeHost` may use them; desktop and passkey roles need negative
authorization tests. Capture/update operations 22 and 23 remain unsupported.
CDDL, feature negotiation, and field/lease definitions are implemented together.

### Lifetime, cancellation, and user edits

- The agent creates a nonzero random 128-bit lease bound to the authenticated
  connection, browser request ID, tab/frame/document/origins, record ID/revision,
  unlock epoch, and monotonic expiry no later than the remaining overall request
  deadline (maximum five seconds). It cannot be extended or transferred. Consume
  it even on retrieval failure. Disconnect, cancellation, timeout, lock, and
  epoch changes invalidate it.
- Preserve admission and terminal-publication checks. Lock/cancellation winning
  before publication prevents a secret response. Neither can recall published
  bytes or erase an already filled password. Drop intermediary buffers promptly.
- Keep one automatic-attempt budget per document in the isolated content-script
  world. Consume it before requesting a record, not after success. No match,
  ambiguity, locked state, timeout, error, or DOM replacement restores it. Wait
  for an eligible form before consuming it; page load alone is not enough.
- Detect only visible, enabled, writable sign-in inputs with unambiguous
  username/current-password roles. Reject ambiguous, hidden, read-only,
  registration/password-change targets and cross-origin form actions. Never
  submit. Revalidate the exact elements, form, action, and values before writing;
  do not automatically overwrite nonempty or edited/deleted fields.
- Edits/deletions suppress automatic fill and invalidate any pending completion,
  including an explicit one. A fresh, independently verified extension-toolbar
  action can request another fill. It bypasses none of the origin, document,
  form, lease, or unlocked-state checks. Page messages cannot assert user action.
- Keep one document-local state instance across mutation callbacks and worker
  reconnections. Worker restart cannot inject a new budget or replay a request.
  `pagehide` invalidates pending work; BFCache/history restoration requires
  explicit filling. Later steps of a multi-step sign-in within the same document
  use explicit filling in this conservative first implementation.
- Persist no credentials, selections, URLs, or requests in extension storage.
  Do not bridge page `postMessage` or external-extension messages to this API.
  An isolated world does not hide a deliberately filled password from scripts
  already running in the permitted page.

See [isolated content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts)
and [permission declarations](https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions).
Website permission allows form inspection, not broader credential matching.

### Review and validation gates

This maps to browser/native-host boundaries TB-02–TB-04, exact-origin invariant
I-06, spoofed origins T-01, same-origin scripts T-02, excessive disclosure T-03,
and stale completion T-06 in the existing threat model. A native host cannot
independently attest the active website; a compromised authorized extension
remains a residual risk.

Development code now connects the content script, browser-observed document
binding, native host, and agent operations. A shared origin corpus runs in
TypeScript, the native host, and the Rust core. Protocol/controller/runtime
tests cover role substitution, replay/expiry, account mutations, lock at
admission/publication, cancellation, disconnect, bounds, and forbidden fields.
The account-mutation generation and lease deadline are rechecked under the
terminal commit gate, including after credential encoding.

The opt-in `tests/browser-dom.mjs` suite executes the bundled content script
against real Chrome/Edge DOMs using fake extension messaging and intercepted
disposable fixtures. It does not load the installed extension, authenticate a
native host, or exercise a real vault. Passing it is not integrated acceptance.

Before closing #17, independently review the response/lease rules and test the
signed installed chain in both browsers. Include ports, schemes, IDNs/lookalikes,
subdomains, frames, dynamic forms, back navigation, validation errors, edits,
worker restart, and lock during requests. Record exact revisions/browser
versions and inspect logs for canaries. #20 owns the broader integrated Slice 1
release matrix. Only disposable accounts are permitted until those gates pass.

## Consequences

- The first browser slice proves the complete extension-to-agent trust chain
  without exposing credentials or creating a broad native API.
- One request per process costs a process launch for each explicit status
  probe, but makes cancellation, crashes, worker suspension, and stale state
  easier to reason about.
- Missing application and crashed/unavailable native components intentionally
  share one public category because browser error strings are not a stable or
  security-relevant API.
- The issue #17 amendment adds exact HTTPS website context, credential
  selection, and fill responses. It preserves closed schemas,
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
