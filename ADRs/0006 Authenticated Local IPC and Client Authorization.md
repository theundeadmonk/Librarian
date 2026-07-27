# ADR 0006: Authenticated Local IPC and Client Authorization

**Status:** Accepted
**Date:** 2026-07-25
**Accepted:** 2026-07-25
**Specification version:** 1.0
**Scope:** Windows 11 local vault-agent transport, peer identity, framing, lifecycle, and per-client authorization
**Decision issue:** [#12](https://github.com/theundeadmonk/Librarian/issues/12)
**Security baseline:** [[Threat Model]]

## Context

The vault agent is the only process allowed to own unlocked vault keys, decrypt
records, mutate the vault, or use passkey private material. The desktop app,
native-messaging host, and Windows passkey provider therefore need a local
protocol, but exposing a discoverable endpoint without authenticating the
process at both ends would simply move the vault boundary into an
attacker-controlled process.

This is a bidirectional authentication problem:

- The agent must reject an unapproved process even when it runs as the same
  Windows user and knows the endpoint name.
- Every client must authenticate the agent before sending a master password,
  credential, passkey transaction, or other sensitive payload.
- An approved client must receive only the operations and data required for its
  role. Package membership alone does not make every component equally trusted.
- Discovery data, process identifiers, role claims, protocol fields, and local
  messages are untrusted input.

The threat model explicitly requires mitigations for endpoint squatting,
same-user impersonation, cross-session access, replay, confused deputies,
downgrade, oversized input, cancellation races, stale clients, and partial
updates. Transport encryption by itself would not establish which executable
is at either end.

## Research basis

This decision was reviewed against primary sources current on 2026-07-25:

- Microsoft’s current
  [Windows IPC overview](https://learn.microsoft.com/en-us/windows/apps/develop/communication/interprocess-communication)
  confirms that full-trust Windows App SDK applications can use Win32 IPC
  directly. Its July 2026 App Services guidance requires package identity and
  an out-of-process background task for Windows App SDK providers, which would
  add a second service process rather than preserve the existing Rust agent.
- Microsoft documents that a named pipe accepts an explicit security
  descriptor and that its
  [DACL is checked for both server and client access](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
  Microsoft recommends a logon SID when access must be limited to one terminal
  session.
- `CreateNamedPipeW` provides `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `FILE_FLAG_OVERLAPPED`, and `PIPE_REJECT_REMOTE_CLIENTS`.
  `GetNamedPipeClientProcessId` and `GetNamedPipeServerProcessId` provide the
  kernel-observed process identifiers for both-direction checks.
- Windows access tokens expose the user SID and logon SID. The AppModel APIs
  expose the package full name, package family name, and application identity
  for a process opened with `PROCESS_QUERY_LIMITED_INFORMATION`.
- Microsoft’s July 2026
  [package-identity overview](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/package-identity-overview)
  states that the package full name incorporates name, version, architecture,
  resource identifier, and publisher. Exact package-full-name comparison is
  therefore also the mixed-version guard for Slice 1.
- Microsoft defines
  [SecurityIdentification](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
  as allowing a server to obtain a client's identity and privileges without
  letting it act as that client when accessing resources.
  [`OpenThreadToken`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
  explicitly supports query-only access to a SecurityIdentification token with
  `OpenAsSelf`, and the AppModel APIs expose
  [package identity from that token](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagefullnamefromtoken).
  Librarian uses that pipe-bound token to close the PID-reopen race while
  retaining least-privilege impersonation semantics.
- Microsoft Security Intelligence’s January 2026 update for
  [named-pipe impersonation tooling](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=VirTool%3AWin64%2FImpersonate%21rfn&ThreatID=2147938841)
  documents active abuse of predictable, weakly protected named-pipe servers.
- The password-manager case studies in
  [Man-in-the-Machine, USENIX Security 2018](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-bui.pdf)
  show practical pipe-squatting and multi-instance attacks. The paper’s key
  mitigation for Windows named pipes is to validate the process, user, session,
  and binary at both ends rather than at the server alone.
- The internal native-host boundary remains consistent with Chrome’s current
  [native-messaging specification](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging):
  Chrome launches a separate native host, restricts it by extension ID, and
  applies its own framing and message limit. Browser identity is not delegated
  to the vault agent; the host is one separately authenticated client.
- IPC payloads use the deterministic subset of
  [CBOR from RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html).
  Recent primary research,
  [Secure Parsing and Serializing with Separation Logic Applied to CBOR, CDDL, and COSE](https://arxiv.org/abs/2505.17335),
  formally establishes non-malleability for deterministic CBOR and reinforces
  the value of unambiguous CDDL schemas and verified parsing. Librarian uses a
  deliberately smaller fixed-array subset and keeps verified parser generation
  as a future hardening option rather than introducing an unreviewed parser
  migration in Slice 1.

## Decision summary

1. Use local, duplex Windows named pipes for the trusted local protocol.
2. Create a random endpoint for every agent start, restrict it to the current
   logon session, reject remote clients, and never treat the endpoint name as a
   secret or authorization token.
3. Authenticate the connected process at both ends before either side reads an
   application frame or sends sensitive data.
4. In production, require the same signed MSIX package full name, package
   family, Windows user, logon SID, session, integrity policy, and exact
   role-specific executable path. Use the package application identity when the
   process has one.
5. Derive the client role from verified process identity. Never trust a role,
   path, package, process identifier, origin, or capability claimed in a
   message.
6. Use a fixed, bounded binary frame and a deterministic, strictly decoded CBOR
   payload. Reject unknown required semantics, noncanonical encodings, trailing
   data, and unknown fields.
7. Bind every request to one authenticated connection, a random connection
   identifier, a strictly increasing request identifier, the current unlock
   epoch, and a server-clamped monotonic deadline.
8. Enforce a closed per-role operation table. There is no general vault API,
   arbitrary query facility, raw cryptographic primitive, or ciphertext write
   operation.
9. Make lock, cancellation, disconnect, peer exit, agent restart, and upgrade
   win over in-flight success.
10. Keep unpackaged development mode explicitly non-production and incapable
    of satisfying the release gate for real credentials.

## Transport and endpoint discovery

### Agent scope

Run one non-elevated vault agent for one Windows logon session. The agent is
not a Windows service and does not listen across user sessions.

Before creating listeners, the agent holds the protected, session-local named
mutex `Local\Librarian.Agent.Singleton.v1` for its process lifetime. An
existing object fails startup closed. A same-session process can therefore
cause denial of service by squatting the name, but cannot become an
authenticated agent or make a second agent open the vault.

The agent creates an eight-instance pipe pool before publishing discovery
metadata:

```text
\\.\pipe\LOCAL\Librarian.Agent.v1.<128-bit-random-hex>
```

The first instance uses:

```text
PIPE_ACCESS_DUPLEX
| FILE_FLAG_FIRST_PIPE_INSTANCE
| FILE_FLAG_OVERLAPPED
```

Every instance uses:

```text
PIPE_TYPE_BYTE
| PIPE_READMODE_BYTE
| PIPE_WAIT
| PIPE_REJECT_REMOTE_CLIENTS
```

The remaining seven instances are created before the name is advertised. Each
accepted instance is disconnected and reused. The agent must not replenish a
lost listener under an advertised name because a hostile same-user process
could race to create that instance. If any listener handle is lost, the agent
closes the pool, rotates the random endpoint, and atomically publishes a new
descriptor.

This design combines:

- an unpredictable per-start name;
- `FILE_FLAG_FIRST_PIPE_INSTANCE` against pre-start squatting;
- a fully allocated pool against the named-pipe multi-instance attack;
- mutual process verification if a squatter still wins; and
- bounded connection capacity.

A hostile local process can still cause temporary denial of service by racing
startup or repeatedly connecting. It cannot become an authenticated peer merely
by winning that race.

Within the agent process, a runtime also reserves the vault target before
opening it. Existing targets retain a stable open file-identity handle in
addition to their normalized canonical path, so hard links, alternate casing,
and syntactic aliases cannot create two owners for one vault. Missing targets
use a canonical parent plus a case-normalized final component on Windows; the
reservation is upgraded to the published file identity while the ownership and
commit gates are both held. Unlock captures the identity of the guarded file
that was authenticated, then compares and binds that exact identity under the
same two gates before publishing the unlocked state. A replaced target already
leased through another path therefore fails closed.

### Pipe security descriptor

Do not use the default security descriptor. Create a protected DACL containing
only:

- the current logon SID; and
- LocalSystem.

Do not grant `Everyone`, `Anonymous`, `Network`, `Builtin Users`, or
Administrators as a group. The logon SID, rather than only the user SID,
prevents another interactive session for the same account from connecting.
Post-connect process authorization remains mandatory because every ordinary
process in the same logon session satisfies this DACL.

The production implementation must build the descriptor with Windows SID and
ACL APIs, validate the resulting ACL, and cover it with a negative access test.
The descriptor is defense in depth; it is not the client authorization policy.

### Discovery descriptor

After the complete pipe pool is listening, atomically publish a deterministic
CBOR descriptor in the package’s non-roaming per-user local state:

```text
Librarian/agent-endpoint-v1.cbor
```

The descriptor is limited to 4096 bytes and contains only:

```text
[
  descriptor_schema,
  pipe_name,
  agent_pid,
  agent_process_creation_time,
  package_full_name,
  protocol_major_min,
  protocol_major_max,
  startup_nonce
]
```

The descriptor:

- is not a bearer credential;
- contains no secret, key, password, account metadata, or authorization token;
- uses safe create/replace, no-follow, regular-file, ownership, size, and
  parent-path checks equivalent to the vault filesystem boundary;
- is written only after listeners are ready;
- is removed by stable file identity if validation, durability, or ancestor
  revalidation fails after atomic replacement, without deleting a concurrently
  substituted file;
- is deleted through the same no-follow, owner-verified handle that was opened
  with delete access, both during failed-publication cleanup and ordinary
  removal; a pathname replacement is preserved and reported as a conflict;
- is removed before intentional shutdown; and
- is considered stale unless the connected server independently passes the
  complete peer-verification sequence.

Clients may use a stale descriptor only to produce an actionable
`agent_unavailable` state. They must not delete, repair, or trust it while a
server identity remains ambiguous.

## Mutual peer authentication

### Server authenticates client

Immediately after `ConnectNamedPipe` completes and before reading any
application bytes, the agent must:

1. Call `ImpersonateNamedPipeClient`, open the resulting
   SecurityIdentification thread token with query-only access, and immediately
   `RevertToSelf`. Failure to acquire the token rejects the connection. Per
   Microsoft's
   [`RevertToSelf` contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself),
   failure to revert terminates the agent process because continuing could
   execute vault work in the client's security context.
2. Query the pipe-bound token for user SID, logon SID, session, integrity,
   elevation, AppContainer state, package full name, package family, and
   application identity. This token—not a subsequently reopened PID—is the
   authority for the security context that established the connection.
3. Call `GetNamedPipeClientProcessId` on the connected pipe handle.
4. Open that process with only `PROCESS_QUERY_LIMITED_INFORMATION |
   SYNCHRONIZE`.
5. Retain the process handle for the lifetime of the connection so PID reuse
   cannot substitute a new process and peer exit can cancel work.
   Recheck that handle after complete frame assembly and immediately before
   runtime admission; a frame buffered before process exit is not admissible.
6. Query the retained process token and require an exact match with every
   pipe-bound token field. A connector that exits before `OpenProcess` cannot
   become an approved client merely because its numeric PID is later reused.
   Then require:
   - the expected Windows user SID;
   - the same logon SID;
   - the same Windows session;
   - the approved non-elevated integrity policy; and
   - no unexpected AppContainer or elevation state.
7. Require the token-bound AppModel identity to contain:
   - the Librarian package family;
   - the exact package full name of the running agent; and
   - the expected application identity when that role has one.
8. Query the executable image from the retained process and require the exact
   role entry beneath the
   registered, signed package install root.
9. Derive exactly one client role from the installed component manifest.
   Zero or multiple matches are authorization failure.
10. Close the connection without a protocol response on any identity failure.
    Identity-observation APIs are side-checked: a server-side connection can
    expose only its retained client observation, and a client-side connection
    can expose only its retained server observation.

The exact package full name intentionally rejects a partially updated product
set. A package family match alone is insufficient because it would allow an old
and new component from the same product family to communicate during a mixed
update.

### Client authenticates server

Immediately after `CreateFileW` connects and before sending even `ClientHello`,
every client must perform the symmetric sequence:

1. Open the pipe using
   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION |
   SECURITY_EFFECTIVE_ONLY`. This permits the agent to query the connection's
   token identity but not to access resources as the client.
2. Call `GetNamedPipeServerProcessId`.
3. Open and retain the process handle with
   `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`.
4. Require the expected user, logon SID, session, non-elevated integrity,
   package family, exact package full name, agent image path, and agent
   application identity.
5. Confirm that the observed PID and process creation time agree with the
   discovery descriptor, but treat disagreement as rejection rather than using
   the descriptor as proof.
6. Send `ClientHello` only after every check succeeds.

This check is mandatory for the desktop because the next request may contain
the master password. It is equally mandatory for the native host and passkey
provider because a fake agent could solicit or manipulate credential and
signing transactions.

### Package and development policies

Production clients and agents must have package identity. Missing package
identity is an authorization failure, not a fallback to path-only trust.

The package manifest maintained by issue #19 owns the immutable role mapping:

| Role | Expected production image | Additional identity |
|---|---|---|
| Agent | `Librarian.VaultAgent.exe` | Agent application identity |
| Desktop | `Librarian.Windows.exe` | Desktop application identity |
| Native host | `Librarian.ChromiumNativeHost.exe` | Registered native-host manifest and exact extension ID are checked at the browser boundary |
| Passkey provider | `Librarian.PasskeyProvider.exe` | Registered out-of-process COM application identity |

Names are normative role slots; issue #19 may choose final package-relative
paths without changing the authorization model.

Unpackaged builds may enable a compile-time `disposable-development` policy
that pins exact canonical image paths for the probe and future integration
tests. It must:

- be impossible to enable through an environment variable, registry value,
  command-line switch, or mutable user configuration;
- keep `SECURITY.md`’s real-credential prohibition visible;
- reject copied executables and unexpected paths; and
- never satisfy the production readiness check.

## Framing and payload encoding

### Fixed frame header

The trusted protocol is a byte stream. Every frame begins with one 40-byte
header. Multi-byte integers use network byte order.

| Offset | Size | Field | Version 1 rule |
|---:|---:|---|---|
| 0 | 4 | Magic | ASCII `LBIP` |
| 4 | 1 | Header version | `1` |
| 5 | 1 | Message kind | Closed enum |
| 6 | 2 | Flags | Must be zero |
| 8 | 2 | Protocol major | Zero for `client_hello`; selected exact major otherwise |
| 10 | 2 | Protocol minor | Zero for `client_hello`; selected exact minor otherwise |
| 12 | 4 | Payload length | `0..65536` before allocation |
| 16 | 16 | Connection ID | Zero only for `ClientHello`; server-random afterward |
| 32 | 8 | Request ID | Big-endian; message-kind rules below |

The decoder must read the header into a fixed-size buffer, validate it, enforce
the payload bound before allocation, read exactly the declared bytes, and
reject EOF, timeout, trailing bytes, or a second frame while a malformed frame
is pending. Resynchronization after malformed input is forbidden; close the
connection.

### Message kinds

Version 1 defines only:

| Kind | Direction | Meaning |
|---|---|---|
| `client_hello` | Client to agent | Version and feature offer plus untrusted role claim |
| `server_hello` | Agent to client | Selected version, derived role, limits, state, and connection ID |
| `request` | Client to agent | One role-authorized operation |
| `response` | Agent to client | One terminal result for the matching request |
| `cancel` | Client to agent | Idempotent cancellation of one request on the same connection |
| `event` | Agent to client | Bounded state transition such as `locked` or `shutting_down` |

Unknown kinds and nonzero flags close the connection.
`cancel` is header-only and therefore requires a zero payload length.

### Strict deterministic CBOR

The payload is one definite-length CBOR array described by checked-in CDDL in
issue #13. Version 1 permits:

- unsigned integers;
- byte strings;
- UTF-8 text strings with field-specific byte limits;
- booleans;
- null only where the schema names it; and
- definite-length arrays.

Version 1 forbids:

- maps;
- tags;
- floats;
- indefinite-length values;
- duplicate or alternative representations;
- unknown fields;
- trailing data; and
- nesting deeper than eight levels.

Every decoded payload is re-encoded and compared byte-for-byte, or validated by
an equivalent deterministic decoder, before dispatch. Secret-bearing buffers
use zeroizing ownership from allocation through final response disposal.
Public request and response constructors enforce the same bounds and nonzero
identifier invariants as their decoders, so the implementation cannot emit a
message it would reject on receipt.

## Handshake and version negotiation

Peer authentication precedes the protocol handshake.

The `ClientHello` frame uses zero for the header’s protocol major, protocol
minor, connection ID, and request ID. Zero is an explicit pre-negotiation
sentinel, not a supported protocol version. The server validates the fixed
header and bounded payload under only the header-version rules before decoding
the offered protocol range. Any other value in those four fields rejects the
connection.

`ClientHello` payload:

```text
[
  client_nonce: bstr .size 32,
  min_major: uint,
  max_major: uint,
  min_minor: uint,
  max_minor: uint,
  claimed_role: uint,
  component_build_id: bstr .size 32,
  required_features: [* uint]
]
```

The role and build ID are compatibility assertions only. The agent compares
them with the role and package derived from the process; they never grant
authority.

`ServerHello` payload:

```text
[
  server_nonce: bstr .size 32,
  selected_major: uint,
  selected_minor: uint,
  derived_role: uint,
  granted_features: [* uint],
  max_payload_bytes: uint,
  max_in_flight: uint,
  agent_state: uint,
  unlock_epoch: uint
]
```

The server generates the nonzero connection ID in the `ServerHello` header.
That header carries the selected protocol major and minor and a zero request
ID. Every subsequent request, response, cancellation, and event carries the
selected exact version and nonzero connection ID. The negotiated payload limit
applies symmetrically to every request and response envelope. It cannot be
lower than the 21 bytes required for a canonical detail-free failure.

Version rules:

- Version 1 accepts protocol major 1 only.
- Offered bounds must be nonzero and well ordered.
- There is no major-version downgrade.
- Select the highest common minor version only when every required feature is
  supported.
- Unknown required features, an empty intersection, inconsistent build
  identity, or a future mandatory field returns `incompatible` and closes.
- Optional features are explicit identifiers, not inferred from ignored
  fields.
- Package-full-name equality normally prevents mixed releases before version
  negotiation. The handshake remains necessary for development, repair, and
  future side-by-side compatibility tests.

## Request binding, replay, and cancellation

After `ServerHello`:

- the 128-bit connection ID must match every frame;
- only `request` frames allocate IDs: the client begins at 1 and each later
  request ID is strictly greater than the last request ID sent;
- request-frame validation and ID issuance occur before that request worker
  contends for the global admission gate, so a later cancel cannot misclassify
  an already received request as never issued;
- a zero, reused, decreasing, or wrapped `request` ID closes the connection;
- a `response` echoes the exact ID of one in-flight request and is terminal;
  responses may arrive in any order, but an unknown, duplicate, or already
  terminal response ID closes the client connection;
- a `cancel` header carries the nonzero ID of the target request. It allocates
  no new ID and does not change the request high-water mark. Repeating a cancel
  for the same connection-local ID is allowed; cancellation of an already
  terminal request is ignored, while zero or a never-issued ID closes the
  connection;
- `event` frames use request ID zero, allocate no ID, and receive no response;
- `ClientHello` and `ServerHello` use request ID zero as specified above;
- an operation that depends on unlocked state includes the last observed unlock
  epoch and fails if it is stale;
- the agent captures the current epoch again before side effects and before
  plaintext or signature disclosure;
- client-supplied timeouts are relative durations, clamped by the agent, and
  converted to a server monotonic deadline before waiting for the admission
  gate, so admission backpressure consumes rather than resets the request
  budget;
- `cancel` is idempotent and refers only to an in-flight request on the same
  connection; and
- disconnect or peer-process exit cancels all work owned by that connection.

Every pending overlapped read or write is cancelled and synchronously drained
before its stack `OVERLAPPED` structure or caller buffer is released, including
when the monotonic deadline has already expired before the wait begins.
Authenticated pipe connections use process-wide owned-handle types and
per-direction I/O gates, allowing one frame reader and response workers to
share a connection without interleaving same-direction byte-stream operations.

Admission, registration, cancel, disconnect, lock, and terminal response
commitment share one ordering gate. An admitted request is registered before a
lock or disconnect may complete. A terminal response remains behind that gate
until the authenticated transport synchronously writes all bytes or reports
failure, including authorization, stale-epoch, and capacity rejections; it
cannot be queued for a later write after a lock acknowledgement or disconnect.
Authenticated `not_found` results remain authorization-bound at this terminal
gate because existence is vault-derived metadata; cancellation, deadline,
lock, or epoch change replaces them before publication.
Status state and unlock epoch are captured together while this gate is held.
The server uses that paired snapshot when constructing `ServerHello`; callers
must not compose handshake status from the separate diagnostic accessors.
Likewise, replaying a cached create-vault result refreshes its status and epoch
at terminal commitment instead of returning the snapshot cached by the
original request. Because that replay discloses only current non-secret status,
an already committed create may report the current locked state; an original
in-flight create remains subordinate to a concurrent lock.

After a secret-bearing request waits for the vault mutex, it repeats the
cancellation, monotonic-deadline, lock-state, and epoch checks before doing
cryptographic work. Authentication of account pages and mutation snapshots
repeats those checks before every encrypted record, so large vaults do not turn
one admission check into an uninterruptible scan.

No authorization token, connection ID, request ID, nonce, or discovery field is
accepted on a different connection. Captured frames are therefore unusable as
authorization even before the operation-specific nonce and transaction checks
required for passkeys.

## Client capabilities

The agent first decodes the fixed operation code, checks it against the
connection’s derived role, and only then decodes the operation-specific body.

### Desktop client

The desktop may request:

- agent and vault status;
- create vault;
- unlock with master password;
- lock;
- paginated account summaries;
- get one account;
- add, update, and delete one account; and
- the explicitly designed Windows Hello enrollment/removal operations added by
  issue #15.

Only the desktop may submit a master password. Password buffers are single-use,
bounded, cleared immediately after the agent copies them into its secret type,
and never echoed.

Issue #15 publishes agent-owned Windows Hello operations in protocol 1.1.
Enrollment and removal require the current unlocked epoch and an idempotency
key. Unlock begins from the locked state and binds both admission and terminal
publication to the epoch observed before the Windows prompt. Lock, disconnect,
cancellation, timeout, or any intervening epoch change invalidates the
completion.

Enrollment and unlock requests contain only a nonzero parent-window value.
Before invoking Windows, the agent requires that the window exists and that
`GetWindowThreadProcessId` matches the already authenticated desktop peer
process. The agent selects the stored credential, salt, protector, and
installation key, invokes the native ceremony itself, and consumes the PRF
result inside its process. Removal has an empty body. No Windows Hello request
or response contains a credential ID, PRF salt, PRF output, protector,
installation key, VRK, or other secret material.

Protocol 1.0 continues to reject these operation bodies as unsupported.
Negotiation of the Windows Hello feature requires minor version 1 and the
corresponding explicit feature identifier. An older peer cannot infer support
from reserved operation numbers.

### Chromium native-messaging host

The native host may request:

- agent and lock status;
- exact-origin match metadata;
- one selected credential for one browser-observed origin and short-lived
  browser request context; and
- the specific capture/update intents added by Slice 2.

It may not unlock, list the vault, retrieve arbitrary record identifiers, read
password history, access passkey material, or perform backup/recovery actions.
The agent independently parses and compares the origin. A native-host claim is
not browser-origin authority.

### Windows passkey provider

The provider may request:

- lock status;
- make one credential for the complete Windows-authorized transaction;
- get one assertion for the complete Windows-authorized transaction;
- delete one named credential through the Windows callback; and
- cancel its own transaction.

It may not retrieve a private key, submit arbitrary bytes to a generic signing
operation, enumerate password records, unlock the vault, or perform account
CRUD. Issue #18 must bind RP ID, client data, challenge, user handle, algorithm,
credential ID, request kind, user-verification result, cancellation token, and
unlock epoch before any key use.

### No implicit privilege inheritance

The agent has no operation that accepts:

- raw SQL;
- a filesystem path;
- raw vault ciphertext;
- an unrestricted search predicate;
- an arbitrary cryptographic algorithm or signing payload;
- a client-selected role or capability;
- a caller-provided package or process identity; or
- a “debug”, “admin”, “trusted”, or “bypass” flag.

New operations require a protocol-minor change, a threat-model mapping, a
per-role authorization decision, negative tests for every other role, and a
review of disclosed fields.

## Resource limits and concurrency

Version 1 defaults:

| Resource | Limit |
|---|---:|
| Endpoint descriptor | 4096 bytes |
| Pipe instances / authenticated connections | 8 |
| Frame payload | 65,536 bytes |
| Header read | 2 seconds |
| Peer verification plus handshake | 2 seconds |
| In-flight requests per connection | 4 |
| In-flight requests globally | 32 |
| Issued request IDs per connection lifetime | 65,536 |
| Cached mutation idempotency outcomes in the replay window | 1,024 |
| Peer-authentication retry delay | 25 ms exponential backoff, 1 second cap |
| Concurrent password KDF operations | 1 |
| Concurrent Windows Hello ceremonies | 1 |
| Concurrent vault mutations | 1 |
| Concurrent lock transitions | 1 |
| Ordinary operation deadline | 5 seconds |
| Password KDF or lock-transition deadline | 30 seconds |
| Windows-mediated Hello or passkey transaction | 120 seconds |
| Event queue per connection | 8 |

All limits apply before unbounded allocation or work. The server may advertise
lower limits, subject to the minimum failure-envelope size. A client cannot
raise them. Before the synchronous transport callback receives any terminal
response, the agent checks the exact canonical response-envelope length against
that connection's negotiated limit. An oversized successful body is discarded
and replaced by detail-free `operation_failed`; an idempotent mutation outcome
remains cached so a retry over a connection with an adequate limit cannot
repeat the side effect.

Lock uses the transition deadline because it must cancel and synchronously
drain both an in-flight password KDF and any local create-vault KDF or generated
key material before acknowledging that key state is clear. Create holds a
dedicated drain gate from before password work until all local vault and
recovery material has either been published or dropped. Lock and shutdown
cancel first, then wait for that gate. A successful lock retains its transition
authority through the synchronous terminal response write, so unlock cannot
publish in the gap between the state change and its acknowledgement. Lock must
not inherit the shorter ordinary-operation cap while waiting for work that was
legitimately admitted with the KDF cap.

Backpressure is explicit:

- excess connections are rejected;
- excess frames receive `busy` only after client authentication and only while
  their admission-wide deadline remains live; capacity discovered after that
  deadline returns `deadline_exceeded`, not a retryable backoff, for both
  per-connection and global capacity;
- KDF, mutation, and lock transitions are serialized;
- expensive operations consume bounded global permits;
- event overflow closes the slow connection rather than retaining unbounded
  state; and
- repeated peer-authentication failures use listener-pool-wide exponential
  backoff, reset only by successful authentication, without producing
  secret-bearing diagnostics.

## Agent states and failure behavior

| State or event | Required behavior |
|---|---|
| Starting | No endpoint is advertised until the full listener pool and locked vault state are ready. |
| No vault | Only status and desktop create-vault are available. |
| Locked | Status, desktop unlock, and explicitly safe provider lock-status are available; no secret-bearing operation succeeds. |
| Unlocking | One unlock attempt owns the transition. Other unlocks receive `busy`; lock/cancel wins. |
| Unlocked | Role capabilities apply and every request is bound to the current epoch. |
| Lock requested | Increment the epoch, cancel secret-bearing work, clear key state, then acknowledge lock. |
| Client disconnect or exit | Cancel its requests and zero pending request/response buffers. |
| Agent crash | Kernel closes pipes. Restart begins locked with a new endpoint and connection IDs. |
| Stale descriptor | Client rejects the observed server, reports `agent_unavailable`, and sends no payload. |
| Updating or repair | Agent locks, removes discovery, drains no secret response, and exits. Mixed package full names reject. |
| Incompatible protocol | Return one non-secret `incompatible` result only to an authenticated peer, then close. |
| Windows sign-out | Lock and exit. No endpoint survives the logon session. |

After the core authenticates an unlock, the runtime retains the vault mutex
through extraction of the authenticated cryptographic vault identifier. A lock
or shutdown that starts in that interval cancels the unlock, waits for the
guard, clears the session, and produces a terminal lifecycle result rather than
turning the expected race into a connection-fatal internal error. If the
unlock deadline instead expires while publication waits for the transition
gate, the runtime clears the session and preserves `deadline_exceeded` rather
than misreporting cancellation.

Ambiguous completion is failure. A client may retry an idempotent status read
after reconnecting. A mutating request requires an operation-specific
idempotency key and status check designed in issue #13; it must not be blindly
replayed after a timeout or disconnect.

The implementation binds each cached mutation result to an HMAC-SHA-256
fingerprint of the complete canonical operation and body under a random
per-agent-start key. Reusing a key for a different payload is a conflict, and
the cache retains neither a plaintext credential nor a reusable unkeyed
password digest. The raw bounded body is fingerprinted and its key is reserved
before operation-specific decoding, so a terminal malformed-body result claims
the same key/payload pair and a corrected payload must use a new key. Only
operations defined as idempotent mutations may carry a key; a key on a read,
status, unlock, or lock request is rejected during canonical envelope
validation. The cache is a bounded first-in, first-out replay window: admitting
a new mutation evicts the oldest completed outcome when necessary, while
in-flight keys remain reserved. Exhausting the window therefore cannot
permanently disable mutations; clients must not rely on replay results after an
entry has aged out.

Every terminal `operation_failed` result from an admitted idempotent mutation is
also cached. A storage error observed after SQLite commit can be
indistinguishable from a pre-commit failure at the public boundary; replaying
the same key must return the same terminal result rather than risk applying an
add, update, or delete twice. Recovery or reconciliation uses a new operation
only after the vault has been authenticated again.

The replay window is scoped to the cryptographic vault identifier in the
authenticated header, in addition to the owned file identity. When a locked
runtime successfully authenticates a different vault at its owned path, even
after an in-place overwrite that preserves filesystem identity, it clears
completed outcomes before binding and publishing that identity. If an old
idempotent mutation is still in flight, the identity transition fails closed
instead of allowing that reservation to repopulate the new vault's cache.

Cancellation, deadline, or epoch change observed at a mutation's commit gate
uses a distinct rollback result. It does not masquerade as storage corruption
and does not lock the shared vault session; only an actual integrity, storage,
or cryptographic failure invalidates that session. A mutation retains the gate
through successful commit verification, but releases it before classifying any
failure or synchronizing the locked runtime state, so failure handling never
re-enters the non-reentrant gate while holding its original guard.

## Public error model

Only authenticated peers receive protocol errors. Version 1 exposes:

```text
invalid_request
unauthorized_operation
locked
not_found
conflict
busy
cancelled
deadline_exceeded
agent_unavailable
incompatible
operation_failed
```

Errors contain the request ID, stable code, retry category, and a random
correlation identifier. They do not contain a path, SID, package name, process
ID, origin other than the caller’s already supplied origin, record count,
account value, secret length, SQL/cryptographic error, panic text, or raw
payload.

Identity failure, malformed pre-handshake input, impossible framing, replay,
and ambiguous downgrade close the connection without an error payload.

## Secret ownership and diagnostics

- The transport adapter owns fixed header buffers and bounded payload buffers.
- After strict decoding, operation-specific secret wrappers own password,
  credential, TOTP, recovery, and passkey values.
- Request and response types containing secrets are non-cloneable by default
  and have redacted formatting.
- Encode directly into pre-sized zeroizing buffers. Do not serialize a secret
  through an ordinary reallocating vector or general-purpose JSON object.
- Clear buffers on success, error, cancellation, disconnect, lock, timeout, and
  process shutdown.
- Never place protocol payloads, endpoint descriptors, SIDs, package paths,
  master passwords, credentials, passkey transactions, or decrypted values in
  logs.
- Diagnostics allow only event name, stable error category, component role,
  protocol version, bounded timing, and random correlation identifier.

The named pipe is not additionally encrypted in version 1. The kernel pipe,
session DACL, mutual packaged-process authentication, and connection binding
address the stated unprivileged-local-process threat. A process capable of
reading kernel pipe buffers, debugging the agent, or injecting code into an
approved process is already within the threat model’s administrator,
kernel-control, or full-session-malware exclusion. Adding an ad hoc encryption
layer would not repair compromised endpoints and would introduce another key
distribution protocol.

## Prototype evidence

The checked-in
[`Librarian.WindowsIpcProbe`](../platform/windows-ipc-probe/)
is a disposable Windows executable, not a production transport. The
authoritative Release build runs it on Windows.

The probe proves:

1. user SID, logon SID, session, exact image, package, and application identity
   policy fails closed;
2. an unpackaged process cannot satisfy the production package requirement;
3. the pipe DACL contains only LocalSystem and the current logon SID;
4. `FILE_FLAG_FIRST_PIPE_INSTANCE` rejects a duplicate server;
5. overlapped accept and marker I/O stop on peer exit or a ten-second
   deadline rather than hanging the authoritative build;
6. client and server authenticate the kernel-reported peer PID and executable
   before exchanging an application byte;
7. the server rejects the same executable copied to an unapproved path; and
8. the client rejects a copied executable that squats on the expected pipe
   name.

The probe uses disposable marker bytes only. Its copied-binary fixture remains
an independent anonymous-QoS boundary test. The production Rust transport
separately exercises SecurityIdentification token capture and rejects a
substituted process observation whose token identity does not match the
pipe-bound token.

Observed on the supported Windows 11 development machine:

```text
[PASS] identity policy fails closed
[PASS] pipe DACL is logon-session scoped
[PASS] first pipe instance blocks duplicates
[PASS] peer exit cancels pending accept
[PASS] client and server attest each other
[PASS] server rejects a copied client
[PASS] client rejects a copied server
7 passed; 0 failed
```

The probe deliberately verifies that missing package identity fails the
production policy. A positive signed-package test, wrong-signer test, real
cross-user logon test, and mixed-version package test require the coherent MSIX
fixture owned by issue #19 and remain release gates before real credentials.

## Required negative tests

Issue #13 must turn this decision into deterministic protocol tests. Issues #19
and #20 add package and end-to-end cases.

| Threat | Required test |
|---|---|
| Endpoint discovery | Stale, truncated, oversized, replaced, redirected, future-version, and post-publication failure descriptors |
| Server squatting | Copied binary, wrong package, wrong signer, wrong path, stale PID, PID reuse, and pre-created endpoint |
| Client impersonation | Unknown executable, copied executable, wrong package, wrong AUMID, wrong user, wrong logon SID, wrong session, elevated peer, and exited peer |
| Multi-instance interception | Full pre-created pool, duplicate instance attempt, listener loss and endpoint rotation |
| Impersonation abuse | Client uses identification-only security QoS; server can query but cannot use the token for resource access; pipe-bound token must exactly match the reopened retained process |
| Framing | Partial header, bad magic, bad header version, invalid pre-negotiation version, unknown kind, nonzero flags, payload-bearing cancel, length 65,537, early EOF, trailing data, slow read, exited-peer buffered frame, and frame flood |
| CBOR | Nonpreferred integers, indefinite values, map, tag, float, invalid UTF-8, excessive depth, wrong array length, unknown field, and noncanonical re-encoding |
| Authorization | Every operation attempted by every unauthorized role |
| Replay | Zero/reused/decreasing/wrapped request, unknown/duplicate response, invalid cancel target, nonzero event ID, cross-connection ID, stale epoch, and post-restart request |
| Versioning | Old minor, future minor, wrong major, no common version, unknown required feature, and mixed package versions |
| Lifecycle | Starting, locked, unlocking, lock race, cancellation race, disconnect, peer exit, agent crash, restart, update, repair, sign-out, and stale client |
| Resource use | Ninth connection, fifth per-client request, 33rd global request, KDF flood, mutation flood, event backpressure, and deadline expiry |
| Disclosure | Canary secrets absent from errors, logs, crash output, endpoint descriptor, process command lines, and non-owning client memory |

Fuzz targets must exercise the frame header, strict CBOR decoder, handshake,
each operation schema, and state machine with allocation and execution limits.
Corpus entries may contain only disposable canaries.

## Alternatives considered

### Windows App Services

Rejected for the trusted agent boundary. Current Windows App SDK guidance
requires packaged consumers and an out-of-process background-task provider.
That would create a second service process, impose a `ValueSet` request model,
and complicate the existing long-lived Rust agent lifecycle. Package identity
is useful, but App Services do not remove the need for role authorization,
strict parsing, cancellation, and secret ownership.

### Packaged COM or local RPC

Rejected for Slice 1. Both are viable Windows mechanisms and RPC provides
strong framing and security callbacks, but neither automatically establishes
the role of an arbitrary same-user executable. Correct RPC still requires
authenticated bindings, a local-only interface, security callbacks, per-method
authorization, versioning, and client/server application identity checks.
MIDL/COM activation and a C++/Rust boundary would add substantial implementation
surface without eliminating Librarian’s key authorization work.

Reconsider only if the named-pipe implementation cannot satisfy lifecycle,
package-identity, or performance validation.

### Loopback TCP, HTTP, WebSocket, or gRPC

Rejected. A loopback port is not process identity, is exposed to browser and
network-protocol concerns, requires separate server authentication, and is more
susceptible to port squatting and cross-origin confusion. TLS would add local
certificate/key distribution but would still not prove which approved
component holds the key.

### Shared secret or bearer token in a file, registry, environment, or command line

Rejected. A same-user process can discover or copy such a token, and command
lines, environment blocks, crash reports, and backups create additional leak
paths. Connection identifiers and nonces bind requests but never grant initial
authority.

### Deterministic pipe name only

Rejected. It is simple to discover and pre-create. The design uses a per-start
random name, first-instance enforcement, a pre-created pool, and mutual process
verification. Randomness is defense in depth, not authentication.

### One operation set for all packaged components

Rejected. Compromise of the native host would become full vault access and
compromise of the passkey provider would become an arbitrary signing oracle.
Role capabilities are closed and independently tested.

### Additional application-layer encryption

Not selected for version 1. It would require provisioning and rotating a key
that is inaccessible to other same-user processes while still available to all
three clients. Package and process identity already protect the approved local
endpoints for the stated threat model. Reconsider only if a future platform
boundary crosses users, machines, sandboxes without package identity, or an
independent review identifies a concrete in-scope pipe-confidentiality gap.

## Implementation boundary for issue #13

Issue #13 should implement this decision in three layers:

1. A portable Rust protocol crate owns frame validation, deterministic CBOR
   schemas, version negotiation, request IDs, role capabilities, error types,
   state transitions, and fuzz targets.
2. A narrowly scoped Windows transport adapter owns named-pipe handles,
   security descriptors, endpoint discovery, process/token/AppModel
   observation, and peer-handle lifetime. Any required unsafe Rust is isolated
   in this platform crate, documented per block, denied everywhere else, and
   reviewed independently.
3. The existing `vault-agent` owns vault state and dispatches typed,
   already-authorized operations. Transport code cannot open the vault or call
   raw cryptographic primitives.

The probe is evidence, not reusable production code. Copying its broad C++
test harness into the agent is prohibited.

Issue #13 implements these layers as:

- `crates/agent-protocol`, containing the checked-in CDDL, fixed frame codec,
  canonical operation bodies and results, closed role table, negotiation,
  replay/cancellation state machine, bounded event queue, and arbitrary-input
  conformance tests;
- `platform/windows-ipc`, containing the complete listener pool, protected
  DACL and single-agent mutex, overlapped deadline/peer-exit I/O, mutual
  token/AppModel observation, retained process handles, identification-only
  client security QoS, pipe-bound client-token/process matching, and guarded
  atomic discovery descriptor lifecycle; and
- `crates/vault-agent::runtime`, containing the sole vault owner, global/KDF/
  mutation/lock admission, a commit gate that orders publication and terminal
  transport writes against lock, cancel, disconnect, and sign-out, typed
  desktop dispatch, encoded-size-aware bounded account paging,
  connection-bound cancellation, lock epochs, stable file-identity ownership,
  per-record authority checks during authenticated reads and mutations,
  coherent handshake and response status snapshots, authenticated unlock
  ownership rebinding, core-failure state synchronization, sign-out shutdown,
  and bounded keyed idempotency outcomes whose terminal failures are retained
  and whose replayed state is refreshed at terminal commitment.

The production entry point remains fail closed until issue #19 supplies the
signed MSIX manifest, immutable role paths, package-local state path, and
positive packaged identity fixture. There is no runtime switch that downgrades
the production peer policy to unpackaged path trust.

## Consequences

### Benefits

- Both directions authenticate before secrets cross the boundary.
- Exact package full name turns partial update into a closed failure.
- Each component has a materially smaller blast radius.
- The protocol is portable, deterministic, bounded, fuzzable, and independent
  of the Win32 transport.
- Agent restart and lock have one enforceable epoch and cancellation model.
- No user pairing flow, persistent bearer token, or extra service account is
  required, preserving the low-friction product goal.

### Costs

- Package identity and coherent MSIX installation are mandatory production
  dependencies.
- The Windows adapter needs a small, carefully reviewed native/unsafe boundary.
- Process identity checks and a fixed listener pool add lifecycle complexity.
- Same-session denial of service remains possible and needs rate limiting.
- Signed-package, wrong-signer, cross-user, update, and repair tests cannot be
  completed until the issue #19 package fixture exists.

## Residual risk and review triggers

An attacker with administrator/kernel control, debug access to the agent, or
the ability to inject code into an approved packaged process can bypass this
boundary. That matches the threat model’s existing full-session-malware
exclusion; reducing that risk further would require platform application
control, stronger process isolation, or protected-process mechanisms outside
the MVP.

Review or supersede this ADR before:

- allowing extension-only or temporary access;
- accepting an unpackaged production client;
- adding another local client or operation;
- running an agent as a Windows service or across sessions;
- supporting Android, Apple platforms, or remote synchronization;
- changing package identity, signing, update, or native-host registration;
- introducing application-layer encryption or a persistent client key; or
- relaxing any frame, deadline, concurrency, or capability limit.

## Acceptance mapping

- Distinct desktop, passkey-provider, and native-host operations are defined in
  the capability table.
- Endpoint discovery alone grants nothing; DACL, mutual process/token/package
  checks, exact role paths, and package-full-name equality are required.
- Framing, schemas, versions, limits, errors, deadlines, cancellation,
  concurrency, and incompatible behavior are explicit.
- Starting, locked, crashed, stale, updating, sign-out, and incompatible states
  fail closed.
- Replay, confused-deputy, cross-user, downgrade, oversized-message, squatting,
  and impersonation threats have concrete mitigations and negative tests.
- The agent exposes typed role operations only, not a general-purpose vault
  API.
