# Windows Hello PRF Probe

This disposable Windows executable validates the platform contract proposed
for issue #15 before any real vault key depends on it.

It is not a vault unlock implementation. It never opens a Librarian vault,
accepts a password, or persists PRF output. Its manual mode creates a uniquely
named disposable platform credential, verifies that Windows returns a stable
32-byte WebAuthn PRF result after user verification, and removes the
credential before exiting.

## Non-interactive self-test

The authoritative Windows Release pipeline runs:

```powershell
.\artifacts\bin\x64\Release\Librarian.WindowsHelloProbe.exe --self-test
```

This reports the installed WebAuthn API version and whether Windows currently
has a user-verifying platform authenticator. A missing authenticator is a
supported fail-closed state, so the CI-safe self-test does not display Windows
Hello UI and does not fail merely because Hello is not enrolled. It also uses
synthetic assertions and injected API results to reject malformed
authenticator data, wrong relying-party hashes, missing user-verification
flags, wrong credentials, missing or malformed PRF output, salt-independent
output, cancellation, and credential-deletion failure without creating a real
credential.

## Explicit manual test

Only run the following with disposable development state:

```powershell
.\artifacts\bin\x64\Release\Librarian.WindowsHelloProbe.exe --manual-test
```

Manual mode requires WebAuthn API version 8 or later, an enrolled Windows Hello
platform authenticator, an interactive console window, and explicit approval
of four Windows-owned prompts. It uses the relying-party identifier
`librarian.local`, requests the platform authenticator with user verification
required, supplies a creation-time PRF evaluation through the API v8
`pPRFGlobalEval` field, and verifies the returned authenticator-data
user-verification flag. It requires the creation-time result and two assertions
against the same random salt to match, and requires a third assertion against an
independent salt to differ. Copied PRF bytes are zeroed immediately after
comparison and are never printed.

Cancellation, missing enrollment, unsupported PRF, a malformed result, or
credential removal failure returns a nonzero exit status. No fallback is
attempted.

## Deliberate limitations

Passing this probe proves only that the local Windows broker and platform
authenticator can create a PRF-enabled credential and deterministically release
PRF output after system-owned user verification. Production work still needs:

- agent-owned enrollment and unlock request schemas;
- binding to the authenticated desktop process, current session, request, and
  unlock epoch;
- Rust-owned VRK wrapping and full authenticated vault open;
- protected device-local metadata and rollback-anchor storage;
- cancellation, sign-out, restart, corruption, removal, and fallback tests.

The manual test never asks Codex to read or handle a PIN, fingerprint, face
template, or other Windows Hello material.
