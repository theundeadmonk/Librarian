# Windows Local IPC Security Probe

This disposable Windows executable validates the riskiest operating-system
assumptions behind
[[../../ADRs/0006 Authenticated Local IPC and Client Authorization]].

It is not the vault agent, a reusable transport library, or authorization to
store real credentials. Production implementation belongs to
[issue #13](https://github.com/theundeadmonk/Librarian/issues/13).

## What it verifies

- peer policy checks the user SID, logon SID, Windows session, exact executable
  path, package identity, and application identity;
- missing package identity fails the production policy;
- the pipe DACL contains only LocalSystem and the current logon SID;
- `FILE_FLAG_FIRST_PIPE_INSTANCE` rejects a duplicate server;
- both client and server query and validate the kernel-reported peer PID before
  exchanging an application byte;
- a server rejects the executable copied to an unapproved path; and
- a client rejects that copied executable when it squats on the pipe name.

The client opens the pipe with anonymous security QoS. The probe never
impersonates a client and exchanges only disposable marker bytes.

## Run

The authoritative Windows Release pipeline builds and runs the probe:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build.ps1 `
  -Configuration Release `
  -Platform x64
```

Expected probe result:

```text
[PASS] identity policy fails closed
[PASS] pipe DACL is logon-session scoped
[PASS] first pipe instance blocks duplicates
[PASS] client and server attest each other
[PASS] server rejects a copied client
[PASS] client rejects a copied server
6 passed; 0 failed
```

## Deliberate limitations

The development executable is unpackaged, so the probe verifies that production
policy rejects it and uses exact-path policy only for disposable tests. Positive
signed-package, wrong-signer, alternate-user, and mixed-package-version tests
require the coherent MSIX fixture from issue #19.
