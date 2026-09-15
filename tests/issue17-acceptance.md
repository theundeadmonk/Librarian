# Issue 17 acceptance evidence

## Verified implementation

The authenticated Chrome/Edge acceptance matrix passed on 2026-09-15 for
`65d053cff36f35586bf0feec7863aca11479e862`. The independently built lab package
records a clean tracked source tree and hashes for every transferred file.
Current CI, review, and merge status are tracked in
[PR #44](https://github.com/theundeadmonk/Librarian/pull/44), not inferred from
this fixed execution record. Issue #17 closes when the PR is merged.

| Acceptance requirement | Evidence |
| --- | --- |
| Exact scheme, host, and effective port | Chrome and Edge exact/default-port matches, positive non-default-port and IDN accounts, and negative scheme/port/subdomain/lookalike cases |
| Reject embedded/non-web/malformed contexts | Real same-origin and cross-origin frames, data/blob/about documents; malformed/noncanonical origin rejection in the shared Rust/TypeScript corpus and native protocol tests |
| Automatic fill at most once | Dynamic forms, validation errors, back navigation, same-document worker termination/restart |
| Respect user edits/deletions | Automatic refill suppressed after edits and validation failures; standalone password regression leaves unrelated email controls untouched |
| Explicit action can fill again | Browser-generated extension action after edits, back navigation, unlock, and worker restart |
| Bounded single-record disclosure | Exact native response schemas; duplicate-match refusal; browser-owned document binding; runtime single-use selection/unlock-generation tests; no master-password, vault-key, or bulk-record operation exposed to the extension |
| Lock during an outstanding request | Actual browser request paused before native connection; authenticated Lock acknowledged before resume; real locked response and no filling |

## Authenticated Windows run

Run: `Librarian.I17.R623b65b3ae4a4d6f9dad0736`, disposable Windows 11 Home VM.

| Browser | Initial | Extended | Total |
| --- | ---: | ---: | ---: |
| Chrome for Testing 152.0.7977.82 | 34 | 15 | 49 |
| Edge 153.0.4234.32 | 34 | 15 | 49 |
| Total | 68 | 30 | 98 |

The run passed actual Windows Desktop-role IPC authentication, creation of
five fixed synthetic accounts, repeat-seed refusal, and authenticated
lock/fixed-fixture unlock. All four browser batches passed their bounded
browser-log canary scans and browser cleanup, with zero unexpected or
forwarded fixture requests and no form submissions. The runner exited zero.
Owned lab processes stopped; temporary guest signing trust, the private
signing key, lab native-host registry keys, and scheduled task were removed.
The lab package, encrypted test vault, and guest-only profiles remain for
diagnosis. No existing user vault was accessed or changed.

The Initial and Extended report `notRun` lists are per-batch, not aggregate:
Extended supplies Initial's duplicate/positive-port/IDN cases, while Initial
supplies Extended's action/restart/lock cases. Independent review is recorded
separately below. A physical toolbar click was not performed.

Artifacts are retained locally under
`artifacts/authlab-Librarian.I17.R623b65b3ae4a4d6f9dad0736/vm-results/`.

| Artifact | SHA256 |
| --- | --- |
| `results-status.json` | `3E59CAAF0A6ED91CACAE018B0BC37888E643FA40BDAE3879082C7CEF6C1307D8` |
| `cleanup.json` | `6147D6AC6F4112BDCDCD0D7E9894A452045E40C589CD0EF91C32A21774BAD52C` |
| `results-chrome-Initial-fill-chrome.json` | `777CF4AC34F99588621656C3A501A70AA34B04E4306A426049BB42AFC944672E` |
| `results-chrome-Extended-fill-chrome.json` | `21741841696FC8917634C88F83DFD1EF22018EA94699BEC6FF971E94FDBA5B82` |
| `results-edge-Initial-fill-edge.json` | `992E8C207251DC86A0B02A5F1E534ABDDDB9E14D39834A3598C85B68026E86AE` |
| `results-edge-Extended-fill-edge.json` | `70287E8B303893B7E0F69FC25C9A642F218F8D9832555E0CA15919727670A876` |

## Review and regression

Codex identified an unrelated form-less email field being paired with a
standalone current-password input. A real Chrome DOM regression first failed,
then passed after the fix. Four form-ownership unit cases now run in CI, and
the same regression passed in both actual browser DOM suites and the
authenticated VM matrix. All 102 extension unit tests passed. The review
thread was answered and resolved; [Codex's re-review of the tested code found
no further issues](https://github.com/theundeadmonk/Librarian/pull/44#issuecomment-5686829503).

The preceding full pinned local Release pipeline passed 274 Rust tests (one
pre-existing manual Argon2 benchmark ignored), extension tests, native/runtime
component integration, Windows boundary/shell checks, and unsigned installer
structure/ICE validation. Log:
`artifacts/logs/issue17-expanded-regression-20260915.log`. The final form fix
also passed Chrome and Edge DOM regression and all extension unit tests.
Final-head Windows/Linux/parity CI status must be checked on the PR.

## Scope and reproduction

The opt-in `.codex-build-issue17-auth-lab.ps1` and
`.codex-run-issue17-auth-lab.ps1` are restricted to the named disposable VM.
Each attempt uses a new package-local vault containing only fixed public test
credentials. Windows session/inactivity checks remain active; the harness
does not automate password-manager/authentication UI or inject fake activity.

The launcher compiles the actual production C++ source. Its generated copy
changes only the lab package name, publisher, protected install subdirectory,
and unchanged header's include path. Reversing those substitutions recovers
the original source. Payload hashing, identity convergence, and inherited
native stdio behavior are unchanged. Agent/native-host code is production
code; the Desktop-role seeding client and package identity are test-only.

Browser actions use a process-owned debugging pipe to dispatch the actual
extension action event to a unique tab target; no handler or native response
is mocked. Worker shutdown is verified by bounded observation of actual
target destruction before a fresh worker is required.

This establishes Issue 17's authenticated lab behavior, not a new production
MSI lifecycle run or an unrestricted security audit. The browser lock barrier
is before native admission; agent selection/publication race tests are
separate runtime IPC coverage. Windows Hello UI, general installer lifecycle,
and broad crash-artifact checks remain with their owning issues. `SECURITY.md`
still prohibits real credentials pending the project's release gates.
