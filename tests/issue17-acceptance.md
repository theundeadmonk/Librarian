# Issue 17 acceptance evidence

## Current status (2026-09-15)

Issue 17 is not yet complete. Local regression has passed; the expanded
authenticated browser batch and independent review remain gates.

Draft PR: <https://github.com/theundeadmonk/Librarian/pull/44>. Linux CI passed
for the initial implementation commit; Windows CI and independent Codex review
were still running at this checkpoint. Do not treat that as a current-head
CI or review all-clear.

The complete pinned Release pipeline passed on Windows: 273 Rust tests
(one pre-existing manual Argon2 benchmark ignored), extension unit tests,
native/runtime component integration, Windows boundary and shell checks, and
unsigned installer structure/ICE validation. Log retained locally at
`artifacts/logs/issue17-expanded-regression-20260915.log`.

An earlier independently staged lab run, `Librarian.I17.Rafe5c5605d714656a48ce471`,
passed real Windows Desktop-role IPC authentication, five synthetic account
creation operations, repeat-seed refusal, lock/unlock, and 74 browser checks
(22 Initial + 15 Extended in each of Chrome and Edge). Its browser-log canary
scans and cleanup passed. No existing vault was accessed. Aggregate report
SHA256: `AA768279FF00C7BC2241C4D73753C26B73E5B27B2DB49D34C63326095486853D`.
That run used a test-only native launcher, and did not cover explicit browser
actions, worker termination, or lock ordering during an outstanding fill.

## Expanded harness (pending authenticated execution)

The opt-in `.codex-build-issue17-auth-lab.ps1` and
`.codex-run-issue17-auth-lab.ps1` are confined to the explicitly named disposable
Home VM. They use a fresh package-local vault containing only fixed public
test credentials. They do not automate password-manager UI, bypass Windows
session checks, or alter the existing product vault.

The new launcher is built from the actual production C++ source. A generated
copy changes only its lab package name, publisher, protected install
subdirectory, and header include path. Reversing those substitutions must
recover the original source byte-for-byte. Payload hashing, identity
convergence, and inherited native stdio behavior remain unchanged. This is
production-logic lab coverage, not an MSI upgrade or production identity test.

Chrome and Edge both passed the separate action-only self-test. It uses the
browser's process-owned debugging pipe to dispatch the real extension action
event to an unambiguous tab target. It does not invoke the handler directly.
This is automated action coverage, not a physical toolbar click.

The fixture-only transport checks also passed in Chrome and Edge: five Initial
and fifteen Extended checks per browser. They verify actual HTTPS/HTTP/IDN/port
document contexts plus data/blob/about pages with exactly two empty fields.
They load no extension and provide no credential-disclosure evidence. Lab
configuration serialization and reject-before-write launcher scope checks
are included in the ordinary Windows CI guard tests.

The expanded authenticated batch adds explicit retry after edits/back/lock,
same-document worker termination and restart, cross-origin embedded forms,
and data/blob/about-document refusal. Its lock test pauses the actual browser
request before native connection, acknowledges authenticated Lock, resumes,
and requires the real locked response with no fill. Agent publication-order
race coverage is supplied separately by runtime IPC tests; the browser test
does not claim to pause the agent after a credential has been published.

The first expanded attempt was correctly refused by the production Windows
inactivity guard before seeding. The prepared replacement uses the real
launcher and requires ordinary fresh user input in the VM before execution.
Neither attempt is counted as a passing expanded batch.
