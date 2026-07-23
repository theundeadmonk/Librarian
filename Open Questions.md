# Open Questions

These items are intentionally unresolved. They should be answered through feasibility work, security design, or user testing rather than silently assumed.

## MVP design

- Define the first-run onboarding flow and what “setup complete” means.
- Design the desktop app's post-unlock home screen and account-management navigation.
- Define the exact auto-lock behavior and default inactivity duration.
- Define accessible wording for passkeys, authentication codes, recovery, and backup without security jargon.
- Define the smallest useful set of settings; everything else should have an opinionated default.
- Decide how to communicate that storing a password and its authentication secret together trades factor separation for simplicity.

## Windows and browser feasibility

- Confirm packaging, registration, upgrades, and removal of the native passkey component.
- Define and authenticate the native messaging protocol between the extension and desktop app.
- Decide what the extension should do when the native app is missing, locked, updating, or incompatible.
- Test form detection against multi-step, dynamically rendered, embedded, and unusual sign-in forms.
- Define strict origin-matching rules and the UI for suspicious or ambiguous matches.

## Cryptography and secret handling

- Select vetted libraries, algorithms, record format, key hierarchy, and versioning. Do not invent cryptographic primitives.
- Specify how the master password, Windows Hello, vault key, backup key, and recovery key relate to one another.
- Decide whether either the master password or recovery key can restore a backup alone, or whether both are required.
- Calibrate password-based key derivation for supported Windows hardware.
- Specify sensitive-memory handling across native and extension process boundaries.
- Define database integrity, rollback detection, corruption handling, and crash recovery.
- Commission an independent review before storing real family credentials or distributing publicly.

## Backup and recovery

- Design the recovery kit and a simple way to confirm that the user stored it separately.
- Define backup frequency, retention count, rotation, and behavior when the synchronized folder is unavailable.
- Decide how the app detects stale backups without becoming noisy.
- Test restoring passwords, passkeys, authentication secrets, history, and metadata on a clean computer.
- Define a recovery path when the user remembers neither the master password nor the recovery key; permanent loss may be the only secure answer for the MVP.

## Password and authentication behavior

- Define password-generator defaults and compatibility behavior for websites with unusual rules.
- Define how registration and password-change success is detected without incorrectly saving failed attempts.
- Define the pending-credential lifetime and recovery interface.
- Define supported authentication parameters, clock-drift handling, and validation behavior.
- Decide how and when stored recovery codes appear in the account interface.

## Architecture follow-up gates

- The initial monorepo, portable Rust core, native Windows shells, vault-agent boundary, and technology direction are accepted in [[Architecture]] and its linked ADRs. Material changes require an amended or superseding ADR.
- Validate the repository skeleton, exact stable toolchain versions, bootstrap, and build policy in [issue #7](https://github.com/theundeadmonk/Librarian/issues/7).
- Complete the Slice 1 data-flow and threat model in [issue #8](https://github.com/theundeadmonk/Librarian/issues/8).
- Select the key hierarchy, record format, SQLite binding and schema, vault-layer encryption, migrations, and corruption behavior in [issue #9](https://github.com/theundeadmonk/Librarian/issues/9).
- Select and threat-model the authenticated local IPC transport, peer verification, protocol versioning, client authorization, agent lifecycle, and incompatible-state behavior in [issue #12](https://github.com/theundeadmonk/Librarian/issues/12).
- Define and validate signed application, provider, native-host, and extension update behavior through [issue #19](https://github.com/theundeadmonk/Librarian/issues/19).
- Prove the deterministic and real-browser acceptance strategy without production credentials or external production services in [issue #20](https://github.com/theundeadmonk/Librarian/issues/20).

## Future platform constraints — not MVP work

- After the Windows MVP, validate Android Credential Manager and Apple Authentication Services provider lifecycles against the portable vault-core boundary.
- Decide whether future Kotlin and Swift bindings should use UniFFI only after a bounded interoperability and secret-memory spike.
- Define which record-format and recovery guarantees must remain identical across platforms before implementing mobile applications.
- Do not create Android, macOS, iPhone, or iPad applications, placeholder directories, or CI jobs during the Windows MVP.

## Fast follow

- Import 1Password exports.
- Import LastPass exports.
- Provide clear duplicate detection and an import preview before committing records.
- Evaluate encrypted interoperable export without normalizing plaintext CSV as a backup format.

## Later product questions

- Extension-only or temporary access on public and employer-managed computers.
- Multi-device encrypted synchronization.
- Family organizer and adult-member roles.
- Sharing, revocation, family recovery, emergency access, and notifications.
- Children and dependent family members.
- Native macOS, iPhone, iPad, and Android applications.
- Broader item types beyond credentials.
