# Librarian

> A passkey-first credential manager that stays out of the way.

Librarian is an opinionated password and passkey manager designed to make strong authentication straightforward for nontechnical users. The secure choice should be the easy choice: use passkeys when available, handle passwords cleanly when necessary, and keep authentication codes in the same coherent experience.

## Project status

Librarian is in early Windows MVP planning and architecture validation. It is **not production-ready and must not be used to store real credentials**.

The MVP is intentionally limited to:

- One user on Windows 11.
- A native Windows desktop application and passkey provider.
- Google Chrome and Microsoft Edge through a Chromium Manifest V3 extension.
- A local encrypted vault with recoverable encrypted backups.

Android, macOS, iPhone, iPad, Linux, non-Chromium browsers, family features, and live cloud synchronization are outside the MVP.

## Documentation

- [MVP specification](MVP.md)
- [Accepted architecture baseline](Architecture.md)
- [Slice 1 threat model](Threat%20Model.md)
- [Architecture decision records](ADRs)
- [Issue #9 vault-cryptography hardening review](security/hardening/issue-9/hardening.md)
- [Settled product decisions](Decisions.md)
- [Open questions and decision gates](Open%20Questions.md)
- [Research index](Research.md)

These Markdown files also form an Obsidian vault. Product behavior in the MVP
specification is normative. Architecture records marked **Accepted** define the
Slice 1 baseline; proposed cryptography and authenticated-IPC decisions plus
unresolved recovery, signing, and production-security gates remain explicitly
tracked.

## Development approach

The MVP will be delivered as four complete Windows vertical slices. The first slice proves the trusted local foundation end to end: create and unlock a vault, store one account, fill it in Chrome and Edge, and create and use a vault-backed passkey through the Windows provider.

The existing passkey-provider feasibility spike is intentionally maintained separately from this production repository because it contains disposable Microsoft sample code and mock credential storage.

The production repository now has a Windows-only foundation for the accepted component boundaries. Its trusted Rust path can exercise one encrypted website account with disposable test values, but no desktop, browser, or provider client can reach those operations and production credential use remains prohibited until the security gates are complete. See [Windows development](DEVELOPMENT.md) for the pinned toolchain and single-command build.

## Security

Read [SECURITY.md](SECURITY.md) before testing or reporting a vulnerability. Do not submit real credentials, recovery material, passkey private material, or authentication secrets in an issue, discussion, test fixture, or log.

## License

Librarian is available under the [MIT License](LICENSE).
