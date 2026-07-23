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
- [Architecture decision records](ADRs)
- [Settled product decisions](Decisions.md)
- [Open questions and decision gates](Open%20Questions.md)
- [Research index](Research.md)

These Markdown files also form an Obsidian vault. Product behavior in the MVP specification is normative. Architecture records marked **Accepted** define the Slice 1 baseline; unresolved cryptography, IPC, recovery, signing, and production-security decisions remain explicitly tracked.

## Development approach

The MVP will be delivered as four complete Windows vertical slices. The first slice proves the trusted local foundation end to end: create and unlock a vault, store one account, fill it in Chrome and Edge, and create and use a vault-backed passkey through the Windows provider.

The existing passkey-provider feasibility spike is intentionally maintained separately from this production repository because it contains disposable Microsoft sample code and mock credential storage.

## Security

Read [SECURITY.md](SECURITY.md) before testing or reporting a vulnerability. Do not submit real credentials, recovery material, passkey private material, or authentication secrets in an issue, discussion, test fixture, or log.

## License

Librarian is available under the [MIT License](LICENSE).
