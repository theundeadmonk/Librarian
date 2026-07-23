# Librarian

> A passkey-first password manager that stays out of the way.

Librarian is an opinionated credential manager designed to give nontechnical people the safest available sign-in experience without making them understand password-manager machinery.

Its default behavior should be obvious, calm, and reversible. Advanced capability may exist, but it must not make the everyday experience more complicated.

## Current focus

The current project is the single-user, Windows-only MVP. The implementation and acceptance boundary is Windows 11 with Google Chrome and Microsoft Edge. Other platforms and the broader family product begin only after the four Windows MVP slices have been proven.

- [[MVP]] — canonical scope and acceptance criteria
- [[Architecture]] — accepted Windows-first technical architecture and implementation order
- [[ADRs/0001 Monorepo|Architecture decisions]] — accepted baseline and its rationale
- [[Decisions]] — choices already made and why
- [[Open Questions]] — unresolved work that must not be mistaken for a decision
- [[Research]] — evidence and platform references behind the direction

## Product promise

Librarian should make the secure action the easiest action:

- Prefer passkeys whenever a website supports them.
- Handle passwords cleanly when a website still requires one.
- Handle time-based authentication codes so the user does not need a second authenticator app.
- Use native operating-system security and recognizable system surfaces.
- Avoid repeated prompts, silent surprises, and configuration-heavy workflows.
