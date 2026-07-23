# ADR 0001: Monorepo

**Status:** Accepted
**Date:** 2026-07-22
**Scope:** Product source, protocols, packaging, and tests
**Decision issue:** [#6](https://github.com/theundeadmonk/Librarian/issues/6)

## Context

The Windows MVP contains a desktop app, passkey provider, local agent, browser extension, native-messaging host, shared vault logic, packaging, and end-to-end tests. Future Android and Apple applications may reuse the vault format and security core, but they are not MVP deliverables.

Changes to credentials, protocols, or vault formats frequently cross component boundaries. Splitting those components into independent repositories would make compatible changes, security review, and test-vector updates harder to coordinate at this stage.

## Decision

Use a modular monorepo with explicit component ownership and dependency boundaries.

The repository will contain only active Windows MVP components and shared code. Android and Apple projects will be added when those products enter implementation; empty future-platform directories and build pipelines are prohibited during the MVP.

Root-level automation should provide a small set of consistent developer and CI entry points while allowing Rust, C++/WinRT, and TypeScript to retain their native build systems and lockfiles.

[Issue #7](https://github.com/theundeadmonk/Librarian/issues/7) validates the initial repository structure and pinned toolchains. If implementation evidence invalidates this decision, supersede this ADR explicitly rather than allowing the repository to drift.

## Consequences

### Benefits

- One reviewed change can update a protocol, all clients, its test vectors, and packaging.
- End-to-end Windows acceptance tests can run against a known-compatible component set.
- Security-sensitive dependency and format changes are easier to discover and audit.
- The later mobile applications can consume the same versioned core without creating a second source of truth.

### Costs and controls

- CI can become slow; use path-aware jobs without weakening the full release pipeline.
- Mixed toolchains can confuse local setup; provide one documented bootstrap command and pin every toolchain.
- A monorepo can become tightly coupled; enforce public interfaces and prohibit imports across private component boundaries.
- Release versions may differ by artifact; maintain a product release manifest that records the compatible versions shipped together.

## Reconsider when

Split a component only if independent teams, regulatory isolation, access control, or genuinely independent release governance outweigh the cost of cross-repository protocol coordination. Repository size alone is not sufficient reason.
