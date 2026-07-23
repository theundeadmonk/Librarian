# Security Policy

## Current status

Librarian is pre-production software. Its cryptographic design, key hierarchy, local IPC boundary, browser integration, backup recovery, dependency chain, packaging, and update mechanism have not completed the security review required for real credentials.

Do not use the project to store real passwords, passkeys, authentication secrets, recovery codes, or recovery material.

## Reporting a vulnerability

Report suspected vulnerabilities privately through this repository's GitHub private vulnerability reporting feature. Do not open a public issue for a vulnerability that could expose credentials, bypass authorization, weaken cryptography, or compromise recovery material.

Include only the minimum information necessary to reproduce the problem. Never include real credentials or personal data. Disposable test credentials are required for demonstrations and proofs of concept.

Because the project has not reached a supported release, there is not yet a published security-support matrix or response-time commitment.
