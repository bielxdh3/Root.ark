# Root.ark Security Status

Root.ark has completed several bounded security-stabilization phases covering authentication configuration, browser rendering, session handling, WebSocket authentication, dependency validation, upload and archive boundaries, backup recovery, trash behavior, and runtime-artifact isolation.

This public document intentionally does not retain exploit-ready reproduction steps, obsolete vulnerable snippets, private paths, or a chronological dump of every historical finding. Detailed evidence belongs in focused pull requests, tests, and private vulnerability reports when disclosure would increase risk without helping users operate the project safely.

## Current position

- Root.ark is still under active development and is not production-ready.
- The default expectation is a private, administrator-controlled deployment on a trusted network.
- A strong explicit `JWT_SECRET` is required; no public fallback secret should be used.
- Browser authentication uses server-controlled session boundaries rather than persistent browser bearer-token storage.
- User-controlled text must be rendered as text, not injected as HTML.
- WebSocket authentication must not place credentials in URLs and must preserve session freshness checks.
- Local data, databases, backups, uploads, credentials, keys, and environment files must remain outside Git.
- Optional scanning, cloud, WebDAV, backup, and synchronization behavior still depends on deployment-specific validation.
- The approved future zero-knowledge product direction is not equivalent to the current implementation and requires separate architecture and migration work.

## Public security guidance

Use [SECURITY.md](../../SECURITY.md) to report vulnerabilities responsibly. Do not open public issues containing working exploits, real credentials, private paths, personal data, or sensitive deployment details.

## Evidence and regression coverage

Security changes should be backed by focused automated tests, exact-revision validation, disposable data, dependency review, and a clean-checkout artifact check. Historical pull requests and the repository test suite remain the authoritative public evidence for merged remediation work.

## Remaining responsibility

A passing test suite does not make an arbitrary deployment safe. Operators are responsible for network exposure, reverse-proxy configuration, TLS, secret management, operating-system permissions, enabled providers, backup handling, and the exact revision deployed.

The route-scoped HTTP request limits use a per-process in-memory store. Each process or container enforces its own budget; deployments with multiple workers need a shared rate-limit store for a deployment-wide budget. This does not close Issue #94: the separate multi-process `/upload-chunk` gate remains open.
