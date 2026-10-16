# Phase 14 deployment resilience

Status: `IMPLEMENTED-UNVERIFIED` until the focused Phase 14 gate and the
dependency-backed regression gate complete at the final commit.

This bounded slice adds standard-library deployment guards around existing
authentication, TOTP, master-key, and cloud-provider boundaries:

- `GET /health` is an unauthenticated liveness response.
- `GET /ready` is an unauthenticated readiness response and returns `503` when
  JWT, explicit TOTP policy, Secure session-cookie, master-key, or
  selected-provider configuration is missing or invalid. `NODE_ENV=production`
  enables the cookie `Secure` attribute by default; an explicit insecure
  production cookie setting aborts startup. It returns only safe status codes and provider names;
  paths, credentials, keys, and raw provider errors are not exposed.
- Provider failures normalize to bounded categories. Retry/backoff and
  cancellation helpers cap attempts and delays, while idempotency helpers
  share in-flight work and remove failed entries.
- Sync object startup, backup creation, and restore validation attest that
  protected sync records contain ciphertext/AAD fields only. They reject
  plaintext/key fields, malformed protected bytes, AAD mismatch, and invalid
  persisted state without decrypting content or handling file keys.
- Log values and metric labels have a standard-library redaction helper for
  bearer tokens, JWT-like values, credentials, keys, passwords, and paths.

Existing backup checksums, pre-restore backups, trash, file versions, provider
contracts, and route shapes remain unchanged. Ciphertext-only attestation is a
structural/canonical-AAD check; it does not claim decryption or provider
interoperability proof. Provider, TLS, production, native dependency, browser,
remote CI, and release validation remain outside this local phase.

Focused failure-mode coverage is in `test/phase14-deployment-resilience.test.js`.
