# Phase 14 deployment resilience

Status: `IMPLEMENTED-UNVERIFIED` until the focused Phase 14 gate and the
dependency-backed regression gate complete at the final commit.

This bounded slice adds standard-library deployment guards around existing
authentication, TOTP, master-key, and cloud-provider boundaries:

- `GET /health` is an unauthenticated liveness response.
- `GET /ready` is an unauthenticated readiness response and returns `503` when
  JWT, explicit TOTP policy, master-key, or selected-provider configuration is
  missing or invalid. It returns only safe status codes and provider names;
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

## Journal topology

Cloud relocation cleanup and WebDAV MOVE recovery persist journals and claim
files in `temp/.incoming`. Automatic stale-claim takeover relies on the owner
host and operating-system process identity being visible to the recovering
process, plus exclusive file creation and atomic rename behavior from the
journal filesystem. Cloud-backed API `/rename`, `/move`, version restore, and
version delete, WebDAV `MOVE`, and approval/rejection mutations share one coarse
cross-process mutation claim, acquired before provider listing/cache hydration,
journaling, provider staging, or approval's asynchronous version uploads and
held until the local outcome and cleanup intent are recorded. Rename and move
reload version history under the claim; restore holds it through awaited cloud
version synchronization. Pending
WebDAV journals reserve both source and destination object names from later API
mutations until reconciliation removes the journal. This serializes overlapping
relocations while allowing stale same-host claims to be taken over through the
existing process-identity checks. Run processes sharing these data and journal
paths on one host with that process visibility. Sharing the journal directory
between hosts is unsupported: a claim naming another host remains live
indefinitely, and its object names stay reserved. Do not delete such a claim
based only on age; first stop or verify the owner and inspect the local
transaction state. Safe multi-host recovery requires a shared coordinator and
fencing on provider operations, which this implementation does not provide.

Treat `temp/.incoming`, `temp/`, and their runtime-root ancestors as
service-private state. Run under a dedicated service account and prevent
untrusted host users or processes from creating, replacing, or renaming entries
there while Root.ark is active. Exclusive claims and identity rechecks protect
against cooperating application workers and process interruption; they do not
protect journal recovery from a malicious local writer that can modify these
paths. Deployments that cannot enforce this filesystem boundary must not rely
on the journal takeover and recovery guarantees.

These guarantees cover process termination followed by restart and recovery on
the supported same-host journal filesystem. Journal contents and lock files are
flushed before use, but atomic file replacement does not explicitly flush the
parent directory; sudden power loss or filesystem/controller failure is not a
durability guarantee. Claim lock publication requires same-directory hard-link
support; unsupported journal filesystems fail closed before mutation begins.
