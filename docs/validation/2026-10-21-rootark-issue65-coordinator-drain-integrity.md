# Root.ark #65 — PG/witness drain precondition and genuine witness integration

**Date:** 2026-10-21
**Branch:** `cdx/rootark-dual-recovery-20261019`
**Acceptance status:** PARTIAL, isolated experimental shared PostgreSQL gate; **not** issue #65 completion or production authorization.

## Bounded coordinator milestone

- The reference `Zk1SharedGateWitnessCoordinator` closes the **physical PostgreSQL WRITE gate first**, then asks a separately trusted witness to prepare quiescence, and issues a signed witness reservation only after both authorities report zero active workers. It snapshots the exact owner-approved operation, checks the approved tuple after the verifier callback, passes independent byte copies into adapters, verifies the exact pinned Ed25519 reservation including `expires_at`, and refuses expired tickets at the final return boundary.
- An independent P1/P2 reviewer discovered one additional **P2 precondition violation**: the coordinator previously accepted witness `{status:'QUIESCING',activeCount:0}` as fully drained, advanced PostgreSQL to PENDING and called `witness.reserve()`. This was reproduced in the actual disposable PostgreSQL integration test, returning PENDING instead of QUIESCING (**RED**). The corrected gate requires **literal `DRAINED` plus `activeCount===0` from witness and `activeCount===0` from PostgreSQL** before `markPending` (**GREEN**).
- A bounded READ-ONLY final reviewer independently exercised QUIESCING/0, PG-active, witness-active, and both-drained cases, reported **no confirmed residual P1/P2** in the specific coordinator correction and independently reran real PostgreSQL **11/11 PASS** before the additional genuine-witness test.

## Real witness integration added

`test/issue-65-shared-gate-real-witness.test.js` provisions a throwaway scope in the official PostgreSQL 18.6 disposable lab and a separate SQLite witness ledger with an independently signed synthetic Ed25519 CAS-status responder. The witness's real signed initialize reservation is resolved, PG is initialized at the same committed head, and one worker is admitted independently by **each** authority. The test proves that no signed reservation is issued until *both* real durable admission records are finished, that PG denies a previously authorized physical chunk after QUIESCING, and that a witness process reopen preserves the exact original pending reservation and the PG PENDING gate. The coordinator adapter deliberately translates the mTLS witness-client method shape to the local engine method shape; the integrated production caller must use the actual pinned remote transport, not silently call the local engine as a substitute.

**Evidence:** the disposable real PostgreSQL runner includes this test in addition to all prior cases, returning **12 passed / 0 failed / 0 skipped**, exit 0, with the runner verifying and deleting its own labeled disposable Docker container. The existing issue-65 focused Node suite (before the extra PG-only integration test) returned **260 total / 250 passed / 0 failed / 10 skipped**; the PG-specific tests are intentionally run using the real disposable backend rather than interpreted as successes when skipped.

## Security boundaries still blocking release

The integration proves **PG physical ciphertext writes** are transactionally generation-fenced on a single PostgreSQL primary with two independent worker/process clients; it does **not** prove a geographically independent replicated authority, external provider PUT/GET/read/egress, independently enforced worker termination, nor a privileged actor cannot bypass the trusted PG role. The local SQLite witness is not a geographically independent operator. Both trust authorities can become stuck pending after a lost remote acknowledgement, which is intentionally fail-closed, but an externally validated terminal resolution/reconciliation process has not been integrated into PG.

Normal upload/download, restore, versions, backup, WebDAV, S3/Google Drive and synchronization remain outside the new gate. Network ciphertext **GET/egress remains disabled** after a real independent review reproduced an unsafe post-partition write leak in an earlier draft; ordinary PG row locks alone do not fence a Node HTTP emitter if its SQL connection dies. Device client/recovery/migration completeness, provider acceptance, anti-rollback across hosts, availability under partitions and disaster recovery still require independently tested implementation. No push, merge, deploy, real user content mutation or issue closure is implied.
