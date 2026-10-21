# Root.ark #65 — shared PostgreSQL gate and protected ciphertext-write integration

**Date:** 2026-10-21
**Parent commit:** `32d38c1`
**Scope:** isolated opt-in PostgreSQL-only reference data plane; **NOT** the production ZK-1 release

## Implemented

`db/zk1-gate-authority.sql` defines a durable shared head, active-admission ledger and ciphertext chunk table. `Zk1SharedPgGateAuthority` uses one PostgreSQL primary and a row lock on the exact head for START, QUIESCING, FINISH, PENDING and each **physical PostgreSQL ciphertext INSERT**. A separate TLSv1.3/mTLS listener enforces scoped certificate fingerprint and role grants; the new strict mTLS client additionally pins the server certificate and refuses unexpected replies, non-2xx outcomes and timeouts. The new `Zk1SharedPgCiphertextSink` gives the trusted gateway a bounded write-only adapter: one worker per upload, per-chunk gate checks, idempotent same-worker START/PUT retries on lost response, and FINISH in a finally block on completion or failure.

The independent PostgreSQL integration tests exercise two separate PG pools, two independent Node processes, held physical INSERT transactions, SIGKILL mid-write (uncommitted bytes rolled back), TLS-scoped role authorization, denied unpinned TLS peer, late write after QUIESCING, idempotent worker recovery and lost START/PUT ACKs followed by revocation before the next chunk.

**Evidence:** `node lab/issue-65-packet-b/run-shared-gate-postgres.js` ran **7/7 passed, 0 failed, 0 skipped**, exit 0, with loopback-only disposable PostgreSQL. It verified the exact container identity before destroying only its own test container. Previous RED executions caught missing client/sink modules and the prior test teardown ordering issue before a 5/5 passing baseline. `npm run validate:syntax` checked **302 files, 0 failures**; artifacts and Git whitespace validation exited 0.

## Strict trust boundaries and known omissions

This experiment is **not** the complete distributed GateAuthority contract. A single PG primary shared by separate processes demonstrates cross-process transactional ordering but not a deployed, independently owned, multi-failure-domain consensus/storage system. The SQL schema does **not** yet implement independently verified runtime DB least-privilege roles or operator-pinned anti-rollback state, and testing uses disposable superuser credentials. No live user files or credentials are involved.

No public Root.ark legacy upload, download, versions, sync, backup/restore, WebDAV, S3 or Google Drive route is reclassified or routed through this gate. The sink is only usable after an **independent trusted caller** has verified user/session permissions, signatures and the exact ZK keyring/manifest binding. The current listener deliberately has **no GET/egress endpoint** and denies GET admission: it is not safe to stream network ciphertext while holding a PostgreSQL row lock inside an asynchronous JavaScript callback, because a severed SQL connection may release the lock before the socket stops writing. There is no remote stop attestation beyond the gateway's authenticated FINISH assertion, no independent data-plane stop ACK, signed ticket/CAS terminal-proof integration, external-provider fencing or reversible legacy migration. A double-lost START acknowledgement may strand a durable admission fail-closed until authenticated operator reconciliation. No epoch/token revocation protects already exported ciphertext.

An independent adversarial reviewer **reproduced this network-egress defect as a P1** against the earlier experimental callback: after killing its PostgreSQL backend, another authority completed QUIESCING while the old callback still emitted ciphertext, and the old request failed only at its later COMMIT. The unsafe public callback and all GET/egress routes were removed rather than presenting a mere post-hoc error as physical fencing. The bounded final independent review reported **PASS with no confirmed P1/P2** in the remaining PostgreSQL-write-only and pinned-mTLS-sink scope; this is *not* issue-wide acceptance.

Do not enable the experimental endpoint as production Zero-Knowledge storage without real provider enforcement, genuinely independent status and witness authorities, signed request/receipt binding, end-to-end security review and distributed failure tests.
