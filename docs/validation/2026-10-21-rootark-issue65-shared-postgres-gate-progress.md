# Root.ark #65 — shared PostgreSQL reference gate and physically atomic ciphertext writes

**Date:** 2026-10-21
**Branch:** `cdx/rootark-dual-recovery-20261019`
**Status:** PARTIAL / NON-PRODUCTION. Does **not** close issue #65.

## New implementation and narrow guarantee

`db/zk1-gate-authority.sql` creates a separate `zk1_gate` schema with a
durable per-scope `(revision,digest,generation,phase)` row, exact worker-bound
admission rows and an immutable ciphertext-chunk provider. This is **not**
automatically created by `server.js`; trusted owner/CAS head provisioning
must be supplied by a separate independently authenticated operator. The
schema revokes PUBLIC access. It deliberately creates no default runtime
user/grants, network exposure, or instance credentials.

`src/services/zk1SharedPgGateAuthority.js` uses **real PostgreSQL primary**
transactions and `SELECT ... FOR UPDATE` over that shared head to serialize
one-shot worker admissions, generation changes, QUIESCING, FINISH, pending
closure and every actual ciphertext **INSERT**. It rejects mismatched scope,
head, epoch-generation, principal/worker/action/object, stale admission and
different-byte retries for the same chunk. `beginQuiesce` increments the
generation, stops new admissions and marks existing workers `STOP_REQUESTED`.
`markPending` refuses unfinished admissions. An interrupted PostgreSQL write
rolls back when its database transaction/connection is lost.

An isolated, non-Root.ark mTLS listener (`zk1SharedPgGateHttpsServer.js`)
allows explicitly configured certificate fingerprints, scope and role on
admission, ciphertext PUT, FINISH and transition requests; untrusted HTTP
bodies cannot supply the principal. It accepts ciphertext only. **No normal
Root.ark file route is switched to ZK by this change.** This reference still
lacks independently governed bootstrap, per-host operational root custody,
complete normative signed ticket binding and resolution/reopening.

`zk1SharedPgGateHttpsClient.js` requires an exact pinned TLS peer certificate
fingerprint in addition to mTLS, canonical scope and typed JSON results. The
bounded `zk1SharedPgCiphertextSink.js` uploads an async iterable one
ciphertext chunk at a time using that remote client, retries a single lost
START/PUT acknowledgment with the **same** worker and bytes, and always
attempts authenticated FINISH. A denied later chunk never changes a prior
already committed ciphertext chunk; no plaintext or keys are processed by the
gate. The sink does not itself publish a signed manifest or represent a
completed normative upload.

## Critical adversarial correction — unsafe egress removed

An independent review **proved a P1** against the first version: while an
asynchronous ciphertext-egress callback waited with decrypted/opaque data in
process memory, terminating its PostgreSQL backend connection implicitly
released the head row lock. A second authority began QUIESCING and the first
callback still emitted ciphertext **after QUIESCING**; the first task failed
only at a later COMMIT. This was reproduced on disposable PostgreSQL 18.6,
not inferred from static analysis.

The unsafe arbitrary external-I/O callback and exposed `emitCiphertextChunk`
API were **removed**. Only a **private** effect callback issuing physical
SQL through the **same PostgreSQL transaction** remains. The mTLS GET/egress
route was removed (404), and GET admissions are refused by that listener
until an independently fenced data-plane egress protocol exists. Thus no
network egress guarantee is currently claimed or offered. This is a
conservative reduction of capability to preserve safety, not completed
physical network/remote-provider fencing.

## Real-world validation and limitations

The disposable official PostgreSQL 18.6 runner
`lab/issue-65-packet-b/run-shared-gate-postgres.js` provisions an isolated
database on an ephemeral **loopback-only** port, runs tests, validates its
container ID and labels, and removes only its own disposable container.
Tests exercise two independent PostgreSQL pools, independent Node processes,
real physical chunk INSERT serialization, immutable ciphertext retries,
cross-scope denial, generation fencing, killed workers, crash rollback,
actual TLS client-certificate ACL and transition withholding, pinned mTLS
client calls, loss of START and PUT ACK and a QUIESCING boundary between two
sequential chunks. The last disposable real PostgreSQL 18.6 run finished
**7 passed / 0 failed / 0 skipped**, exit 0; verified its labeled container
cleanup. This is still a *single-machine Docker plus two-process* integration,
not evidence of a multi-host physical deployment or fault-tolerant cluster.

**Not proven:** this is a single PostgreSQL primary in one Docker daemon,
not geographic multi-host deployment, independent certificate/domain
administration, quorum/failover consistency or resistance to privileged
DB administrator manipulation. The lab uses synthetic credentials and a
superuser; production isolation would require a dedicated controlled role,
TLS pinning between gate and PostgreSQL, networking restrictions and separate
operator custody. The mTLS `reserve` principal still needs authenticated
**owner-approved** v1 operation verification before initiating a mutation;
unreviewed mTLS role-bearing operators can currently deny service to their
configured scope by quiescing it.

No STOP acknowledgment yet proves physical termination of **non-PostgreSQL**
workers. No S3, Google Drive, local disk, WebDAV, normal upload, backup,
version, restore, share, sync or browser egress path is protected by this
PostgreSQL reference backend. There is no unified atomic witness/CAS/PG
authority yet; `PENDING` is a local reference gate state, **not** a signed
canonical witness/CAS terminal outcome. No automatic reopening or migration
of real user data occurs.
