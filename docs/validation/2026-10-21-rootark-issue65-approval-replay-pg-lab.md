# Root.ark #65 — PostgreSQL approval nonce replay ledger (experimental)

**Release status: LAB_ONLY_NON_AUTHORIZING / PRODUCTION NO-GO.** This milestone
does not install a route, migrate any existing database, authorize a device,
accept a ciphertext publication, or select a trusted CAS/witness provider.

## Experiment and threat boundary

`src/services/zk1ExperimentalPgApprovalReplayLedger.js` records one opaque
device-approval candidate per `(account, compartment, nonce)` in a durable
PostgreSQL 18 tombstone. `rawSignedApproval` is hashed with SHA-256, with the
candidate's device key ID, keyring ID, signed manifest revision/digest,
witness sequence and expiration committed in the same database row. The SQL
server, not the caller's claimed clock, validates that expiration lies within
the next 300 seconds. The unique constraint serializes conflicting writers;
duplicate use is a denial even when all supplied bytes are identical or when
the previous success response was lost. Tombstones are never expired or
reclaimed by this module. A new process/pool sees the previous row.

The runtime role is a distinct **LOGIN** fixture identity that inherits only
`zk1_approval_replay_writer` (NOLOGIN). Every call checks the current SQL
session role against an exact disposable prefix, rejects superuser/CREATEDB/
CREATEROLE, gate or STOP role membership/SET ROLE, and ensures the login lacks
SELECT/UPDATE/DELETE/TRUNCATE and schema CREATE. The SQL login has *INSERT
only*. A plain INSERT is used rather than ON CONFLICT or RETURNING, so it
does not need SELECT privileges to inspect nonce tombstones. A PostgreSQL
unique-constraint violation, expired candidate, denied privilege, connection
loss or invalid request produces a generic denial without SQL contents.

The independent review found two additional SQL privilege/provenance defects
in the initial iteration: table-level checks missed restricted per-column
SELECT/UPDATE grants, and the pool could substitute a privileged client
after checking a different connection. Both were reproduced as **RED** with
real PG (7 PASS / 2 FAIL), then corrected by inspecting *any-column*
SELECT/UPDATE/REFERENCES and running the identity preflight and physical
INSERT on the **same leased backend connection**. Tests include a deliberately
alternating restricted/admin pool and separately provisioned disposable
NOINHERIT-style privilege-escalation candidates; a request never receives an
authorizing response.

A further independent P2 review found that an otherwise restricted pooled
client returned while still inside somebody else's `BEGIN` could produce
`rowCount=1` without any durable COMMIT. The new regression reproduced this
false positive. The ledger now executes `DISCARD ALL` **before** admission
preflight (PostgreSQL refuses it while a client is inside a transaction),
leases only that verified SQL connection, executes an explicit owned `BEGIN
ISOLATION LEVEL READ COMMITTED`, and reports success only after its matching
`COMMIT` resolves. Errors attempt rollback and quarantine the client with
`release(true)`; lost COMMIT ACK is a denial and retry remains constrained by
the durable unique key. This protects only the lab-specific pool; it must
not be adapted to application-owned shared transactional pools or run against
real data.

**Important:** SQL role isolation is not proof of crypto verification.
`consumeCandidate` intentionally does not check Ed25519 signatures, owner
manifest history, independently pinned witness HEAD, device enrollment or
revocation, TLS/OS identity or live CAS state; all are prerequisites to a
separately reviewed authorizing service. As a result the returned object is
always `{ replayRecordCommitted: true, cryptographicApprovalVerified: false,
liveAuthorityVerified: false, authorizesRelease: false,
protectedIoAdmission: false }`. This output is evidence only that *a caller*
burned a nonce. A compromised fixture writer can burn arbitrary challenge
nonces and cause denial of service, but cannot grant access with this API.
SQL administrators, PostgreSQL backup rollback, compromised root/host or
privileged in-process code are outside this bounded test; no independent
trusted high-water, operator signer or multi-host availability proof exists.

## Targeted adversarial validation

Run `node lab/issue-65-packet-b/run-approval-replay-postgres.js`. This creates
one random, **labeled disposable** Docker `postgres:18.6-alpine3.24` container
with loopback-only port binding, independently random admin/writer fixture
credentials, and a separate lab-only schema. It loads the normal Gate schema
only *inside that disposable container* to provision disjoint Gate/STOP roles;
the actual replay SQL lives in
`lab/issue-65-packet-b/approval-replay-lab.sql` and is never applied to the
Root.ark live database. Exact Docker ID and both labels are verified before
cleanup; no other resources are removed.

Focused tests cover: malformed input; a privileged admin rejected as replay
writer; SQL permission denial for SELECT, UPDATE, DELETE, TRUNCATE and gate/
STOP escalation; duplicate signed bytes and altered bytes; cross-keyring
nonce reuse; 12 concurrent attempts across distinct PostgreSQL connections
with exactly one committed winner; **two separately spawned Node child
processes** racing a single nonce and a restarted child denied by the same
committed tombstone (credentials delivered by local parent IPC, not process
arguments/environment); expiration enforced by PostgreSQL clock;
SQL connection destruction before COMMIT rolling back a pending insert; and
committed tombstones preventing retries across new connection pools.

The initial PostgreSQL run failed closed on ambiguous `$9` binding
(SQLSTATE 42P08), then on unnecessary ON CONFLICT privileges (SQLSTATE 42501).
Both defects were corrected with explicit `::bigint` and a direct INSERT
whose primary-key conflict is treated as denial. Subsequent focused runner:
**6/6 PASS native Windows and 6/6 PASS WSL Node 22; cleanup verified=true.**
After the independent-review fixes and OS-process/crash regressions the final
disposable PG18 lab reported **10/10 PASS native Windows and 10/10 PASS WSL
Node 22, 0 FAIL/0 SKIP**, plus exact labeled Docker cleanup verified=true.

These tests do not demonstrate cryptographically valid consumed approvals,
separately owned anti-replay authority, durable backup-restore floor, physical
remote GET/egress STOP, witness/CAS continuity, or protected data release.
No normal server, browser client, sync/WebDAV, S3/Drive or recovery flow may
depend on this experiment as a positive authorization decision.
