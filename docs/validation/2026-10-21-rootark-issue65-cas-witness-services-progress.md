# Root.ark #65 — durable CAS/status and witness service progress (2026-10-21)

## Scope and decision

This is a **development-branch progress report**, not issue #65 acceptance.
The branch started from `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`, in
`E:\servidor\.worktrees\zk-dual-recovery-20261019`. It contains older
uncommitted work and must **not** be reset. No real user data has been migrated.
No commit, push, merge, deployment, or issue closure was performed by this phase.

The protocol engines are deliberately separate from Root.ark `server.js`.
`bootstrapNew` is explicit; real signing/transport credentials must be
provisioned out of band, and the processes in tests use disposable identities.

## Concrete implementation

- `zk1DurableWitnessLedger.js`, `zk1WitnessHttpsServer.js`,
  `zk1WitnessHttpsClient.js` and `zk1-witness-standalone.js`: witness identity,
  scope-specific mTLS principal ACLs, Ed25519 pinned owner/provisioner
  authorization over a full genesis operation, signed reservation/head/terminal
  receipts, durable pending gate and idempotent restarts.
- `zk1DurableCasStatusLedger.js`, `zk1CasStatusHttpsServer.js`,
  `zk1CasStatusHttpsClient.js`, `zk1CasWriteHttpsClient.js` and
  `zk1-cas-status-standalone.js`: single-node CAS/status signer and independent
  process endpoint; witness-signed ticket validation; v2 public signed manifest
  validation; commit/final-cancellation under immediate SQLite write lock;
  nonce-bound signed terminal status and client-certificate role/scope ACLs.
- `zk1CasTerminalAnchor.js`: a **separate local signed journal and per-operation
  intent directory**, including strict identity checking, hash-chain,
  signature verification, replay fencing, fsynced prepared intent and terminal
  event, cross-handle serialized append and recovery of an interrupted
  SQLite-commit-to-journal confirmation. Staged intent creation is atomic using
  a private complete file and a no-overwrite hard link. An unfinished staging
  file is not treated as an authoritative intent.

## Negative cases covered

Actual red-to-green regressions have reproduced and rejected: unauthorized
cross-keyring reservation/resolve/head; forged genesis signature or altered
manifest digest; TLS bad pin and redirect; slow incomplete request on shutdown;
missing CAS authority, lost ACK, replay, late commit; coherent fake SQLite
commit or cancellation without the CAS terminal seal; SQLite-only rollback of
an authentic commit into cancellation; missing/tampered anchor; two separate
handles assigning a duplicate anchor sequence; crash after SQLite commit but
before journal confirmation; and a deadline crossing during signed commit
preparation or a valid prepared intent resumed after expiry.

### Later 2026-10-21 bootstrap/foreign-SQLite preservation hardening

New work in the same uncommitted development worktree (not in the historical
234-test snapshot) corrects a confirmed data-preservation failure. Previously,
`Zk1ProtectedObjectStore` issued SQLite WAL and `CREATE TABLE` mutations before
discovering that a pre-existing database belonged to another application. A
synthetic pre-existing table's database-file SHA-256 changed despite the
expected startup error.

The constructors of **protected object store, CAS/status and witness** now
inspect persistent identity on a `better-sqlite3` **read-only** handle before
opening a write connection, verify identity a second time on that specific
write connection before mutating it, and refuse symlink final components.
Fresh SQLite creation uses `O_EXCL` and pins the exclusive-created file's
`fstatSync` identity before closing its descriptor, then validates that the
write connection is associated with a path whose file identity matches. CAS
also validates the pre-existing signed terminal anchor **before** its first
write-capable SQLite open. These are fail-closed safeguards, not a proof of
operator-resistant filesystem immutability.

Tests added/expanded:

- `test/issue-65-protected-content-bootstrap.test.js`: preserves the bytes
  and sidecars of an unrelated ordinary SQLite, refuses corrupt foreign
  SQLite and identity-fingerprint mismatch, prevents silent recreate, and
  injects a swap of a synthetic foreign SQLite at the exclusive-fd close
  boundary; foreign rows and checksum remain unchanged.
- `test/issue-65-authority-bootstrap-preservation.test.js`: exercises CAS and
  witness startup against unrelated SQLite databases, CAS pre-existing signed
  anchor, and adversarial replacement immediately after exclusive create;
  checks original foreign database file hashes.
- Independently reproduced **P2 before fix**: the object store could mutate a
  replacement SQLite after `O_EXCL` close. An independent reviewer re-ran the
  same attack after fd-based identity pinning: `ZK_CONTENT_BOOTSTRAP_REQUIRED`,
  unaltered foreign rows and database bytes. No further P1/P2 was confirmed
  by that reviewer **in the object-store/bootstrap scope only**. A subsequent
  separate bounded READ-ONLY independent follow-up of CAS/witness and the
  anchor constructor reported no confirmed P1/P2 there. The reviewer reran
  the CAS/witness adversarial file-swap regression **2/2** and independently
  simulated a replacement during the second stat check; both constructors
  rejected the swapped data without changing the foreign DB bytes. Neither
  review is a whole-issue or cross-host security acceptance.

**Residual boundary:** a local actor able to rename or overwrite paths after
the final inode/path check and before SQLite's first write can still race the
constructor. Better-sqlite3's pathname-based opening cannot atomically bind
DDL to a held file descriptor here. A read-only SQLite connection inspecting
a foreign WAL-mode database may also create or modify SQLite `-wal`/`-shm`
coordination sidecars; the foreign main-database content is not modified by
the checked regression. Never characterize this preflight as fully side-effect
free against all foreign SQLite files, nor as protection against a compromised
local filesystem operator.

### Later 2026-10-21 witness I/O admission reference gate (local-host only)

The witness engine now provides a durable `beginIoAdmission`/
`finishIoAdmission` reference gate under the **same SQLite immediate write
ordering** as `reserve`. A committed matching head, action/object identity,
worker identifier and trusted mTLS principal are required. The start operation
is idempotent only for the exact same active worker; a terminal worker ID
cannot be reused. Reservations are rejected while a worker is ACTIVE, even
after a witness restart. The witness's pinned mTLS endpoint provides
`/v1/admission/start` and `/v1/admission/finish` scoped to an explicit `admit`
role. The development-only protected HTTP content routes now hold admission
through synchronous SQLite I/O and until Node signals response `finish` or
`close`. Unknown/lost completion acknowledgement leaves the witness admission
active and blocks revocation conservatively. Single lost start/finish ACKs are
retried exactly once with the **same** worker/admission IDs; neither retry
creates a replacement worker. Persistent outage after those attempts may
strand an admission pending an independently verified recovery procedure.

This is **not** the required independent, cross-host linearizable
`GateAuthority`: one SQLite authority, a trusted single gateway and a
cooperative Node egress boundary are assumed. Privileged filesystem control,
multiple uncontrolled gateways, fake finish acknowledgements, lower-level
provider reads/writes, OS/network buffering, application-process compromise,
and existing normal upload/download/sync/backup/WebDAV/cloud paths are not
fully fenced. A stalled worker deliberately blocks reservation; a future
independent liveness/reconciliation design must prove its termination before
release. The protocol's complete QUIESCING/STOP_REQUESTED and distributed
fence acknowledgement phase is **still absent**. The two recovery paths and
multi-provider migration remain incomplete as in the earlier sections.

**Status hints in HTTP responses are not protection grants.** The Ed25519
receipt/nonce/floor, exact signed public manifest history and current epoch
must still be verified independently by a client or an actual protected-content
admission gateway.

## Remaining security boundaries: NOT COMPLETE

1. **Independent authority**: tests use different OS processes and TLS signing
   identities, but not separately operated hosts, hardware trust roots,
   non-rollbackable external high-water or independent key custody. Coherent
   rollback of *both* SQLite and local anchor is outside the current defense.
2. **Crash operations**: the fail-closed exclusive `.append.lock` may require
   verified operator recovery if its owning process dies; never delete a lock
   solely based on its age. A prepared intent without a manifest on the CAS
   host requires an exact authorized caller retry (or separately engineered
   reconciliation); it does not permit a contradictory cancellation.
3. **Physical protected-content fencing**: existing Root.ark upload/download,
   backup/restore, WebDAV, sync, S3 and Google Drive paths are **not** gated by
   this CAS/witness protocol. A signed witness head alone cannot quiesce E/S,
   enforce versions or revoke already known plaintext/key material.
4. **Client migration**: the existing experimental opaque browser vault and
   public signed history are not yet one complete `zk-1` keyring/file client.
   Migrating legacy encrypted/plaintext/backup/remote data is not complete.
   Legacy routes were preserved and **no real storage was mutated**.
5. **Server administrator threat model**: the Root.ark browser application
   presently serves JavaScript from the server; a compromised server replacing
   client code remains a supply-chain/plaintext-exfiltration threat until
   independently trusted application-code delivery is addressed.

## Verification

The following counts are **historical snapshots at distinct worktree states**;
do not combine them as one acceptance run. After the additional bootstrap
patches, the bounded witness/CAS/bootstrap tests passed **33/33**, with zero
failures/skips; the separate CAS/content/browser/mTLS focused suite passed
**20/20**, both on disposable synthetic fixtures. The full repository suite,
syntax validation and artifacts/diff checks must be reported at their actual
new results below; previous full-suite results are not evidence for this
exact latest worktree.

For this latest worktree, all discovered `test/issue-65-*.test.js` files plus
the Packet B mock lab finished **241 passed, 0 failed, 0 skipped** (`node
--test --test-concurrency=4 --test-reporter=tap`, exit 0; log:
`rootark_issue65_focused_latest_20261021.log` in the machine's temporary
folder). `npm run validate:syntax` checked **294 files / 0 failures**;
`npm run validate:artifacts` and `git diff --check` exited 0, apart from
existing line-ending warnings. PostgreSQL integration remains unprovisioned
and is **not** counted as a successful database-backed acceptance test.

- Focused durable CAS + witness suite: **31 tests passed, 0 failed** immediately
  after deadline/intent fixes; subsequent CAS/witness client additions have
  their own real-mTLS integration checks. Individual integrated `node:test`
  tests contain multiple adversarial assertions.
- Latest `node --test --test-concurrency=4 --test-reporter=tap`
  `test/issue-65-*.test.js` plus `lab/issue-65-packet-b/mock-packet-b.test.js`:
  **234 passed / 0 failed / 0 skipped (exit 0)** on the earlier pre-bootstrap-fix source.
- Earlier `npm run validate:syntax`: **284 checked / 0 failed**. Both
  `npm run validate:artifacts` and `git diff --check` exited 0. Two pre-existing
  CRLF-to-LF warnings were emitted by Git; no file content was discarded.
- The full repository suite **was rerun after the bootstrap corrections**:
  `npm test` (`node --test`) reported **1,816 tests; 1,749 passed; 0 failed;
  67 skipped; exit 0**. The report is stored at
  `rootark_issue65_post_bootstrap_full_20261021.log` in the machine's temporary
  directory. Skipped tests include unprovisioned optional PostgreSQL lab runs;
  skipped tests are never represented as passed. This result verifies the
  current local test snapshot, **not** complete #65 acceptance or remote CI.
- A bounded independent reviewer confirmed earlier P1/P2 issues and their
  remediations and then reported **no confirmed P1/P2 within the bounded
  CAS transaction/anchor/witness-client files** after the latest fixes.
  This finding is not a full threat-model review or issue-level acceptance.

## Conclusion

**Partial implementation, issue #65 OPEN.** The signed protocol authorities
are usable as development components with single-node, single-operator
limitations. The issue cannot be declared complete or merged until its actual
protected content I/O, client, recovery, migration, independent trust, CI and
adversarial acceptance criteria are met.
