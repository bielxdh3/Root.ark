# Root.ark issue #65 — delegated physical chunk-writer SQL isolation

**Status:** locally tested PostgreSQL 18.6 reference, NOT a deployed
multi-host Zero-Knowledge or remote I/O system.

## Adversarial finding

The first supervised child lab (`7770be4`) received the same
`zk1_gate_runtime` SQL login used by the independent GateAuthority. That
login is allowed to insert `zk1_gate.admission`, update the authoritative
`head`, and physically insert ciphertext. An independent reviewer
reproduced in disposable PostgreSQL that a compromised CHILD holding this
credential could create its own ACTIVE admission and inject staging chunks
while a scope remained OPEN. This is a real P2 child-to-controller privilege
escalation (not a bypass of post-QUIESCING physical fencing).

## Least-privilege correction

- `zk1_chunk_writer_runtime` is a new non-login, non-admin, non-inheriting
  PostgreSQL role. A separate operator-provisioned LOGIN is granted only
  its membership; the gate and STOP SQL logins remain separate.
- This role can SELECT the head, admission and physical ciphertext tables
  to check scope, revision, digest, generation, worker ID and process binding,
  and INSERT limited ciphertext chunks. It cannot INSERT admissions, UPDATE
  head/generation or admission, INSERT SEALED or physical STOP receipts, or
  DELETE/TRUNCATE ciphertext. This is checked against `pg_catalog` by
  `verifyZk1ChunkWriterRuntimePool` before any child write.
- The operator-owned, schema-qualified, fixed `reject_chunk_after_seal`
  PostgreSQL trigger is `SECURITY DEFINER` with pinned
  `search_path=pg_catalog` and no dynamically interpolated SQL. It alone
  locks the authoritative head `FOR UPDATE` during the actual INSERT,
  preserving physical fencing without exposing UPDATE on head to the child.
  Public EXECUTE is revoked on that trigger function.
- In the disposable lab, only the distinct restricted writer URL is
  delivered after trusted START over the exact parent-owned ChildProcess IPC
  channel. The child never inherits the gate or STOP private key/passwords
  in process environment, and still checks exact recorded process, admission,
  revision and generation before physical SQL.

## Tests and status

New `test/issue-65-chunk-writer-role.test.js` checks that independently
provisioned writer-only SQL credentials pass identity validation while
admin, gate and STOP credentials are denied. Attempts to mint an ACTIVE
admission, UPDATE head or INSERT STOP proof fail with SQL permissions.
An actual permitted chunk write succeeds while OPEN and a late write after
QUIESCING is rejected. The existing supervised-child tests still require
physical INSERT under an authoritative row lock and SIGKILL rollback
followed by signed STOP and PENDING.

TDD included RED failures before the verifier and while the writer had no
UPDATE right for PostgreSQL `FOR UPDATE`/`FOR SHARE`; the final fixed
SECURITY DEFINER path passed **34/34** focused tests, **0 FAIL, 0 SKIP** in
Windows Node 24 against disposable PostgreSQL 18.6, with exact labeled
container cleanup confirmed.

## Remaining trust limits

The independent *gate* SQL credential still has broader authoritative
privileges: a compromised gate controller (or DB administrator) could mint
admissions while OPEN. These privileges must never be delegated to a child
or ordinary app. The new writer role limits the CHILD only; it cannot prove
owner/device authenticity, a live CAS/witness head, or anti-rollback.
The lab does NOT authorize existing strict remote HTTPS START/PUT/SEAL/FINISH,
nor guarantee quiescence of remote cloud/S3/GDrive/WebDAV operations,
download/GET egress, descendant processes, buffered sockets, multi-host
partitions or crashed supervisors that lost the original OS handle.

Never run this schema against real production data without independently
approved deployment policy, operator role provisioning and acceptance tests.
