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
- The original role could SELECT head/admission/ciphertext/SEALED globally
  and INSERT chunks directly. A second independent P2 attack exploited this:
  a writer credential enumerated two distinct tenants and inserted a staging
  chunk in an unrelated OPEN object with a legitimate ACTIVE PUT admission.
  The hardened role now has NO raw SELECT/INSERT/UPDATE/DELETE/TRUNCATE on
  shared tables, and cannot mint admissions or STOP evidence.
- A trusted gate operator inserts an immutable `writer_binding` tuple only
  after verified START: one independently provisioned writer LOGIN maps to
  exactly one admission, scope, object, worker, generation, epoch and process
  PID. `session_user` from the actual PostgreSQL authenticated login, not
  caller-provided scope/worker claims, selects this tuple. No binding table
  SELECT is granted to writers. Unique constraints prevent rebinding.
- The only physical writer effect is `zk1_gate.write_bound_chunk(index,bytes)`,
  a fixed SECURITY DEFINER function with no scope/object/admission arguments.
  It checks immutable binding, OPEN/ACTIVE and READ COMMITTED, locks the head
  FOR UPDATE, and inserts into the physical table (which also fires the
  independently maintained post-SEALED/OPEN trigger). An optional exact
  boolean binding verifier leaks no broad table rows. Both routines pin
  `search_path=pg_catalog`, use schema-qualified objects and revoke PUBLIC
  execution. `verifyZk1ChunkWriterRuntimePool` checks this least-privilege
  SQL identity before the child starts.
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

### Additional restricted-login P2: dormant SET ROLE membership

Independent PG18.6 adversarial review found that the original writer
identity preflight tested only `pg_has_role(..., 'USAGE')` for gate/STOP
membership. A login assigned writer privileges and also assigned gate
`WITH INHERIT FALSE, SET TRUE` could pass because direct `USAGE` was false
and then issue `SET ROLE zk1_gate_runtime`. This would restore authority
to mint admissions and mutate the gate. A separate RED regression
`writer preflight rejects NOINHERIT login with SET ROLE access to the gate`
demonstrated an actual falsely accepted restricted login on disposable PG.
The verifier now requires both `MEMBER` and `SET` to be false for the
gate and STOP roles, even if inherited `USAGE` is false. Focused real PG
regression **35/35 PASS**, 0 FAIL/0 SKIP, exact Docker cleanup verified.

### Cross-scope P2 — bounded local remediation

The independently reproduced cross-tenant metadata enumeration/ciphertext
poisoning attack above has a local SQL-specific mitigation: an unbound login
cannot write, direct SELECT or INSERT of protected tables is denied, the
operator cannot rebind the same login to a different active tenant, and the
only delegated write function has no tenant identifier parameter. Physical
post-quiesce fencing is still performed under the same SQL row lock and
transaction as the actual INSERT. This does **not** stop an attacker who
steals the already-bound writer credential from injecting ciphertext into
the one legitimate object's staging area *while that admission is OPEN*.
The separately authenticated owner/device root and sealing process must
detect that manipulation before publication. A PostgreSQL login or signed
STOP receipt does not attest a remote OS process or prove device integrity.

Final local delta validation after the immutable per-login binding and
function-only writer API: disposable PostgreSQL 18.6 **35/35 PASS, 0 FAIL,
0 SKIP**, exact container identity/labels cleanup verified; syntax
**338 checked, 0 failed**, artifact and whitespace checks PASS on the
shared worktree at this point. The bounded test covers a simultaneously
ACTIVE foreign PUT, no raw global SELECT or INSERT, no binding replay to
another admission, the sole bound write, QUIESCING late denial, child
SIGKILL rollback, and independently signed STOP. Tests run on Windows
Node 24 for the PostgreSQL fixture; not a two-host/cloud acceptance claim.
The lab does NOT authorize existing strict remote HTTPS START/PUT/SEAL/FINISH,
nor guarantee quiescence of remote cloud/S3/GDrive/WebDAV operations,
download/GET egress, descendant processes, buffered sockets, multi-host
partitions or crashed supervisors that lost the original OS handle.

Never run this schema against real production data without independently
approved deployment policy, operator role provisioning and acceptance tests.
