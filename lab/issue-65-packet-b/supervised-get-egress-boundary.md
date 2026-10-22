# Root.ark #65 — disposable supervised GET/egress physical STOP lab

**Status:** `LAB_ONLY_NON_AUTHORIZING` — single-host research evidence, not a protected-content endpoint or release gate. The Packet B provider-neutral proposal remains unapproved. The scope of this milestone is limited to four new implementation/test files plus this report.

Run from the worktree with a cached Docker Official PostgreSQL 18 image, running Docker Desktop, and WSL Node 22 available:

```powershell
node lab/issue-65-packet-b/run-supervised-get-egress.js
```

The runner creates its own labeled PostgreSQL 18.6 container with a loopback-only random port, loads `db/zk1-gate-authority.sql`, provisions separately named disposable login credentials for the gate and STOP roles, and runs the *same* targeted tests under native Windows Node and WSL Node 22. Cleanup accepts only the exact created Docker container ID plus both labels. No persistent container, network route, migration, key, production credential, application server or deployment is needed.

## What was physically exercised

The **local parent** owns a pinned Ed25519 host signing key and the actual `ChildProcess` handle. It first verifies its PostgreSQL gate login has the restricted `zk1_gate_runtime` privileges and that its STOP recorder was independently preflighted with the separate restricted STOP login. The local fixture supplies a fresh account ID, compartment ID, keyring ID, generation-bound revision/digest, synthetic device-fingerprint-shaped principal, object ID, and worker ID. The parent calls the **actual** PostgreSQL `get` admission with the scope and supervisor-owned host key ID, process epoch and process PID; the gate commits the exact admission and verifies its current generation. A foreign scope, malformed action/identity, privileged gate pool, unverified recorder or disconnected gate fails before the child can listen.

The parent starts a **separate, directly owned Node child** with a stripped environment. Only that child binds `127.0.0.1` and owns the actual HTTP response socket. A one-shot random fixture token selects the authorized local test client; the token itself grants no permission on the gate or product service. The child has no database credentials, real content, storage adapter or private STOP key. It accepts only `GET /fixture-ciphertext`. Before starting its first 16 KiB of fresh synthetic random bytes, the child requests a parent-side admission recheck. The only allowed continuation after the initial partial response also rechecks the same exact admission and live SQL generation. There is no proxy or production GET code change.

Tests use a **real loopback TCP client** that receives a nonzero prefix, pauses its `IncomingMessage`, and leaves the child HTTP response open with another 16 KiB deliberately withheld. `beginQuiesce` durably closes admission at generation `g+1` while the old direct child is still alive. A late GET attempt is rejected, old-generation replay returns `proceed:false`, further continuation is rejected, and premature `FINISHED` and `PENDING` attempts fail. Only after the supervisor stops this exact owned process and observes **both operating-system `exit` and `close`** does it sign the scope/admission/generation/PID/epoch proof. The separately restricted STOP role durably records the signature; the gate re-verifies it and permits `FINISHED`, then `PENDING`. The test then resumes reading the original socket and acknowledges partial bytes emitted **before** the stop; a new connection to the old port fails. A separate adversarial test applies `SIGKILL` while a streaming response is partial and confirms that recovery still requires the original OS child handle to have closed. Both native Windows and WSL Node 22 exercise real PostgreSQL 18.

## Strict limits; remaining blockers

This proves only that, for this fixture, the exact directly supervised Node HTTP listener and its owned response process have stopped before the recorded terminal transition. It does **not** prove that the TCP peer did not consume or subsequently receive kernel, TCP or application buffers emitted earlier. It cannot recall bytes already delivered. A PostgreSQL generation check and a later Node `response.write` are **not atomic**: a grant may race `QUIESCING` before the supervisor kills the child. The test does not prove an exact zero-byte emission boundary at the SQL commit instant. STOP completion blocks `PENDING` until the directly owned process is closed, but the supervisor does **not** control process descendants, kernel socket buffers, other hosts, cloud providers, independently managed gateways or future processes after supervisor restart.

There is **no independently verified active/revoked device identity** here: the synthetic fingerprint is trusted fixture data, not authenticated device approval, fresh external witness authority or signed recovery status. The local SQL gate and separate SQL STOP role reside on one disposable PostgreSQL instance and are not independently administered availability domains. No production storage reads, signed client responses, browser security, TLS/mTLS, remote GET, migration, multi-host fencing, failover or transfer-provider acceptance is established. The fixture token is not a production authorization mechanism. The program is not imported by normal Root.ark server/storage routes.

Production protected GET remains **blocked** until an independently accepted fresh-head and active-device admission is connected to a selected provider's actual content read and egress effect boundary. A production egress broker must close the write-vs-gate linearization gap, prove its worker/process and descendants or external effects have stopped, reconcile after host restart, and handle socket buffering honestly. If this cannot be proven, the protected endpoint must refuse transfer; this lab does not grant an exception.

## Durable quiescence / lost-ACK reconciliation follow-up

A real disposable PostgreSQL adversarial regression injects a lost reply
**after** the scope's QUIESCING/generation transition committed. Before the
fix, the parent set `stopping=true` but left `phase=listening`, rejecting
even an identical retry and stranding its local STOP workflow. RED:
4/5 PASS, 1 FAIL. The controller now copies and pins the full operator-only
scope, revision, digest, operation ID and reservation ID on the first
quiescence call. It continues to reject all new GET grants or response
continuations while confirmation is uncertain. An identical retry
re-reads the authoritative PostgreSQL transition idempotently; any changed
reservation or operation ID is rejected. Successful reconciliation permits
STOP of the *same* physically owned child, independently signed exit+close
evidence, FINISHED and PENDING. Concurrent identical retries share the
same in-flight request, never a new reservation. GREEN: real local PG18
GET/egress lab **5/5 PASS** on native Windows and **5/5 PASS** on WSL
Node 22; verified disposable container cleanup.

This closes an availability/replay corner in the **local synthetic
controller only**. It does not make a PostgreSQL gate-read and a TCP
`response.write` atomic, authorize real protected GET, prove buffers were
un-sent, or establish durable supervisor identity after a host restart.

## 22 October — physically sealed ciphertext GET read adapter

The opt-in `Zk1SharedPgSealedGetReader` makes the same isolated listener send
**actual PostgreSQL-persisted and SEALED ciphertext**, byte-for-byte, when a
trusted local operator supplies the exact expected ciphertext-root commitment.
It is still a development fixture, not a product GET route. It refuses a
privileged application/admin connection at preflight, requires a strictly
STOP-attested scope, and transactionally locks the shared PostgreSQL head while
checking current `OPEN` phase, revision, digest, generation, scope and keyring,
the exact active GET admission and physically supervised host-key/PID/epoch,
and the immutable sealed object's expected root. The two bounded 16 KiB chunks
are selected from the real `ciphertext_chunk` table. The egress child has no
PostgreSQL credentials and only receives the authorized ciphertext frames over
supervisor-owned IPC. Malformed frames cause child termination.

An independently instantiated gate connected through a separate PostgreSQL
pool commits `QUIESCING` while an actual TCP client holds a partial ciphertext
response. The original child cannot receive the second frame, and a signed
STOP receipt for the exact OS child remains mandatory before `FINISHED` and
`PENDING`. A wrong operator-provided root results in HTTP 503 with zero content.
The partition test closes the egress operator's PostgreSQL pool after its first
frame, then uses the surviving gate and independent STOP recorder to finish the
original in-flight admission. No positive continuation is possible from the
disconnected pool.

**Security boundary:** The expected ciphertext-root commitment is supplied
by the *trusted fixture operator*; this module does not independently verify
an owner signature, authenticated device, signed witness head, CAS monotonic
floor, epochs, revocations, replay ledger, fresh external reservation or
independent approval proof. A real client cannot treat this adapter as a
protected GET endpoint. The second gate instance models a remote host using
a separate pool but runs in the same test process and availability domain.
PostgreSQL row-lock release happens before the socket write. A cross-host
`QUIESCING` commit can therefore race a previously granted frame, and already
buffered TCP ciphertext can remain deliverable after physical STOP. There is
no multi-host supervisor reconciliation, mTLS GET endpoint, remote provider
read, foreign-host physical process attestation or failover guarantee.

## 22 October — optional independently signed owner/CAS quorum on supervised GET

The separately constructed `Zk1SharedPgWitnessCasEgressGuard` extends this
disposable **development-only** GET experiment. Its authority inputs are an
externally pinned SHA-256 of the owner's Ed25519 SPKI bytes, the matching
owner-public SPKI, the exact owner-signed ciphertext-root checkpoint, the
linked signed owner manifest-history checkpoint, the operator-pinned expected
scope/revision/digest/epoch/root, and a fixed CAS witness floor.

At setup the guard imports the operator-pinned public key, checks its digest,
verifies the full owner history and ciphertext-root signatures using the
existing browser-compatible verification helper, binds a snapshot of the
signed root, and checks a fresh nonce-signed remote CAS witness head using
an **independently configured mTLS client** with CA, TLS fingerprint, witness
Ed25519 key and witness/status key IDs. Every GET launch and both physical
ciphertext frames then require another pinned, fresh witness signed head plus
the existing PostgreSQL `OPEN`/generation/admission/readback checks. Any CAS
floor advance, wrong root, changed epoch-linked owner proof, wrong SPKI pin,
TLS peer swap or disconnected witness closes authorization before the next
frame. The gate's physical STOP, independently signed OS `exit`+`close`
receipt and `PENDING` drain remain mandatory after a failed transfer.

The adversarial test uses a **real separate Node OS process** running the
existing `Zk1WitnessCasAnchorFloor` on a private SQLite journal and real
mTLS listener. This process owns the witness signing key. It accepts only a
separate scoped service certificate to request nonce-bound signed CAS heads;
the principal is never granted a recovery/IO role. A legitimate CAS signed
journal append advances that floor and fences the paused TCP GET response.
Bad SPKI, tampered owner signature, wrong object/scope/revision/root, lost
witness process and changed floor are tested. Fixture TLS certificates, owner
keys and SQLite journals are temporary and deleted after the test.

**Remaining security limits:** owner SPKI digest and expected CAS floor come
from trusted fixture provisioning, not an established production owner
enrollment or distributed key-rotation protocol. The test runs separate
processes and distinct PostgreSQL roles/pools but not separately administered
machines, TLS GET/PUT gateway nodes, or independent disaster-recovery zones.
The witness floor is a **global monotonic change fence**, not a positive
signature authorizing a specific device. Signed, active-device/revocation
history, signer epoch membership, witness/CAS terminal-status agreement,
external anchor persistence after compromise, bounded authorization lifetime
and product GET/PUT routing are outside this step. The socket write still
occurs after PG commits/row locks are released; a grant could race a STOP
before the next mTLS/SQL check. Bytes already issued may remain buffered in
the OS or network. **This does not establish zero-byte egress atomicity or
authorize production use.**

Local dependency limitation: the workstation's WSL Node 22 resolves the
Windows-compiled `better-sqlite3` addon (`invalid ELF header`); the three
new cross-process SQLite witness cases automatically skip if native SQLite
cannot open. The original eight PostgreSQL egress/STOP cases remain active.

## 22 October — mandatory quorum for all hardened physical GETs

The normal `new Zk1LabSupervisedGetEgress(...)` constructor now **rejects**
an absent/null/forged `Zk1SharedPgWitnessCasEgressGuard`, including when the
caller provides a valid `Zk1SharedPgSealedGetReader` and a matching persisted
ciphertext root. Hardened construction also requires both that reader and the
expected root. Arbitrary caller flags (`allowUnverified`, `legacyLabMode`,
`unsafeLegacyLabOnly`) cannot bypass the check. The private mode flag cannot
be changed through a writable public property on an existing instance. The
fresh, owner-SPKI-bound remote mTLS witness check remains mandatory before
opening a child listener, before first ciphertext-frame authorization and
before the final TCP frame. An absent or partitioned witness fails closed.
Once a signed witness check fails, a private process-local fence permanently
blocks additional grants even if connectivity returns or a caller toggles
public state. Only quiescence and the independently observed physical STOP
workflow may finish the in-flight admission.

To keep historical local transport experiments reproducible, tests that
intentionally transfer **synthetic random bytes** or directly read PostgreSQL
without independent witness must call the distinct and explicitly dangerous
`Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture(...)` entry point.
This explicit opt-in factory is strictly **test/lab-only**; it is not accepted
by hardened construction, not a device-grant mechanism, and must never be
mounted behind a production route. It refuses a simultaneous `quorumGuard`
instead of silently downgrading a previously authenticated guard.

The hardened and synthetic paths retain physical process STOP/`FINISHED` /
`PENDING` requirements. Continuation is additionally serialized: overlapping
callbacks cannot both issue the second ciphertext frame across asynchronous
PostgreSQL/witness reads. The regression suite compares constructor behavior
against the published vulnerable baseline (RED) and verifies the corrected
constructor (GREEN), alongside multi-client continuation and real paused TCP
client witness-partition/STOP adversarial fixtures.

**Still a DEV-only boundary:** this change does not make the PG row-lock and
network write atomic, confer positive current-device/revocation provenance,
prove independent cloud/CAS service custody, or protect bytes that were already
buffered before QUIESCING/STOP. Fail-closed admission is necessary but is not
a production-ready end-to-end protected GET authorization.
