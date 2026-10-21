# Root.ark #65 — strict single-process STOP receipt, signed host evidence and distinct SQL roles

**Date:** 2026-10-21
**Scope:** disposable, experimental PostgreSQL 18.6 lab only. **No production activation.**

**Subsequent correction:** This document records the initial **26/26** STOP
lab baseline. The independent conditional P2 (compromised STOP SQL login
forging arbitrary raw proof bytes) was subsequently reproduced in RED and
mitigated for the normal trusted GateAuthority route by **independent pinned
Ed25519 verification at FINISH and PENDING**. The later **27/27** real-PG
verification and surviving raw-SQL collusion limitations are recorded in
`2026-10-21-rootark-issue65-strict-physical-stop-evidence.md`. Do not read
the earlier count or threat-boundary paragraph below as the latest verdict.

## Problem and change

The isolated PostgreSQL data-plane login `zk1_gate_runtime` previously could
directly mark a worker `FINISHED` and advance QUIESCING to PENDING without
actual STOP, even after the monotonic head trigger. An independent reviewer
reproduced that restricted-login SQL attack. Physical PostgreSQL writes after
QUIESCING were already fenced, but a reported drained worker was not proof.

The new **opt-in** `zk1_gate.head.require_stop_proof=true` mode requires a
separately recorded STOP receipt before admitting the worker's FINISHED state
or permitting PENDING. It binds a fresh, supervised host public-key ID,
16-byte process epoch and actual OS process PID to the worker's admission at
START, and those fields are immutable in the database. Existing reference
non-strict scopes remain explicitly experimental; do **not** configure them
for normative ZK-1 operation. No migration of preexisting user scopes occurs.

The bounded host-supervisor prototype owns the OS `ChildProcess` handle and
Ed25519 private key in its own process. It launches a **single disposable
Node child**, does not inherit the gate/STOP database credentials, and
signs a canonical CBOR `rootark-zk1-physical-worker-stop/v1` receipt only
**after both actual child `exit` and `close`** have occurred. The receipt
authenticates the exact compartment/account/keyring, worker/admission,
principal, generation, process epoch/PID, host key and bounded stop timestamp.
Concurrent STOP requests share one in-flight termination/signature promise;
lost-ACK retries return the **identical** signed wire bytes.

`zk1_stop_runtime` is a **separate, NOLOGIN, non-superuser restricted role**.
The disposable runner provisions a new random stop-recorder login that
inherits only that role, not `zk1_gate_runtime`. Runtime checks reject
shared, privileged or over-granted identities. The gate login cannot insert
STOP receipts; the STOP login cannot insert ciphertext, alter the head phase,
or finish an admission. The STOP recorder validates the pinned Ed25519 proof,
its freshness, the exact worker/process tuple, and inserts the immutable
record under the same PostgreSQL head row lock. The gate's physical SQL
trigger requires that record before permitting FINISHED, and PENDING
requires all workers completed. A lost receipt acknowledgement can replay
the exact persisted wire even after PENDING.

## Evidence and attacker bounds

- Synthetic RED before the strict SQL enforcement: a restricted gate login
  could forge FINISHED then advance PENDING; after enforcement raw SQL
  FINISHED/PENDING without a STOP record is rejected.
- Verified genuine single-child OS exit/close, Ed25519 pin/worker/epoch/PID
  binding, timestamp/signature tampering, malformed proof denial, exact
  replay, concurrent STOP requests and zero admission-before-bind proofs.
- Verified a second restricted stop SQL login cannot mutate phase or write
  ciphertext; and the first gate login cannot insert STOP evidence.
- Verified distinct PID/epoch at START cannot reuse the same admission;
  recorded STOP PID/epoch must exactly match the immutable admitted values.
- Disposable PostgreSQL 18.6 runner **26/26 PASS** with zero skipped/failing
  tests and identity-verified cleanup; signed-proof Node unit suite **4/4 PASS**.

## Guarantees explicitly NOT provided

The **two SQL roles and signed host receipt are independent only if their
credentials and signing key truly remain isolated**. PostgreSQL verifies
identity/epoch/hash and writer privileges, but does **not** cryptographically
verify Ed25519 inside its SQL trigger: a fully compromised **STOP SQL role**
can insert fabricated raw wire with matching SHA-256 bytes. A compromised
host supervisor with the Ed25519 private key can also lie. This remains a
trusted external STOP-attestation boundary, not an independently verified
hardware-root proof or general malicious-host-resistant distributed fence.

The supervised worker fixture has **no descendants, provider requests,
unreaped handles or network egress**. `ChildProcess` exit/close says nothing
about child-created OS descendants, remotely buffered TCP bytes, asynchronous
provider operations or a worker on another host. There is no verified real
multi-host STOP transport, replay-proof host enrollment, cross-provider
generation control, quorum/anti-rollback authority, normative owner signature
binding, safe GET/egress adapter or migration of existing files. The PG
PENDING gate remains fail-closed without a separately proven signed terminal
resolution. Those are material issue #65 acceptance blockers.

No push, merge, deployment, live key custody or real file mutation occurred.
