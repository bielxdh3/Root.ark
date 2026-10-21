# Root.ark #65 — local witness QUIESCING milestone

**Date:** 2026-10-21
**Base commit:** `543fa6f`
**Status:** DEVELOPMENT-ONLY / PARTIAL — **not** a distributed GateAuthority or release acceptance

## What changed

The independently startable development witness now has a pre-reservation
`prepareQuiesce(operation)` that stores an **exact canonical operation** in
`witness_quiesce` under the same SQLite immediate transaction ordering as
I/O admission start/finish and reservation. It accepts only a previously
committed, exact expected head; genesis cannot quiesce. The existing mTLS
`reserve` role and scoped principal ACL also control `/v1/quiesce`.

The first quiescence operation closes the gate even with **zero active** I/O
workers. While this marker exists, `beginIoAdmission` refuses all new starts,
and `freshHead` refuses to sign a committed receipt, including when quiescence
begins between signing and the final SQLite write-locked check. Existing I/O
workers can finish through their existing authenticated mTLS binding. Only a
reservation with the **byte-identical operation**, after **all active workers
have finished**, atomically removes QUIESCING and records the normal signed
PENDING reservation. Other operations are rejected. A restart does not clear
QUIESCING or reissue the prior committed head. No v1 signed wire message is
changed; QUIESCING/DRAINED is a local mTLS JSON control response only.

An authenticated, exact idempotent retry of a worker whose START was **already
durably admitted before QUIESCING** may retrieve its original admission ID.
Its mTLS response carries `proceed: false`: the protected-content gateway must
**finish** that existing worker without emitting content. New workers always
remain denied. This repairs a lost START ACK race that previously stranded an
ACTIVE record with no known completion ID.

A bounded independent review confirmed a **P2 availability flaw** in the
first version: quiescence with an expired operation stranded the scope. The
repair provides **explicit** `cancelExpiredQuiesce` via an mTLS reserve-scoped
endpoint. It must match the stored exact operation and existing verified head;
under the same SQLite immediate lock, at least 30 seconds must have elapsed
after the operation deadline and **no worker may remain ACTIVE**. Only this
pre-ticket gate may be aborted: while the marker exists no signed reservation
was issued, so this is **not** a CAS terminal-status cancellation. No timer
silently releases the gate and no v1 signed wire protocol changes.
The same cancellation transaction records a per-scope persisted **clock
high-water**; future reservations, admissions, quiesce starts and witness-head
issuance reject a clock earlier than that floor. This prevents an expired
aborted operation from issuing a new ticket simply because a local clock was
rolled back. It does not establish an independently trusted, non-rollbackable
hardware clock or an external high-water service.

## Verified boundaries

- TDD observed RED for absent `prepareQuiesce`, then GREEN for durable
  quiescence, restart, exact reservation binding, pending transition, wrong
  operation denial and withheld committed heads.
- A second RED proved that an initial zero-active `DRAINED` response did not
  prevent a worker from entering before `reserve`. It was repaired by
  persisting the pre-reservation marker **even for zero active workers**.
- Synthetic race interleaves a quiescence write after a committed head has
  been signed but before issuance; it is denied before any receipt returns.
- Real mTLS listener/client tests cover quiesce, withheld heads, new-worker
  denial, drained reservation, cross-keyring rejection and explicit expired
  cancellation. RED/GREEN cancellation tests cover early, unrelated operation,
  active worker and crash/restart scenarios.
- The first pre-repair issue-65 suite was **246/246**; it is historical, not
  sufficient validation of the later expiry repair. After the first expiry
  fix, the issue-65 suite passed **248/248**. After the further lost-ACK and
  clock-floor fixes, the latest issue-65 suite plus the Packet B mock passed
  **249/249**, 0 failures, 0 skips, exit 0; log
  `rootark_issue65_quiesce_repaired_focused_20261021.log` in the host
  temporary folder. Earlier `npm run validate:syntax` checked **295** files
  with zero failures; a fresh final syntax run also checked **295** with zero
  failures, and artifact and diff checks exited zero.
- A bounded independent READ-ONLY reviewer reproduced two P2 availability
  issues (expired quiesce and START ACK loss during quiescence) and the clock
  rollback replay weakness. After the repairs, the reviewer returned **PASS:
  no confirmed residual P1/P2 in this narrow scope**, including a separate
  real-mTLS old-worker retry/finish adversarial probe and a second-connection
  SQLite rollback probe. These results do **not** attest to whole-issue #65
  security or cross-host GateAuthority.

## Still unsafe for production

This is an **individual SQLite witness** with a cooperative, trusted local
gateway; it is NOT the spec's actual independent, shared linearizable CAS gate.
It does not send STOP_REQUESTED or prove a physical worker stop, fence
provider I/O and network egress per chunk, handle separate hosts or replicas,
or enforce normal legacy/backup/sync/WebDAV/S3/Google Drive routes.

An unresolved quiescence intentionally fails closed across restarts. Expired
pre-ticket operations have an explicit, narrowly scoped cancellation path
only when the head is unchanged and all active workers have finished. A
crashed/unreachable worker, lost credentials, compromised reserve principal or
untrustworthy clock may still prevent safe reopening. This work **does not**
supply a cross-host abort/reconciliation protocol, independently trusted owner
authorization for later operations, or independent key custody. Never report
`DRAINED` as a physical stop proof or a usable
fresh-head receipt, and never allow a CAS commit before the ordinary signed
reservation is durably issued.

No real user files were touched; no migration, push, merge, deployment or
issue closure is authorized by this milestone.
