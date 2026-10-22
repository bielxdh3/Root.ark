# Issue #65 — CAS ↔ independent witness signed floor (2026-10-22)

## Scope and authority

This development increment binds the locally signed CAS terminal journal to a
separately owned witness floor. It is not a proof of production deployment,
independent key custody, or remote object durability. The PR stays DRAFT; no
merge or deployment is part of this increment.

* `Zk1WitnessCasAnchorFloor` owns a distinct SQLite database configured with
  WAL, `synchronous=FULL`, and signed, contiguous, canonical Ed25519 terminal
  events. It rejects gaps, forks, unsigned heads, non-identical replays,
  tampering and locally observed rollback. Every signed head lookup checks a
  consistent read snapshot against immutable process-pinned evidence for **all**
  historical rows; corrupting an earlier SQL row without touching the final
  head must not produce a fresh witness signature. A single framed streaming
  SHA-256 chain binds the full snapshot without storing per-row private hashes.
  Duplicate or non-increasing sequences within one advance batch are rejected
  before a durable write; an identical sequence may be retried in a new call.
* `Zk1WitnessCasAnchorHttpsClient` uses pinned TLS 1.3 mTLS, a pinned witness
  signing identity, and a fresh 32-byte nonce for signed floor lookup. An HTTP
  successful `/advance` response alone is **not** an authoritative receipt;
  the CAS must fetch and verify an independently signed fresh floor.
* Witness HTTPS accepts `/v1/cas-anchor/head` and `/v1/cas-anchor/advance`
  only for an exclusive `cas-anchor` mTLS principal. Existing content roles
  cannot obtain this capability.
* The CAS status ledger checks/reconciles the independent floor at reservation,
  commit and protected read boundaries. Interrupted or lost ACK commits are
  reconciled from signed records rather than interpreted as durable network ACK.
* The CAS terminal journal signs the `witnessRequired`/`witnessKeyId` genesis
  policy in strict mode. Editing the mutable SQLite `cas_anchor_witness_required`
  marker alone cannot downgrade a previously strict CAS into legacy mode.
* The witness standalone requires an explicit owner-retained
  `casAnchorFloor.trustedMinimumHead`, supplied **outside** its own database,
  before starting the floor. A validly signed old SQLite prefix below this
  minimum is rejected. The CAS standalone obtains the fresh witness head
  before reopening strict local CAS state for writes.

## Local evidence

On this worktree after the strict genesis and standalone patches:

* Nine relevant test files covering CAS/witness HTTP, terminal anchor, status
  ledger, independent floor, and both standalone processes: **36 PASS / 0 FAIL**.
* Additional adversarial RED→GREEN test: modifying historical SQL sequence 1
  while the signed high-water sequence 2 remains intact initially allowed the
  witness to sign an inconsistent floor; the per-row pinned evidence check
  now rejects it. The four new test files ran **8 PASS / 0 FAIL** afterward.
* Further RED→GREEN: a duplicate valid signed record repeated *inside the same*
  advance batch originally desynchronized the in-memory digest after SQL commit;
  duplicate batches now fail before insertion, and the five dedicated floor
  tests pass after the fix.
* `npm run validate:syntax`: **400 checked / 0 failed**.
* `npm run validate:artifacts`: **exit 0**.
* `git diff --check`: **exit 0**.
* The disposable real PostgreSQL 18 fixture previously ran **67 PASS / 0 FAIL**
  with verified cleanup, before this independent CAS-witness increment.

Full-suite and independent final P1/P2 audit results must be recorded from
their actual executions; earlier PASS results cannot substitute for them.

## Trust and recovery limits

* CAS SQLite/WAL, CAS journal and witness SQLite are **not** one atomic global
  transaction. Recovery uses signed journal events and verified fresh heads;
  local fsync alone does not prove independently retained bytes.
* The witness owner's minimum must be **advanced and preserved independently**
  of witness storage, and the CAS must possess an independently pinned
  continuity floor. An editable, co-located JSON config is not independent
  custody. Simultaneous rollback of every trusted store and its external
  owner checkpoints cannot be detected cryptographically by these local files.
* The CAS signer private key and witness signer private key require distinct
  custody; compromise of the signer defeats its signatures. The strict signed
  genesis specifically mitigates SQLite-marker-only downgrade, not key theft.
* This is CAS **history anchoring**. It does not implement distributed physical
  STOP fencing for remote egress or establish provider-side durable retention.
  Separate end-to-end authorization/restore/client/multi-host requirements of
  issue #65 remain development work, not production release gates.
* Throughput at the witness's 100,000-event valid upper bound requires special
  consideration: synchronous full-snapshot checking can block the Node event
  loop for hundreds of milliseconds per fresh receipt. The current complete
  verification is intentionally fail-closed; asynchronous isolation / bounded
  servicing is a follow-up needed before claiming high-volume availability.
