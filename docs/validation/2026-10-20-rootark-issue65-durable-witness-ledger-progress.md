# Root.ark issue #65 — isolated durable witness engine follow-up

Date: 2026-10-20 (America/Porto_Velho).
Branch: `cdx/rootark-dual-recovery-20261019`.
Baseline HEAD: `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`.

## Bounded implementation

`src/services/zk1DurableWitnessLedger.js` adds an **isolated, opt-in
SQLite-backed witness state-machine engine**. It is not mounted into
`server.js`, and no keys, external providers, real accounts or user
files are created or migrated by it. It requires separately supplied
Ed25519 witness signing credentials, a distinct pinned CAS-status
Ed25519 verifier identity, a terminal-status provider callback and
explicit first-time bootstrap. The signing key is not persisted in the
database. A missing state file without explicit bootstrap, absent
identity row, mismatched key ID/public fingerprints, or shared
signing identity fails closed.

- Signed canonical v1 reservation tickets bind the exact keyring,
  expected and proposed heads, IDs, request/package digests and expiry.
  A durable reservation closes the witness gate in a SQLite immediate
  transaction **before returning** its ticket.
- A different request while pending is rejected. A lost-ACK retry of the
  **byte-identical signed ticket** returns the original receipt under
  the transaction lock without appending duplicate events.
- Direct caller-generated fresh-head nonce is bound into a signed v1
  response. A pending reservation returns `pending` (never an
  acceptable committed head). Concurrent reservation during signing
  causes the signed candidate to fail an immediate, serialized
  last-head check with `WITNESS_GATE_CHANGED` instead of issuing
  an already stale committed receipt.
- `resolve` requests a **new, witness-generated nonce** from a
  configured CAS-status authority callback and verifies strict
  deterministic CBOR, Ed25519, pinned key, nonce and the complete
  original reservation query. The callback is passed independent
  cloned buffers to prevent mutation of the verified challenge or
  reserved head. The signed proof's `observed_at` must fit the
  30-second skew bound. Final non-commit cancellation requires
  expiry + 30 seconds, and initialization cancellation leaves a
  persistent no-reinitialize tombstone. Invalid/unavailable proof
  keeps the pending gate closed.
- SQLite WAL+`synchronous=FULL` retains signed immutable
  reservation, commit and cancellation events. Every witness
  fresh-head read reconstructs/validates the per-scope journal
  signatures and state; missing reservation/terminal rows fail closed.
  Reservation insertion reserves capacity for **both** itself and the
  terminal event. An exhausted ledger refuses new reservations
  **before** closing the gate. Ticket validity is rechecked under
  the final write transaction after asynchronous signing.

## RED→GREEN evidence / independent review

`test/issue-65-durable-witness-ledger.test.js` uses only disposable
SQLite paths and ephemeral test keys. It covers restart/pending
barrier, trusted signed status, forged status rejection, revoked
initialization, key separation/bootstrap, sequential revisions, lost
ACK, corrupted journal, competing SQLite handles, stale committed
head during signing, untrusted transport mutating nonce and signed
head digest, stale signed `observed_at`, ledger exhaustion and
expiry during signature generation.

An independent read-only worker reproduced **three P1 source faults**
in the original new component (signed committed head after pending
reservation; untrusted callback nonce mutation; untrusted callback
proposed-digest mutation), plus **P2** event-capacity and expiration
insertion races. All were corrected with observed RED→GREEN tests.
A lost-ACK retry regression was also fixed after it failed on the
original implementation. The bounded final review reported
**0 confirmed residual P1/P2 in the reviewed witness engine paths**.
The focused test module passed **15/15** at the review checkpoint;
the additional freshness/capacity/ACK regression set is included in
the subsequent final exact run below.

## Limitations — not issue #65 closure

This is a reusable **engine**, not yet a separately operated witness
service, not a selected trust-root/certificate/transport deployment,
not a cross-host CAS or CAS-status authority, and not a physical
storage/egress admission gate. A full coherent rollback of its local
SQLite database cannot be detected without a separate independent
monotonic anchor and direct validated fresh witness reads. Its
serializing `freshHead` check only linearizes *issuance*; it cannot
serialize protected I/O admission with the application storage
provider when there is no connected gate. The signed status provider
must be operated independently and truthfully; a compromised CAS
status signing root defeats terminal-proof trust.

No data-plane operation should treat an emitted witness receipt as
authorization by itself; no default app route uses this engine.
The larger #65 remains open pending selected multi-operator topology,
shared CAS/terminal fencing, physically enforced gateway/storage
epoch fences and crash/failover validation, client secure key custody,
full-device client workflow and reversible legacy migration.

## Exact scoped validation after final witness corrections

- A further RED→GREEN regression confirmed lost reservation ACK recovery:
  exact re-submission after restart yields the original signed ticket
  without duplicating events; a different request digest remains
  `WITNESS_PENDING`. Independent READ-ONLY review after this change
  found **no confirmed P1/P2 in this bounded component**.
- `node --test test/issue-65-durable-witness-ledger.test.js`:
  **15/15 passed**, 0 failed, exit 0.
- All `test/issue-65-*.test.js` plus Packet B mock:
  **Windows 216/216 passed, 0 failed, 0 skipped**; **WSL 214 passed,
  2 Windows-Edge-only skipped, 0 failed**; both exited 0.
- `npm run validate:syntax`: **271 checked, 0 failed**, exit 0.
  `npm run validate:artifacts` and `git diff --check` both exited 0
  (two preexisting line-ending warnings from tracked Markdown files).
- The earlier single unsplit repository test run
  (`node --test --test-concurrency=2` all `test/*.test.js`) was
  **1,697 passed, 57 skipped, 0 failed** BEFORE this new witness
  component was added. It remains historical evidence and does NOT
  count as an exact-final-candidate full release gate.

These are local engineering tests with synthetic keys and disposable
storage, **not** proof of service-process/operator independence or
an exact SHA CI gate. The code and all earlier authorized uncommitted
work remain preserved in the existing isolated worktree. No release,
merge, issue closure or change to live legacy data has occurred.
