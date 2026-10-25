# Issue #65 — opt-in independent multi-witness physical-floor readback

## Vulnerability reproduced and precise trust boundary

Before this change, two different independently pinned mTLS witness clients
could each accept a valid, freshly signed **higher-sequence** CAS/physical floor
whose last hashes diverged. The single-witness verifier checks the same
operator minimum per client, but does not compare views across operator sites.
That is not evidence of a forged signature; it is a missing cross-host
**equivocation veto**. The packet-B threat model requires conflicting witness
views to stop progress rather than silently diverge.

`Zk1IndependentWitnessFloorQuorum` adds an operator-selected, fail-closed
**readback fence**, not consensus or a remote persistent monotonic register:

- Two to four actual `Zk1WitnessCasAnchorHttpsClient` instances are required.
  The peers must have distinct pinned Ed25519 witness SPKI fingerprints,
  16-byte witness signer IDs, mTLS server-certificate fingerprints and HTTPS
  endpoints. All must use the same explicitly pinned CAS status key ID and
  `requirePhysicalAdmission: true`.
- Every check calls each client's **native** `freshHead()` method, issuing an
  independent random nonce over TLS 1.3 mutual authentication with X.509 peer
  pinning, and validating each signed witness physical-floor-v2 response.
  A caller's later override of `client.freshHead` cannot substitute a fixture.
- Every response must have the **exact same** `{ sequence, lastHash,
  physicalFenceDigest }` as the **operator externally retained** input.
  Neither a signature alone, a future sequence, a stale signed prefix, nor a
  CAS-only `{sequence,lastHash}` can update that floor. Unavailable or forked
  peers deny reads; no best-effort single-host fallback exists.
- The existing optional `Zk1SharedPgWitnessCasEgressGuard.establish` can now
  receive this quorum as its `witness`, with a three-field `witnessFloor` that
  agrees with the quorum's immutable enrolled floor. For each subsequent
  `authorize` (including supervised ciphertext GET continuation), both witness
  connections must still prove that exact floor. Existing single-witness
  operator integration remains unchanged.

To advance to a legitimately newer floor, an **independently governed**
operator must first reconcile the signed CAS/physical histories, persist a
new high-water out of band and then construct a new quorum with that value.
This code deliberately has no writable floor store and accepts no server-
furnished trust pins or credentials. On restart/restore, the externally
retained high-water must be supplied again. An attacker who can roll back the
operator's external state together with every witness cannot be detected.

## Evidence boundaries

`test/issue-65-independent-multihost-witness-floor.test.js` uses two real,
separate loopback HTTPS servers, native OpenSSL CA/client/server certificates,
mutual TLS and **two independently generated Ed25519 witness signers** with a
shared CAS status key ID. Their signed floor responses are synthetic, **not**
PG readbacks. The test shows both valid differing sequence-5 signed replies
individually pass a sequence-4 minimum, but the new quorum rejects the fork;
it also covers exact-match readback, signed rollback, unilateral advance,
minimum downgrade, explicit operator re-enrollment after a later floor,
reused authority, absent second host, override attack and a genuine
owner-signed-root-backed `Zk1SharedPgWitnessCasEgressGuard` positive GET.

The existing opt-in `run-supervised-get-egress.js` uses disposable real
PostgreSQL 18 and tests gate/STOP/sealed ciphertext GET. It is **separate** from
the dual-signed-head synthetic experiment. Its existing single-witness path
tests the backward-compatible GET guard, not deployment of two real hosts.

## Explicit nonclaims

The two TLS endpoints run on one physical developer machine. Distinct keys,
ports and certificate pins do not prove different operators, physical failure
domains, or separately custodied private keys. The monitor detects disagreement
only while both peers are reachable and honest about their own signed views.
It cannot prove signed CAS ancestry between two higher floors; it instead
rejects all unapproved advances, waiting for separate operator reconciliation.
No provider credentials, cloud PUT/GET/fsync, multi-provider recovery, atomic
PG×SQLite×witness commit, distributed lease, consensus, durable remote floor
storage, production restore guarantee or global STOP fence is claimed.
Production remains **NO-GO**. This is an opt-in developer defense, not a
default change to normal client/browser recovery or a replacement for the W14
restore journal, W4 standalone issuer or W10 provider egress work.
