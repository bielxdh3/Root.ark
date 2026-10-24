# Root.ark #65 — experimentally challenged witness head + replay ledger

**Status: LOCAL, NON-AUTHORIZING SECURITY LAB. PRODUCTION NO-GO.**

This milestone augments the committed historical approval/replay experiment
without changing its `authorizesRelease:false` or `protectedIoAdmission:false`
contract. It does not add a content route, authorize encryption-key release,
change provider I/O or implement live CAS/recovery transition admission.

## What is different

The new `inspectAndRecordExperimentalOnlineApproval` accepts a proposed
device/ciphertext approval and independent witness mTLS connection settings,
not caller-supplied `rawWitnessHead` or `witnessNonce`. It snapshots the
candidate's signed approval, object commitment, scope and pins before network
I/O; generates a fresh CSPRNG 32-byte witness challenge; fetches `/v1/head`
over the existing TLS 1.3 mutual-authenticated, server-certificate-fingerprint
pinned client; and then uses the existing deterministic-CBOR Ed25519 verifier
with the actual fetched receipt and fresh nonce. Wrong certificate fingerprint,
head nonce, scope, signed manifest digest, old timestamp, pending gate, offline
witness or revoked signer denies before the replay insert. Successful
inspection consumes the *approval* nonce under the disposable PostgreSQL
writer role and unique per-compartment tombstone, with result only after
explicit SQL COMMIT. The new mTLS challenge is distinct from that signed
approval's nonce.

The local verifier obtains its clock time **after** the HTTPS response, not
before sending the challenge. This avoids false denial when a healthy
witness signs in the next clock second while the request is in flight.
The caller cannot override that timestamp; the approval bytes, device pins,
scope and root remain snapshotted before the asynchronous request.

An independent reviewer identified a **conditional evidence-integrity gap**:
`instanceof` accepted a forged object inheriting the ledger prototype whose
overridden `consumeCandidate` could return fake `replayRecordCommitted:true`.
The ledger now captures minted instances and their pool bindings privately;
the crypto/replay wrapper invokes only the original module-owned SQL
implementation and rejects forged prototypes or injected method overrides.
This does not attest an arbitrary supplied SQL pool or protect against a
compromised in-process runtime. It closes that specific API impersonation
case under the laboratory threat model.

## Validation and boundaries

The focused runner `node lab/issue-65-packet-b/run-approval-replay-postgres.js`
uses a labeled, disposable PostgreSQL 18.6 instance with restricted SQL role,
and an ephemeral loopback mTLS witness with separate disposable signing key.
Its provider returns fresh signed receipts over a real HTTPS connection but
is **in the same local machine/testing trust domain**, not an independently
governed witness or remote host. The mTLS test deliberately exercises a
bad TLS pin, committed/pending/stale/wrong-nonce/wrong-digest/unavailable
responses, a mutated candidate while the HTTPS request is in progress and a
repeat replay claim, including a correctly signed HEAD delayed across a
clock-second boundary. A separate test proves forged/overridden ledger methods
cannot claim COMMIT. The same runner retains process-race, restart, lost-ACK,
role/ACL and anonymous PostgreSQL volume cleanup controls.

The signed receipt proves only the trusted test key signed a recent response
to this challenge; it does not prove operator independence, high-water
anti-equivocation, malicious database restore resistance, post-read device
non-revocation, availability/health of a remote provider or that another host
cannot issue conflicting state. The signed device must be active in the
verified supplied manifest history, but there is no atomic binding of the
observed head, approval nonce and actual GateAuthority admission. The
experimental result always says `freshLiveAuthorityVerified:false`, since
a recent witness HTTP answer is not full normative live authority.

Issue #65 still requires independently provisioned trust roots, a separately
operated durable CAS/witness/terminal status, linearizable generation fencing
through each actual remote PUT/GET/egress/socket/provider effect, normative
device custody and client recovery flows, sync/WebDAV, versions, backups,
multiprovider compatibility, adversarial multi-host/rollback tests, and a safe
reversible migration. No push, merge, production changes or real-data
migration are authorized by this experiment.
