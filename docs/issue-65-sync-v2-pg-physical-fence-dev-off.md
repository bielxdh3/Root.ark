# Sync v2 PostgreSQL + independently held physical fence — DEV-OFF

The unmounted `zk1SyncAtomicPgPhysicalFenceDevOff.js` is a strict adapter for
an independently operated **physical** DELETE+MOVE witness and the existing
read-only PostgreSQL 18 batch verifier. It neither opens an ACK endpoint nor
creates a physical attestation; it owns **no signer**, WAL durability barrier,
physical lease, CAS signer, or locally fabricated success fallback.

Its constructor requires a real `attestorPool` read-only PostgreSQL connection,
an externally supplied `externalPhysicalFence.withCurrentRead(challenge, fn)`
that holds a live lease during `fn`, and a separately pinned Ed25519 witness
public key. It also requires an explicit non-empty immutable
`ownerBindings` roster keyed by scope and containing the exact scope,
accountId, storeId, username, and compartmentId. The adapter refuses a
challenge that differs from these operator trust inputs even if a witness
signs it. The operator must provision these bindings independently of writer
input; an arbitrary writer-controlled roster is not an authority. The SQL verifier is the existing
`zk1SyncPgBatchIndependentReadback.js`, which rejects destructive PostgreSQL
privileges, hostile DML/DDL grants, altered ciphertext, replayed/unbound
operation IDs, invalid owner-device authorization, broken DELETE+MOVE pairing,
stale policy and conflicting scope heads. SQL row consistency alone remains
`witnessVerified:false` and `clientAckAuthorized:false`.

For each nonce-bound protected pair, the adapter independently checks:

1. The external physical witness's **Ed25519 signature** and the precise v2
   witness domain, owner/account/storage identity, reserved DELETE+MOVE
   `operationIds`, exact canonical `envelopeDigests`, sequence-fencing epoch,
   store-head digest, commit ID, nonce, and `physicalDurable:true` statement.
2. The independent PostgreSQL read-only verifier returns the **same exact
   pair, commit ID, store head, policy username and compartment ID** in a
   validated transaction. PostgreSQL alone does not attest the account/store
   UUID binding; those must be pinned by an independent operator registry and
   are currently verified only against the separately signed witness. An HTTP 200,
   unsigned SQL readback, or local `fsync` claim cannot replace the witness.
3. The independently supplied physical lease remains held both before and
   after SQL verification and after the protected continuation returns; an
   expired or throwing lease is denied. The wrapped `assertHeld` returns the
   exact boolean `true` expected by the CAS ledger and also checks that the
   callback has not been detached. Only one awaited continuation is allowed;
   detached late callbacks cannot authorize a success. The adapter records a
   separate callback-success bit only after the final lease assertion, so a
   hostile provider swallowing an SQL error or post-continuation lease failure
   and returning an otherwise matching value cannot produce a false success.

Provider and readback operations have independent finite wall-clock deadlines
(defaults 8 seconds and 5 seconds). A timed-out PostgreSQL call is **not**
considered cancelled: unresolved operations remain counted in bounded
in-flight sets, including one pending operation per scope, until they really
settle. This prevents retries from silently accumulating unlimited blocked
pool acquisitions. The limit denies rather than fabricating a physical proof.

The adapter forwards the signed `{receipt,lineage}` untouched for the existing
`Zk1SyncAtomicCasFloorLedgerDevOff` to recheck, including the signed physical
lineage and external CAS/high-water checks the ledger requires. **It does not
itself create lineage or an external physical witness.** Missing components,
unexpected responses, stale leases, failures and equivocation are fail-closed.

The companion test exercises signed synthetic physical proofs and a synthetic
SQL verifier to validate strict protocol negative cases. This injection is
available only under `NODE_ENV=test`, and is never a proof of real PG/WAL
durability. Negative coverage includes wrong SQL owner policy/compartment,
detached callbacks, unbounded provider reads and held-lease failures. Real
PostgreSQL 18 permission/integrity tests exist separately in
the hosted disposable PG gate; this test does not replace or weaken them.
The disposable PG18 integration now also drives this **actual adapter** using
the real least-privilege attestor connection, persisted signed DELETE+MOVE
rows, and a deliberately synthetic Ed25519 lease/witness. It verifies normal
admission, rejected username/compartment and digest changes, and rejection of
the runtime/writer SQL credential. It still does not constitute a real physical
barrier, host independence, or protected ACK proof.
The same disposable PG18 lab additionally runs the actual
`Zk1SyncAtomicCasFloorLedgerDevOff` with the new PG fence and a distinct
Ed25519-signed SQLite retained anchor. A real persisted SQL pair advances the
local and retained floor exactly once; identical retries cannot append again,
and a real PostgreSQL policy revocation makes the subsequent revalidation
fail closed without advancing the retained floor. The test uses synthetic
physical evidence and an in-process anchor, so it proves code integration,
**not** independent custody or physical durability.

## Open integration gates

The real independent Sync v2 physical provider must still implement and prove
the exact reserved operation-to-physical-commit binding, a physical durability
barrier controlled by a different OS/custody identity, independent revocation
and fencing over active leases, recovery after split commits, and externally
non-rollbackable minimum custody. Until the physical provider is implemented,
deployed and independently validated, this adapter is **DEV-OFF / NO-GO** and
MUST NOT be wired to production protected SyncEngine acknowledgments.
