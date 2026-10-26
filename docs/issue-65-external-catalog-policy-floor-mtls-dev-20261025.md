# Issue #65 — opt-in external catalog policy + FLOOR terminal adapter (DEV only)

## Strict scope

Root.ark main base `a0b483c` already integrates W20/W25 catalog witness
admissions, external Ed25519 policy pinning, immutable terminal seals and
cleanup-only START replay. This step adds
`src/services/zk1CatalogExternalAuthorityHttps.js` without enabling any
production route/CLI, changing the existing W25 witness schema or introducing
secret keys into writer-controlled JSON.

The module exports a TLS 1.3 mTLS HTTPS **server** (external authority/operator
process) and a pinned mTLS **client** (callable from an authorized consumer).
Both methods return deterministic CBOR Ed25519 signatures using the **exact
domains and field bindings** that `Zk1DurableWitnessLedger` validates:

- `policyGrant(request)`: the requested scope, owner revision/digest, signer
  device, epoch, operation ID, CAS signer fingerprint, catalog sequence/digest,
  expiration and TLS peer fingerprint are compared to an operator-provided
  **fresh authoritative owner-state callback**. It is read twice across the
  asynchronous boundary; the server generates its own 32-byte nonce and
  signing time. No callback/no exact state/invalid clock => DENY.
- `floorTerminal(witnessSignedAdmissionTicket)`: checks the **distinct pinned
  witness Ed25519 signature**, canonical typed fields, TLS peer identity and
  expiry. A separate operator-provided physical-evidence callback must return
  a valid Ed25519 signature under yet another **pinned physical authority key**
  over the precise admission ID, operation, owner revision/digest, signer,
  epoch, sequence, catalog digest, nonce, principal and **committed=true**.
  The evidence is time bounded. A generic FLOOR `readHead` or client claim
  cannot substitute for operation-specific durable physical finalization.
- **W30 revocation-fence hardening:** every physical terminal proof also
  signs the positive integer `commit_fence`, its unique position in an
  operator-controlled durable monotonic ordering shared with owner
  revocations. After potentially slow physical proof reads, the server
  synchronously invokes `trustedOwnerPolicy` with
  `{kind:"terminal-finalize",ticket,ticketHash,physicalProof,
  physicalCommitFence,...exactOriginalPolicyBinding}` immediately before
  FLOOR signing. That call must synchronously return the exact trusted owner
  binding plus `physical_commit_fence` and `owner_revocation_fence`
  (null only when no revocation is recorded). The trusted operator must
  independently check the physical commit and its durable position:
  **commit→revoke** can ACK already-finalized physical work, but
  **revoke→commit** must DENY. A missing/async/malformed callback, changed
  original binding, or commit fence not strictly preceding the revocation
  fence fails closed. This never grants fresh admission or restarts work.
  Last-fence check, final time sample and Ed25519 signing run in one
  synchronous JS turn (no await after checking live owner state).
- Separate Ed25519 keys for policy, FLOOR terminal, witness, and physical proof
  are mandatory; duplicate SPKI fingerprints fail closed. TLS CA verification,
  server SPKI SHA-256 pin, exact allowed client certificate fingerprint, mTLS
  request certificate and bounded JSON/CBOR payloads are mandatory. All errors
  return generic denial without exposing keys or trust decisions.

The separate-process development integration test provisions disposable native
OpenSSL CA/server/client certificates and an actual child-process HTTPS server.
The child retains separate Ed25519 keys and an independently opened SQLite
`synchronous=FULL` fixture recording test owner decisions and simulated
physical commits. The W25 witness is a different SQLite instance/process and
consumes both network-returned signatures at its **existing**
`beginCatalogAdmission` / `completeCatalogAdmission` API. Tests reject:
missing operator authority, wrong epoch, wrong TLS server SPKI, another
CA-authorized mTLS client, forged witness ticket, FLOOR before a physical
record, altered FLOOR proof, and owner revoke after completion; restart retains
the real terminal seal.
In W30 follow-up, the disposable child uses a separate SQLite FULL
`authority_order` table and `BEGIN IMMEDIATE` to serialize simulated
physical commits/revocations. Tests cover both orders, owner revocation
while an awaited physical proof is intentionally delayed, and denied
nonce/ticket replay after an unauthorized post-revocation commit.

## Explicit NO-GO / what is NOT implemented

The test child's owner policy and physical commits are **lab-controlled SQLite
fixtures** (via private test IPC). They are not authoritative owner grants and
they are **not real physical provider/fsync/remote custody evidence**.
In particular, the physical proof is test-only, not produced by the current
opaque independent FLOOR head/CAS service: that service does not independently
bind a **specific operation ID** to the W25 signed admission terminal, nor
does it share a durable cross-authority revocation order. Distinct
processes on one host cannot establish independent administration, key custody,
off-host monotonic anti-rollback, cross-host revocation linearizability, or
multi-provider physical durability.

This adapter **never** signs a policy or terminal by itself without operator
injected trusted callbacks and pinned keys. It is not registered into the
application and there is no production launcher/issuer, fallback, synthetic
owner permission or privilege-bearing JSON mode. The owner/operator still
must supply independently governed current owner authorization (with revocation
fencing) and real physical CAS confirmation that is durably and cryptographically
bound to the exact witness ticket. A valid signed unresolved ACTIVE admission
still blocks owner revocation until independently audited physical reconciliation;
no automatic timeout-based release exists.
The required synchronous, independently governed owner/physical fence is
**only a contract** outside this lab fixture; a forged counter or separately
sampled wall clocks are not a replacement for a truly serialized durable
commit/revoke order. No cross-host or independent-custody guarantee is claimed.

Therefore this proves interoperability of real TLS/Ed25519/process boundaries
in a disposable development lab only. PR #228 and issue #65 remain **DRAFT /
NO-GO for production** until the two independent authority dependencies,
strong external custody, and adversarial multi-host integration are implemented
and independently reviewed.
