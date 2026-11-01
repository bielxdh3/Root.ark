# Sync v2 independent retained high-water operator — development prototype

`src/services/zk1SyncAtomicRetainedAnchorDevOff.js` is a **separate-custody-ready,
unwired DEV-OFF** SQLite WAL/FULL monotonic high-water authority for the Sync v2
atomic batch CAS contract. It is deliberately separate from the ZK1 legacy
inventory witness, historical recovery, and terminal-status protocols.

An owner must inject a private Ed25519 signing key, exact immutable account/store
scope bindings and a separately retained, previously trusted `{scope,sequence,
headHash}` minimum for **every** scope. A new file can be created only with
`bootstrapNew: true` and an explicitly trusted zero-sequence/genesis minimum;
the file is created exclusively inside a private authority directory. There is
no public RPC for provisioning scopes, rotating keys, resetting a floor or
changing the owner's trusted minimum. Existing databases are audited in a
read-only SQLite snapshot before a writable connection is opened.

The precise Sync v2 adapter shape is:

* `readSignedHead({scope,nonce})` — signs `{version:1,scope,nonce,sequence,
  headHash}` as canonical JSON under the dedicated
  `rootark-sync-atomic-batch-retained-highwater-v1\0` domain. The caller pins
  the distinct Ed25519 public key; freshness is enforced by its own nonce.
* `compareAndAdvance({scope,expectedSequence,expectedHeadHash,sequence,
  headHash})` — strictly compares a current per-scope head and advances **one**
  sequence inside a SQLite IMMEDIATE transaction; returns `false` on stale
  compare, and fails closed on corrupt data, invalid schema, or a wrong owner.

Every returned signed head is checked against all locally persisted per-scope
hash-linked history, **individual Ed25519-sealed append records**, and the
trusted minimum. Writer-side advances enforce those invariants inside an
atomic transaction. A SQLite-only attacker cannot forge a later history row
by recomputing public SHA-256 hashes while the Ed25519 private key remains
outside their authority. Hostile triggers, unknown schema
objects, signer/identity changes, old or weakened schema, and signed replay are
denied. Tests use real `better-sqlite3`, WAL, and Ed25519, with adversarial
reopens, two distinct SQLite connections (not an independent-host proof), historical tampering, owner
identity drift, stale forks, and separately injected rollback minima.

The separate opt-in `zk1SyncAtomicRetainedAnchorHttpsDevOff.js` transport adds
TLS 1.3 mutual client authentication, exact certificate fingerprint scoped
read/advance grants, server CA/hostname and certificate pin checking, and
client-side Ed25519 receipt verification. An unsigned HTTP successful
compare **cannot** authorize a floor: the client insists on a separate fresh
nonce-signed head after the compare. Real TLS/SQLite/Ed25519 tests cover denied
roles, unauthorized/foreign principals, incorrect server pin and signing pin,
missing client certificate, stale CAS and prohibited extra protocol fields.
The endpoint is not mounted in the normal Root.ark server and no production
capability is enabled. Operator certificate scope grants are deployment trust
inputs and the transport cannot prove physical bytes or owner custody.

**No deployment or ACK authorization is implied.** A local SQLite file remains
rollbackable by a privileged administrator or a stale backup. WAL/FULL is not
proof of separate physical durability, nor does this module implement an
independently operated mTLS service, operator key custody, physical witness, fencing lease,
or independently persisted update of the owner's trusted minimum after each
advance. Until those are implemented and tested, this prototype MUST NOT be
wired to protected SyncEngine ACK or represented as a production authority.
