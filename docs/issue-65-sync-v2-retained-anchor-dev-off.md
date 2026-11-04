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
* `readSignedBindingHead({scope,nonce})` — separately signs a domain-separated
  v2 statement binding `scope`, immutable `accountId`, `storeId`, nonce,
  sequence and head hash. This must be checked when comparing two authorities:
  the legacy scope-only head does **not** prove the same owner/storage identity.

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
The hosted transport suite also cuts a real TLS socket immediately after a
successful SQLite CAS: the caller must deny the missing response, while a new
nonce-signed read can discover the committed floor and a retry stays stale.
All mTLS requests have an absolute wall-clock deadline, including DNS/TLS
setup and slowly streamed responses, independently of socket inactivity.
The advance and its required signed readback share one overall client deadline.
Principal grants are static at server creation: revoking or rotating an
operator certificate requires replacing the running service and its TLS
sessions. This prototype has no online CRL/OCSP policy or live grant reload.
The additional `scripts/zk1-sync-retained-anchor-server-dev-off.js` is a
separately launched **opt-in process**. It requires `NODE_ENV=test` or
`development`, `ROOTARK_SYNC_RETAINED_OPERATOR_DEV_OFF=true`, and exactly one
absolute path to an operator-owned private JSON configuration. Its exact v1
schema requires `version`, `host` (numeric IP), `port`, private-directory file
basenames `database`, `serverKey`, `serverCert`, `clientCa`, `signerKey`,
`ownerBindings`, `trustedMinimumHeads`, and certificate `principals` grants.
It refuses to create an absent SQLite database or silently reset a minimum;
only explicit separate offline bootstrap of the existing anchor is supported.
The runner reads configuration and signing/TLS trust material through pinned
file descriptors with stable inode checks and owner-only leaf permissions;
Windows additionally uses the existing native ACL verifier on each file,
including the SQLite database, not just on their parent directories. The
operator uses the resident verifier for successive private trust-file reads
to avoid recompiling it for each certificate or key; each read still gets a
fresh validation. Insecure POSIX leaf permissions have a
negative startup test. The runner refuses symlinked and non-private authority
files and directories;
the operator should run under a separate operating-system identity. Only
test mode permits ephemeral port `0`. The real hosted tests launch a child
process over mTLS and demonstrate local CAS integration, remote divergence
denial, absent-grant denial, simultaneous conflicting CAS from two real
operator processes against one SQLite WAL, and failure after operator termination. Their
physical-fence evidence is deliberately synthetic: separate *processes* are
not independent *hosts*, custody or a physical durability proof.

An opt-in **v2 operator configuration** adds the required `minimumFence` object
with exact fields `hostname`, `port`, `servername`, `pinnedServerFingerprint`,
`publicKeyFile`, `caFile`, `certFile`, and `keyFile`. All file names are private
operator-owned trust files. The independent minimum signer must differ from
the primary signing key. Its separately running authority has its own mTLS
permissions and immutable scope/account/store bindings. There is no local
fallback when the independent authority is unavailable.
The primary's offline-bootstrap database is **v2-sealed** using the trusted
minimum public key: it persists a separate exact-schema
`atomic_anchor_minimum_fence` binding. Any v1 operator trying to open this
database fails its four-table schema audit; v2 startup also rejects a changed
minimum signer. The HTTPS factory additionally refuses a configured minimum
whose public signing key does not match the database's immutable pinned key;
checking only whether an independent operator exists is never sufficient.
Existing legacy v1 databases are not silently migrated.

V2 startup requires a fresh independently signed minimum that exactly matches
each local scope head **and account/store identities**. Every head read checks
the independently signed binding statement again. On an advance, the
independent minimum commits and is signed **before** the primary SQLite CAS.
A crash between these steps intentionally leaves the primary locked: it cannot
serve a signed stale head, acknowledge an uncertain commit, or silently repair
the divergence. Hosted tests exercise two actual operator processes and deny
a restored primary SQLite snapshot with an old valid Ed25519 history prefix.
The test also advances the minimum while leaving the primary at its old tip,
modeling a crash between the two commits; the operator then refuses startup.
To simulate an actual old SQLite backup rather than WAL roll-forward, the
disposable test first closes both primary processes and removes only that
fixture database's newer WAL/SHM sidecars before restoring its old snapshot.

This protects against restoring **only the primary database**. Running both
operators under the same CI OS identity is NOT independent custody, and a
simultaneous rollback of both stores remains possible. Nor can the independent
minimum prove that an authorized writer's proposed head was physically durable.
An independently operated, non-rollbackable custodian and normative physical
witness are still required before any protected ACK is permissible.
The endpoint is not mounted in the normal Root.ark server and no production
capability is enabled. Operator certificate scope grants are deployment trust
inputs and the transport cannot prove physical bytes or owner custody.

**No deployment or ACK authorization is implied.** Both DEV-OFF operators use
SQLite and can be simultaneously rolled back by an administrator with custody
of both stores. The v2 remote-first minimum does persist a second signed head
on every successful advance; it does **not** establish a non-rollbackable
minimum in genuinely separate operator custody. WAL/FULL is not physical
durability proof, and normative physical witness, independent signing-key
custody, long-lived fencing leases, and authorized crash reconciliation remain
unproven. This prototype MUST NOT be wired to protected SyncEngine ACK or
represented as a production authority.
