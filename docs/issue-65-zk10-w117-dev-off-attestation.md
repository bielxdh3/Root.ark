# ZK10 DEV-OFF signed account policy verifier (W117)

This proof-of-protocol is **not a production deployment, owner authorization,
complete migration attestation, or off-host custody certification**. The module
`src/services/zk10LegacyCutoverFence.js` is deliberately unmounted in production.
The implementation does not accept local flags (`externallyVerified`, `cutover`,
JWT account IDs) as authorization, nor can its test fixture prove separation of
machines, operators, keys, or durable external retention.

## Server-owned interface

`createZk10LegacyCutoverFence(config)` returns a privately branded object with
`withCurrentAccountLegacyPolicy({ authenticatedUsername, operation }, callback)`.
`isAuthenticZk10LegacyCutoverFence(value)` checks an internal `WeakSet` so a
duck-typed caller cannot install a fake policy. The authenticated username must
come from server middleware; **the server-owned resolver**, not a JWT account
claim or HTTP parameter, must return `{ immutableAccountId: 16-byte UUID,
serverAccountIdentity: {durableUserId: 16-byte UUID, authenticatedUsername} }`.

At construction, the operator supplies privately retained, immutable map pins:
`independentlyPinnedIdentityBindings` maps each authenticated username to its
durable ID and immutable account UUID (aliases of the same identity may share
these two IDs); `independentlyPinnedOwnerRoots` maps account UUIDs to pinned
Ed25519 owner root public keys and canonical ZK account IDs. Missing/conflicting
pins are a 503 error, including account rename/recycle or restored local IDs.
The operator must keep these pins outside databases, backups and writable app
state. Such operational custody is an **unverified deployment prerequisite**.

The config also supplies *two distinct* fixed `https://` endpoints, pinned
TLS server certificate SHA-256 fingerprints, trusted CA, required mTLS client
certificate/key, and distinct independently pinned Ed25519 authority and
CURRENT witness signing keys. TLS 1.3, hostname verification, fixed paths,
bounded responses and deadlines are mandatory. The independently retained
minimum has `{sequence,digest,enrollmentRoot}`; genesis is sequence 0 with
the all-zero digest and `enrollmentRoot:null`.

Every call verifies an authority signed HEAD ancestry from that minimum, an
operation-specific fresh nonce bound admission, a 256-level sparse Merkle
membership/negative membership against the signed HEAD, and a *separately*
signed witness CURRENT head with the **same** generation, digest and nonce.
The witness additionally signs its own account-specific membership decision,
immutable account UUID and durable identity digest; a generic global HEAD
alone cannot authorize a negative membership classification. In production,
the witness must independently retain the ever-enrolled set and refuse an
attempt to reclassify any formerly enrolled identity as never-enrolled.
An enrollment requires the owner-signed domain-separated account statement,
immutable UUID, canonical ZK account ID, complete-corpus inventory root,
the explicit all-legacy egress cutover, a closed migration disposition, and
no compatibility grants. Owner generation history must be contiguous with
signed prior digest; rotations require signatures by both old and new owner.
Unknown, stale, forked, unsigned, conflicting, missing or unreachable state
fails 503. A definitive authenticated `protected_enforced` denies legacy with
403. Only a current signed `never_enrolled` negative proof proceeds.

Admission includes an operation-specific authority lease, held throughout the
callback, followed by a pinned release call. The callback receives `signal`
and `assertActive()`; routes **must** abort streams on signal, validate active
leases before each write/egress and hold the callback until HTTP `finish` or
`close`. The external custody implementation must atomically serialize lease
creation and owner cutover, prevent new cutover while a lease is active, and
enforce lease expiry on actual data-plane I/O. The transport alone cannot prove
any such atomicity. A release failure after durable work is indeterminate and
returns 503; it cannot roll back effects already performed.

This prototype currently accepts `never_enrolled` and `protected_enforced`
only. Migration compatibility grants have no positive path; they fail closed
pending a separate scoped owner-signed, independently admitted mixed-mode
protocol. The owner's `complete_corpus: true` statement is authenticated but
not by itself proof that all historical or derived plaintext copies were
inventoried and disposed of. Account rename provisioning, owner enrollment,
full-corpus migration, independent retention, lease atomicity, comprehensive
route coverage and durable cross-process concurrency remain separate launch
blockers. Existing historical server-readable data cannot be erased by a
prospective cutover.

**Coverage blocker:** The signed `legacy_egress_scope: "all"` field declares
the owner's desired policy, but does not prove that the server enforces it.
The current DEV-OFF adapter is scoped to the W101 Sync integration. Legacy
egress routes outside it remain unfenced, including `server.js` handlers for
`/files/search`, `/files/:name`, `/list`, `/versions`, `/download`, `/history`,
`/share/:token` and its previews/downloads, `/preview/file` and text previews,
plus `src/routes/backups.js`, ordinary uploads and native WebDAV. Each covered
path needs a verified external lease held across the real read/write/egress
boundary. Anonymous share-token routes additionally require a trusted
object-to-immutable-owner mapping because no authenticated username is
available. Until all paths are fenced and proven adversarially, no
account-wide confidentiality or production `protected_enforced` claim holds.

## Disposable tests

`node --test test/issue-65-zk10-account-policy.test.js test/issue-65-zk10-legacy-mtls.test.js`

The mTLS test generates ephemeral RSA certificate chains and Ed25519 signers
in a restricted temporary directory and starts two real TLS 1.3/mTLS HTTPS
servers. It verifies protocol signatures, owner rotation/generation history,
signed negative membership, protected 403, unrelated legacy admission, owner
versus I/O lease ordering, rollback, stale/forked CURRENT, invalid pin,
forged owner/head, and unreachable authority. The fixture's authority and
witness run on the **same test host** and establish no off-host evidence.
