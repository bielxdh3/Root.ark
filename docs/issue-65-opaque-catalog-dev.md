# ZK1 opaque catalog (Issue #65, development-only opt-in)

Generic sync-v2 metadata is **never** used as a ZK1 catalog source.
The opt-in `/zk-1/v1/catalog/commit` and `/zk-1/v1/catalog/read`
endpoints require an authenticated owner session, upload/list permissions,
current active device Ed25519 signature, pinned owner history and independent
witness of the recovery-manifest head.

The bootstrap registers the catalog only with an explicit
`opaqueCatalogAuthority` (external to local SQLite) supplying a pinned
Ed25519 `publicKey`, `readHead({scope,nonce})` and **linearizable**
`compareAndSwap({scope,expectedSequence,expectedDigest,nextSequence,nextDigest,nonce})`.
Both operations must issue canonical deterministic-CBOR
`rootark-zk1-opaque-catalog-cas/v1` statements signed over the domain
`Root.ark/zk-1/opaque-catalog-cas/v1\0`, with exact scope, head sequence,
digest, 32-byte challenge nonce and observation time. An echo-only service is
not an independent CAS authority.

Each owner-enrolled active device signs an entire catalog of immutable
ciphertext **versions**, sorted by 16-byte opaque object ID and revision.
A signed header commits the count, 32-entry page digests, owner manifest head,
epoch, signer and predecessor catalog digest. Entries contain only ID,
revision, epoch, ciphertext hash and fixed-size (284-byte) AES-256-GCM sealed
metadata. The metadata key remains on the client; its AEAD AAD binds scope,
object ID, revision and epoch. The catalog database never holds plaintext
file names or paths.

Clients call `verifyZk1OpaqueCatalogPage` with independently pinned owner
genesis, current fresh witness, private-branded owner history, external CAS
signer and remembered catalog floor before using a page. Page digest
comparisons permit skipping unchanged pages; the next mutation requires a
complete new signed inventory. Version-specific GET uses the returned ID,
revision and original ciphertext digest.

Bounds: 4096 versions, 128 catalog heads, 32 entries/page, signed challenges
expiring within 60 seconds, and 220 UTF-8 bytes per locally encrypted name.
Deletion, trash, move, rename, normal browser browse UI and a deployed
catalog-CAS service are not implemented. A signed catalog compared against
local stored ciphertext versions cannot independently prove first-genesis
completeness against a malicious SQLite operator: an owner-verified starting
inventory checkpoint remains required for comprehensive backup claims.
If remote CAS commits but local persistence fails, reads reject until
separately reviewed reconciliation. No production durability claim.
