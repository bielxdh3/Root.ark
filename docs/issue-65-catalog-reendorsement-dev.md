# Issue #65: catalog re-endorsement after device revocation (DEV)

`/zk-1/v1/catalog/commit` accepts the next complete signed head only from a
currently ACTIVE device in the witnessed owner V2 history, with current
manifest revision, digest, epoch, exact previous independently witnessed
catalog digest, and a fresh one-use device signature. Re-endorsement preserves
the old immutable entries and advances the external CAS sequence.

Before any CAS attempt, the service audits **every** locally archived catalog
head and page: owner-rostered Ed25519 signatures (including a signer revoked
*after* its historical epoch), deterministic bytes, previous-digest chain,
per-page signed hashes and total counts. Each existing `(object_id, revision)`
must retain precisely the original metadata ciphertext, ciphertext digest and
AEAD epoch. The new complete set must match **all** physical immutable
`zk_content_version` rows and independently recomputed ciphertext hashes.
Missing, rewritten, duplicated or physically corrupted versions fail closed.

An authenticated new ciphertext revision may represent a rename/move with its
own fresh metadata AES-GCM AAD `(scope, object_id, revision, epoch)`; this never
changes the old version's metadata. The server cannot decrypt or validate AES
tags without the user-held metadata key. The active signing device must verify
the plaintext/AEAD locally before attesting new metadata. Historic names
require the original epoch and its retained key; a changed epoch causes
decryption failure, never an implicit migration. No name/path plaintext or CEK
is stored by the catalog.

**External integration limitation:** the independent standalone
`zk1OpaqueCatalogCasLedger` currently fixes a catalog signer key. The focused
HTTP tests use an independently signed CAS test authority whose policy permits
the new device, and prove the service boundary only. Production-equivalent
revocation recovery remains blocked until the standalone authority verifies
an owner-signed/witnessed signer transition and accepts the new ACTIVE key.
Local SQLite integrity and independent CAS are not external cloud durability,
nor proof that the original inventory contained every legacy object.
