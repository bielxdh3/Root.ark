# Root.ark #65 — immutable local ciphertext version retention

**Status: experimental local protected-content plane only. PRODUCTION NO-GO.**

Prior `Zk1ProtectedObjectStore` PUT revisions updated the sole
`zk_content_object` row, irreversibly erasing the previous opaque ciphertext
in the local SQLite fixture. This prevented local historical-version evidence
and safe future restore from retaining the original encrypted bytes.

The experimental store now adds `zk_content_version` with primary key
`(scope,id,revision)`. Every authenticated new PUT appends the exact opaque
ciphertext, its SHA-256 digest, epoch and provenance label `transactional`
**inside the same SQLite IMMEDIATE transaction** as the latest projection,
head watermark, durable nonce and trusted-clock record. The previous bytes
remain intact. SQL UPDATE and DELETE triggers deny accidental mutation;
the store enables and verifies SQLite `recursive_triggers=ON` per connection
so a conflicting `INSERT OR REPLACE` cannot bypass the DELETE trigger;
failed/duplicate version INSERT rolls back all effects, including nonce
consumption, so retry of the exact signed request remains possible.

On restart, the store verifies bounded historical rows, contiguous
per-object revisions beginning at one, ciphertext digests, account scope,
and exact equality of the last archived bytes/revision/epoch with each
current object. It fails closed on missing/gapped/tampered history. Capacity
is deliberately finite: 4,096 archive entries or 256 MiB of ciphertext;
no automatic eviction, pruning or unapproved retention policy exists.
Exceeding capacity blocks a new PUT without destroying old versions.

An existing **pre-archive experimental database** has already lost former
revisions through overwrites. Its missing archive cannot be reconstructed
honestly; reopening it now returns
`ZK_CONTENT_VERSION_HISTORY_REQUIRED` on a read-only identity preflight,
without modifying the original file. It requires a separately approved
backed-up, reversible migration. Never run destructive migration or reset to
recreate an archive. This is an intentional fail-closed schema compatibility
boundary, not a claim that historical data was recovered.

## Focused tests

`node --test test/issue-65-protected-ciphertext-version-retention.test.js`
creates only an OS temporary fixture and proves two distinct signed PUT
revisions survive, nonces cannot replay, stale revision conflict leaves
archive unchanged, direct SQL UPDATE/DELETE/INSERT OR REPLACE is refused,
and restart preserves
both byte-for-byte. An injected INSERT-abort trigger causes the entire
latest-object/nonce/head transaction to roll back; after removing the
fixture-only trigger, the same signed nonce can succeed without a phantom
revision. Explicitly tampered historical bytes and missing history each
fail closed on restart; incomplete older schema is not silently migrated.
Existing integration regression tests cover the separate local witness/CAS
read, device revocation and content authorization behavior.

## What this does NOT prove

The archive is in the **same locally administered SQLite** as the mutable
latest ciphertext projection. An administrator controlling that file can
replace/restore the whole database, alter both ciphertext and digest, drop
triggers or supply older signed state; SHA-256 and immutable triggers do not
provide independent freshness, host separation or durability across storage
failure. No public read-previous-version endpoint, owner-controlled
retention/trash, cloud provider replication, WebDAV/sync, backup restore,
client key rewrap, authenticated root catalogue or client recovery UI is
introduced. This module is never authorization for production GET/PUT.
Normative #65 still needs independent linearizable CAS/witness/PG gate and
effect-point physical I/O fencing across every provider and host before
protected operation can be released.
