# Issue #65 — independent SQL-only atomic batch readback (DEV-OFF)

The Sync v2 client challenges an independent witness with the exact original
signed DELETE and MOVE operation IDs and their canonical-envelope SHA-256
digests. That challenge does **not** contain a trusted `commitId`. The
`zk1SyncPgBatchIndependentReadback.verifyCurrentSignedPair` API resolves the
unique current SQL batch by both signed IDs and both exact digests while
holding **one PostgreSQL 18 `REPEATABLE READ READ ONLY` snapshot**. It then
performs the existing complete verification of the persisted original signed
envelopes and ciphertext, latest scope head and chained marker, policy epoch,
current device grant, authorization signatures and absence of destructive or
column-level DML privileges in the attestor login.

`zk1SyncAtomicSqlReadbackHttpsServer` is an **optional, separate-process
development adapter** for that readback. Its sole route is
`POST /v2/sync-atomic/sql-observe` over TLS 1.3 with required CA-authenticated
client certificates and exact pinned client-certificate SHA-256 fingerprints.
Each certificate is allowed only its operator-injected exact
`scope/accountId/storeId` tuples. It accepts the original pair IDs/digests and
a fresh 32-byte nonce, limits request bytes, concurrent requests, headers,
TLS handshake time and connections, and returns only SQL observation evidence.
The trusted server operator sets a bounded observation deadline (six seconds by
default); a deadline sends HTTP 503 but **does not cancel** an in-flight SQL
read. Up to eight unresolved readbacks can exist; their slots remain occupied
after HTTP timeout until the actual readback settles, preventing unbounded
connections under a hung database at the cost of failing closed until recovery.
The PostgreSQL pool must independently configure connection/query timeouts and
the operator must restart an isolated failed observer when required. No caller
can override this deadline from its request body.
There is no writable database credential, issuer ticket endpoint, encryption
key or Ed25519 signer in this service. It must never be mounted in the normal
Root.ark HTTP server or exposed by mutable sync JSON configuration.

**Never use this response as a protected client ACK:** it deliberately has no
`atomicAdmission`, no signed witness `statement` or `signature`, no signed CAS
floor and always reports `physicalDurable: false`, `witnessVerified: false`,
`clientAckAuthorized: false`. An HTTP `200` means that **at the database
snapshot** the exact signed pair, head and current grant were consistent. It
does not mean that this head remains current when the response reaches the
client. It does not establish physically independent WAL/fsync observation,
off-host signer custody, external monotonic fencing, or a protected second
CAS authority. The injected account/store UUID grant is an operator claim,
not a PostgreSQL-certified or physically attested identity mapping.

The PostgreSQL 18 disposable lab exercises real signed commits, role denial,
rollback, signed-ID/digest confusion and a real TLS1.3 mTLS request against the
live read-only database pool. Its combined lab process holds other temporary
test credentials **only in the disposable test**; a real isolated operator
must never run the observation endpoint alongside a writer, issuer or DB
owner. Separate operator-held current identity certificate roots and floors,
physically independent signed WAL/commit evidence, a durable off-host CAS
service with restart/failover fencing, and an independently audited end-to-end
negative corpus remain required before any protected ACK or production GO.
