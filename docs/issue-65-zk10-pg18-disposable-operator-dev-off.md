# Root.ark issue #65 — disposable ZK10 PostgreSQL18 operator protocol (DEV-OFF)

**Status: DEVELOPMENT LAB ONLY. NOT A PRODUCTION OPERATOR.**

**Base:** published #236 `741fdcf6ce30f8b4228bbe92d7a24d812740507d`.
This isolated worktree also carries *byte-identical reviewed prerequisites*: W117
`src/crypto/rootark-zk10-account-cutover-v1.js` (Git blob `6975ded84ae2cbec21e4d1190e60b6f3532d160e`)
and W62 `src/services/zk10ExternalOwnerCutoverCasClient.js` (Git blob
`2205f2966371644873d8784b07c2f8aa17150fe0`). No original W62
worktree, staging index, or published branch was changed.

## Scope

`lab/issue-65-zk10-pg18-operator/operator.js` implements the three W62 wire
paths `/v1/zk10/current`, `/v1/zk10/cutover/cas` and
`/v1/zk10/cutover/readback`. All messages use independently pinned
Ed25519 owner/operator public keys, signed domain-separated wire payloads,
an exact account UUID and identity digest, fresh challenge, 256-level sparse
Merkle proof, monotonically linked signed account HEAD and signed receipt.
Only *initial* generation-1 owner cutover with no compatibility grants is
recognized. SQL uses a real PostgreSQL 18 transaction and `SELECT ... FOR
UPDATE` for a single-account compare-and-swap. Signed head/receipts are
retained as TEXT so PostgreSQL JSONB key reordering cannot change signed
bytes. A second CAS cannot silently overwrite the protected head.

The separately launched `server-child.js` exposes **loopback-only
TLS 1.3/mTLS** with CA verification and a pinned client certificate
fingerprint. `client-child.js` runs the exact reviewed W62 client as a
separate OS process using CA and server-certificate pin verification.
The network transport is *not* injected into production bootstrap.

## Execution

Explicit opt-in (not a mandatory production/CI gate):

```text
node lab/issue-65-zk10-pg18-operator/run-disposable.js
```

The runner reuses the reviewed `runDisposablePgLab("gate")` machinery:
fresh random-name `postgres:18.6-alpine3.24` container, owner/label checks,
localhost-only ephemeral PostgreSQL port, **no ambient DATABASE_URL**, no
production credentials, and verified anonymous-volume cleanup. A dynamic
Docker Desktop host port is rediscovered after restart using the same
verified disposable container ID. The test fails if the actual server version
is not exactly 18.6 or if either host SQL readback or signed protocol
verification fails. Raw TAP, database URL and private keys are withheld.

`pg18-e2e-case.cjs` checks two independent client PIDs, real client/server
mTLS, pinned genesis CURRENT, rejection of a foreign owner signature, one
owner-signed CAS committed in PostgreSQL while its HTTPS ACK is dropped,
uncertain/no-resend behavior, an **actual child-process restart and real
PostgreSQL container restart**, W62's separate signed CURRENT plus exact
operation-specific signed readback, and rejection of an attempted repeat
cutover. Both operator and client signer keys are ephemeral, test-only and
held together in a restricted temporary directory. Only this test-created
container is stopped/restarted/removed.

## Explicitly unproven / production NO-GO

- Same host/operator controls the client, signing keys, witness, database and
  fixture certificates. A real independent custodian or externally retained
  monotonic floor **has not been provisioned or demonstrated**.
- `initialPhysicalDigest` is a **signed opaque value**, not proof of PG18
  physical STOP, all-legacy-IO drain, durable off-host storage, or a
  synchronized account-wide lease. Caller-supplied lease ID, fencing epoch
  and expiry are *claims*, not evidence of a physical lease reservation.
- Actual production no-downgrade admission, all Sync/WebDAV/WS/backup/share/
  anonymous routes, mapping old owner UUIDs to immutable account identities,
  signer independence, rotation and generations >1 are outside this slice.
- This server is not wired to `server.js`, supplies no production role or
  authorization capability, and should never be used with a live PG URL.
  W62's `authorizesProductionCutover` stays `false`.

**No changes to release gates, CI thresholds, production Docker, or live data.**
