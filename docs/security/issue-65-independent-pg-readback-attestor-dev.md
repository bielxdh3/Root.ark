# Issue #65 — independent PostgreSQL readback attestation (DEV)

This opt-in bridge adds a **separately pinned Ed25519 readback signature** to
the existing immutable physical inventory intent and PostgreSQL WAL-flush
barrier. It does not make Root.ark production-ready and does not authorize
ciphertext egress, device enrollment, restore, deletion, or legacy cutover.

## Trust boundary

- A separately operated `Zk1PgPhysicalAttestorHttpsServer` must run in its own
  OS process, with a **different Ed25519 signing key** from the writer, inventory
  ledger, CAS/FLOOR and witness. Only the attestor process can load that key.
- The server receives a constrained mTLS client certificate and a fixed scope
  allowlist. The client pins the server's TLS fingerprint; the bridge pins the
  attestor's **public Ed25519 key out of band**, never from a response.
- The attestor's `Zk1SharedPgPhysicalCiphertextVerifier` uses a separate
  PostgreSQL pool/login with only the `zk1_physical_attestor_runtime` read-only
  permissions. It checks direct and reachable `SET ROLE` privileges, signed
  prewrite physical inventory intent, exact immutable admission `operation_id`,
  generation, revision, epoch, ciphertext bytes, chunk root, SHA-256 and WAL
  flush barrier. The connection is never shared with the writer's PG pool.
- On `POST /v1/physical/attest`, the attestor signs canonical CBOR under
  `Root.ark/zk-1/physical-pg-readback-attestation/v1\0` only after the verifier
  returns its physically re-read, WAL-flushed result. The receipt binds scope,
  object, revision, epoch, inventory sequence/root, operation_id, digest,
  ciphertext SHA-256, chunk root/count, generation, admission_id, 32-byte
  caller nonce and short-lived issuance time.
- In strict opt-in mode, `Zk1PgPhysicalInventoryBridge` requests this proof and
  verifies it independently before *and* after a signed inventory append or
  reconciliation. The writer needs **no PG attestor login** in that mode.
  A valid writer signature or a self-reported `verified: true` result cannot
  substitute for the pinned attestor signature.
- The standalone inventory mTLS server also accepts `physicalAttestorClient`
  together with an independently provisioned `pinnedPhysicalAttestorPublicKey`.
  Under that opt-in it verifies a freshly challenged remote attestor proof
  before ledger append and again before returning a positive committed
  result; historical committed-operation lookup rechecks it too. A forged
  inventory/writer signature is insufficient. The inventory service obtains
  physical digest/root/count only from the signed PG attestation, never from
  untrusted append JSON. Legacy in-process physical mode remains explicitly
  non-independent and does not silently substitute for a failed remote proof.
  Strict construction additionally requires the inventory ledger's public
  signing key, rejecting a missing identity or one equal to the attestor's
  Ed25519 pin. The caller must also provide an independently retained
  `pinnedInventorySignerPublicKey`; a mutable ledger facade cannot choose its
  own alternate identity. The strict mode remains an admission guard: historical signed
  inventory entries do **not** yet embed the physical attestation/hash.
- The attestor listener admits only one in-flight verification per pinned
  mTLS client fingerprint, eight overall and sixteen live connections. A
  busy request fails closed; it is not queued while its PG readback is active.

## Operator integration (no deployment performed)

Construct the server from `src/services/zk1PgPhysicalAttestorHttpsServer.js`
in an independently supervised process with its own Ed25519 key, mTLS keys,
scope ACL and `Zk1SharedPgPhysicalCiphertextVerifier({pool: attestorReadOnlyPool})`.
The `pool` must use a separately granted PostgreSQL login. The reference
HTTP client is `createZk1PgPhysicalAttestorHttpsClient`, whose
`requestAttestation({scope, operation, nonce})` returns signed CBOR bytes.
Pass that client plus the separately retained `pinnedPhysicalAttestorPublicKey`
to `Zk1PgPhysicalInventoryBridge` or the independent inventory mTLS service.
For the inventory mTLS server additionally pass `pinnedInventorySignerPublicKey`
from separately held operator trust configuration, not from a mutable ledger
property. This does not replace the client's own independent inventory pin.
Do not set the pinned key from the client,
remote response, app database, or issuer-controlled operation.

Existing non-strict DEV bridge construction still supports in-process
readback; it makes **no independent-host custody claim**. No production route
or default application behavior was changed by this patch.

## What was and was not tested

- The cryptographic tests reject a forged writer key, wrong operation_id,
  epoch, inventory root, digest, chunk count, nonce, clock and unflushed proof.
  A reviewer-found P2 where a malicious proof value was converted to a Buffer
  before its length check has a RED-to-GREEN regression test for coercion and
  oversized inputs. A separate reviewer-found key-reuse P1 now fails closed
  when the inventory signer equals the proposed physical attestor identity.
- The mTLS test uses real TLS 1.3 certificates and a **separate Node child
  process**; it rejects another client fingerprint, another scope, and a
  changed server pin. For transport determinism the child's readback is an
  explicitly **synthetic protocol fixture**, not a PostgreSQL read.
- A second real mTLS inventory endpoint test checks that a forged writer
  signer cannot get an append, a valid independent signer can, and a captured
  proof cannot satisfy the next nonce. Its PG readback is synthetic too.
- Concurrent live mTLS requests with the same authorized client certificate
  verify that the attestor rejects excess simultaneous readbacks rather than
  amplifying PostgreSQL work.
- The verifier unit test exercises the exact fields returned by the readback
  function and checks that the WAL barrier was invoked. It simulates SQL
  results; it does not prove a real PG transaction or power loss.
- The pre-existing disposable PostgreSQL 18 labs verify the restricted login,
  immutable SQL intent, physical bytes and WAL separately. A **new combined
  PG18+separate-process mTLS** run is still required before this pathway can
  be treated as independently validated against a real database.

## Residual blockers

This remains development **NO-GO**. SQLite signed inventory, PostgreSQL
commit, the attestor key, CAS/FLOOR, witness and external S3/Drive/WebDAV
stores do not share an atomic transaction. A signed receipt proves only a
bounded local PG observation by its attestor, not independent hardware, cloud
fsync, permanent durability, multi-host custody or release authorization.
The operator must maintain independent key/pin custody and monotonic anchors.
Further work must couple the attested receipt to the normative witness/FINISH
fence and owner restore grant at CAS, then prove restart, malicious writer,
rollback/fork, full historical migration and multi-host recovery in real labs.
