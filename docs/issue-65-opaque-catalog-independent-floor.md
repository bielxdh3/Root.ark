# Issue #65: independent monotonic opaque catalog floor (development)

The CAS authority must contact a separately administered floor service before
it can sign a catalog head receipt. The floor service maintains its **own**
SQLite WAL/FULL database, Ed25519 PKCS#8 signing key and mTLS identity. It
verifies the catalog owner's Ed25519 head signature and atomically advances the
expected sequence/digest. When V2 signer rotation is configured, the floor
independently checks owner-rooted recovery history, the signed witness head,
and a **fresh witness challenge** before accepting a new active signer.
Revoked devices, stale epochs, and a different signer at the same owner revision
are rejected. Its signed response binds the exact account,
compartment, keyring, CAS signer SPKI SHA-256, sequence, digest and fresh nonce.

The CAS service pins the floor's Ed25519 SPKI public key and TLS certificate
fingerprint. Each startup and each head/CAS request fetches a **fresh signed
floor head**; a stale `minimumHead` configuration never acts as authoritative
freshness. A local SQLite rollback behind the separately retained floor is
rejected on startup. Failure of floor TLS, identity, signature, state or
availability always prevents new catalog CAS receipts. After a local FULL
commit but before receiving the floor ACK, the CAS authority reconciles the
fully verified immutable, owner-signed snapshot history with the remote floor
one head at a time, then fetches another signed head before replying. A
conflicting digest fails closed. The catalog CAS signer and the independent
floor signer must be **different** Ed25519 private keys.

## Provisioning

The separately administered machine runs:

`NODE_ENV=development node scripts/run-zk1-opaque-floor-service.js ABSOLUTE_CONFIG_PATH`

The separate floor service's strict JSON configuration must contain exactly:

`developmentOnlyOptIn` (`true`), `bindHost` (IP), `port` (1024–65535),
`databasePath` (private absolute SQLite path), `bootstrapNew` (true only on
first creation), `signingPrivateKeyPath` (floor-only Ed25519 PKCS#8),
`casSignerPublicKeyPath` (pinned CAS Ed25519 SPKI),
`catalogSignerPublicKeyPath` (pinned owner/device Ed25519 SPKI),
`trustedScope` (`account_id`, `compartment_id`, `keyring_id` in canonical
base64url), `tlsKeyPath`, `tlsCertPath`, `clientCaPath`, and
`authorizedClientFingerprint256` (pinned mTLS CAS-client certificate).
For owner-rooted V2 signer rotation, add an `ownerTrust` field containing
`genesisDigest`, `witnessPublicKeyPath`, `witnessKeyId`,
`minimumHead` (`revision`, `digest`) and `witnessTransport` (`endpoint`,
`caPath`, `clientKeyPath`, `clientCertPath`, `serverFingerprint256`, `timeoutMs`).
These identity pins and the floor's durable owner revision cannot be lowered
by editing the catalog CAS configuration. The floor must independently reach
the pinned witness; absence or failed verification refuses the CAS transition.
An existing static-signer floor cannot be restarted in V2 mode without a
separate owner trust identity provisioning ceremony.

The catalog CAS service's previous strict JSON configuration gains six
**required** fields: `floorEndpoint` (HTTPS base URL with explicit port and
trailing `/`), `floorCaPath`, `floorClientKeyPath`, `floorClientCertPath`,
`floorServerFingerprint256` and `floorSignerPublicKeyPath` (out-of-band pinned
Ed25519 SPKI). Keys and certificate pins are provisioned by distinct operators;
do not distribute the floor signing private key to the catalog CAS service.

Back up and restore the floor's SQLite and its signing identity under the
independent operator's controls. Never bootstrap a replacement floor at
sequence zero using an old CAS database: that loses the monotonic guarantee.
Without a higher-level owner-signed rotation ceremony, changing the pinned
floor signing SPKI is a trust reset and must be explicitly approved out of
band. The floor process must run on a different security and failure domain;
running both processes on one administratively controlled machine does **not**
establish independence.

## Evidence and limits

`node --test test/issue-65-opaque-cas-real-multiprocess.test.js` exercises
separate OS processes, distinct SQLite databases and Ed25519 keys, pinned
mTLS, concurrent writers, nonce replay, stale static configuration, floor ACK
loss, catalog ACK loss, power loss after local FULL commit, signed restart
reconciliation, forged floor SPKI, service unavailability and malicious CAS
SQLite rollback. A separate signer-rotation mTLS test verifies the V2 path
with two mutually authenticated HTTPS servers and owner/witness proof.
The owner-V2 fixture uses separate TLS endpoints and databases in the same
test process; the rollback/fork fixture uses separate OS processes.
These are local development fixtures, not evidence of
remote-host physical independence, cloud durability, external WORM retention
or production deployment. The floor SQLite itself must be independently
protected against administrator rollback and disaster recovery regressions.
