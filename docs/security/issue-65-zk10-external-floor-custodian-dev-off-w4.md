# Issue #65 ZK10 — bounded durable floor component, DEV-OFF W4

**Not R1 production custody.** This is an independently instantiable Node
library, **not** an HTTP listener, a replacement for the owner/issuer/witness,
or evidence of an independent administrator. It does not alter ZK10 routes,
the release gate or production deployment. It always reports
independentOffServerCustodyProven: false. Production remains **NO-GO**.
Read the [W170 wire contract](issue-65-zk10-external-floor-attestation-w170.md).

## Trust setup: nothing is self-provisioned

The operator must explicitly supply devOff: true, absolute databasePath and
anchorDatabasePath in existing restricted directories, ownerPublicKey (an
independently pinned Ed25519 public KeyObject), custodianPrivateKey (a separately
retained Ed25519 private KeyObject) and its pinned custodianSpkiSha256.
The library also refuses to start under NODE_ENV=production.
The owner and custodian keys must differ. This component does not generate,
persist, load, or default a signing private key. The two SQLite filenames must
be different and cannot be direct symlinks or hardlinks.

Initial boot requires an authentic owner-signed bootstrap commitment, domain
Root.ark/zk10/custodian-owner-genesis/v1 followed by a NUL byte, with these
canonical fields in this order:

    type, sequence, head_digest, enrollment_root, immutable_account_id,
    identity_digest, lease_serial

Its signature is Ed25519 base64url. The first sequence must be positive and
lease_serial must be zero. Both SQLite files must be absent at first boot and
both must exist at restart. A bootstrapping signature is never sufficient to
replace an existing database or missing high-water file.

An operator can instantiate createDevOffZk10MonotonicFloorCustodian(config)
from src/services/zk10DevOffMonotonicFloorCustodian.js. To obtain a signed
W170 CURRENT, attest(request, ownerLease) additionally requires a separately
owner-signed assertion **for every lease**; its signature domain is
Root.ark/zk10/custodian-owner-lease/v1 followed by a NUL byte, canonical fields:

    type, sequence, head_digest, enrollment_root, immutable_account_id,
    identity_digest, operation, nonce, lease_id, lease_serial,
    issued_at_ms, lease_expires_at_ms

Request fields immutable_account_id, identity_digest, operation, nonce,
lease_id and lease_expires_at_ms must match that signed assertion exactly.
Nonce is 32 random bytes in canonical base64url, lease ID is 16 bytes,
and lease_serial must increase by exactly one. The signed head may stay
identical or advance by one sequence. Downgrades, same-sequence digest changes,
account/identity swaps, expiry, malformed time values, forged owner signatures
and replayed nonce/lease IDs are rejected. The helper never creates a lease.
The disposable journal caps the lease serial at 100,000; exhaustion fails
closed, with no automatic reset or rotation.

After the high-water commits, the component signs exactly the 12 W170 fields
in the documented order with its separately pinned custodian Ed25519 key,
domain Root.ark/zk10/external-floor-current/v1 followed by a NUL byte. Its
response is a floor wrapper with a base64url signature, and it never signs
before completing the durable writes. Failure reports generic codes only.

## High-water and crash behavior

- Both SQLite stores enforce journal_mode=DELETE and synchronous=EXTRA;
  updates use BEGIN IMMEDIATE transactions. The separate minimum retains the
  signed head, account, identity and lease serial; the primary retains that
  floor plus consumed nonces and lease IDs.
- The minimum file is committed FIRST, then the primary. Interrupted or
  ambiguous fsync between these commits leaves a mismatch and restart
  **fails closed**. The helper never automatically resets or repairs it.
- An older primary file restored alongside the newer minimum is rejected,
  including after restart. Missing anchor, key mismatch, incomplete pair,
  expired signed lease or replay also fails closed.
- This is **not an atomic distributed transaction across two SQLite stores**.
  A crash between commits can make the custodian unavailable until a separately
  owner-authorized and audited recovery procedure is designed.
- **Critical external blocker:** two SQLite files on one machine are NOT
  independent off-host custody. Restoring BOTH to an older snapshot can evade
  local detection. A truly separately administered and immutable high-water
  medium, off-host independent key custody, physical durability verification
  and operator trust decisions remain mandatory. Separate filenames, fsync
  settings, and two generated fixture signers do not prove any of those.

No trusted current issuer proof, real lease serialization, mTLS server,
identity bridge, owner key custody, physical cutover or production route is
provided. A secure TLS1.3/mTLS facade would have to independently authenticate
the live caller, issuer and lease *before* calling this helper; blindly
forwarding app-controlled JSON is forbidden. No lease-to-I/O authorization,
provider registration or production release gate is implemented.

## Disposable test evidence

Run: node --test test/issue-65-zk10-external-floor-custodian-w4.test.js

Tests use two distinct test-only Ed25519 custodian signers, temporary SQLite
files, exact W170 signature verification, invalid bootstrap/signers, stale
or forged leases, nonce/lease replay, parallel same-lease invocation,
owner-authorized head advance, restart and an older-primary rollback while
the higher minimum is retained. These tests do not prove a real off-host
operator, network, actual Windows/Linux crash durability or a production R1.
