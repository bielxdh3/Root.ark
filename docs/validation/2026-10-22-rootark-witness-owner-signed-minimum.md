# Issue #65 — owner-authenticated witness minimum (development increment)

The independent witness's `casAnchorFloor.trustedMinimumHead` was previously
accepted as unsigned data in its operator JSON. A malicious **storage/config
editor** could lower that configured value, then roll the witness SQLite floor
back to an authentic previously signed prefix. A valid historical CAS signature
does not prove the prefix is the newest known floor.

This change adds an **opt-in mandatory signed minimum** controlled by **two
independently retained** environment pins: the owner signer fingerprint AND the
exact current signed-checkpoint digest. With both pins present in the witness
service environment, startup requires a separate Ed25519 owner signature over
the exact witness/status identities, floor sequence/hash and issued/expiry
timestamps. Missing, altered, expired, key-swapped, old-but-authentic or
re-signed-by-another-owner configuration fails closed **before floor or main
witness SQLite is opened for writing**. It does not change legacy behavior when
both explicit environment pins are absent, and a signature present without the
pins is not silently ignored.

## Operator-supplied trust inputs

Set the environment variable
`ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256` to exactly 64 lowercase hex
characters: SHA-256 of the **separately trusted owner's Ed25519 public SPKI
DER**. ALSO set `ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256` to 64 lowercase
hex characters: SHA-256 of the exact owner-signed checkpoint bytes as detailed
below. Both variables must be provisioned and advanced independently of mutable
witness JSON. Never provision the owner private key to the witness host.

The existing `casAnchorFloor` object must then include an `owner` object:

```json
{
  "dbPath": "E:\\independent-witness\\cas-floor.sqlite",
  "trustedMinimumHead": {
    "sequence": 2,
    "lastHash": "<64 lowercase hex from independently retained checkpoint>"
  },
  "owner": {
    "publicKeyPath": "E:\\witness-operator\\owner-public.pem",
    "issuedAt": 1792700000,
    "expiresAt": 1792703600,
    "signature": "<canonical Ed25519 base64url 64-byte signature>"
  }
}
```

The example timestamps/sequence are illustrative only, **not** valid for any
real deployment. The owner signs the following exact UTF-8 input using Ed25519:

```
ASCII("Root.ark/zk-1/cas-owner-floor/v1\0") ||
UTF8(JSON.stringify({
  type: "rootark-zk1-cas-owner-floor/v1",
  witnessKeyId: <witnessKeyId as base64url 16 bytes>,
  statusKeyId: <statusKeyId as base64url 16 bytes>,
  sequence: <independently observed integer high-water>,
  lastHash: <independently observed lowercase SHA256 hex>,
  issuedAt: <UNIX seconds>,
  expiresAt: <UNIX seconds>
}))
```

The signature is unpadded base64url, exactly 86 characters. Witness startup
rejects an issued timestamp more than 120 seconds in the future or more than
24 hours in the past, an expired signature, or a validity duration longer than
24 hours. The owner signer must differ cryptographically from the CAS status
signer and the witness signer.

The `ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256` value is computed by:

```
SHA256(ASCII("Root.ark/zk-1/cas-owner-floor/v1\0") ||
       UTF8(JSON.stringify(<exact signed statement above>)) ||
       BASE64URL_DECODE(owner.signature))
```

Advance this external digest whenever the owner approves a newer witnessed
CAS minimum. An attacker with access only to the witness JSON/database cannot
replay a prior still-valid signed checkpoint after its separately pinned digest
has changed. The key fingerprint alone would not provide this property.

## Verification

The standalone witness subprocess regression includes valid startup and
negative cases for a false owner key pin, missing checkpoint pin, stale valid
checkpoint replay, stripped owner signature, changed floor, forged owner
private key, and expired signed checkpoint. The
independent `casAnchorFloor` SQLite remains subject to signed journal and
physical rollback validation. Run:

```powershell
node --test test/issue-65-witness-cas-anchor-standalone.test.js
npm run validate:syntax
npm run validate:artifacts
git diff --check
```

## Unchanged trust limitations

* A checkpoint signer/public pin in the **same** editable configuration offers
  no independent trust. The pin must be provisioned through a distinct authority
  and protected service environment. If the process environment or owner private
  key is compromised, this opt-in check cannot defend it.
* An old owner-signed minimum **cannot** be replayed after the independently
  retained latest checkpoint digest is advanced; however, if that digest is
  not updated, is rolled back too, or the service environment is compromised,
  the older floor can still be accepted. The owner must advance and retain
  its monotonic minimum outside the witness and CAS domains.
* A hostile operating-system clock can bypass freshness assumptions. Real
  independent storage/key/clock custody and remote multi-host execution are
  not established by a localhost subprocess test.
* HTTP ACKs, a signed historical journal, and this owner minimum do not prove
  S3/Google Drive/WebDAV long-term durability or remote physical STOP.
* This is a development increment only: PR #228 remains draft, no merge/deploy.
