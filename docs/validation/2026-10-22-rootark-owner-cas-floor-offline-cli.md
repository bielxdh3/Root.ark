# Issue #65 — offline owner-side CAS witness minimum signer

`scripts/zk1-owner-cas-floor-sign-offline.js` creates a version-2 Ed25519
owner-authenticated CAS floor checkpoint without network access. It shares
the *exact* domain, field order, signing bytes, signer fingerprint and
checkpoint digest implementation with `scripts/zk1-witness-standalone.js` via
`src/crypto/rootark-zk1-owner-cas-floor-checkpoint.js`. Its signed statement
includes `witnessSpkiSha256` and `statusSpkiSha256` in that exact order after
the two 16-byte key IDs, computed from the independently provisioned public
Ed25519 SPKI DER keys. It uses domain `Root.ark/zk-1/cas-owner-floor/v2\0`
and type `rootark-zk1-cas-owner-floor/v2` exclusively. The prior signed v1
domain/type is rejected by the standalone witness even with valid v1 pins.

The owner must independently establish and retain the newest witnessed CAS
`sequence` and `lastHash`. The CLI **does not inspect witness or CAS databases,
ask either service for a floor, or authenticate the provenance of a floor
provided to it**. Passing a server-supplied historical floor as the operator
input is unsafe; the explicit `--confirm-independent-minimum` flag and
`source` declaration record the owner's responsibility, not a proof of it.

## Offline invocation

Prepare a dedicated, operator-controlled directory, accessible only to the
trusted owner, containing separately provisioned PEM files for the owner
private/public Ed25519 pair and the witness/status **public** Ed25519 keys.
Do not place owner private key material on the witness or CAS hosts. The
owner private key may be encrypted at rest only when decrypted by a separate,
secure provisioning step; this non-interactive CLI accepts a directly usable
PKCS#8 PEM and does not handle passphrases.

Create `minimum.json` inside the owned directory:

```json
{
  "source": "owner-retained-independent-floor/v1",
  "witnessKeyId": "abcdefghijklmnopqrstuv",
  "statusKeyId": "ABCDEFGHIJKLMNOPQRSTUV",
  "trustedMinimumHead": {
    "sequence": 2,
    "lastHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "issuedAt": 1792690000,
  "expiresAt": 1792693600
}
```

These identity, hash and timestamps are **illustrative**. Supply exact
base64url key IDs of 16 bytes, the independently held latest witnessed
sequence/hash and current Unix-second timestamps. The CLI rejects issuance
older than 120 seconds or more than 60 seconds into the future, expiration
at/before the current clock, and validity over one hour. The witness has its
own freshness checks (up to 24 hours); this signer deliberately uses a
shorter window. Keep clocks synchronized and treat a skew warning as a failed
signing request.

From a PowerShell terminal with Node 22, use absolute paths for **all**
arguments (the operator chooses directory and artifact file names):

```powershell
node scripts/zk1-owner-cas-floor-sign-offline.js `
  --owned-dir 'E:\OwnerCAS' `
  --input 'E:\OwnerCAS\minimum.json' `
  --owner-private-key 'E:\OwnerCAS\owner-private.pem' `
  --owner-public-key 'E:\OwnerCAS\owner-public.pem' `
  --witness-public-key 'E:\OwnerCAS\witness-public.pem' `
  --status-public-key 'E:\OwnerCAS\status-public.pem' `
  --output 'E:\OwnerCAS\checkpoint-2.json' `
  --confirm-independent-minimum
```

The output file is newly created and never overwritten. Its JSON includes
`casAnchorFloor.trustedMinimumHead`, the **exact** `casAnchorFloor.owner`
object consumed by the standalone service, and both independent `envPins`:

* `ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256`: SHA256 of owner Ed25519 SPKI DER.
* `ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256`: SHA256 of the domain,
  canonical statement and raw 64-byte owner signature.

The witness config additionally needs its independently selected
`casAnchorFloor.dbPath`. Keep **both witness/status public-key fingerprints**
from the owner-provisioned checkpoint consistent with the actual witness
private key's public half and CAS status public key. A config editor substituting
either signer while preserving its 16-byte key ID fails before SQLite opens.
Place the owner **public** PEM at an appropriate
absolute path on the witness host and update only
`casAnchorFloor.owner.publicKeyPath` if the path differs; that path itself is
not in the signed statement. Provision the two pins **out of band** in the
witness service environment and retain/advance the current checkpoint digest
in owner-controlled storage. Never source those pins from editable witness
JSON. A prior valid checkpoint must not replace a newer retained digest.

The CLI fails closed on malformed or extra fields, outside-owned/missing
paths, symlinks or junctions observed in parent components, public/private
key mismatch, any reused owner/witness/status Ed25519 signer, identical
witness/status key IDs, stale/expired timestamps,
invalid floor encoding, output path collisions or unsafe exclusive creation.
It emits only `OWNER_FLOOR_SIGNED` or `OWNER_FLOOR_SIGN_FAILED` to the console,
never private-key material. Private PEM buffers are zeroed after import.

## Validation and limits

```powershell
node --test test/issue-65-owner-cas-floor-offline-signer.test.js
node --test test/issue-65-witness-cas-anchor-standalone.test.js
git diff --check
```

The standalone subprocess test signs with the offline CLI, starts the real
witness against a disposable genuine signed CAS floor, and rejects altered
minimum/key, authentic signed-v1 downgrade (including same-ID impostors),
v2 signer substitution at floor zero, and old signed-checkpoint replay. The
CLI test verifies the v2 Ed25519 signature binds both public fingerprints;
it additionally
rejects key reuse (including identical witness/status PEM contents at different
paths), duplicate authority IDs, divergent PEM, forged source, bad timestamps,
outside-owned paths and overwrite attempts without creating an artifact.

This owner-side convenience tool cannot verify that an operator's minimum
came from a physically durable independent quorum. The explicit owner source
assertion is not cryptographic provenance. Local filesystem adversaries able
to swap Windows directory junctions between checks can still race standard
Node path/file APIs (no portable `openat` / directory-handle confinement).
Windows ACL enforcement and clock integrity are operator responsibilities;
an attacker controlling the host, owner key, pin environment or retained
monotonic checkpoint can defeat the intended independent trust boundary.
No production or multi-host attestation is claimed.
Signed v1 installations require fresh owner-side v2 signing and independent
reprovisioning of both pins; no downgrade mode exists under signed-owner policy.
