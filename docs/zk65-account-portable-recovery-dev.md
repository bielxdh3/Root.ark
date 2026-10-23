# Issue #65: offline account portable snapshot coordinator (development only)

`public/client/rootark-zk1-account-portable-recovery.js` exposes two UMD/browser and
CommonJS functions: `createArchive` and `recoverArchive`. It uses the existing
`rootark-zk1-keyring-portable-archive.js` cryptographic and trust checks for each
keyring. The normal authenticated browser workspace exposes an explicit offline
selection flow in development mode; it does not add server archive routes.

The browser selection file is a **user-supplied offline** JSON document with
`schema: "rootark-zk1-account-workspace-selection/v1"`, `accountId`, and 1–8
`keyrings`. Every keyring entry explicitly provides `scope`,
`pinnedCurrentHead: { revision, digest, epoch }` (base64url digest),
`signedDeviceGrant`, `ownerHistory` (genesis-to-current signed chain),
`signerKeyId` (base64url), `deviceId`, `holderSecretFile` (32-byte binary input),
and `files` (names of locally selected files during create, `[]` during recover).
The browser requires the externally selected current owner public key/SPKI pin,
current session/grant/head/history and independently provisioned browser floor
for **each keyring**. Recovery additionally requires the independent account
archive SHA-256, not a hash inside the encrypted package. Creation requires the
owner PKCS#8 signing key supplied locally and proves it matches that owner key.
The encrypted archive, its digest, and recovered contents are downloaded locally;
no plaintext/CEK is uploaded. Inputs and output buffers are cleared after use.

The UI packages only the local file selection per keyring; it does **not** prove
the set is the complete signed keyring/account inventory or include all versions.

## Opt-in recovery of an older owner head (DEV, browser)

Normal `archive-recover` and `account-recover` still require the ordinary
owner-current-head equality and cannot automatically fall back to historic mode.
For an older keyring archive, explicitly check **archive-historical-opt-in** and
select an additional independent local JSON proof file with schema
`rootark-zk1-keyring-history-endorsement/v1`, `scope`, and
`historicalRecovery: { signedOwnerHistoryChain, currentSignedDeviceGrant,
currentOwnerRootCheckpoints }`. The 2–64 signed checkpoints must start at
genesis and finish at the currently PINNED head. The current grant must be
ACTIVE, owner-signed, match the separately imported grant exactly, and the
1–12 current root checkpoints must re-endorse **every exact archived ciphertext
root** under that current head. The browser reconstructs Ed25519 history proof
brands from the imported genesis chain; serialized `verified: true` flags do not
count. The crypto module rechecks the historical archive's original signed
history and roots, plus the newly signed current grant and all endorsements.
Historic recovery also requires one-use PoP from the **current ACTIVE device**:
select its private Ed25519 PKCS#8 in the ordinary browser `private` field.
The client module issues a fresh, in-process WeakMap-branded challenge bound to
the selected archive hash, owner SPKI/head, scope and current signed grant; the
browser signs it with a non-extractable imported device key, then the module
consumes it only once. Neither nonce nor signature is accepted from a user JSON
file or server response. If key possession cannot be established, no historical
plaintext is released.

For an older archive in `account-recover`, explicitly check
**account-historical-opt-in** and supply `currentOwnerRootCheckpoints` on each
affected keyring within the independently selected account JSON. The existing
`ownerHistory`, `signedDeviceGrant` and `pinnedCurrentHead` on each keyring then
represent the CURRENT independent owner authority. A keyring whose archive head
still matches current must *not* include historical checkpoints; a keyring whose
archive head differs *must* include them. One invalid keyring aborts the entire
account batch and no local file is released. All inputs are opt-in, locally
selected, bounded and session/CSRF/logout fenced. Neither flow uploads
plaintext or CEK nor authorizes production restore, account completeness,
online revocation, witness custody, or independent external durability.
Every affected keyring's JSON selection must additionally name `devicePrivateFile`,
and the user must select the corresponding *current* device PKCS#8 file in
`account-historical-device-privates`. Each per-keyring one-use challenge binds
both the individual archived keyring SHA-256 and the independently pinned
account archive SHA-256; missing, reused, or incorrect private keys deny the
entire operation. The browser never imports a caller-provided PoP nonce.

- `createArchive({ accountId, ownerSigningKey, ownerPublicKey,
  independentOwnerSpkiSha256, keyrings })` accepts 1–8 existing keyring-archive
  **creation inputs**. They must belong to the same account and resolve to the
  same independent owner SPKI fingerprint. Each keyring must already have a
  genuinely owner-signed active device grant, signed history and per-object
  ciphertext-root proofs. Entries are sorted by compartment and keyring ID.
- Its result contains `archive` and `archiveSha256`. The serialized aggregate
  is bounded to **16 MiB**; each included keyring separately retains the
  existing 12-file and per-keyring limits. The aggregate includes each encrypted,
  owner-signed keyring archive and its digest. The aggregate manifest is owner
  Ed25519-signed using its own domain separation.
- **Outside the server and independently of the archive**, the holder must retain
  the exact `archiveSha256`, the owner SPKI SHA-256, and the **current** owner
  revision/digest/epoch for **every** keyring. `archiveSha256` returned by the
  creation function is not itself proof of independent custody.
- `recoverArchive({ accountArchive, independentlyPinnedAccountSha256,
  accountId, ownerPublicKey, independentOwnerSpkiSha256, keyrings })` requires
  an ordered array of all keyrings' recovery inputs, each with `scope`,
  `pinnedCurrentHead`, independent `ownerPublicKey` and
  `independentOwnerSpkiSha256`, 256-bit `recoverySecret`, `signerKeyId`, `deviceId`
  and `previousOwnerHistoryProof`. Each keyring's existing verifier checks the
  owner grant/history/root before decrypting its encrypted bundle.
- The API returns plaintext locally only when **all** keyrings pass, and wipes
  already opened files and internal copies of holder secrets on failure.
  The caller owns successful returned `file.data` buffers and must clear them
  after use. No plaintext or content encryption key is sent to the server.

## Historical recovery: additional device proof of possession

An archived keyring may be recovered under a later owner-signed head **only**
with the verified genesis-to-current owner history, a fresh owner-signed ACTIVE
grant at the independently pinned current head, and newly owner-endorsed roots
for **every** archived ciphertext object. These facts alone do **not** prove
possession of the device private key named in the grant.

For each *attempt*, the verifier holding the live `RootarkZk1KeyringPortableArchive`
module instance must call `issueHistoricalRecoveryChallenge` with exactly:

- `archiveSha256`: independently pinned keyring ciphertext archive SHA-256;
- `accountArchiveSha256`: independently pinned aggregate SHA-256 for an account
  recovery, or `null` for direct keyring recovery;
- `scope`, `pinnedCurrentHead`, `independentOwnerSpkiSha256`, and
  `currentSignedDeviceGrant` matching the intended restore.

The verifier exports the challenge's **domain-separated bytes** through
`historicalRecoveryChallengeMessage(challenge)`. The authorized device, after
independently checking the requested restore purpose, signs those bytes with
the non-extractable Ed25519 private key corresponding to the **current grant's**
`authorization_public_key`. Include the result as canonical base64url in
`historicalRecovery.devicePoP = { challenge, signature }` along with the chain,
current grant, and fresh root endorsements. Never sign these bytes using the
owner's root signing key in place of the enrolled device key.

The challenge is a 256-bit verifier-generated nonce bound to the archive,
aggregate (if applicable), owner SPKI, exact scope, current revision/digest/epoch
and entire current grant. It expires after 120 seconds, rejects clock rollback,
and is consumed once on verification, even on a failed signature. It has a
private in-process identity: JSON cloning or importing it into another tab,
process, or browser session does **not** transfer the verifier's one-use state.
Mint a new challenge for each retry. The previously supported nonhistorical
recovery mode does not require a device challenge.

This demonstrates possession of the device signing key for a bounded **offline
ceremony**, not an externally authenticated time source, independent witness,
live revocation proof, complete historical inventory, or production access
permission. The device must not sign unsolicited challenges.

This implements portable recovery of **file bundles inside keyrings**. It is
**not** complete account state restoration, an independent witness/CAS grant,
actual dual recovery, online revocation validation, proof of durable external
storage, or permission for production restore. Compartment membership outside
the supplied signed snapshots and server-side authorization remain separate.
