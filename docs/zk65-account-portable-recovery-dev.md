# Issue #65: offline account portable snapshot coordinator (development only)

`public/client/rootark-zk1-account-portable-recovery.js` exposes two UMD/browser and
CommonJS functions: `createArchive` and `recoverArchive`. It uses the existing
`rootark-zk1-keyring-portable-archive.js` cryptographic and trust checks for each
keyring. It does not integrate with the authenticated workspace or server routes.

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

This implements portable recovery of **file bundles inside keyrings**. It is
**not** complete account state restoration, an independent witness/CAS grant,
actual dual recovery, online revocation validation, proof of durable external
storage, or permission for production restore. Compartment membership outside
the supplied signed snapshots and server-side authorization remain separate.
