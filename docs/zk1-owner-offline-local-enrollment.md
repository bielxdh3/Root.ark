# Owner-side offline ZK1 V2 enrollment (development only)

Status: **bounded executable development ceremony**, not a server endpoint,
production enrollment service, physical witness verification, or integrated
device revocation/rotation UI. The existing normal authenticated browser can
generate a fresh device enrollment request, answer the HPKE+Ed25519 challenge,
and import the final `rootark-zk1-v2-owner-browser-delivery/v1` JSON.

## Trust boundary

This tool executes **on a trusted owner-controlled host**, separate from
Root.ark's application/storage server. No owner private key, device secret,
compartment root, epoch key, CEK or plaintext is posted to a server.
Owner/actor private keys and compartment epoch keys must be supplied by a
locally trusted JavaScript provisioning module. That module is executable
trusted operator code, never a remote downloaded plugin or user request.
It must:

1. Read the genuine base manifest, base signed witness receipt, full ordered
   signed transitions and epoch keys from owner-controlled offline storage.
2. Call `verifyTrustedDeviceRecoveryHistoryV2` from
   `src/crypto/rootark-zk-recovery-history-v2.js` to return an actual
   **WeakMap-branded verifiedHistory**, not caller-supplied `verified:true`.
3. Return exactly the fields `verifiedHistory`, `trustedOwnerPublicKey`,
   `trustedCommitmentSignerPublicKey`, `trustedPriorCommitment`,
   `trustedActorPrivateKey` and `ownerPrivateKey`. The latter two signing
   identities are different: the **current ACTIVE device** signs the proposed
   V2 transition; the independently pinned **owner** signs the grant only
   after committed-head confirmation.

Only populate the CLI directory with operator-owned files (no writable access
by other users). Use an ephemeral dedicated folder on a trusted filesystem.
The CLI rejects symlinks in its owned directory and existing output names.
The path checks are not atomic defenses against a hostile local administrator
replacing directory components concurrently.

## Running the ceremony

Run `node scripts/zk1-owner-offline-enroll-local.js` with **all** these
parameters; they cannot be omitted or inferred from a server response:

```text
--owned-dir E:\my-offline-owner-fixture
--context-module owner-context.js
--owner-spki <independently obtained SHA-256 of owner Ed25519 SPKI, base64url>
--witness-spki <independently obtained SHA-256 of witness Ed25519 SPKI, base64url>
--head-revision <current externally pinned revision>
--head-digest <current externally pinned V2 manifest digest, base64url>
--head-epoch <current externally pinned epoch>
--prior-receipt-sha256 <independent SHA-256 of previous signed commitment receipt, base64url>
```

`owner-context.js` must live inside `--owned-dir` and export an async function
returning the trusted object above. The owner must independently verify
**the source** of the SPKI hashes, head, prior receipt hash and scope.
A hash copied from the proposed request or from an untrusted server is
**not an independent pin**. The CLI cannot attest how you obtained the pins.

With `request.json` already in that folder:

1. Start the CLI and **keep that process running**.
2. Transfer its `challenge.json` to the new browser via an independent
   channel. The browser uses its *own* new device Ed25519 PKCS#8 and X25519
   PKCS#8 keys to export `rootark-v2-device-pop-response.json`. Copy that
   JSON **only** as `response.json` into the owner folder.
3. The owner CLI verifies the one-shot PoP, current ACTIVE actor, complete
   history and monotonic timestamps, and writes `candidate.json`. Its
   `manifestBase64` is an existing-device-signed candidate, **not**
   proof of durable commitment or an owner-approved new device. Send this
   candidate to the independently controlled CAS/witness process for
   **actual** commit; do not invent a success receipt locally.
4. After independently confirming that exact operation and manifest digest
   reached the committed head, transfer the externally signed and current
   `rootark-zk1-offline-commitment-receipt/v1` to the owner directory
   as `committed-receipt.json`. It must bind the exact operation ID,
   fresh PoP challenge, request nonce, commit nonce, prior receipt hash,
   strictly increasing witness sequence and expiry. The CLI checks the
   Ed25519 signer against its separately pinned witness SPKI.
5. Only then is `browser-delivery.json` created. The normal V2 browser must
   **still** receive the owner and witness SPKI pins, current head and hash
   of the previous commitment receipt over independent channels. Importing
   the JSON alone never self-certifies a device. The ZK1 strict server
   independently requires its current full owner-signed V2 history and
   fresh witness authority before a ciphertext GET.

No private signing key or plaintext is included in `candidate.json` or
`browser-delivery.json`. These files do contain public scope identifiers,
device public keys, signed manifest metadata, and **wrapped epoch keys**
(ciphertext). Protect them against unauthorized modification.

## Failure and revocation boundaries

The entire ceremony is **one live Node process** for at most five minutes.
Unexpected exit, expired PoP, stale prior receipt or lost commitment
confirmation prevents delivery and requires a **new operation, new PoP
challenge, a newly verified authoritative head and new output directory**.
Do not deserialize or fake the private WeakMap provenance after a crash.
A signed-but-uncommitted candidate cannot be used as current head.
If an old candidate was in fact committed before a crash, first refresh the
owner's externally pinned head/history; never retry against stale revision.

This bounded release does **not** automatically revoke devices or rotate
compartment encryption roots. Both are separate state transitions requiring
new epoch keys, signed V2 authorization, an independent witness/CAS commit and
verified post-commit current head. **Do not mark a device revoked from a
locally staged manifest, self-reported revision, expired proof, or a removed
browser file.** Historical ciphertext already downloaded cannot be revoked.

The tool proves cryptographic signature continuity and signed witness claims;
it does not prove actual independence of physical custody, remote storage
durability, availability, absence of malicious local code, or production
acceptance. The exact current tool remains development-only and does not
alter normal Root.ark UI, sync routes or the 9-pin multiprovider restore gate.

## Executable dry-run and negative tests

Run on either Node 22 or Node 24:

```text
node --test test/issue-65-owner-offline-local-orchestrator.test.js
```

The disposable E2E test spawns the **real CLI in a separate Node process**,
rebuilds verified V2 history from signed fixtures and epoch keys, uses a
second browser crypto implementation to answer PoP, signs a genuine
test-only Ed25519 receipt and verifies delivery. Additional adversarial
cases reject forged owner/witness pins, wrong prior hash/current head,
wrong PoP, unsigned self-reported head, hostile signer, wrong nonce,
replayed witness sequence, expired receipt, digest fork, incorrect owner
private key and clock rollback. No production data/keys or external
providers are used by the test.
