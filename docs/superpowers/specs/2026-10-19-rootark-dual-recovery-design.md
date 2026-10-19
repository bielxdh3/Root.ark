# Root.ark Dual Recovery: Draft Specification for Independent Review

- **Status:** `REVISED_DRAFT_FOR_INDEPENDENT_REVIEW` — revision 3; not approved for implementation.
- **Architecture direction:** The owner approved shared compare-and-swap (CAS) as the target. No shared database, storage service, deployment topology, client keychain, or rollback witness is assumed to exist.
- **Issue:** [#65 — Architecture: Zero-Knowledge v1](https://github.com/bielxdh3/Root.ark/issues/65).
- **Baseline:** `Root/main` SHA `0636d638eee1ca5a75fde59936a9dbd3c66077cd`.
- **Review boundary:** This document describes both recovery paths and their target guarantees. It authorizes no code, dependency, migration, UI, deployment, release, issue close, or PR merge.
- **Independent review:** Revisions 1 and 2 received static architecture/security reviews; revision 3 awaits independent review. This is not a formal cryptographic audit. Owner approval of this detailed specification is pending.
- **Revision 3 rule:** Section 12 is normative for the reviewed findings and supersedes conflicting details in Sections 4–11. Earlier sections remain context only where they do not conflict. This revision changes this specification only; it does not implement or approve the design.

## Revision history

| Revision | Date | Basis | Changes |
|---|---|---|---|
| 1 | 2026-10-19 | Initial draft at `64512a2f94444ef7d9380e6e525d48b9ceeddbae`, based on `Root/main` `0636d638eee1ca5a75fde59936a9dbd3c66077cd` | Initial shared-CAS target and explicitly blocked integrations. |
| 2 | 2026-10-19 | Independent static review verdict `REVISIONS_REQUIRED_FOR_SPEC_APPROVAL` against revision 1; not a formal cryptographic audit | Adds authenticated transition history plus independent freshness witness protocol; actor/operation authorization matrix and HPKE+Ed25519 target proof; exact non-circular package-envelope binding and crash states; bounded KDF execution; rootKey compatibility evidence; complete epoch coverage; honest secure-storage rollback limits; TTL policy; proposed module/test ownership map. |
| 3 | 2026-10-19 | Independent static review verdict `REVISIONS_REQUIRED_BEFORE_SPEC_APPROVAL` against revision 2; not a formal cryptographic audit | Adds a durable pending-reservation read/admission gate and independently trusted CAS terminal-status proofs; defines compromised-package replacement with mandatory forward epoch rotation; clarifies effective TTL, history-capacity warnings/exhaustion, target HPKE-proof limits, and required adversarial test cases. Preserves all infrastructure and product-approval blocks. |

## 1. Purpose and guarantees

Protected content must have two independent recovery paths:

1. A user-held password-protected emergency package can authorize a replacement device and restore the key material actually contained in the package, even when no trusted device is available.
2. A currently authorized trusted device can authorize a replacement device and transfer the key material it still holds, even when no recovery package is available.

Both paths operate on the client. Login, account password reset, TOTP, administrator status, or possession of server data is not content-key authorization. If the user loses every trusted device and every usable package, there is no administrative master key or hidden fallback; protected content may be unrecoverable.

The server stores and relays only public authorization metadata, signatures, wrapped keys, and opaque encrypted package bytes. It never receives a package password, Argon2 output, device private key, recovery signing key, epoch key, CEK, or plaintext. A package copy may be retained by the server as ciphertext, but the user-held export remains independently retainable and is not replaced by the server copy.

## 2. Current verified capabilities and limits

The following observations were made against the stated baseline and task worktree. No host or production inspection was performed.

| Area | Verified state | Design consequence |
|---|---|---|
| Account persistence | `db/index.js` defaults `DB_ENABLED` to false. When enabled, it selects SQLite from `DATABASE_URL` or `data/rootark.sqlite`. Local selected env settings do not establish a live authoritative backend. | Do not assume SQLite is enabled, shared, or authoritative. |
| Sync persistence | `server.js` defaults `SYNC_OBJECTS_FILE` to `./data/sync-objects.json`. `SyncObjectStore` holds process memory, uses an instance-local Promise queue, and writes JSON. | No cross-process/replica CAS is present; this store cannot host recovery coordination. |
| Existing SQLite transactions | An unrelated rate-limit store uses immediate SQLite transactions. No recovery repository, shared volume, replica topology, backup/restore guarantee, or deployment-wide CAS is evidenced. | A local SQLite transaction is not shared-CAS evidence. No SQLite-only fallback is allowed. |
| Node client | `sync-client/rootark-sync-v2.js` reads file/device private keys from environment variables and constructs them in memory. No OS credential store or durable high-water store is in that path. | Trusted-device integration and durable rollback protection are blocked. Do not persist recovery keys in env files or plain files. |
| Browser client | Existing browser crypto provides AES-GCM JSON helpers. Protected records use IndexedDB with caller-supplied keys. No integrated browser Argon2id, HPKE, Ed25519 recovery lifecycle, device keychain, or rollback-resistant high-water mark is present. | Browser recovery is blocked; IndexedDB is not a keychain or rollback defense. |
| Crypto library | `src/crypto/rootark-zk-1.js` provides deterministic CBOR, AES-256-GCM, HPKE X25519/HKDF-SHA256/AES-256-GCM, Ed25519 authorization helpers, and a libsodium Argon2id13 wrapper. `deriveRecoveryKey` accepts explicit KDF limits but does not impose a recovery profile ceiling. | Reuse the frozen suite; add strict recovery-specific profile checks only after approval. |
| Existing keyring | `src/crypto/rootark-zk-keyring.js` is an in-memory, unwired library. Manifest v1 has account ID, epoch, devices, wraps, and an epoch-keyed MAC; it has no compartment ID or revision. Same-epoch rollback is not detected. | It is not a persistence, signed authorization, or rollback-safe recovery integration. |
| Local validation setup | Repository workflows pin Node 22; `package.json` declares no `engines.node`. The current task runtime is Node 24.14.1; the worktree has no `node_modules` and current temp/cache variables are outside E:. | No tests or dependency install were run. If implementation is later approved, validation must first use E:-only caches/temp/output and a repo-aligned Node 22 runtime. |

## 3. Threat model

### Assets and trust boundaries

Assets are plaintext, CEKs, compartment epoch keys, device HPKE/Ed25519 private keys, the recovery signing private key, the package password, the encrypted recovery package, signed manifests, CAS revisions, local caches, and server backups. Boundaries are the user, authorized device, replacement device, browser or native runtime, Root.ark service/operator, persistence provider, backup/restore process, and network.

### Attacker capabilities and required outcomes

| Attacker or failure | Required outcome | Limit that must be stated |
|---|---|---|
| Database, backup, or ordinary administrator reader | Cannot decrypt the package, unwrap epoch keys, or recover content from opaque state alone. | If the attacker also obtains a weak package password, the package permits offline guessing; no server rate limit stops offline guessing. |
| Curious, compromised, or malicious service | Cannot forge device/recovery signatures or decrypt keys. It may deny service or withhold records. | CAS on a trusted backend enforces update ordering; by itself it cannot prove to a first-use client that a malicious server has not hidden a newer head. |
| Network attacker | Cannot alter or substitute a package, manifest, target device key, or recovery operation undetected. | Availability and traffic metadata remain exposed. |
| Stolen package ciphertext | Cannot be opened without the user secret; parser/KDF bounds prevent attacker-selected memory/CPU amplification. | Security depends on password entropy and the approved Argon2 profile. |
| Stolen password plus package | Attacker can read the package’s included keys and recovery signer. | Revoke the registered recovery signer and rotate future keys from another trusted authority. Past copied keys/data cannot be revoked. |
| Compromised or revoked device | A revoked device cannot authorize new devices or receive new epoch keys after revocation. | Previously copied keys, plaintext, caches, and ciphertext remain outside retroactive revocation. |
| Replayed, reordered, forked, or concurrent updates | Stale CAS, duplicate operations, conflicting forks, and revision rollback fail closed. | A malicious storage operator restoring an old database image needs a separately trusted monotonic witness/high-water source to be detectable by a new device. None is verified today. |
| Malformed package or hostile KDF header | Reject before expensive Argon2 allocation; expose generic non-secret errors. | Runtime memory/time availability still depends on device resources. No weaker fallback is permitted. |

The desired confidentiality claim assumes clients and user-held secrets remain uncompromised. It does not hide object count, ciphertext size, timing, request frequency, or required opaque routing metadata. It does not provide recovery after all keys and recovery material are lost.

## 4. Cryptographic profile proposed for review

This uses the existing `rootark-zk-1` suite and its frozen primitives. The recovery package envelope and recovery manifest v2 are new application profiles and must be independently reviewed, registered, and approved before implementation. They are not silently treated as already frozen.

| Purpose | Proposed profile |
|---|---|
| Canonical encoding | RFC 8949 deterministic CBOR: definite lengths, preferred serialization, shortest integer/length forms, deterministic map ordering, unique keys, and no unsupported tags/floats/trailing bytes. |
| Password KDF | Pinned `libsodium-wrappers-sumo` 0.8.4; explicit `crypto_pwhash_ALG_ARGON2ID13` (Argon2id v1.3), 32-byte output, 16-byte random salt, `opslimit = 3`, `memlimit = 268435456` bytes (256 MiB). Do not use `ALG_DEFAULT`. These are proposed hidden protocol parameters, not a user-selectable setting. At startup/build, verify the pinned wrapper’s profile constants match; otherwise fail closed. |
| Password bytes | Non-empty UTF-8 byte string of the exact supplied string, limited to 1..1024 bytes; no trimming, case folding, or Unicode normalization. The UI/password guidance is a separate unapproved UX decision. |
| Package encryption | AES-256-GCM, fresh 12-byte CSPRNG nonce, 16-byte tag. The Argon2 output is dedicated to one package encryption and is not reused for another purpose. Re-export creates a fresh salt, nonce, and package ID. |
| Device key delivery | Existing frozen RFC 9180 HPKE base suite: X25519/HKDF-SHA256/AES-256-GCM (`mode=0`, `kem_id=0x0020`, `kdf_id=0x0001`, `aead_id=0x0002`), with the existing Root.ark context binding. |
| Authorization | Distinct Ed25519 authorization key per device and one distinct Ed25519 recovery authorization key per active package registration. Never reuse an X25519 HPKE key as an Ed25519 signing key. |
| Bounds | Reject a package larger than 8 MiB before parsing; accept only the exact v1 KDF parameter tuple before Argon2 runs; cap decrypted state to 7 MiB and enforce keyring limits (at most 256 devices and 64 epochs). |

The package lock currently pins both `libsodium-wrappers-sumo` and its resolved `libsodium-sumo` dependency at 0.8.4. The upstream 0.8.4 wrapper API exposes `crypto_pwhash` with explicit output length, salt, operation limit, memory limit, and algorithm; the upstream libsodium submodule header defines MODERATE as 3 operations and 268435456 bytes. These source facts support the candidate tuple only. They do not establish wall time, peak memory, worker behavior, or allocation-failure behavior on supported Node 22 builds. Keep the tuple provisional until the exact locked artifact passes the Node 22 verification in Section 12.1. If any supported client cannot allocate the profile, recovery is blocked on that client; do not downgrade silently.

## 5. Recovery-package v1 proposal (initial draft; superseded where revised by Section 12)

### 5.1 Exact outer envelope

The wire envelope is a deterministic CBOR map with exactly these fields; unknown, duplicate, missing, or mistyped fields fail closed:

```text
{
  type: "rootark-recovery-package",
  suite: "rootark-zk-1",
  version: 1,
  purpose: "recovery-package",
  account_id: bstr(16),
  compartment_id: bstr(1..128),
  package_id: bstr(16),
  base_revision: uint(1..2^64-1),
  base_manifest_digest: bstr(32),
  kdf: {
    id: "argon2id13",
    salt: bstr(16),
    opslimit: 3,
    memlimit: 268435456,
    output_length: 32
  },
  aead: { id: "AES-256-GCM", nonce: bstr(12) },
  ciphertext: bstr(0..8 MiB),
  tag: bstr(16)
}
```

`package_id`, salt, and nonce are generated with the platform CSPRNG. `base_revision` and `base_manifest_digest` identify the package activation snapshot carried inside the payload, not a promise that no later manifest update has occurred. The restore client requires the current record to be at least that revision and the active recovery key IDs to match; Section 8 explains the remaining first-use rollback limit. Define
`aad = ASCII("Root.ark/zk-1/recovery-package/v1") || 0x00 || deterministic_cbor(header)`;
`header` is the exact outer map with `ciphertext` and `tag` removed. The package key is the 32-byte Argon2id output, and encryption is the existing AES-256-GCM operation over the inner payload using that key and `aad`. No field is reserialized with JSON or inferred from a caller after authentication.

The parser first enforces total-byte and deterministic-CBOR bounds, exact fields/types/lengths, account/compartment expectations, profile version, and exact KDF tuple. Only then may it allocate the fixed KDF memory. Wrong password, tag failure, altered AAD, unknown version/suite, scope mismatch, or malformed payload returns one generic recovery failure without key-bearing diagnostics.

### 5.2 Exact encrypted payload contents

The decrypted deterministic-CBOR payload has exactly:

```text
{
  type: "rootark-recovery-state",
  version: 1,
  account_id: bstr(16),
  compartment_id: bstr(1..128),
  package_id: bstr(16),
  revision: uint(1..2^64-1),
  current_epoch: uint(1..2^32-1),
  manifest: RecoveryManifestV2,
  manifest_digest: bstr(32),
  epoch_keys: [{ epoch: uint, key: bstr(32) }, ...],
  recovery_authorization: {
    hpke_key_id: bstr(16),
    hpke_private_key: bstr(32),
    authorization_key_id: bstr(16),
    ed25519_private_seed: bstr(32)
  }
}
```

All outer and inner identities, package ID, revision, epoch, and manifest digest must match. The manifest must validate structurally and cryptographically. Epoch entries are sorted, unique, and must cover every epoch required by the manifest for a package advertised as complete; otherwise package creation fails with `KEY_COVERAGE_INCOMPLETE`. Do not claim that keys a creator device never held can be recovered. Device private keys, passwords, sessions, plaintext, filenames, and per-file CEKs are never included. The client uses epoch keys to unwrap only the content keys it is separately authorized and able to retrieve.

The package’s recovery HPKE private key and Ed25519 signing seed are random client-generated material, independent of the password and device keys. Their distinct public keys and `hpke_key_id`/`authorization_key_id` are registered in the signed manifest. Package encryption protects both keys at rest; possession of the password and package is sufficient for the package path, subject to current server state and the limitations in Section 8. Each epoch key is also wrapped to the package’s recovery HPKE public key using the frozen HPKE tuple plus the recovery-specific deterministic-CBOR info/AAD profile in Section 6. The enclosing Ed25519-signed manifest authenticates the wrap. New epoch keys receive a new such wrap in the same CAS transition as the epoch/revision update. Thus an active package can obtain later epochs without caching its password or silently regenerating the package. Revoking the package stops new wraps and recovery authorization; prior package copies retain keys they already obtained.

### 5.3 `rootKey` compatibility decision proposed

The current keyring creates a random 32-byte `rootKey`, but the keyring source has no consumer that derives epoch keys, authorizes devices, or encrypts content from it; epoch keys are independently random. The recovery package therefore **omits `rootKey`** to avoid exporting an unused secret. Recovery restores the active manifest, its available epoch keys, and the recovery authorization key; it does not claim to reproduce the old in-memory `rootKey` value.

The format is a recovery snapshot for a new keyring v2 API, not a byte-for-byte serialization of the v1 JavaScript object. Before any implementation, deprecate or remove the unused v1 `rootKey` field from the v2 recovery API and verify there are no external consumers. Do not silently replace it with a new key and call the old key restored. If a real consumer is found or the owner requires preservation, stop and version a reviewed format that includes it; do not repurpose it as a derivation root without a separate cryptographic design.

## 6. Manifest v2 and authorization signatures (initial draft; superseded where revised by Section 12)

The proposed v2 manifest is compartment-scoped. Its exact deterministic-CBOR map has the following fields. `core` is the fields through `operation`; the MAC and actor signature are appended afterward:

```text
{
  type: "rootark-zk-keyring-manifest",
  version: 2,
  suite: "rootark-zk-1",
  account_id: bstr(16),
  compartment_id: bstr(1..128),
  revision: uint(1..2^64-1),
  current_epoch: uint(1..2^32-1),
  epochs: [{ epoch: uint, key_ref: bstr(32) }, ...],
  devices: [{
    device_id: text(1..64),
    hpke_key_id: bstr(16),
    hpke_public_key: bstr(32),
    authorization_key_id: bstr(16),
    authorization_public_key: bstr(32),
    enrolled_epoch: uint,
    revoked_at_epoch: null | uint
  }, ...],
  wraps: [{ device_id: text, epoch: uint, key_ref: bstr(32), wrap_id: bstr(16), enc: bstr(32), ciphertext: bstr(48) }, ...],
  recovery_authority: null | {
    package_id: bstr(16),
    hpke_key_id: bstr(16), hpke_public_key: bstr(32),
    authorization_key_id: bstr(16),
    authorization_public_key: bstr(32), status: "active" | "revoked"
  },
  recovery_wraps: [{ package_id: bstr(16), hpke_key_id: bstr(16), epoch: uint, key_ref: bstr(32), wrap_id: bstr(16), enc: bstr(32), ciphertext: bstr(48) }, ...],
  previous_manifest_digest: bstr(32),
  operation: {
    operation_id: bstr(16),
    operation_type: registered text,
    actor_type: "device" | "recovery-package",
    actor_key_id: bstr(16),
    target_device_id: text | null,
    target_device_key_digest: bstr(32) | null,
    expires_at: uint,
    request_digest: bstr(32)
  },
  mac: bstr(32),
  actor_signature: bstr(64)
}
```

The exact operation-type registry is `initialize`, `enroll-device`, `revoke-device`, `register-package`, `replace-package`, `revoke-package`, `recover-device`, and `compromise-package`; unknown values fail closed. The first manifest is revision 1 and uses 32 zero bytes as `previous_manifest_digest`. Its initial device supplies proof of possession for both key pairs and signs the initial state; an authenticated account session may create an empty compartment but conveys no content-key authority. For upgrade from manifest v1, a prior authorized client must also possess a registered Ed25519 authorization key; if it does not, upgrade remains blocked pending reviewed enrollment. Each later manifest binds the SHA-256 digest of the entire prior canonical signed manifest. Every state mutation increments revision by exactly one; only key rotation increments `current_epoch`, by exactly one. Neither counter wraps; exhaustion blocks the operation. Operation lifetime and clock-skew admission are defined normatively in Section 12.3; expiry does not replace CAS replay protection.

`target_device_key_digest` is SHA-256 of deterministic CBOR `{hpke_key_id, hpke_public_key, authorization_key_id, authorization_public_key}`. Device and recovery key IDs must be unique within the compartment and must match the public keys derived from their private keys. The initial `initialize` signature is the only exception to previous-manifest signer lookup: verify it against the new device authorization public key after proof of possession and account authorization to create an empty compartment. It does not authorize reading any pre-existing content.

For each epoch `e`, compute `key_ref = SHA-256(ASCII("Root.ark/zk-1/recovery-key-ref/v1") || 0x00 || deterministic_cbor({suite, account_id, compartment_id, epoch:e}))`. This binds account and compartment into the expected key reference without changing the frozen content-envelope AAD profile. A device epoch wrap and a recovery epoch wrap use the existing HPKE suite and unique CSPRNG 16-byte `wrap_id`. Define a common canonical `context` map with exact fields `suite`, `account_id`, `compartment_id`, `purpose`, `recipient_type`, `recipient_id`, `recipient_key_id`, `epoch`, `key_ref`, and `wrap_id`. For device wraps, set `purpose="key-wrap"`, `recipient_type="device"`, `recipient_id=device_id`, and `recipient_key_id=hpke_key_id`; for recovery wraps, set `purpose="recovery-package"`, `recipient_type="recovery-package"`, `recipient_id=package_id`, and `recipient_key_id=recovery_authority.hpke_key_id`. `info = ASCII("Root.ark/zk-1/keyring-wrap-info/v2") || 0x00 || deterministic_cbor(context)` and `aad = ASCII("Root.ark/zk-1/keyring-wrap-aad/v2") || 0x00 || deterministic_cbor(context)`. The HPKE ciphertext is exactly 48 bytes for a 32-byte epoch key. The enclosing manifest actor signature authenticates the persistent wrap; opening the same valid static wrap on another recovery is allowed, while each new authorization operation has its own one-time replay/idempotency identifiers. This is a new keyring-v2 application context profile using existing algorithms, not a new cipher; it requires independent review and suite registry approval.

Manifest v2 retains the existing limits of 256 devices and 64 epochs. Epochs are contiguous and sorted; `key_ref` is recomputed and checked for every epoch. When recovery authority is active, there is exactly one valid, signed recovery wrap per manifest epoch; with no active recovery authority there are no accepted recovery wraps. Unknown/missing/duplicate wraps, key refs, device IDs, or key IDs fail closed.

The manifest MAC remains HMAC-SHA-256 under a purpose-separated HKDF-SHA-256 key derived from the current epoch key. Its exact HKDF `info` is deterministic CBOR of `{type:"rootark-keyring-manifest-mac-info-v2", suite:"rootark-zk-1", purpose:"manifest-mac", account_id, compartment_id, current_epoch, revision}`; salt is empty and output is 32 bytes. The MAC covers canonical `core`, excluding `mac` and `actor_signature`. The actor signature covers `ASCII("Root.ark/zk-1/recovery-manifest/v1") || 0x00 || deterministic_cbor(core_with_mac)` and uses the active Ed25519 public key from the previous validated manifest. It is not a self-signature by the newly proposed key. The service verifies the actor signature against the prior public state and checks CAS semantics; it cannot verify the epoch-keyed MAC because it never receives the epoch key. Clients must verify the MAC before using key material. `request_digest` is SHA-256 over `ASCII("Root.ark/zk-1/recovery-cas-request/v1") || 0x00 || deterministic_cbor(request_core)`, where `request_core` contains the expected prior revision/digest, operation ID/type, actor type/key ID, target identifiers and target-key digest, expiry, and proposed manifest core with `request_digest`, `mac`, and `actor_signature` omitted. It binds the semantic state transition, including package ID and public keys, but deliberately excludes encrypted package bytes to avoid a circular dependency: the package AAD contains the signed manifest digest. The CAS adapter separately computes and stores `request_body_digest = SHA-256(deterministic_cbor({manifest_digest, package_envelope_digest}))` outside the manifest for exact-byte idempotent retries. `package_envelope_digest` is SHA-256 of the newly supplied envelope when changed, the existing envelope digest when unchanged, and 32 zero bytes when no package is active. A repeated operation ID succeeds as a retry only if both digests match; the body digest is not an authorization or anti-rollback trust root.

For ordinary changes the actor is an active device authorized by the prior manifest. For package-only recovery it is the active recovery authorization key registered by the prior manifest. Both paths require the replacement device to prove possession of both its newly generated Ed25519 and HPKE private keys; the Ed25519 proof binds the hash of both public keys, and the HPKE proof is a one-time random challenge encrypted to the target HPKE key and returned inside the signed confirmation. The signature and MAC do not make an unauthenticated login session a content authority.

Package activation is one atomic transition: the device prepares manifest revision `r+1` with the new recovery key and all currently held epoch recovery wraps; the package payload contains that exact signed manifest and uses its revision/digest as `base_revision`/`base_manifest_digest`; the CAS from `r` to `r+1` commits the manifest and encrypted package envelope together. The manifest contains the package ID and public keys but not the envelope digest, avoiding a circular digest. If CAS loses, discard that envelope and prepare a new operation from the latest state. On later epoch rotations, the trusted device creates a separately scoped signed recovery wrap for the new epoch and commits it with the incremented epoch and revision. No password is cached on the service or device to update the package.

Existing manifest v1 remains read-only during a reviewed migration. No implicit v1/v2 fallback is permitted. Initializing v2 for an existing compartment requires an already authorized client, the expected compartment ID, current epoch material, and a successful CAS create from absent state. This migration and endpoint wiring are blocked until storage and product compatibility are reviewed.

## 7. Independent recovery flows (initial draft; superseded where revised by Section 12)

### 7.1 Emergency package path

1. An authorized device validates the current compartment manifest, revision, epoch, and the complete set of epoch keys it claims to export.
2. It generates a package ID, distinct recovery HPKE and Ed25519 key pairs, salt, and nonce. It prepares the next manifest with both recovery public keys, creates recovery-purpose HPKE wraps for all available epochs, seals a payload containing the exact next signed manifest and private recovery keys, then reopens the exact encoded export locally to check identities, digest, coverage, and key fingerprints without logging secrets.
3. After the separate user export/retention verification UX is approved, the device submits the signed manifest and encrypted envelope together in one `register-package` or `replace-package` CAS transition. CAS atomically activates the recovery key and package record; a failed CAS leaves no active package.
4. With no trusted device available, the replacement device generates fresh HPKE and Ed25519 keys locally, obtains current opaque state, opens the user-held or opaque server copy using the user secret, validates its activation snapshot, and verifies that the current state is not older than that snapshot and still names the same active package ID and both recovery key IDs. It then opens the currently registered recovery wraps for later epochs. It signs a one-time `recover-device` request with the active recovery key and proves possession of both target private keys. If the current state cannot be authenticated to the package’s known state or protected high-water/witness, return `ROLLBACK_RESISTANCE_INCOMPLETE`; do not accept a lower or conflicting state.
5. The recovery signer authorizes only the named account, compartment, target keys, active package ID, expected current revision/digest, operation ID, expiry, and epoch coverage. The client HPKE-wraps available epoch keys to the target; the manifest transition is submitted by CAS. The target validates all scope/signature/revision checks, stores its private keys only in approved secure storage, then verifies recovered content locally.

A package copy is immutable. Replacement uses a new package ID/salt/nonce and a CAS transition; it never edits an existing package in place. A suspected package compromise must revoke its registered recovery public keys and rotate future epoch material through another authority. If both the package and all trusted devices are compromised/lost, the service cannot safely distinguish the rightful user from a package thief; fail closed. Historical re-encryption is separate and never automatic.

Package lifecycle is `local-draft -> locally-validated -> user-retention-confirmed -> active -> replaced-or-revoked`. Only the signed CAS commit changes server state. Client reopen proves cryptographic readability of the exact encoded copy but cannot prove long-term user retention; product acceptance requires an owner-approved user-held restore exercise. Replacing a package rotates both recovery keypairs and wraps all available epochs to the new HPKE key. Revoking a compromised package sets its authority inactive and rotates the epoch without wrapping the new epoch to the revoked key. Retained server/backup ciphertext is not proof of erasure and cannot reactivate a revoked key under current state.

### 7.2 Previously trusted device path

1. The replacement device generates new HPKE and Ed25519 keys locally and proves possession of both keys in a scoped request.
2. A currently authorized source device loads and validates its current manifest against its durable local minimum revision/digest. It verifies that it is not revoked and has the epoch keys it will transfer.
3. After explicit user authorization in a separately reviewed UX, the source device signs the one-time enrollment request, binding account, compartment, source device ID/key, target device ID and both target public keys, operation ID, expected revision/digest, expiry, and allowed epoch coverage. The user must confirm an authenticated pairing channel or matching target fingerprint; server-relayed IDs alone are insufficient.
4. The source device HPKE-wraps only keys it currently holds to the target device’s HPKE public key. No private key or plaintext is sent to the server.
5. Server CAS accepts only the exact current base revision/digest and active source signature. The target verifies the response and imported keys, persists keys and high-water state using the approved device secure store, then proves content recovery locally.

A device enrolled after an earlier epoch may not possess historical epoch keys. The protocol transfers only the keys it actually holds and must report coverage honestly. Revocation blocks future authorization and future epochs, not prior key copies or plaintext. Device removal increments both revision and epoch; the new epoch is wrapped only to remaining authorized devices.

Device lifecycle is `unregistered -> pending-request (client-local, expiring) -> active (after signed CAS) -> revoked`. No server-side pending request grants access. An approved device operation increments revision; enrollment alone does not increment epoch, while revocation increments both and produces new wraps only for remaining devices and any active recovery key. A pending request expires after the same proposed 300-second limit and cannot be replayed after its operation ID is committed.

## 8. Shared CAS, monotonic revisions, and rollback guarantees (initial draft; superseded where revised by Section 12)

### Logical stored record

One logical record is keyed by opaque `(account_id, compartment_id)` and contains only `revision`, `current_epoch`, canonical signed manifest, manifest digest, active package ID, and the encrypted package envelope (or a content-addressed immutable blob referenced by the record). It contains no password, Argon output, private signing key, epoch key, CEK, or plaintext. If a blob is stored separately, it must be written immutably before the pointer CAS; orphaned blobs are harmless and cleanup is non-authoritative. The manifest pointer and revision update must be atomic.

### CAS operation contract

The future adapter must provide a linearizable conditional update for every supported process and replica:

```text
compareAndSwap(
  account_id, compartment_id,
  expected_revision, expected_manifest_digest,
  operation_id, request_digest,
  new_signed_manifest, new_opaque_package_state
)
```

It succeeds only when the stored revision and digest equal the caller’s expected pair, the signed next revision is exactly `expected_revision + 1`, the prior-manifest digest matches, the actor signature is valid under the prior active authorization key, operation scope/expiry is valid, and the operation ID is unused. Manifest and package pointer commit together. It returns a receipt containing new revision, digest, and operation ID; the caller verifies these against the signed payload. The receipt is not an independent anti-rollback trust root. No last-write-wins or eventual-consistency acceptance is permitted.

The same operation ID and identical semantic request digest and request-body digest after a lost response returns the original committed result. Reuse of that ID with different bytes fails. Concurrent writers from one base revision have exactly one winner; losers must refetch, revalidate, and prepare a new signed operation. Ambiguous timeouts do not justify resubmitting different state.

### High-water and deployment guarantees

Each trusted client must atomically persist `(account_id, compartment_id, max_revision, manifest_digest, current_epoch)` in non-exportable OS-backed secure storage before reporting success. It rejects a lower revision or a conflicting digest at the same revision. The storage must be tested for restart, app restore, device backup/restore, rollback, and loss behavior on each supported client runtime. The current Node environment-variable key path and browser IndexedDB do not meet this requirement.

Shared CAS guarantees concurrency ordering and crash durability only if the chosen backend actually provides these semantics. It does not by itself make a malicious server or operator unable to replay an old database snapshot to a brand-new device with no prior high-water mark. Detecting that case requires a separately trusted rollback-resistant client anchor or independent transparency/witness service. Neither is identified or verified. Until one is approved and demonstrated, the design must report `ROLLBACK_RESISTANCE_INCOMPLETE` for first-use/package-only bootstrap and must not claim protection against malicious storage rollback. Backend backup restore must preserve/advance an independently durable revision watermark; if that cannot be proven, disable recovery CAS after restore and fail closed. No local SQLite fallback, per-process queue, or lower-revision acceptance is allowed.

## 9. Explicitly blocked integrations (retained; clarified by Section 12)

| Integration | Current blocker | Evidence required to unblock |
|---|---|---|
| Shared server CAS adapter/endpoints | Actual authoritative backend and deployment topology are not identified or verified. Current JSON store is process-local; SQLite is opt-in with no shared topology evidence. | Owner identifies backend/topology; adapter proves atomic conditional updates across supported replicas, crash/restart durability, retry/idempotence, backup/restore watermark behavior, authorization, and outage fail-closed behavior. |
| Rollback resistance for new devices | No trusted device high-water store or independent witness is integrated. A shared CAS alone cannot prove latest state to a first-use client against a malicious server. | Confirmed OS-backed client storage and/or independently operated witness with documented bootstrap, loss, and restore semantics; adversarial fork/rollback proof. |
| Trusted-device storage/flow | Node private key is env/in-memory; no verified OS keychain or atomic high-water API. Browser IndexedDB is not sufficient. | Owner identifies supported client runtimes and exact secure-storage APIs; verify non-exportability/access control, atomic updates, rollback limits, loss, and recovery behavior. |
| Browser/mobile package recovery | Browser code lacks integrated Argon2id/HPKE/Ed25519 recovery; candidate provenance and runtime memory behavior are not validated. | Pinned reviewed client-compatible backend, verified artifacts/vectors, profile-cost tests, memory/failure behavior, cross-client fixtures, and supported-platform evidence. |
| Protected-content end-to-end recovery | Keyring is not connected to file encryption; no real authorized client executes either recovery path. | One real client proves package-only recovery with no trusted device; separately prove trusted-device-only recovery with no package; verify protected content decrypts locally and service remains opaque. |
| User-facing export, retention, verification, enrollment, compromise/re-export UX | Existing product plan marks recovery UI `[DO NOT IMPLEMENT YET]`; exact package retention, password guidance, user verification, consent, and warnings are not approved. | Separate UX specification and UI-UX-PRO-MAX review; owner approval before visible workflow. |
| Production migration/release | No production target has been identified or authorized; no migration or release is in scope. | Separate exact-target, exact-SHA authorization and production/release gates. |

No portion of this table is resolved by the shared-CAS architecture approval alone.

## 10. Validation and acceptance required after separate approval (retained; mapped by Section 12)

Tests use synthetic accounts, devices, packages, and content only. No production, user data, real secrets, migration, deployment, or issue closure is permitted by this specification.

Required crypto cases include package round-trip; wrong password; modified outer field/AAD/tag/ciphertext; wrong account/compartment/package ID/revision; truncated, oversized, duplicate, unknown, noncanonical, or unsupported CBOR; altered KDF cost rejected before Argon2; profile constants mismatch; key coverage gaps; epoch/revision mismatch; MAC/signature failure; and best-effort secret clearing on success and failure.

Required authorization/state cases include package-only recovery with zero trusted devices; trusted-device-only recovery with no package; target key proof-of-possession; revoked device rejection; expired/replayed operation rejection; idempotent same-request retry; changed-body idempotency collision; concurrent CAS; same-epoch rollback; cross-replica reads/writes; process restart; crash between blob write and pointer CAS; database restore; conflicting fork; client high-water rollback; and store unavailability. Unit tests or in-memory mocks cannot satisfy persistence, restart, device-keychain, or end-to-end rows.

Before implementation, the plan must map each invariant to an owning module/adapter, an initially failing test, and verification evidence. TDD, targeted tests, and exact-head final verification are required after approval. Current validation was not run: no dependencies were installed and no recovery code was changed.

## 11. Independent review questions and approval gate

The independent reviewer should assess the cryptographic profile, exact envelope/AAD, recovery signer lifecycle, rootKey omission and v2 API compatibility, epoch coverage, trusted-device authorization, revision signature/MAC design, CAS semantics, backup/restore, and first-use rollback limitation. The owner should then approve or revise this specification. In particular, confirm or revise:

1. The exact MODERATE Argon2id profile (3 operations, 256 MiB) and its cost on every target runtime.
2. Separate recovery HPKE and Ed25519 keys inside the user-protected package and their revocation/rotation behavior.
3. Omitting the currently unused `rootKey` from recovery snapshots, with a new v2 recovery API rather than pretending to restore it.
4. Retaining an opaque encrypted package copy server-side while also requiring an independent user-held copy.
5. The shared-CAS and anti-rollback guarantees, including the unresolved first-use/malicious-rollback limit and required external witness or protected client anchor.
6. The proposed 300-second operation lifetime and package verification/retention boundary.

Until those reviews and approvals occur, this document remains a draft and implementation must not begin.

## 12. Revision 3 normative design

This section is the normative design for the independent-review findings. It replaces any conflicting package, authorization, history, CAS, freshness, client-storage, and recovery-flow details above. The selected dual-recovery design and shared-CAS target remain intact. The witness, CAS-status authority, bounds, formats, and protocols below are proposals for independent review; they are not approved or deployed.

### 12.1 Cryptographic profile and bounded KDF work

The only proposed package KDF tuple remains Argon2id v1.3 with a 16-byte random salt, 32-byte output, operation limit 3, and memory limit 268435456 bytes. The package header must contain this exact tuple and the explicit Argon2id13 algorithm identifier. Parsers reject any other tuple before invoking the KDF; there is no profile downgrade or attacker-selected allocation.

The current lockfile pins both libsodium-wrappers-sumo 0.8.4 and libsodium-sumo 0.8.4. The upstream 0.8.4 wrapper API declares crypto_pwhash as a synchronous function returning its derived bytes. The matching upstream libsodium submodule header defines MODERATE as 3 operations and 268435456 bytes. This confirms the source constants, not acceptable latency, peak memory, or failure behavior on the target runtime. The only runtime observed here is Node 24.14.1; repository workflows use Node 22. Do not freeze this profile until the exact lockfile artifact is exercised on every supported Node 22 OS with:

- fixed vectors checked against an independent Argon2id13 implementation;
- wall time and peak resident memory measured on the minimum supported hardware;
- allocation failure and worker termination behavior confirmed;
- a proof that parsing rejects malformed or unsupported KDF fields before allocation.

The Node foundation must run each derivation in a dedicated worker thread, with at most one active recovery KDF per process and no unbounded queue. If one derivation is already active, return a retryable KDF_BUSY result without starting more work. A worker error, timeout, memory failure, or unsupported platform fails closed; no fallback parameters are allowed. A synchronous call must not block the app or HTTP event loop. No browser or mobile profile is implied.

### 12.2 Exact package commitment without a digest cycle

For an existing signed manifest at revision r, the package activation transition is revision r+1. In the package envelope, base_revision and base_manifest_digest refer to the complete signed manifest at r, not the package activation manifest. The envelope adds activation_revision, operation_id, and activation_context_digest.

Before encryption, the authorized source constructs this exact canonical activation_context map:

| Field | Value |
|---|---|
| type, version, suite | rootark-recovery-activation-context, 1, rootark-zk-1 |
| account_id, compartment_id, keyring_id | Exact scope and keyring identity from the previous manifest |
| package_id | Newly generated 16-byte package ID |
| previous_revision, previous_manifest_digest | r and SHA-256 digest of the complete signed manifest at r |
| activation_revision, operation_id | r+1 and the 16-byte activation operation ID |
| hpke_key_id, hpke_public_key | Newly generated recovery HPKE public key and its 16-byte ID |
| authorization_key_id, authorization_public_key | Newly generated recovery Ed25519 public key and its 16-byte ID |
| witness_base_receipt_digest | SHA-256 of the exact signed witness receipt for revision r |

Compute activation_context_digest as SHA-256 of the domain string Root.ark/zk-1/recovery-activation-context/v1, one NUL byte, and deterministic CBOR of activation_context. The context excludes the final manifest digest, package-envelope digest, manifest MAC, and actor signature. The exact envelope header includes the context digest and the exact scope, package, base revision, activation revision, and operation ID. AES-GCM AAD is the recovery-package domain string, one NUL byte, and deterministic CBOR of that header with only ciphertext and tag omitted.

The outer deterministic-CBOR envelope has exactly this field set; unknown, duplicate, missing, mistyped, or noncanonical fields fail before KDF allocation:

| Field | Encoding and constraint |
|---|---|
| type, suite, version, purpose | Exact strings rootark-recovery-package, rootark-zk-1, and recovery-package; version 1 |
| account_id | 16-byte string |
| compartment_id | 1–128 bytes |
| package_id | 16-byte string |
| base_revision | Unsigned 64-bit integer r |
| base_manifest_digest | 32-byte digest of the complete signed previous manifest at r |
| activation_revision | Unsigned 64-bit integer exactly r+1 |
| operation_id | 16-byte string |
| activation_context_digest | 32-byte digest defined above |
| kdf | Exact map: id argon2id13, salt 16 bytes, opslimit 3, memlimit 268435456, output_length 32 |
| aead | Exact map: id AES-256-GCM, nonce 12 bytes |
| ciphertext | Byte string; total envelope must not exceed 8 MiB |
| tag | 16-byte string |

The KDF map is not a negotiable input. The parser checks all lengths, total size, canonical encoding, account/compartment expectation, package purpose, and exact profile before deriving. Password bytes are the exact supplied UTF-8 string bytes, 1–1024 bytes, with no trimming, case folding, or Unicode normalization.

The decrypted payload is deterministic CBOR with exactly these top-level fields: type rootark-recovery-state; version 1; account_id; compartment_id; keyring_id; package_id; previous_revision; previous_manifest_digest; activation_revision; operation_id; activation_context; activation_context_digest; witness_base_receipt; previous_manifest; current_epoch; epoch_keys; and recovery_authorization. The previous_manifest is the complete signed manifest at previous_revision. epoch_keys is a sorted list of exactly one 32-byte key for every epoch in that manifest, with no missing or duplicate epoch. recovery_authorization contains hpke_key_id (16 bytes), hpke_private_key (32 bytes), authorization_key_id (16 bytes), and ed25519_private_seed (32 bytes). The payload must not exceed 7 MiB. It does not contain the final signed manifest at r+1 or its digest. All keys remain client-only.

The activation_context map contains exactly the fields in the table above. witness_base_receipt contains exactly type, witness_key_id, account_id, compartment_id, keyring_id, revision, manifest_digest, witness_sequence, nonce, observed_at, status, and signature. Its type is `rootark-recovery-witness-base/v1`, and its signature domain is `Root.ark/zk-1/recovery-witness-base/v1`. The status must be committed. This immutable package snapshot receipt is a different wire type and signature domain from the fresh `rootark-recovery-witness-head/v1` response in Section 12.4. The nonce is 32 bytes, the signature is 64 bytes, and all scope/head fields must match the previous manifest at r. The receipt is verified with the independently pinned witness key. The epoch_keys array contains entries with exactly epoch (unsigned integer) and key (32 bytes), sorted by epoch. The recovery_authorization map contains exactly hpke_key_id (16 bytes), hpke_private_key (32 bytes), authorization_key_id (16 bytes), and ed25519_private_seed (32 bytes). The final activation manifest at r+1 is obtained from the authenticated transition history, not copied into the package.

After encrypting, compute package_envelope_digest as SHA-256 of the domain string Root.ark/zk-1/recovery-package-envelope/v1, one NUL byte, and the exact encoded envelope bytes. The final signed manifest at r+1 stores the exact envelope digest and the activation-context fields in its recovery-authority record. Its MAC and actor signature cover those fields. The server recomputes the digest from the exact submitted bytes; it does not authorize from a caller-supplied digest. Compute manifest_digest as SHA-256 of ASCII(Root.ark/zk-1/recovery-manifest-digest/v1), one NUL byte, and deterministic CBOR of the complete signed manifest including MAC and actor signature. Compute request_digest as SHA-256 of ASCII(Root.ark/zk-1/recovery-cas-request/v2), one NUL byte, and deterministic CBOR of request_core. request_core contains the exact expected prior revision/digest, operation ID/type/actor/target, `compromised_package_id`, `recovery_policy_change`, issue/expiry, target_pop_proof, proposed manifest core including activation_context_digest and package_envelope_digest, and the post-transition active package-envelope digest or null. It excludes only request_digest, MAC, actor signature, and the external witness ticket. No separate request-body digest is a trust root.

There is no cycle: the encrypted package commits to the prior manifest and an activation context; the final manifest commits to the exact ciphertext bytes; neither digest is included in the bytes whose digest it defines. On import, the client hashes the exact package bytes, compares that result to the signed activation manifest, recomputes the activation-context digest from the decrypted payload, checks the previous manifest digest, and then validates the revision r+1 activation transition. An alternate or earlier envelope for the same package ID fails this binding.

Before CAS, the client must write and re-read the exact encrypted export bytes and reopen those exact bytes locally. This proves byte identity and cryptographic readability only; it does not prove long-term user retention. For package registration/replacement, a separate explicit user confirmation in the owner-approved retention UX is also required before CAS; that confirmation is the user's assertion of independent retention, not a cryptographic proof. If export, re-read, or that confirmation fails or is absent, the package remains unregistered and no CAS request is sent. User retention UX and activation confirmation remain separately blocked.

### 12.3 Normative authorization matrix and target proof

Every transition is checked against the previous validated manifest. A new key in the proposed manifest cannot authorize its own addition. The service checks the same matrix and signature using public state; clients independently re-check it and the manifest MAC.

The manifest v2 field set in Section 6 is retained except for these normative additions and replacements. Add immutable keyring_id as a random 16-byte value at initialize. recovery_authority, when present, has the prior public key/status fields plus activation_revision, previous_revision, previous_manifest_digest, operation_id, activation_context_digest, and package_envelope_digest. All six activation fields are required while active and remain as a tombstone binding after revocation. The operation map is exactly operation_id (16 bytes), operation_type (registered value), actor_type, actor_key_id (16 bytes), target_device_id (text or null), target_device_key_digest (32 bytes or null), compromised_package_id (16 bytes or null), recovery_policy_change (`device-only` or null), target_epoch_coverage (sorted unique epoch integers), target_pop_proof (exact proof map or null), issued_at, expires_at, and request_digest (32 bytes). `compromised_package_id` is required only for `compromise-package`; `recovery_policy_change` is `device-only` only for a separately owner-approved voluntary package revocation; all other uses are null. The proof map is required only for enroll-device and recover-device and is null for other operations. A package activation's request_digest includes the exact package_envelope_digest, every operation-specific field, and target proof. All prior deterministic-CBOR, MAC, signature, and suite rules remain, with the final actor signature covering the complete updated core and being checked against the prior manifest.

| Operation | Active device actor | Recovery-package actor |
|---|---|---|
| initialize | Allow only when no keyring exists; first device proves both keys and signs an empty-compartment state. | Deny. |
| enroll-device | Allow from an active device in the previous manifest. Require explicit scoped user consent, fresh target keys, target proof, and wraps only for source-held epochs. | Deny. |
| revoke-device | Allow from an active device in the previous manifest. Target must currently be active; revocation is permanent and the same transition rotates the epoch and wraps the new key only to remaining active authorities. | Deny. |
| register-package | Allow only if no package is active. Require the exact envelope binding in Section 12.2 and complete epoch coverage. | Deny. |
| replace-package | Allow from an active device only for a planned, non-compromise replacement. Atomically revoke the prior package authority and activate the new package binding; do not imply compromise response or epoch rotation. | Deny. |
| revoke-package | Deny if compromise is suspected. A planned revocation may be allowed only with `recovery_policy_change=device-only`, at least one remaining active device, and a separately owner-approved policy and explicit user-confirmation UX; until that policy/UX is approved, deny. | Deny. |
| recover-device | Allow from an active device in the previous manifest. | Allow only when the signing key ID matches the active recovery authority in the previous manifest. This actor may perform recover-device only. |
| compromise-package | Allow only from an active device when `compromised_package_id` matches the active package in the previous manifest. The same transition MUST activate a newly generated replacement package, revoke the prior recovery signing and wrapping keys, increment current_epoch exactly once, generate a fresh independent 32-byte epoch key, and bind the new package envelope in the same CAS. Require the source to hold every prior epoch key and create exactly one recovery wrap for each prior epoch and the fresh epoch to the new package. Wrap the fresh epoch only to remaining active devices and the new recovery package; never to the compromised package. Require complete wraps, exact export verification, and retention confirmation before CAS. Missing material fails before commit with `KEY_COVERAGE_INCOMPLETE` or `COMPROMISE_RECOVERY_UNAVAILABLE`. | Deny. |
| Any other operation | Deny. | Deny. |

For each operation, validate the actor type and key ID from the previous state, current non-revoked status, expected keyring/account/compartment, exact prior revision and manifest digest, transition-specific invariants, unique operation ID, and exact next revision. Device IDs and device key IDs/public keys, package IDs and recovery key IDs/public keys, and wrap IDs are never reused across retained history, including after revocation. A new key cannot authorize itself. A package signer cannot enroll through the ordinary operation, revoke a device, register/replace/revoke/compromise a package, rotate a key directly, or mutate unrelated state. A suspected package compromise cannot be resolved by the compromised package signer itself. If no trustworthy active device holds the required epoch keys, return `COMPROMISE_RECOVERY_UNAVAILABLE`; do not invent a new authority or claim the compromised package was revoked. The client that learns of suspected compromise immediately enters a local write hold. A committed `compromise-package` reservation blocks new state-dependent reads and writes until the replacement head is witnessed. Password login, account password reset, TOTP, and administrator status do not satisfy this check.

Target proof binds both fresh target keypairs. The target generates a new HPKE keypair and Ed25519 keypair and a unique device ID. The target_device_key_digest is SHA-256 of ASCII(Root.ark/zk-1/target-device-keys/v1), one NUL byte, and deterministic CBOR containing device_id, hpke_key_id, hpke_public_key, authorization_key_id, and authorization_public_key. IDs and public keys must be unique across the current manifest and retained history; a previously revoked key or device ID cannot be reused.

The authorizing device or recovery client generates a CSPRNG 32-byte challenge and 16-byte challenge_id. The exact deterministic-CBOR challenge context contains type Root.ark-recovery-target-pop, version 1, account_id, compartment_id, keyring_id, operation_id, target_device_id, target_device_key_digest, challenge_id, issued_at, and expires_at. It HPKE-encrypts the 32-byte challenge to the target HPKE public key using the frozen X25519/HKDF-SHA256/AES-256-GCM base suite. HPKE info is ASCII(Root.ark/zk-1/recovery-target-pop-info/v1), one NUL byte, and deterministic CBOR of the challenge context; HPKE AAD is ASCII(Root.ark/zk-1/recovery-target-pop-aad/v1), one NUL byte, and the same canonical context. The resulting encapsulated key is 32 bytes and ciphertext is 48 bytes.

The target decrypts the challenge and returns the exact response map containing challenge_context, challenge, and target_signature. target_signature is Ed25519 over ASCII(Root.ark/zk-1/recovery-target-pop-response/v1), one NUL byte, and deterministic CBOR of {challenge_context, challenge}. The authorizer verifies the target signature, exact challenge equality, scope, key digest, and expiry before signing the state transition. target_pop_proof in the operation map contains exactly challenge_context, enc, ciphertext, challenge, and target_signature; the actor signature covers that complete proof transcript through the manifest core and request_digest. Clients can revalidate the target signature from the retained transcript. The challenge plaintext becomes public only after the target returns it; it contains no secret key material.

In the trusted-device path the target response must return over the separately authenticated pairing channel. A server-relayed ID or public key alone is not consent or proof. The authorizing device is responsible for decrypting the challenge, verifying the returned unpredictable challenge and target signature over that authenticated channel, and only then signing the transition. A public HPKE ciphertext plus the published challenge and Ed25519 transcript is not, by itself, server-verifiable proof of X25519 private-key possession. The server verifies the actor signature, target Ed25519 response, key/scope binding, expiry, and one-time operation fields, but it MUST NOT claim that it independently proved target HPKE possession. A package-only recovery performs the same decrypt-then-sign and verification locally on the replacement client.

The CAS transaction stores operation IDs and challenge IDs as consumed with the state transition. A replay, duplicate challenge with a different operation, expired challenge, or concurrent stale request fails. Only the identical operation ID, semantic request digest, manifest bytes, and package bytes may return the original committed result after a retry. This proves possession of both newly generated private keys; it does not protect a package whose ciphertext and password are both stolen.

Every signed operation has issued_at and expires_at as unsigned UTC seconds. The nominal issuer lifetime is at most 300 seconds: `0 < expires_at - issued_at <= 300`. The operation issuer, CAS admission clock, and witness admission clock must have monitored pairwise skew no greater than 30 seconds. CAS and witness accept only when `issued_at - 30 <= now <= expires_at`; there is no post-expiry grace. Under the stated skew bound, the worst-case real acceptance interval from issuance is at most 330 seconds (5 minutes 30 seconds), not a strict five-minute wall-clock lifetime. Unknown clock health or skew above 30 seconds fails closed. Expiry controls admission only; committed historical transitions remain verifiable after expiry. This bound remains proposed pending independent review.

### 12.4 Authenticated history, shared CAS, and first-use freshness

The stored logical record is keyed by account, compartment, and immutable keyring_id. It contains the current signed manifest and digest, immutable opaque package blobs addressed by their envelope digest, the active-package pointer from the manifest, a consumed-operation ledger, and an append-only contiguous signed-manifest history. Every successful mutation appends exactly one complete canonical signed manifest at revision r+1 while atomically replacing the head, active-package pointer, and operation result. A reservation names the new envelope digest when package bytes change, the current digest when the active package is unchanged, and null when no package remains active. History records contain no private keys, epoch keys, CEKs, password, or plaintext. Package blobs are immutable; revocation changes authority state and never claims backup erasure. History is retained without pruning; expiry of an old operation never deletes its transition proof.

Verification begins from the package payload's complete signed manifest at revision r, then reads every transition from r+1 through the witnessed head. For each entry, the client requires the exact next revision, matching prior digest, canonical full manifest, valid transition under the matrix in Section 12.3, a signature from the authority active in the previous state, no previously consumed operation ID, valid package binding, and the recomputed next-manifest digest. Only after public signature and state checks pass may the client open newly added recovery wraps. It then verifies the manifest MAC using the corresponding epoch key and checks complete coverage. Missing, duplicate, reordered, truncated, altered, oversized, unknown, or unverifiable history fails closed. A current head alone, even if signed, is not sufficient to authorize the intervening state.

Verification is bounded by proposed limits: 4096 transitions, 8 MiB per signed-manifest history entry, 64 MiB total history bytes, and at most 8 MiB returned per page while processing one manifest at a time. No pruning or checkpoint compaction is specified. A CAS that would exceed any limit returns `HISTORY_CAPACITY_REACHED` before committing; it does not drop older proofs or report successful recovery. These are prototype limits, not an unrestricted lifecycle: exhaustion blocks every mutation, including revocation, compromise response, and recovery. Expose used bytes/count and hard limits to clients/operations; propose `HISTORY_CAPACITY_WARNING` at 75% of either the transition-count or byte limit so an owner-visible warning occurs before exhaustion. Include canonical size measurements for manifests at the maximum 256-device/64-epoch bounds and near-limit history fixtures. A checkpoint/rekey design is a separate reviewed and owner-approved protocol; no pruning or proof compaction is allowed in this revision. Until a safe lifecycle beyond these limits is approved, the feature must not be described as production-ready or unrestricted.

Shared CAS remains the target. Every witness object is deterministic CBOR with an exact field set and a signature over ASCII(domain) || 0x00 || deterministic_cbor(all fields except signature). A fresh-head receipt has type `rootark-recovery-witness-head/v1`, uses domain `Root.ark/zk-1/recovery-witness-head/v1`, and contains type, witness_key_id, account_id, compartment_id, keyring_id, current_revision, current_manifest_digest, witness_sequence, nonce, observed_at, status, pending_reservation_id, and signature. For `status=committed`, current revision/digest are non-null and pending_reservation_id is null. For `status=pending`, current revision/digest are null and pending_reservation_id identifies the unresolved reservation; the sequence is informational and is not an acceptable head. A missing response, unknown status, or any non-committed status fails closed. A reservation ticket uses domain `Root.ark/zk-1/recovery-witness-reservation/v1` and contains type, reservation_id, witness_key_id, account_id, compartment_id, keyring_id, expected_revision, expected_manifest_digest, proposed_revision, proposed_manifest_digest, operation_id, request_digest, package_envelope_digest, expires_at, and signature. Expected revision/digest are null only for initialize; package_envelope_digest is the post-transition active package digest or null when none is active. A commit receipt uses domain `Root.ark/zk-1/recovery-witness-commit/v1` and contains type, reservation_id, account_id, compartment_id, keyring_id, committed_revision, committed_manifest_digest, operation_id, witness_sequence, status, and signature; status must be committed. Tickets and receipts are visible to and verified by both client and CAS.

For initialize, the witness reservation's expected head is absent. It succeeds only if the witness has never recorded or tombstoned that account/compartment, and it binds the new keyring_id and revision 1 manifest digest. CAS uses create-if-absent. The first witness commit sets revision and witness_sequence to 1. A lost or deleted CAS row does not permit re-initialization because the witness retains the prior head/tombstone. For every committed keyring operation, revision and witness_sequence each increment by exactly one and never reset; for this generation, committed witness_sequence equals revision. Reservation creation, pending status, and cancellation are retained in a separate durable append-only reservation ledger and do not change the committed revision.

For each keyring write, the client first obtains a signed reservation for the exact expected head, proposed next revision/digest, operation ID, request digest, package-envelope digest, and expiry. The shared CAS then validates the reservation, previous-state actor signature, operation matrix, time bounds, next revision, and exact envelope bytes. In one linearizable durable transaction it appends the history entry, advances the head, stores the opaque package pointer/bytes and operation result, and marks that reservation ID consumed. A separate blob may be written immutably before CAS; an orphan is harmless. The witness receipt is not a content-key authority and never supplies secret material.

The witness is a separate logical trust service, not an existing Root.ark capability or selected vendor. Its Ed25519 verification key must be pinned in an independently authenticated client release/configuration; a key learned only from the Root.ark service is untrusted. For a fresh read, the client generates a new 32-byte nonce and asks the witness directly for the signed fresh-head receipt. The response must echo the nonce and scope. A `committed` response is acceptable only when no reservation for that keyring is unresolved; the client compares that head byte-for-byte with the CAS response. If any reservation is unresolved, the witness MUST return a signed `pending` response and MUST NOT issue an acceptable committed receipt for the earlier head. The witness persists this gate across process crash/restart; if it cannot prove reservation-ledger continuity after restore, it returns no acceptable head. The witness sequence and committed manifest revision are monotonic and may never reset or be learned from the application database. The base receipt for revision r is included in the encrypted package and its digest is in the activation context; a new client still needs a fresh nonce response before accepting current state.

Witness reservations are single-use and serialized per compartment. Creating one durably closes the state-use gate before returning its ticket; while it is unresolved, the witness returns `status=pending`, and clients fail closed for recovery, enrollment, authorization, key unwrap, server-mediated protected-content access, content-write admission, and all keyring mutations. No client or CAS response may authorize against the earlier committed head while the gate is pending. The gate survives witness crash/restart; if reservation-ledger continuity or witness monotonic state is uncertain, the witness stays unavailable. A missing witness response also fails closed.

The CAS provider MUST expose an operation-status proof fetched directly by the witness from a status-authority key that is distinct from and not controlled by the Root.ark application process; that key is independently pinned by the witness and clients. An application-server relay is untrusted. Its deterministic-CBOR object has exactly: type, status_authority_key_id (16 bytes), account_id (16 bytes), compartment_id (1–128 bytes), keyring_id (16 bytes), reservation_id (16 bytes), operation_id (16 bytes), request_digest (32 bytes), package_envelope_digest (32 bytes or null), expected_revision (unsigned integer or null only for initialize), expected_manifest_digest (32 bytes or null only for initialize), proposed_revision (unsigned 64-bit integer), proposed_manifest_digest (32 bytes), observed_revision (unsigned integer or null only when the head is absent), observed_manifest_digest (32 bytes or null only when the head is absent), terminal_status (`committed` or `not-committed-final`), observed_at (unsigned UTC seconds), nonce (32 bytes), and signature (64 bytes). The signature covers ASCII(`Root.ark/zk-1/recovery-cas-status/v1`) || 0x00 || deterministic_cbor(all fields except signature). The proof binds a fresh client/witness nonce and the exact operation, expected/proposed heads, observed head, and terminal status. A `committed` proof's observed head must equal the proposed head; a `not-committed-final` proof's observed head must equal the expected head.

A `committed` proof is valid only if the exact operation/result and proposed head are durably present. A `not-committed-final` proof is valid only after the reservation expiry plus the 30-second skew bound, when the linearizable CAS authority confirms the head is still exactly the expected head, no result exists, and a durable tombstone makes that reservation/operation impossible to commit later. A potentially dishonest application-server assertion is never sufficient. The witness resolves a committed operation only from the exact committed proof; it cancels only from the exact final non-commit proof and emits a deterministic-CBOR cancellation receipt with exactly: type, witness_key_id (16 bytes), account_id (16 bytes), compartment_id, keyring_id (16 bytes), reservation_id (16 bytes), operation_id (16 bytes), status_authority_proof_digest (32 bytes), resolved_at (unsigned UTC seconds), status=`cancelled`, and signature (64 bytes). The receipt uses domain `Root.ark/zk-1/recovery-witness-cancel/v1`; clients accept the unchanged expected head only after verifying both the final non-commit proof and a fresh nonce-bound committed-head receipt with no pending reservation. Otherwise the pending gate remains indefinitely. The protocol explicitly trusts the independently pinned CAS status authority to report truthful linearizable terminal state; compromise of that authority can falsely resolve the gate and defeats this protection. If no such authority is selected, independently pinned, and verified, no reservation can be canceled and the feature remains blocked.

Every new state-dependent authorization or server-mediated protected-content read/write admission must obtain a fresh nonce-bound witness status and be checked through the same per-keyring linearizable gate immediately before the operation. The gate binds the committed revision, manifest digest, and current epoch; a pending reservation closes admissions before the reservation ticket is returned. Existing admitted operations must reach a terminal store outcome before the reservation becomes active; no new admission is issued while pending. After a committed rotation, the storage adapter rejects any operation bound to the old revision or epoch. Offline ciphertext may remain a local unaccepted draft and must reconcile against a fresh committed head before server acceptance. Already-held keys, plaintext, or cached content on a disconnected device cannot be remotely erased or recalled; no retroactive revocation is claimed. If the existing offline-access policy allows current-state-dependent content use without a fresh witness, that behavior cannot satisfy this pending gate and must be resolved before approval. The selected storage providers must prove this shared serialization; a client-only check or mock is not sufficient.

If CAS commits and witness finalization is delayed, the state is `COMMITTED_UNWITNESSED`: no client accepts the proposed head or the earlier head, and no protected operation is admitted. A lost CAS response is queried/retried with the same operation ID and bytes. A lost witness response is recovered only from a fresh nonce read matching the exact terminal proof. A pending reservation is never discarded after timeout. Concurrent writers have one CAS winner; others refetch, revalidate, and create a new operation only after the gate has been resolved.

Every current-state use that can authorize or report recovery requires a direct fresh witness read, no-pending status, and matching CAS history. If the Root.ark store is restored to a lower revision or a conflicting digest, fail with `ROLLBACK_RESISTANCE_INCOMPLETE`; restore the exact witnessed head and contiguous history or disable recovery. If the witness is unavailable, loses its monotonic state, has an unknown signing key, returns an old/forked head, or cannot prove that its reservation gate survived restart, recovery and state-dependent access/mutation fail closed. Never bootstrap a lost witness from the application database or accept an older revision. Witness-key rotation must be signed by the currently pinned root; loss of that root blocks the feature pending a new owner-approved bootstrap procedure.

The proposed witness is itself part of the trust model. A compromised or colluding witness can sign a stale head or split views; this single-witness profile does not claim to tolerate that. If protection against witness compromise is required, a multi-witness quorum or transparency/gossip design needs separate review. Until the owner identifies and approves the witness operator, key bootstrap, and durable store, first-use rollback resistance remains ROLLBACK_RESISTANCE_INCOMPLETE.

### 12.5 Device high-water storage and crash/retry states

The local high-water record is the tuple keyring_id, max_revision, manifest_digest, current_epoch, witness_sequence, and witness_receipt_digest, signed by the device authorization key. It must be stored atomically with the non-exportable device keys and pending/active status by an OS-backed provider that has been verified on that exact client runtime. The signature detects local modification but not rollback of the same signed snapshot. Non-exportable key storage alone does not provide a monotonic counter.

The provider must expose and pass capability checks for atomic update, durability across restart, device backup/restore behavior, and either a hardware/OS rollback-resistant counter or mandatory online witness validation on every state-using operation. If the provider only offers a keychain without rollback-resistant metadata, the client must use the online witness before acting; it must not claim offline rollback resistance. Missing, unreadable, corrupt, lower, same-revision-conflicting, or unverifiable state fails closed. Environment variables, JSON files, ordinary local SQLite, and IndexedDB do not qualify. Browser and current Node environments remain blocked because no such provider was verified.

Package registration and device recovery use these states:

| State | Entry rule and recovery behavior |
|---|---|
| PREPARED | Keys, context, operation ID, and exact bytes exist only in the authorized client. No server authority changed. |
| EXPORT_VERIFIED | Exact package bytes were written, re-read, and reopened locally. This is not proof of long-term retention. |
| RETENTION_CONFIRMED | For package registration/replacement only, the user explicitly confirms independent retention through the separately approved UX. This is a user assertion and must not be inferred from file creation or reopen. Device recovery skips this state. |
| PENDING_AUTHORITY | Before any authority-changing CAS, the exact signed request is durably stored; device recovery also stores the target's new private keys, and package registration stores the exact encrypted envelope. A failure here sends no CAS request. |
| CAS_PENDING | Witness reservation exists and exact request is being submitted. Retry only the same operation ID and bytes. |
| COMMITTED_UNWITNESSED | CAS committed but no final witness receipt is available. Do not report active or accept the head; reconcile the same request. |
| COMMITTED_PENDING_LOCAL_ACTIVATION | Witness confirmed the exact CAS head, but atomic local promotion of target keys and high-water state has not succeeded. Retain the secure pending record and retry the same promotion; never create different keys or a new operation under the old ID. |
| ACTIVE | Exact package commitment, CAS commit, witness receipt, atomic local key/high-water state, and (for package registration) prior RETENTION_CONFIRMED all verify. Only now may the client report recovered access. |
| FAILED_CLOSED | A required artifact, key, receipt, history entry, or storage capability is missing or inconsistent. No lower revision, alternate bytes, or mock state may be accepted. |

If a package export fails, do not send CAS. If CAS commits but its response is lost, query/retry the exact operation and exact package envelope. If CAS commits but witness finalization fails, remain `COMMITTED_UNWITNESSED`. Before a target enrollment CAS, persist pending target private keys and request bytes; after a witnessed CAS, promote those keys and the high-water record in one secure-store transaction. A local promotion failure remains `COMMITTED_PENDING_LOCAL_ACTIVATION`; if the pending key record is later lost or corrupt, the enrolled device cannot claim access and a still-available authorized recovery path is required. For `compromise-package`, keep the new epoch key and replacement package pending until the exact CAS operation is witnessed. A lost CAS, unknown outcome, witness outage, or failed local promotion never advances local active keys and never permits writes with the compromised epoch; reconcile only the identical operation or remain held. Backend restore to an old snapshot is detected by the witness mismatch and requires exact restoration or feature shutdown.

### 12.6 Epoch coverage and rootKey compatibility

At package registration, the source must possess or unwrap every epoch key listed in the previous manifest and create exactly one valid recovery wrap for each contiguous epoch. The source may use only keys it holds through its own authorized device wraps; it cannot request or fabricate a missing epoch. If any epoch is missing, reject the whole registration with KEY_COVERAGE_INCOMPLETE and do not advertise an active complete package. A later rotation with an active package must create the new epoch's recovery wrap in the same signed CAS transition as the epoch and revision update. If that wrap cannot be created, the rotation fails. On recovery, a missing or invalid wrap for any required epoch also fails the complete recovery with KEY_COVERAGE_INCOMPLETE; this spec does not define partial recovery.

The bounded repository inventory found the v1 rootKey created and cleared only in src/crypto/rootark-zk-keyring.js; the keyring module is imported by its focused test but has no in-repository runtime caller. The v1 test asserts the 32-byte field and that the serialized manifest does not contain it. V1 epoch keys are independently random in the source inspected. This supports, but does not prove for external consumers, omission from a separate v2 recovery API. Do not alter or silently migrate v1 objects. The proposed v2 parser rejects a v1 object and any unexpected rootKey field; it never drops, regenerates, or overwrites that legacy value. Before implementation, repeat a bounded call-site and serialization inventory and add a negative compatibility test proving v1 behavior remains unchanged and v2 rejects implicit conversion. Any external importer or real rootKey consumer blocks the omission until a separately reviewed format is approved.

### 12.7 Threat model, limitations, and blocked integrations

| Threat or failure | Required outcome | Remaining limit |
|---|---|---|
| Root.ark server, database reader, backup reader, or administrator | Cannot decrypt opaque package/history or obtain private/content keys. A stale server head is rejected by the fresh independent witness plus authenticated history. | Can deny service, withhold data, or expose traffic size and timing. |
| Malicious Root.ark service or restored old database | Cannot substitute a valid earlier package envelope undetected. CAS head, full chain, exact envelope digest, and witness head must match. | First-use protection is unavailable when the witness is missing, unknown, compromised, or unreachable; fail closed. |
| Unresolved witness reservation, including committed-but-unwitnessed revocation | Signed `pending` status blocks new state-dependent admissions; the witness never presents the old committed head as acceptable until exact resolution. | Service-mediated reads/writes pause. A disconnected device may still use already-held keys or cached plaintext; that access cannot be recalled remotely. |
| Compromised witness | No false claim of freshness is made. Clients reject invalid signatures and still validate the entire authority chain. | A single witness can sign stale/forked heads; protection from this needs a separately approved quorum or transparency design. |
| Compromised recovery package | A trusted active device must atomically replace its authority and rotate to a fresh next epoch; the new epoch is never wrapped to the compromised package. | The old package can decrypt old epochs. Without a trustworthy active device and all required epoch keys, safe rotation is unavailable and must be surfaced as unrecoverable. |
| Compromised CAS-status authority | Witness verifies only independently pinned, nonce-bound terminal proofs and blocks on missing proofs. | The status authority is trusted to report truthful linearizable terminal state; its compromise can falsely resolve a pending gate and defeat this protection. |
| Package ciphertext theft | Bounded parsing and fixed Argon2 profile prevent attacker-controlled KDF cost. | A weak password permits offline guessing; password plus package exposes included keys. |
| Compromised active device | Only transitions in the actor matrix are possible; revoke the device and rotate future keys from another valid authority. | Previously copied keys, plaintext, and ciphertext cannot be revoked retroactively. |
| Local backup/restore or keychain rollback | Signed state detects modification; fresh witness or verified hardware counter detects rollback. | A signature alone accepts an old exact snapshot. No current client provider proves rollback-resistant metadata. |
| Witness/store outage, missing history, or uncertain commit | Do not accept state or report successful recovery. Reconcile exact operation or remain blocked. | Availability is sacrificed to prevent rollback or conflicting recovery. |
| Loss of every trusted device and usable package | No master key or admin recovery exists. | Protected content can remain unrecoverable. |

The shared CAS adapter, durable CAS-status authority and separately pinned key, independent witness service/key bootstrap, persistent reservation ledger, protected-content read/write admission gate, deployment topology, durable secure device storage/high-water provider, browser/mobile recovery, server endpoints, end-to-end protected-content recovery, user-facing export/retention/pairing/compromise UX, v1 migration, and production rollout are all still blocked. The confirmed repository has a process-local JSON sync store and opt-in local SQLite; neither is a shared CAS implementation. The current Node sync client reads device signing material from environment variables into memory; the browser uses caller-keyed IndexedDB and lacks the integrated recovery suite. This specification does not assume a database, cloud service, deployment, keychain, CAS-status authority, or witness exists.

### 12.8 Proposed module, owner, and initial RED-test mapping

These are proposed ownership boundaries and test names only. No listed module or test was created by this revision. After specification approval, each RED case must first be run and observed failing before its implementation. Pure tests never satisfy blocked infrastructure or product rows.

| Invariant | Proposed module and logical owner | Initially failing test and first assertion | Required proof / current status |
|---|---|---|---|
| Fixed KDF profile, parse-before-allocation, one worker, no event-loop blocking | src/crypto/rootark-zk-recovery-kdf.js; crypto owner | test/issue-65-recovery-kdf.test.js: unsupported tuple is rejected before the worker is called; second concurrent request returns KDF_BUSY. | Pure Node test plus exact Node 22 cross-platform vector, memory, timing, and allocation-failure run; profile is not frozen. |
| Exact envelope bytes bind to the signed activation without a digest cycle | src/crypto/rootark-zk-recovery-package-v1.js; crypto owner | test/issue-65-recovery-package.test.js: substitute one byte or an older valid envelope under the same package ID and require digest/binding rejection. | Pure round-trip and adversarial tests only; no server claim. |
| V1 rootKey compatibility and no implicit v1-to-v2 conversion | src/crypto/rootark-zk-recovery-package-v1.js; crypto owner | test/issue-65-recovery-rootkey-compat.test.js: the v1 shape retains rootKey; a v1 object or extra v2 rootKey field is rejected by the v2 parser. | Repeat the bounded in-repo inventory and test before any v2 importer; external consumers remain unknown. |
| Actor/operation matrix, prior-state signer, compromise-only rotation, and operation expiry | src/crypto/rootark-zk-recovery-manifest-v2.js; crypto owner | test/issue-65-recovery-manifest-v2.test.js: wrong actor, compromised-package signer attempting self-revocation, ordinary replace-package used for suspected compromise, unknown operation, and effective 330-second boundary are all rejected/accepted exactly as specified. | Pure signature/state tests including delay boundaries; no server authorization proof. |
| Target HPKE and Ed25519 proof, consent binding, one-time replay | src/crypto/rootark-zk-recovery-authorization.js; crypto owner | test/issue-65-recovery-authorization.test.js: only the live authorizer that decrypts and receives the unpredictable challenge over the approved pairing channel accepts HPKE possession; a public transcript alone is insufficient; repeated challenge fails after the first committed operation. | Pure protocol tests distinguish authorizer proof from server transcript checks; real paired-device UX remains blocked. |
| Complete contiguous signed history and bounded verifier | src/crypto/rootark-zk-recovery-history-v2.js; crypto owner | test/issue-65-recovery-history-v2.test.js: remove, reorder, or alter one intermediate manifest and require failure despite a valid-looking later head. | Pure verifier/adversarial fixtures; never counted as a deployed witness or rollback guarantee. |
| Linearizable shared CAS, append-only log, pending-read gate, terminal status proof, and restart | Backend-specific CAS, CAS-status, and witness adapters; exact module owner/path TBD until the owner confirms infrastructure | test/integration/issue-65-recovery-cas-witness.test.js: stale head/status is never accepted while any reservation is unresolved; cancellation requires a final independently signed no-commit proof. | Must run against the selected real backend and witness across processes/restarts; currently blocked, no mock substitutes. |
| Protected-content access/write admission serialized against keyring reservations | Backend-specific content storage and witness admission adapters; exact owner/path TBD | test/integration/issue-65-recovery-admission-gate.test.js: no new server-mediated read or write admission occurs under revision r after its reservation gate closes; stale revision/epoch admission fails after rotation. | Must use the actual selected content stores and keyring backend; offline held keys/caches remain an explicit residual. |
| Compromised-package replacement, forward epoch rotation, and no final-path loss | src/crypto/rootark-zk-recovery-manifest-v2.js plus package/CAS adapters; crypto/backend owners | test/issue-65-recovery-package-compromise.test.js: compromise revocation, fresh epoch generation, new-package wraps, and envelope activation are one CAS transition; old package cannot open the new epoch; missing alternate authority/coverage fails closed. | Proposed design tests only; real key storage, export retention UX, content-write gate, and backend are blocked. |
| History capacity, high-device/epoch sizing, warning, and hard stop | src/crypto/rootark-zk-recovery-history-v2.js; crypto owner | test/issue-65-recovery-history-capacity.test.js: encode maximum 256-device/64-epoch manifests, measure entry/history bytes, warn at 75%, and reject the first over-limit append without pruning. | Size and fail-closed tests only; checkpoint/rekey lifecycle requires separate approval and limits production claims. |
| Atomic device key/high-water persistence and restore behavior | Client-runtime secure-store adapter; exact runtime/module owner/path TBD | test/integration/issue-65-recovery-device-storage.test.js: restored lower high-water state is rejected or reconciled only with the fresh witness. | Must use the real OS provider on each supported device runtime; currently blocked. |
| Both independent paths restore actual protected content | Authorized-client and content-key integration; module owner/path TBD after client boundary is selected | test/integration/issue-65-recovery-content-e2e.test.js: package-only recovery succeeds with no trusted device and device-only recovery succeeds with no package. | Synthetic content on an actual client; currently blocked. |

The following pending-reservation adversarial cases are mandatory before design approval; the named tests remain proposals and were not created or run by this revision:

1. At revision r, reserve `revoke-device` or `revoke-package`; commit CAS; crash before witness finalization; restore the application store to r; attempt reads/writes with the revoked authority. The witness remains pending and no operation authorizes under r.
2. Repeat with the witness unavailable and after witness process restart. Missing status fails closed, and restart retains the same pending gate; loss of ledger continuity must not produce a committed receipt.
3. Resolve the exact committed proof and accept only the witnessed r+1 history. For cancellation, require the independently signed final `not-committed-final` proof, prove CAS is still exactly r and the reservation is tombstoned against later commit, then accept r only after the witness issues a fresh committed-head receipt.
4. For suspected package compromise, prove the compromised package can open its old epoch but cannot obtain the fresh epoch; no server-accepted new content uses the old epoch after the reservation gate closes; CAS loss does not activate locally generated keys; missing active authority/epoch coverage returns `COMPROMISE_RECOVERY_UNAVAILABLE` or `KEY_COVERAGE_INCOMPLETE` and never silently removes the final recovery path.

### 12.9 Remaining approval gate

Revision 3 remains a draft and is not approved. Independent review must specifically confirm: (1) the pending-reservation gate for fresh reads and state-dependent operations, exact crash/restart behavior, and the independently pinned CAS-status authority/trust assumption; (2) whether the fresh-witness gate is compatible with the previously approved offline-access direction and how existing local copies are described; (3) `compromise-package` semantics, mandatory replacement/forward rotation, and the no-trustworthy-device outcome; (4) the 330-second worst-case operation lifetime under the proposed 30-second skew bound; and (5) the proposed 75% history warning and hard capacity limits. The KDF remains a candidate pending supported Node 22 measurements; `rootKey` omission remains conditional; all-epoch coverage and high-water requirements remain; shared CAS, witness, secure storage, content admission, UX, migration, and deployment have no verified provider. Runtime code, test files, dependency changes, UI, migration, deployment, issue updates, and production work remain prohibited until independent review, owner approval, and prerequisites are confirmed.

## References

- Existing contract: `docs/architecture/zero-knowledge-migration-contract.md`, especially Sections 2.1–2.3 and 4.
- Existing crypto helpers: `src/crypto/rootark-zk-1.js`.
- Existing unwired keyring: `src/crypto/rootark-zk-keyring.js`.
- Existing persistence evidence: `db/index.js`, `server.js`, and the scoped `SyncObjectStore` implementation.
- [Pinned libsodium.js 0.8.4 wrapper API](https://raw.githubusercontent.com/jedisct1/libsodium.js/0.8.4/API_sumo.md).
- [The libsodium submodule Argon2id header used by libsodium.js 0.8.4](https://raw.githubusercontent.com/jedisct1/libsodium/33cc75ab1565d9dcbe808354191bd572ad6b64d0/src/libsodium/include/sodium/crypto_pwhash_argon2id.h).
- [Libsodium password hashing guidance](https://doc.libsodium.org/password_hashing/default_phf).
