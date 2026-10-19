# Root.ark Dual Recovery: Draft Specification for Independent Review

- **Status:** `DRAFT_FOR_INDEPENDENT_REVIEW` — not approved for implementation.
- **Architecture direction:** The owner approved shared compare-and-swap (CAS) as the target. No shared database, storage service, deployment topology, client keychain, or rollback witness is assumed to exist.
- **Issue:** [#65 — Architecture: Zero-Knowledge v1](https://github.com/bielxdh3/Root.ark/issues/65).
- **Baseline:** `Root/main` SHA `0636d638eee1ca5a75fde59936a9dbd3c66077cd`.
- **Review boundary:** This document describes both recovery paths and their target guarantees. It authorizes no code, dependency, migration, UI, deployment, release, issue close, or PR merge.
- **Independent review:** Not yet performed. Owner approval of this detailed specification is also pending.

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

The proposed MODERATE Argon2id cost is deliberately explicit because an attacker-controlled header must not choose memory allocation. Libsodium documents the MODERATE memory profile as 256 MiB and the password-hashing API requires the algorithm and parameters to be stored for deterministic derivation ([official guidance](https://doc.libsodium.org/password_hashing/default_phf)); the pinned upstream Argon2id header defines MODERATE as 3 operations and 268435456 bytes ([libsodium 1.0.20 header](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.20/src/libsodium/include/sodium/crypto_pwhash_argon2id.h)). The actual 0.8.4 wrapper artifact and cross-platform runtime cost still require verification. If a supported client cannot allocate the profile, recovery is blocked on that client; do not downgrade silently.

## 5. Recovery-package v1 proposal

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

## 6. Manifest v2 and authorization signatures

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

The exact operation-type registry is `initialize`, `enroll-device`, `revoke-device`, `register-package`, `replace-package`, `revoke-package`, and `recover-device`; unknown values fail closed. The first manifest is revision 1 and uses 32 zero bytes as `previous_manifest_digest`. Its initial device supplies proof of possession for both key pairs and signs the initial state; an authenticated account session may create an empty compartment but conveys no content-key authority. For upgrade from manifest v1, a prior authorized client must also possess a registered Ed25519 authorization key; if it does not, upgrade remains blocked pending reviewed enrollment. Each later manifest binds the SHA-256 digest of the entire prior canonical signed manifest. Every state mutation increments revision by exactly one; only key rotation increments `current_epoch`, by exactly one. Neither counter wraps; exhaustion blocks the operation. Every operation expires within a proposed maximum of 300 seconds from issuer time; issuer and server reject expired operations using their current time. This TTL is proposed for review and does not replace CAS replay protection.

`target_device_key_digest` is SHA-256 of deterministic CBOR `{hpke_key_id, hpke_public_key, authorization_key_id, authorization_public_key}`. Device and recovery key IDs must be unique within the compartment and must match the public keys derived from their private keys. The initial `initialize` signature is the only exception to previous-manifest signer lookup: verify it against the new device authorization public key after proof of possession and account authorization to create an empty compartment. It does not authorize reading any pre-existing content.

For each epoch `e`, compute `key_ref = SHA-256(ASCII("Root.ark/zk-1/recovery-key-ref/v1") || 0x00 || deterministic_cbor({suite, account_id, compartment_id, epoch:e}))`. This binds account and compartment into the expected key reference without changing the frozen content-envelope AAD profile. A device epoch wrap and a recovery epoch wrap use the existing HPKE suite and unique CSPRNG 16-byte `wrap_id`. Define a common canonical `context` map with exact fields `suite`, `account_id`, `compartment_id`, `purpose`, `recipient_type`, `recipient_id`, `recipient_key_id`, `epoch`, `key_ref`, and `wrap_id`. For device wraps, set `purpose="key-wrap"`, `recipient_type="device"`, `recipient_id=device_id`, and `recipient_key_id=hpke_key_id`; for recovery wraps, set `purpose="recovery-package"`, `recipient_type="recovery-package"`, `recipient_id=package_id`, and `recipient_key_id=recovery_authority.hpke_key_id`. `info = ASCII("Root.ark/zk-1/keyring-wrap-info/v2") || 0x00 || deterministic_cbor(context)` and `aad = ASCII("Root.ark/zk-1/keyring-wrap-aad/v2") || 0x00 || deterministic_cbor(context)`. The HPKE ciphertext is exactly 48 bytes for a 32-byte epoch key. The enclosing manifest actor signature authenticates the persistent wrap; opening the same valid static wrap on another recovery is allowed, while each new authorization operation has its own one-time replay/idempotency identifiers. This is a new keyring-v2 application context profile using existing algorithms, not a new cipher; it requires independent review and suite registry approval.

Manifest v2 retains the existing limits of 256 devices and 64 epochs. Epochs are contiguous and sorted; `key_ref` is recomputed and checked for every epoch. When recovery authority is active, there is exactly one valid, signed recovery wrap per manifest epoch; with no active recovery authority there are no accepted recovery wraps. Unknown/missing/duplicate wraps, key refs, device IDs, or key IDs fail closed.

The manifest MAC remains HMAC-SHA-256 under a purpose-separated HKDF-SHA-256 key derived from the current epoch key. Its exact HKDF `info` is deterministic CBOR of `{type:"rootark-keyring-manifest-mac-info-v2", suite:"rootark-zk-1", purpose:"manifest-mac", account_id, compartment_id, current_epoch, revision}`; salt is empty and output is 32 bytes. The MAC covers canonical `core`, excluding `mac` and `actor_signature`. The actor signature covers `ASCII("Root.ark/zk-1/recovery-manifest/v1") || 0x00 || deterministic_cbor(core_with_mac)` and uses the active Ed25519 public key from the previous validated manifest. It is not a self-signature by the newly proposed key. The service verifies the actor signature against the prior public state and checks CAS semantics; it cannot verify the epoch-keyed MAC because it never receives the epoch key. Clients must verify the MAC before using key material. `request_digest` is SHA-256 over `ASCII("Root.ark/zk-1/recovery-cas-request/v1") || 0x00 || deterministic_cbor(request_core)`, where `request_core` contains the expected prior revision/digest, operation ID/type, actor type/key ID, target identifiers and target-key digest, expiry, and proposed manifest core with `request_digest`, `mac`, and `actor_signature` omitted. It binds the semantic state transition, including package ID and public keys, but deliberately excludes encrypted package bytes to avoid a circular dependency: the package AAD contains the signed manifest digest. The CAS adapter separately computes and stores `request_body_digest = SHA-256(deterministic_cbor({manifest_digest, package_envelope_digest}))` outside the manifest for exact-byte idempotent retries. `package_envelope_digest` is SHA-256 of the newly supplied envelope when changed, the existing envelope digest when unchanged, and 32 zero bytes when no package is active. A repeated operation ID succeeds as a retry only if both digests match; the body digest is not an authorization or anti-rollback trust root.

For ordinary changes the actor is an active device authorized by the prior manifest. For package-only recovery it is the active recovery authorization key registered by the prior manifest. Both paths require the replacement device to prove possession of both its newly generated Ed25519 and HPKE private keys; the Ed25519 proof binds the hash of both public keys, and the HPKE proof is a one-time random challenge encrypted to the target HPKE key and returned inside the signed confirmation. The signature and MAC do not make an unauthenticated login session a content authority.

Package activation is one atomic transition: the device prepares manifest revision `r+1` with the new recovery key and all currently held epoch recovery wraps; the package payload contains that exact signed manifest and uses its revision/digest as `base_revision`/`base_manifest_digest`; the CAS from `r` to `r+1` commits the manifest and encrypted package envelope together. The manifest contains the package ID and public keys but not the envelope digest, avoiding a circular digest. If CAS loses, discard that envelope and prepare a new operation from the latest state. On later epoch rotations, the trusted device creates a separately scoped signed recovery wrap for the new epoch and commits it with the incremented epoch and revision. No password is cached on the service or device to update the package.

Existing manifest v1 remains read-only during a reviewed migration. No implicit v1/v2 fallback is permitted. Initializing v2 for an existing compartment requires an already authorized client, the expected compartment ID, current epoch material, and a successful CAS create from absent state. This migration and endpoint wiring are blocked until storage and product compatibility are reviewed.

## 7. Independent recovery flows

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

## 8. Shared CAS, monotonic revisions, and rollback guarantees

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

## 9. Explicitly blocked integrations

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

## 10. Validation and acceptance required after separate approval

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

## References

- Existing contract: `docs/architecture/zero-knowledge-migration-contract.md`, especially Sections 2.1–2.3 and 4.
- Existing crypto helpers: `src/crypto/rootark-zk-1.js`.
- Existing unwired keyring: `src/crypto/rootark-zk-keyring.js`.
- Existing persistence evidence: `db/index.js`, `server.js`, and the scoped `SyncObjectStore` implementation.
- [Libsodium password hashing guidance](https://doc.libsodium.org/password_hashing/default_phf).
- [Libsodium Argon2id profile constants](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.20/src/libsodium/include/sodium/crypto_pwhash_argon2id.h).
