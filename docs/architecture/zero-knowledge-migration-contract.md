# Zero-knowledge architecture and migration contract

Status: architecture and threat-model proposal for review; not implementation, acceptance evidence, or owner approval.

Repository: `bielxdh3/root.ark`
Branch: `cdx/rootark-roadmap`
Local baseline: `28747c6ebdac873650e2d5a3c6193824e7cc9985`
Policy sources: D-003, D-006, D-007, D-008, and D-009 in `docs/product-discovery.md`

## 1. Acceptance boundary first

Root.ark is not a zero-knowledge product today. The current server-readable encryption and metadata modes, server-side previews/search, ClamAV scanning, server-native WebDAV, one-way synchronization MVP, and existing backup/restore behavior are legacy/current implementation behavior. They are not acceptance evidence for the future zero-knowledge architecture and must not be relabeled as compliant by this document.

This document defines a reviewable target contract and a migration boundary only. It does not implement cryptography, client code, server routes, key storage, migration jobs, synchronization, WebDAV bridges, or dependency changes. No current route or test result proves the target design. A future implementation packet must separately establish algorithm/library approval, client interoperability, threat-model closure, migration safety, and authorized-client decryptability.

The target trust claim is precise: for protected compartments, the service and its administrators may store and operate on ciphertext and minimum operational metadata, but must not possess an ordinary independent path to decrypt content, keys, previews, indexes, or recovery material. This does not erase endpoint compromise, recipient-held copies, traffic/metadata leakage, malicious clients, or operational access to ciphertext.

## 2. Versioned cryptographic envelope

Every protected file, version, encrypted derived artifact, and key envelope must carry an authenticated, versioned envelope. The initial schema should be algorithm-agile rather than naming an unapproved final algorithm:

```text
Envelope {
  format: "rootark-envelope",
  formatVersion: integer,
  cryptoSuiteId: registered opaque identifier,
  compartmentId: opaque identifier,
  objectId: opaque identifier,
  objectType: file | preview | thumbnail | index | recovery,
  contentVersion: integer,
  keyReference: opaque non-secret reference,
  nonceOrIv: suite-defined encoded value,
  ciphertext: bytes,
  authenticatedMetadata: suite-defined protected metadata,
  aadDigest: encoded digest or suite-equivalent binding,
  integrityProof: suite-defined authentication result,
  createdAt: operational timestamp,
  parentVersion: optional opaque/version reference
}
```

The frozen serialization, field encodings, required fields, and suite registry below define the implementation contract. `cryptoSuiteId` must be resolved through a versioned registry with explicit allowed, deprecated, and rejected states. Unknown, deprecated-for-writing, malformed, truncated, or downgraded envelopes fail closed; readers may retain a bounded compatibility window only when the approved registry says so.

No bespoke primitive, improvised composition, home-grown KDF, unaudited nonce construction, or “temporary” cryptography is acceptable. The frozen technical profile in section 2.1 resolves the implementation-only choices; it authorizes only bounded Phase 9 foundation work and does not claim current zero-knowledge behavior or release readiness.

The implementation gate must include positive and negative test vectors for every suite, cross-client round trips, malformed and tampered envelopes, wrong-key and wrong-compartment failures, replay/downgrade attempts, truncation, version transitions, deterministic metadata/AAD binding, and safe error classification without plaintext or key leakage.

## 2.1 Frozen rootark-zk-1 technical profile

This is the accepted Phase 8 architecture/security design for a bounded Phase 9 foundation, not an implementation result, product release, or claim that Root.ark is zero-knowledge today. It freezes the technical parameters below while leaving only genuine product policy in `OWNER_DECISION_PACKET`.

### Frozen suite and library boundary

Use one registered initial suite, `rootark-zk-1`, with these standards-based components:

- Content and derived artifacts: AES-256-GCM with a 256-bit CEK, a 96-bit nonce, and a 128-bit authentication tag. AES-GCM is the AEAD boundary for confidentiality and integrity; implementations must obey the per-key nonce-uniqueness requirement described by [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) and [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- Domain-separated derivation: HKDF-SHA-256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)). Every derived value uses an explicit, length-delimited `info` context containing the suite ID, purpose, compartment ID, object type, content version, and key epoch. HKDF is not used as a password KDF.
- Password-protected recovery packages only: the fixed browser/Node policy in Section 2.2 uses `libsodium-wrappers-sumo` `0.8.4` with `crypto_pwhash`, `crypto_pwhash_ALG_ARGON2ID13`, a 32-byte output, a unique 16-byte salt, and explicit recorded `opslimit`/`memlimit`; passwords never directly encrypt content.
- Device and compartment key delivery: final RFC 9180 HPKE, base mode only, `mode=0x00`, `kem_id=0x0020` (`DHKEM(X25519, HKDF-SHA256)`), `kdf_id=0x0001` (`HKDF-SHA256`), and `aead_id=0x0002` (`AES-256-GCM`), behind the explicit Root.ark envelope defined in Section 2.2. RFC 9180 does not define an application wire format; authenticated-HPKE modes and hand-built X25519-plus-AES compositions are rejected alternatives.
- Device authorization manifests: Ed25519 signatures through the same proposed/reviewed crypto boundary. HPKE base mode authenticates only the recipient possession of the private key; it does not authenticate the sender. Every accepted wrap therefore requires the canonical signed authorization manifest and exact signature-input bytes defined in Section 2.2. Login authentication, device authorization, and content authorization remain separate.

The proposed/reviewed library boundary is one small client-side crypto module exposing typed operations for random generation, AES-GCM, HKDF, Argon2id package protection, HPKE, Ed25519 verification/signing, and secure zeroization where the platform permits it. Application routes, storage adapters, WebDAV, sync, and UI code must not call primitives directly. The module must pin an independently reviewed, standards-conformant implementation, record provenance and supported platforms, verify reproducible artifacts, and expose no fallback to custom or weaker primitives. No formal integration audit has been established. Web Crypto may be used as a backend for the exact AES-GCM/HKDF operations only behind this interface and only after feature, interoperability, and security review; HPKE, Argon2id, and signature operations require the reviewed library backend. The frozen Phase 9 candidates and libsodium policy are recorded in Section 15; no dependency is installed by this document.

### Frozen key hierarchy, separation, and nonce construction

Each file version receives a fresh, uniformly random 256-bit CEK. A compartment encryption root (CER) is generated on an authorized client for each compartment and key epoch. The CER is wrapped to each authorized device public key with the HPKE suite above. The file CEK is wrapped under the current CER using the fixed one-shot per-wrap construction in Section 2.2; a share or recovery envelope creates a separately scoped HPKE-wrapped copy rather than exposing the CER. HKDF derives only purpose-specific subkeys and never reuses one derived key across purposes.

For AES-GCM, the fixed wrapping construction derives a single-use per-wrap key from the CER and `wrap_id`, then uses a fresh 12-byte CSPRNG nonce. There is no durable CER nonce ledger and no alternative wrap construction. `wrap_id` collision, reuse, retry, crash, rollback, or restore ambiguity burns the identifier and derived key and allocates a new 16-byte CSPRNG identifier; all such ambiguity fails closed. Nonces are never derived from filenames, timestamps, object IDs, or attacker-controlled values alone.

### Frozen envelope, AAD, and version registry

Use an explicit Root.ark deterministic CBOR envelope under the RFC 8949 profile in Section 2.2. Direct RFC 9180 HPKE supplies the HPKE `enc` and ciphertext outputs; the application envelope is not an invented COSE recipient structure. If COSE is retained for a signed manifest or a future interoperable binding, use only final RFC 9052 and RFC 9864 semantics with pinned fully specified algorithms. `draft-ietf-cose-hpke-26` is an active Internet-Draft/work in progress, not a final RFC dependency. The registry assigns each suite a status of `allowed-for-read`, `allowed-for-write`, `deprecated`, or `rejected`, plus minimum client version and migration rules.

The protected AAD and HPKE `info` bytes are the exact deterministic encodings defined in Section 2.2. Mutable routing, quota, operational timestamps, and provider fields are excluded unless explicitly versioned and authenticated. The envelope must be self-describing enough to select the registered parser, but must not contain plaintext names, keys, passwords, or recovery material. Unknown fields, duplicate fields, indefinite or non-preferred encodings, unknown suites, rejected versions, AAD mismatch, tag failure, and inconsistent parent/epoch state fail closed.

### Devices, recovery, rotation, and compromise

Every device has a distinct HPKE key pair and Ed25519 authorization key. Enrollment is approved by an existing authorized device or a verified recovery package, then recorded in a signed, compartment-scoped manifest with expiry, epoch, and replay/idempotency state. Login recovery never supplies content keys. Recovery packages contain encrypted CER epochs and authorization metadata, are protected by the user-controlled recovery mechanism, and are tested by the client before acceptance; the service receives only opaque encrypted package material.

Removing or suspecting a device revokes its manifest immediately, increments the compartment authorization epoch, and rotates the CER for future writes. Existing CEKs are rewrapped only when an authorized device has the required keys; historical re-encryption after compromise is explicit and separately verified. A compromise cannot revoke plaintext, exported keys, recipient copies, or already-decrypted caches. Lost recovery material is a fail-closed unrecoverable state unless another authorized device or approved recovery policy exists.

### Derived data, sharing, backup, bridge, and sync boundaries

Previews, thumbnails, indexes, and other derived artifacts use a fresh artifact CEK and the same AEAD envelope family, with AAD binding source object/version, derivation type, schema, and parameters. The server stores only opaque encrypted artifacts and may reject or route them without decrypting them. Server-blind sharing sends a separately scoped recipient envelope (HPKE-wrapped CEK or CER reference) and capability metadata; expiry/revocation stops future delivery but cannot revoke recipient-held plaintext or keys.

Backups contain ciphertext, deterministic envelopes, wrapped keys, manifests, and opaque integrity/migration state only. Cryptographic erasure is complete only after every service-controlled decryptable key, recipient envelope under service control, cache, backup, and restore copy is inventoried and destroyed or made unusable; legacy server-readable copies remain outside the target claim until migrated or expired under approved policy.

The trusted WebDAV bridge is a local client process, not a server route: loopback/OS-authenticated IPC, a short-lived compartment-scoped capability, OS-backed key storage, encrypted/minimized cache, atomic ciphertext writes, and crash journals are required. It decrypts only after local authorization and re-encrypts before upload; server-native WebDAV remains a legacy non-zero-knowledge mode. Sync transports opaque envelopes, signed manifests, versions, capabilities, and idempotency/replay state. Authorized clients, not the service, decrypt and resolve content conflicts; provider or network failure never causes plaintext fallback or an accepted unauthenticated state.

### Migration, rollback, downgrade resistance, and fixtures

Migration uses an explicit state machine and a monotonic envelope/version registry. It is opt-in, compartment-scoped, inventory-first, client-authorized, dual-read/target-write only during an owner-approved window, and never silently downgrades. Each object has an authenticated manifest, idempotency key, checkpoint, and client decrypt-and-verify proof before legacy key destruction. Rollback may restore a deliberately retained prior envelope/state, but cannot restore destroyed keys or external copies; partial or uncertain coordination remains `mixed`, `blocked`, or `migration-failed`.

Phase 9+ implementation and release work must ship RFC/NIST and suite-specific vectors, fixed deterministic fixtures with test-only keys/nonces, cross-language envelope fixtures, round-trip and wrong-key tests, AAD/tag/truncation/duplicate-field tests, replay/downgrade/unknown-suite tests, device/recovery/rotation/compromise tests, migration checkpoint/rollback tests, and fuzz/property tests. Interoperability requires at least two independent implementations or a reviewed reference plus a second client; production acceptance requires reproducible vector results and no plaintext/key leakage in errors or logs. These are not additional Phase 8 design blockers.

### Failure classification

Cryptographic authentication/tag failure, AAD mismatch, malformed or duplicate envelope field, unknown/deprecated/downgraded suite, nonce reuse/rollback, invalid device/recovery authorization, replay, or scope mismatch is `FAIL_CLOSED_SECURITY`. Missing optional provider/network/cache state without a verified ciphertext result is `RETRYABLE_OPERATIONAL`; it must not become plaintext fallback or success. Missing library/backend, unsupported platform primitive, unavailable native binding, or failed reproducibility is `BLOCKED_ENVIRONMENT`. Sharing UX, recovery authority, migration window, retention, and conflict policy remain `OWNER_DECISION`. Any unexpected parser/crypto error is `REQUIRES_SECURITY_REVIEW` and must not disclose sensitive values.

## 2.2 Independent Phase 8 closure corrections — 2026-08-14

This section supersedes any earlier ambiguity in this document. Verdict: **`PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`**. Phase 8 is `ACCEPTED`; Phase 9 foundation work is separately authorized in principle but remains `NOT_STARTED`, and no Phase 9 implementation, dependency installation, runtime cryptography, migration code, or test execution was performed here.

### Standards and application wire profile

`draft-ietf-cose-hpke-26` is the active IETF Internet-Draft as observed on 2026-08-14, not a final RFC and not a normative dependency. It is cited only as work in progress. The implementation target uses final [RFC 9180 HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) directly behind an explicit Root.ark deterministic CBOR envelope. RFC 9180 does not define an application wire format. If COSE is retained, only final [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) and [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) semantics with pinned fully specified algorithms may be used. Root.ark must not describe a `COSE_Encrypt0`-style object with an invented recipient structure as final standards semantics.

The `rootark-zk-1` envelope profile is frozen for bounded Phase 9 foundation work:

- `envelope_version`: unsigned integer `0..65535`.
- `suite`: the exact text string `rootark-zk-1`.
- `compartment_id`, `object_id`, `version_id`, `key_ref`, `sender_key_id`, `recipient_key_id`, and `replay_id`: definite CBOR byte strings, each `1..128` bytes; `wrap_id` is exactly 16 CSPRNG bytes and is never reused.
- `purpose`: one of the registered text strings `content`, `derived-data`, `key-wrap`, `recovery-package`, or `authorization`.
- `epoch`: unsigned integer `0..2^64-1`.
- `expiry`: unsigned Unix seconds `0..2^63-1`; operational creation/observation timestamps are not authenticated protocol fields.
- `hpke_enc`: exactly 32 bytes for the selected X25519 KEM; `hpke_info_digest`, `wrapped_key_digest`, and `ciphertext_digest`: exactly 32 bytes each. The frozen HPKE tuple is `mode=0x00`, `kem_id=0x0020`, `kdf_id=0x0001`, `aead_id=0x0002`.
- `signature`: exactly 64 bytes when an Ed25519 authorization manifest is present; Ed25519 public keys are exactly 32 bytes.

The profile uses RFC 8949 deterministic encoding: preferred serialization, definite lengths, shortest integer and length forms, and deterministic length-first map-key ordering. Maps have unique keys; duplicate keys, indefinite-length items, non-preferred encodings, unsupported tags, floats, trailing bytes, unknown required fields, out-of-range values, and unknown suite/profile versions are rejected before cryptographic processing. Parser errors fail closed and expose no plaintext or key material.

The exact authenticated structures use a two-stage construction to prevent circularity:

1. Perform the base-mode HPKE encapsulation first and obtain `hpke_enc`; then define `manifest_core_map` with exactly `type`, `suite`, `envelope_version`, `compartment_id`, `epoch`, `purpose`, `sender_key_id`, `recipient_key_id`, `object_id`, `version_id`, `key_ref`, `expiry`, `replay_id`, `idempotency_key`, `wrap_id`, and `hpke_enc`. Encode `manifest_core_bytes = deterministic_cbor(manifest_core_map)` and compute `manifest_core_digest = SHA-256(manifest_core_bytes)`.
2. Define `aad_map = {"profile":"rootark-zk-1/aad/v1","suite":"rootark-zk-1","envelope_version":envelope_version,"compartment_id":compartment_id,"epoch":epoch,"purpose":purpose,"object_id":object_id,"version_id":version_id,"key_ref":key_ref,"wrap_id":wrap_id,"manifest_core_digest":manifest_core_digest}` and `aad = deterministic_cbor(aad_map)`.
3. Define `info_map = {"profile":"rootark-zk-1/hpke-info/v1","suite":"rootark-zk-1","envelope_version":envelope_version,"compartment_id":compartment_id,"epoch":epoch,"purpose":purpose,"object_id":object_id,"version_id":version_id,"key_ref":key_ref,"sender_key_id":sender_key_id,"recipient_key_id":recipient_key_id,"wrap_id":wrap_id,"manifest_core_digest":manifest_core_digest}` and `info = ASCII("Root.ark/zk-1/hpke-info/v1") || 0x00 || deterministic_cbor(info_map)`; compute `hpke_info_digest = SHA-256(info)`.
4. After HPKE wrapping and content AEAD have produced their outputs, compute `wrapped_key_digest = SHA-256(wrapped_key)` and `ciphertext_digest = SHA-256(ciphertext)`. Build `manifest_map` by appending `hpke_info_digest`, `wrapped_key_digest`, and `ciphertext_digest` to the exact `manifest_core_map`; encode `manifest_bytes = deterministic_cbor(manifest_map)` and sign the final bytes as specified below. The HPKE operation uses the exact `info` and `aad` bytes; neither uses `manifest_bytes`, so this ordering prevents circularity. This construction is frozen for the bounded foundation; vectors and executable proof belong to Phase 9+.

### Base-mode sender authorization

HPKE base mode is recipient-only and does not authenticate the sender; authenticated-HPKE modes are not part of `rootark-zk-1`. The authorization manifest is mandatory, independent of HPKE success. Define `manifest_core_map` with exactly these fields: `type`=`rootark-authorization-manifest-v1`, `suite`, `envelope_version`, `compartment_id`, `epoch`, `purpose`, `sender_key_id`, `recipient_key_id`, `object_id`, `version_id`, `key_ref`, `expiry`, `replay_id`, `idempotency_key`, `wrap_id`, and `hpke_enc`. After the two-stage construction above, `manifest_map` appends exactly `hpke_info_digest`, `wrapped_key_digest`, and `ciphertext_digest`; `manifest_bytes = deterministic_cbor(manifest_map)` and `signature_input = ASCII("Root.ark/zk-1/authorization-manifest/v1") || 0x00 || manifest_bytes`. `idempotency_key` is a definite byte string `1..128` bytes and `wrap_id` is exactly 16 CSPRNG bytes. Ed25519 signs `signature_input`, not a language object or a re-encoded map.

Verification order is fixed: parse and enforce the profile; obtain the sender public key only from the already-authorized device registry; check the exact Ed25519 signature bytes over `signature_input`; validate suite/version/compartment/epoch/purpose, sender and recipient identifiers, object/version/key reference, expiry, replay and idempotency state; then compare `hpke_enc`, `hpke_info_digest`, and wrapped-key/ciphertext digests before HPKE open or content decryption. Any mismatch, duplicate idempotency key, expired manifest, revoked sender, wrong recipient, or HPKE/manifest disagreement is rejected before decrypt, publish, restore, sync, or migration.

### Wrapping nonce decision

The fixed wrapping construction is one-shot per-wrap AES-256-GCM under the CER. Compute `prk = HKDF-Extract(empty salt, CER IKM)`, then `wrap_key = HKDF-Expand(prk, ASCII("Root.ark/zk-1/key-wrap/v1") || 0x00 || deterministic_cbor({suite, compartment_id, epoch, purpose, object_id, version_id, key_ref, recipient_key_id, wrap_id}), 32)`. `wrap_id` is exactly 16 CSPRNG bytes and is never reused. Use a fresh 12-byte CSPRNG nonce for the single-use `wrap_key`; `wrapped_key` is exactly `nonce || AES-256-GCM(wrap_key, nonce, exact_aad, wrapped_key_plaintext) || 16-byte tag` for the 32-byte wrapped key. Retry, crash, rollback, restore ambiguity, collision, or reuse burns the identifier and derived key and allocates a new pair; fail closed on any ambiguity. A durable CER nonce ledger or alternative wrapping construction is not permitted because single-use derived keys eliminate that ledger.

## 2.3 Phase 9 v2 sender-setup compatibility amendment — 2026-09-29

This amendment adds an authorization-manifest profile that can be constructed with the pinned public RFC 9180 API. It does not revise the frozen `rootark-authorization-manifest-v1` profile, its v1 HPKE info/AAD/signature bytes, or the existing group-wrap flow. `SUITE_VERSION` and the HPKE tuple remain unchanged; `envelope_version=2`, the v2 manifest type, and new domain/profile labels select this application profile. Version/type mismatches, unknown envelope versions, and v1/v2 fallback are rejected.

The v2 manifest core has exactly the existing core fields: `type`, `suite`, `envelope_version`, `compartment_id`, `epoch`, `purpose`, `sender_key_id`, `recipient_key_id`, `object_id`, `version_id`, `key_ref`, `expiry`, `replay_id`, `idempotency_key`, `wrap_id`, and `hpke_enc`. The v2 static core is that same map without `hpke_enc`. The v2 HPKE info map contains exactly `profile`=`rootark-zk-1/hpke-info/v2` plus every static-core field. Its bytes are `ASCII("Root.ark/zk-1/hpke-info/v2") || 0x00 || deterministic_cbor(info_map)`. It therefore binds type, suite, envelope version, complete scope, expiry, replay/idempotency identifiers, and wrap identifier before HPKE setup; it contains neither `hpke_enc` nor a digest of the complete core.

The sender passes those exact info bytes to the supported `createSenderContext({recipientPublicKey, info})` API. RFC 9180 DHKEM binds `enc` and the recipient public key into its KEM context. After setup returns `enc`, the sender constructs the complete v2 core and its deterministic CBOR SHA-256 digest. V2 AAD uses the same v1 scope and wrap fields with profile `rootark-zk-1/aad/v2`, `envelope_version=2`, and that complete-core digest. Only then does it call the HPKE context's `seal(plaintext, aad)`. Production code must not use testing/debug-only encapsulated ephemeral material, private library methods, or a custom key schedule to imitate this flow.

The final manifest appends `hpke_info_digest`, `wrapped_key_digest`, and `ciphertext_digest` to the core and signs the deterministic CBOR bytes under `ASCII("Root.ark/zk-1/authorization-manifest/v2") || 0x00`. V2 recipients reconstruct info and AAD from the parsed manifest; obtain the sender public key from the active device registry and bind it to the expected `sender_key_id`; bind the expected recipient, compartment, object, version, key reference, purpose, epoch, and wrap identifier to trusted local state; verify the Ed25519 signature; compare expected scope and wrapped/content/info digests; and reject an expired manifest using a trusted current Unix time. The recipient then authenticates and opens the HPKE ciphertext before atomically claiming the scoped replay and idempotency identifiers. Plaintext remains local and is returned only after the claim succeeds; on replay or claim failure, the temporary plaintext buffer is cleared best-effort. This ordering prevents a corrupted HPKE ciphertext from consuming a valid replay identifier. The v2 compound opener requires all listed expected-scope fields, an explicit current Unix time, and a replay-claim callback. The integration must persist the claim atomically and treat anything other than a newly claimed result as replay or unavailable state, failing closed. AAD itself does not provide replay protection.

For v2, `openAuthorizationEnvelopeV2` is the only supported higher-level API for opening an authorized envelope and consuming replay state. The exported low-level `hpkeOpen` primitive does not verify a manifest signature, trusted scope, expiry, or replay state. A direct `verifyAuthorization` call that reaches replay-consuming mode for a well-formed v2 envelope rejects with `V2_ENVELOPE_OPEN_REQUIRED` before invoking the replay callback; malformed or incomplete inputs can fail earlier with their specific validation errors. Use the compound opener so ciphertext authentication precedes the atomic replay claim. The legacy v1 verification path remains unchanged.

This is a protocol compatibility increment only. It does not by itself complete the Zero-Knowledge runtime migration, persistent replay storage, migration/recovery UX, second-client interoperability, browser evidence, or production/release acceptance. Those remain separate Phase 9 requirements.

## 3. Keys, compartments, and authenticated metadata

Each file receives a fresh random content-encryption key (CEK). A CEK is never reused across files or compartments. A file version may use a new CEK or an explicitly approved version relationship; the relationship must not make historical key material a universal decryption path.

Each compartment has an isolated root/key hierarchy. User and device authorization keys receive access through compartment-scoped wrapping or envelope records. The server stores opaque key references and wrapped material, not an independently usable universal administrator key. A wrapped key must bind at least the compartment, object, content version, intended recipient/device scope, crypto-suite version, and purpose through authenticated metadata or AAD. A key valid for one compartment, object type, or purpose must fail for another.

Authenticated metadata/AAD must bind the ciphertext to its opaque object identity, compartment, version, content type, parent/version relationship, and integrity-relevant state. Mutable operational fields must be explicitly classified so a metadata update cannot silently rebind ciphertext or keys. Integrity failure is a hard failure: do not preview, index, publish, restore, synchronize, or release the object.

Opaque identifiers should replace plaintext filenames, folder names, user identifiers, and provider keys wherever the target product permits. The system must preserve enough separately authorized metadata to route, quota, deduplicate only where approved, retain, audit, and recover objects. Filename and folder-name protection is feasible only if clients perform name encryption/decryption and the service uses opaque IDs or approved blind lookup structures; this requires a separate searchable-metadata design and must not become an accidental plaintext index.

Unavoidable or likely operational leakage must be documented per deployment: ciphertext byte length and approximate size, object count, opaque identifiers, timestamps needed for operation, version relationships, request timing and frequency, network endpoint information, account/compartment existence where routing requires it, storage-provider placement, quota/retention state, failure categories, and possibly access-pattern or traffic metadata. The service must not claim to hide metadata it must observe to provide the selected operation. Audit records use opaque identifiers and may contain actor, IP/device, timestamp, operation, result, and security state, but not plaintext, keys, recovery material, decrypted names, search terms, previews, or unnecessary payloads.

## 4. Devices, authorization, and recovery

Keys are generated client-side. A trusted device may authorize another device through a compartment-scoped authorization flow; a valid recovery package may authorize a device without an existing device. Device authorization records must be scoped, expiring/revocable, auditable, replay-resistant, and bound to the intended compartment and device key. Login recovery and content-key recovery are separate: changing or resetting a password must not silently recover content keys.

Device removal immediately blocks future service authorization and rotates material used for future content and authorization. It cannot revoke plaintext or ciphertext already downloaded, decrypted, exported, cached, or held by a recipient. Lost-device handling must distinguish a reachable device, an unavailable device, a suspected compromise, and a lost recovery package; each state must have explicit user-visible consequences and fail-closed defaults.

Offline access stores only indispensable protected key material. The client must use OS-backed secure storage and local authentication where available, minimize cache lifetime and scope, bind local records to the device key, and make deletion/expiry behavior explicit. Offline copies are outside the service's ability to revoke retroactively and must be represented in the user/security model.

Recovery packages are generated client-side, protected with a user-controlled mechanism, versioned, exportable, and tested by the user before setup completes. Verification must prove that an authorized client can recover the intended key hierarchy without sending plaintext or usable recovery keys to the service. A suspected package compromise revokes that package for future authorization, records an audit event without the package contents, requires a new package, and rotates material used for future authorization. Historical re-encryption after compromise is separate, expensive, explicit, and never automatic.

## 5. Derived data, scanning, and quarantine

Previews, thumbnails, MIME classifications where product policy requires them, and full-text indexes are generated client-side for protected content where feasible. Derived artifacts are encrypted, carry their own versioned envelopes, bind to the source object/version and derivation parameters through AAD, and follow source authorization, retention, deletion, backup, and rotation state. A client without the relevant key fails closed; it must not receive plaintext or a “best effort” unencrypted derivative.

Scanning occurs client-side before client encryption when feasible. External uploads that cannot be scanned client-side enter quarantine by default and are clearly marked unverified. Quarantine metadata and payloads require a separate policy and audit boundary. An administrator may reject or release only under explicit approved policy and authorization; release does not claim malware verification and never requires server decryption. There is no automatic release based on scanner availability, migration completion, backup restore, or a successful metadata check.

The current ClamAV/server-readable scan path remains legacy behavior during migration. It must not be described as zero-knowledge scanning, and migration must label whether an object was client-verified, externally unverified, or processed by the legacy server-readable path.

## 6. Server-blind sharing and public links

Sharing delivers ciphertext and the required wrapped key material through separately authorized channels. A public link may contain or convey a recipient-held decryption capability only under a server-blind design in which the server cannot independently reconstruct the decryption secret. Link metadata must not turn into a server-readable key registry.

Upload-only and download/share capabilities remain separate. Links require explicit scope, expiry, revocation state, rate and abuse limits, and auditable creation/use/revocation. Revocation blocks future service access but cannot revoke plaintext, decrypted caches, ciphertext, or keys already obtained by recipients. Expired or revoked links fail closed; uncertain link state must not become successful access. The exact link UX, expiry defaults, recipient recovery, and fragment/key delivery mechanism remain owner-dependent until separately approved.

## 7. Backup, restore, and cryptographic erasure

Backups preserve ciphertext, authenticated metadata, crypto-suite and envelope versions, object/version relationships, wrapped envelopes, encrypted previews/thumbnails/indexes, integrity proofs, and the minimum migration/recovery metadata needed by authorized clients. Backup and restore must not create a server/admin plaintext path or universal recovery key. Restore validation must include integrity checks and proof that an authorized client can decrypt representative restored material; a successful archive extraction alone is insufficient.

Cryptographic erasure is a state machine, not a boolean filesystem deletion:

```text
requested → authorized → pending_key_inventory → pending_backup_expiry_or_invalidation
          → key_material_destroyed → verified_complete
          ↘ rejected / failed / requires_review
```

Completion requires an auditable inventory showing that every service-controlled key, envelope, backup copy, cache, and restore structure that could decrypt the scoped content was destroyed or made unusable and independently verified. If an old backup envelope cannot be invalidated safely, erasure remains pending until it expires; it must not be reported complete. D-008's 30-day trash/backup defaults, immediate access revocation, 30-day operational logs, and 180-day security logs remain policy constraints until implementation details are approved.

Erasure does not remove downloaded, exported, already-decrypted, recipient-held, or externally stored copies. It does not promise retroactive revocation of plaintext or ciphertext. Audit records must preserve truthful state transitions without recording keys, plaintext, or recovery packages.

## 8. Synchronization contract

The final product requires a bidirectional, version-aware synchronization protocol. It must define object identity, versions, upload/download direction, conflict detection, conflict representation, renames, moves, deletes, trash/restore, exclusions, encrypted metadata, offline queues, retries, replay protection, device authorization, key availability, recovery, and audit events.

The server may coordinate opaque envelopes, versions, capabilities, and integrity proofs, but must not decrypt protected content or resolve content conflicts by reading plaintext. Conflict resolution must occur on authorized clients or through a separately approved encrypted/metadata-only mechanism. Every operation needs an idempotency/replay key, authenticated scope, freshness/expiry, bounded payload, explicit result state, and safe handling of uncertain remote completion. A one-way sync MVP or cloud retry path is not evidence of this contract.

## 9. Zero-knowledge WebDAV

Protected zero-knowledge WebDAV requires a trusted local bridge or client. Server-native WebDAV must not decrypt protected content. The bridge is a separate trust boundary and must have:

- local authentication and explicit user/device authorization;
- strict path-to-opaque-object mapping without trusting remote WebDAV path text as an identity;
- least-privilege access to selected compartments and files;
- protected local key handling using OS-backed storage where possible;
- encrypted or minimized local caches with expiry, revocation, and clear offline-copy limits;
- bounded request/body sizes, replay protection, safe temporary files, and fail-closed authorization;
- crash journals and recovery that preserve ciphertext and metadata integrity without duplicating plaintext;
- audit events with opaque identifiers and no content, key, or recovery material;
- explicit behavior for unavailable keys, stale authorization, conflicts, rename/delete, trash, and partial writes.

The existing server-native WebDAV implementation is current behavior and remains outside this target acceptance boundary until replaced or explicitly scoped as a legacy non-zero-knowledge mode.

## 10. Migration from current server-readable encryption

Migration is opt-in, explicit, resumable, and compartment-scoped. It must never claim that an existing server-readable object is already zero-knowledge. Before any write, build an inventory containing object/version identity, current encryption mode, plaintext/metadata exposure class, derived artifacts, links, backups, cloud copies, WebDAV/sync references, quarantine state, retention/hold state, and whether an authorized client/key is available. Inventory output must not include plaintext content or keys.

The migration sequence is:

1. **Classify and label.** Mark legacy server-readable, protected target, mixed/transition, externally unverified, unavailable-key, and migration-failed states. Labels remain visible to operators and clients where required.
2. **Obtain client authorization.** The user authorizes a trusted client with the required content keys and confirms scope, cost, offline effects, links, derived data, backups, and rollback limits. Password reset or administrator status cannot substitute for content-key authorization.
3. **Client re-encrypt.** The client reads/decrypts only within its authorized boundary, generates a fresh target CEK/envelope, encrypts content and required derived data, verifies round-trip integrity, and uploads ciphertext plus authenticated metadata. The service never receives plaintext as part of the target flow.
4. **Dual-read/one-write transition.** During an approved compatibility window, reads can recognize legacy and target envelopes, but new writes use only the approved target format. Every object exposes its state; no silent downgrade or implicit legacy rewrite is allowed.
5. **Coordinate references.** Rebind versions, links, sharing envelopes, cloud objects, backup entries, WebDAV/sync references, search/index/preview artifacts, trash, retention, and quarantine labels. A reference that cannot be safely re-enveloped remains mixed or blocked.
6. **Checkpoint and rollback.** Use per-object integrity checkpoints, authenticated manifests, idempotent operation IDs, durable progress, bounded retries, and explicit rollback states. Rollback can restore a prior service-controlled envelope/state only while the old material is intentionally retained; it cannot restore plaintext or keys already destroyed.
7. **Verify before destruction.** An authorized client must decrypt representative and scoped migrated material, validate metadata/AAD/version relationships, and confirm backups/restores where promised. Only after proof may old service-controlled keys/envelopes be destroyed under the erasure rules.
8. **Close or remain mixed.** Failed, unavailable-key, unverified, and uncoordinated objects remain clearly labeled and are not counted as migrated. The service must not report zero-knowledge completion while any service-controlled path can still decrypt the claimed scope.

Backups made during transition must preserve both the state label and the applicable envelope versions. Links, WebDAV, sync, search/index/preview, and quarantine must each have explicit legacy/migrated behavior; no component may silently expose a plaintext derivative or downgrade an envelope to keep compatibility. A migration is complete only for the declared scope, not for the repository as a whole.

## 11. Security and threat-model review

### Assets and trust boundaries

Assets include plaintext content, ciphertext, CEKs, compartment roots, user/device authorization keys, recovery packages, encrypted derived data, opaque identifiers, link capabilities, migration manifests, backup envelopes, audit records, and local offline caches. Boundaries are client endpoint, trusted device, local bridge, Root.ark service, administrator/operator, storage provider, backup/restore service, BielOS or other external system, recipient, and network/transport.

### Attacker capabilities

Review must assume a malicious or compromised client, stolen session, compromised device, rogue recipient, replayed or reordered request, malicious migration input, tampered ciphertext/metadata, malicious or misconfigured provider, compromised bridge host, curious administrator, database/backup reader, and partial service compromise. The target does not protect plaintext already exposed to an authorized endpoint or recipient.

### Required controls and residual risks

| Risk | Required control | Residual limitation |
|---|---|---|
| Service/admin reads content or keys | Client-side generation, compartment isolation, wrapped envelopes, no universal administrator key, no server plaintext operations | A compromised authorized endpoint or malicious client can expose its own plaintext |
| Metadata leakage | Opaque IDs, encrypted names where feasible, field classification, minimum audited metadata, documented traffic leakage | Routing, size, timing, quota, retention, and some access patterns may remain visible |
| Tamper or substitution | Authenticated envelope/AAD, version/object/compartment binding, integrity verification before use | Availability and deletion can still be attacked even when tampering is detected |
| Replay, downgrade, or confused deputy | Version registry, audience/scope binding, nonce/idempotency, expiry, revocation, monotonic state, fail-closed unknown versions | Offline clients need bounded replay windows and explicit reconciliation |
| Recovery abuse | User-verified packages, separate login/content recovery, scoped device authorization, package revocation and rotation | Lost all keys/recovery may make content unrecoverable by design |
| Migration rollback or partial failure | Inventory, checkpoints, manifests, idempotence, dual-read/one-write labels, proof before key destruction | Cross-resource rollback cannot restore keys already destroyed or external copies |
| Backup exposure | Ciphertext-only backup, envelope/integrity preservation, key invalidation inventory, authorized-client restore proof | Existing legacy backups may keep a service-controlled decryption path until migrated/expired |
| Recipient/public-link leakage | Server-blind wrapped-key delivery, separate capabilities, expiry/revocation, recipient-copy warnings | Recipient-held plaintext/keys cannot be revoked retroactively |
| Bridge compromise | Local auth, OS key store, compartment scope, minimized encrypted cache, crash-safe journals, audit | A compromised local endpoint can access content authorized to that bridge |
| Sync conflict abuse | Client-side conflict authority, authenticated versions, replay protection, no plaintext conflict resolver | Usability and conflict resolution remain open architecture work |

Security review verdict: **`PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`**. The frozen design is internally consistent with D-003/D-006/D-007/D-008/D-009. Phase 9+ implementation and environment evidence remain unexecuted; metadata leakage limits, recovery authority, migration scope, sync authority, and bridge deployment retain their documented policy or implementation boundaries. This does not claim current zero-knowledge behavior or release readiness.

## 12. Implementation readiness

The following decomposition records a bounded Phase 9 foundation authorized by the accepted Phase 8 design; it does not claim that foundation work has started or that runtime acceptance exists. Vectors, interoperability, fuzz/property testing, recovery/rotation/compromise execution, bridge crash safety, migration rollback, backup/restore, provider/browser/CI/production, and runtime evidence remain Phase 9+ or environment work.

| Slice | Readiness | Why |
|---|---|---|
| Envelope schema and version registry | **No owner decision required for scaffolding** | Can define versioning, field classes, malformed-state handling, and registry interfaces without selecting the final suite |
| Metadata classification and leakage register | **No owner decision required** | Can inventory required/optional/forbidden fields and document operational leakage before implementation |
| Client test-vector harness | **No owner decision required for harness** | Can build fixture format and negative-test structure; suite-specific vectors are Phase 9 implementation work |
| Key lifecycle state model | **No owner decision required for state model** | Can model device authorization, removal, recovery, rotation, migration, and erasure states without implementing crypto |
| Migration inventory tooling | **No owner decision required for read-only tooling** | Can enumerate current modes, references, derived data, backups, and labels without rewriting data |
| Local bridge threat model | **No owner decision required for threat model** | Can define process, filesystem, key-cache, local-auth, and crash boundaries before selecting platforms |
| Exact algorithm/KDF/library/suite, nonce construction, and envelope serialization | **Frozen technical architecture; not an owner-packet item** | Section 2.1 freezes primitive composition, library policy, KDF domain separation, nonce construction, and serialization; Phase 9 verifies the implementation and provenance, while product owners decide only compatibility and migration policy |
| Sharing-link UX, expiry, and recipient recovery | **Owner-dependent** | Determines consent, usability, revocation expectations, and recipient-held-copy warnings |
| Recovery person/device policy | **Owner-dependent** | Changes account/key separation, social recovery risk, audit, and loss consequences |
| Mixed-mode migration scope and compatibility window | **Owner-dependent** | Determines how long legacy server-readable content and dual-read behavior remain allowed |
| Sync conflict authority | **Owner-dependent** | Determines whether clients, users, or a metadata-only service resolves conflicts without plaintext |
| 2FA coupling | **Owner-dependent** | Authentication assurance and content-key recovery must not be conflated; product policy is open |

## 13. OWNER_DECISION_PACKET

Implementation-only security architecture choices are not irreducible owner decisions. Section 2.1 records the frozen technical profile; a bounded Phase 9 foundation is authorized after this design gate, while implementation and release validation remain separate.

Only the following questions are irreducible owner decisions for the next architecture gate:

1. **Sharing-link UX, expiry, and recipient recovery.** Recommendation: server-blind, least-privilege links with explicit expiry/revocation and clear recipient-copy limits. Alternatives: no public links, or a narrower invite/device-only share model. Consequence: affects usability, recipient-held key risk, revocation promises, and audit. Independent work continues: capability state model and threat analysis.
2. **Recovery authority.** Recommendation: user-controlled verified packages plus trusted devices, with no universal administrator key; decide separately whether an explicitly chosen recovery person/device is allowed. Alternatives: device-only recovery or package-only recovery. Consequence: changes social-engineering, loss, compromise, and support risk. Independent work continues: recovery state transitions and compromise response.
3. **Mixed-mode migration scope.** Recommendation: opt-in compartment/object migration with dual-read/one-write labels and a finite owner-approved compatibility window. Alternatives: block legacy reads until migration or retain a longer legacy mode. Consequence: determines exposure duration, rollback inventory, operational cost, and when “zero-knowledge” may be claimed. Independent work continues: read-only inventory and integrity checkpoint design.
4. **Synchronization conflict authority.** Recommendation: authorized clients resolve content conflicts; the service coordinates opaque versions and integrity only. Alternatives: metadata-only server resolution for a narrowly defined class, or defer sync. Consequence: affects offline usability, convergence, privacy, and conflict-loss risk. Independent work continues: protocol state, replay protection, and version/conflict fixture design.
5. **Authentication/2FA coupling.** Recommendation: keep login assurance, device authorization, and content-key recovery as separate state machines with explicit step-up requirements. Alternatives: product-approved coupling for selected high-risk operations. Consequence: changes recovery and account-takeover risk without granting the server content keys. Independent work continues: threat model and capability/audit matrix.

No owner decision is required to parameterize the frozen technical profile or begin a bounded Phase 9 foundation. Owner decisions remain required for the listed product-policy choices and do not authorize migration, data rewriting, release, or a claim that Root.ark is zero-knowledge today.

## 14. Independent attacker matrix and closure classification — 2026-08-14

This is the fresh Phase 8 attacker matrix. Phase 8 accepts the design controls; implementation-only proof is Phase 9+ or environment-dependent evidence, not a Phase 8 blocker.

| Attacker or failure | Required protection and acceptance evidence | Classification |
|---|---|---|
| Server or administrator compromise | No ordinary server/admin decryption path; client-held keys, manifest verification, ciphertext-only storage, and no plaintext fallback are frozen design controls; negative tests and log review are Phase 9+. | `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Stolen storage or database/backup reader | Envelope/AAD integrity, opaque identifiers, ciphertext-only backups, leakage register, and truthful erasure inventory are frozen design controls; metadata and traffic leakage remain visible risks. | `IMPLEMENTATION_PHASE_REQUIREMENT`; `RESIDUAL_ACCEPTED_RISK` |
| Compromised or revoked device | Signed device authorization, epoch increment, future-content rotation, replay fencing, recovery separation, and explicit historical re-encryption are frozen controls; execution is Phase 9+. | `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Malicious recipient or public-link holder | Server-blind recipient wrapping, expiry/revocation, recipient-copy warnings, and no retroactive-revocation promise must be bound to owner-approved sharing UX. | `GENUINE_OWNER_DECISION` and `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Recovery-package compromise | Password protection, package verification, authorization rotation, compromise response, no login/content-key conflation, and recovery audit behavior are frozen controls; execution is Phase 9+. | `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Replay, rollback, or downgrade | Exact manifest replay/idempotency fields, monotonic suite/epoch state, restore fencing, version registry, and fail-closed unknown/old state are frozen controls; execution is Phase 9+. | `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Provider substitution or malicious cloud state | Provider identity, opaque key containment, authenticated envelopes, digest checks, and no plaintext fallback require provider-backed and failure-injection validation. | `ENVIRONMENT_DEPENDENT_VALIDATION` |
| Synchronization races and conflict abuse | Authenticated version/epoch state, idempotency, client conflict authority, and opaque transport are frozen controls; concurrent/offline fixtures are Phase 9+, while conflict UX remains owner policy. | `IMPLEMENTATION_PHASE_REQUIREMENT` and `GENUINE_OWNER_DECISION` |
| Local bridge crash or compromise | Local authorization, OS key storage, minimized encrypted cache, atomic ciphertext writes, crash journals, recovery fencing, and endpoint compromise boundaries require implementation evidence. | `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Backup/restore rollback or partial failure | Ciphertext-only archives, manifest/digest verification, restore fencing, key-destruction inventory, and rollback labels are frozen controls; proof is Phase 9+. | `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Supply-chain or library compromise | The HPKE and libsodium candidates, integrity observations, backend policy, and zeroization limits are recorded; vectors, transitive provenance, reproducibility, and interoperability are Phase 9+/release evidence. | `IMPLEMENTATION_PHASE_REQUIREMENT`; `RESIDUAL_ACCEPTED_RISK` |
| Metadata, traffic, timing, quota, and access-pattern leakage | Maintain a deployment leakage register and make no stronger privacy claim than D-003/D-009 support. | `RESIDUAL_ACCEPTED_RISK` |

## 15. Library and provenance matrix — read-only evidence observed 2026-08-14

The package versions and integrity values below are read-only npm metadata observations supplied by the independent review. They are not a formal audit, endorsement, reproducible-build result, or implementation selection.

| Candidate | Observed package/integrity | Primary repository or source | Runtime/backend and vectors | Audit, maintenance, zeroization, and supply-chain caveats | Disposition |
|---|---|---|---|---|---|
| HPKE Phase 9 candidate | `@hpke/core` 1.9.0, `sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==`; `@hpke/dhkem-x25519` 1.8.0, `sha512-S1MWWkAfu+TFxySgv5+P3O4Mx/jk7BsoplzQaA1s3sfUJVJ2UsZsSzSsMc+FXJumLXncoJFlO6mK6mDGspfmA==` | [hpke-js](https://github.com/dajiaji/hpke-js) | Candidate only; not installed or production evidence. Exact vectors, pinned transitive provenance, reproducible artifacts, backend support, and interoperability remain Phase 9/release work. | Formal-audit absence alone is not a Phase 8 blocker; concrete incompatibility, unverifiable artifact, or irreproducibility blocks Phase 9. JS zeroization remains limited. | `IMPLEMENTATION_PHASE_REQUIREMENT` |
| Non-selected HPKE provenance | `hpke` 1.1.4, `sha512-cPzmFEsiyNnD7281X5WeZ461mbH+3P+rjWMSNrLO5rks7dAJvFXAyMwCmorB61pxt+jBnd0GQ6CY43TqOxmhCQ==`; `@panva/hpke-noble` 1.1.4, `sha512-+bOeaH/9XP8FlRqSHOy2zDEAG/SMnDfvxGlBh0bIYtEvt6vP3fkInpwV/pdtde7dF1Ujw3pUVMzYfCDPQ3nZZw==` | [panva/hpke](https://github.com/panva/hpke) | Read-only provenance only; no alternative suite or implementation is selected for `rootark-zk-1`. | Later interoperability, provenance, and reproducibility review remains Phase 9/release work; formal-audit absence alone is residual risk. | `RESIDUAL_ACCEPTED_RISK` |
| Noble primitives | `@noble/curves` 2.3.0, `sha512-v7cY+4oWYPQszRj6ZFGzTVL7uP2TaLo1xMhWHzYC5wj0ZhOXQ5x+sBre8rF3hi8cAoi0bh1qXoovoOkdFtvqEg==`; `@noble/ciphers` 2.3.0, `sha512-Clu/xdfgVTf9o7ngLOURaxePwR0j8sjclKEtVij10/jGulwFsPWCvvRgG/XjUVf8Nei+jLG6uwyXzUTGY1DQrw==`; `@noble/hashes` 2.3.0, `sha512-oN+QwyX7VSHotibwubG3kpzbwKrfnyR6OOO+3Nk/53ADL7FmgHHz4TgrbaYKvvOw09u6QTx0oiH1cNCIOuN0CQ==` | [noble-curves](https://github.com/paulmillr/noble-curves) and corresponding upstream package sources | Portable JavaScript primitives; vectors and backend assumptions must be pinned per operation and version. | Upstream audit statements are not a Root.ark integration audit; JS zeroization is limited, and package integrity, transitive supply chain, maintenance, and reproducibility remain Phase 9/release evidence. | `RESIDUAL_ACCEPTED_RISK` |
| Browser Argon2id provenance | `argon2-browser` 1.18.0, `sha512-ImVAGIItnFnvET1exhsQB7apRztcoC5TnlSqernMJDUjbc/DLq3UEYeXFrLPrlaIl8cVfwnXb6wX2KpFf2zxHw==` | [npm argon2-browser](https://www.npmjs.com/package/argon2-browser) | Read-only candidate provenance; browser vectors, reproducibility, and memory behavior remain Phase 9 work. | Not selected by the frozen policy; JS/WASM zeroization is limited and formal-audit absence is residual/release risk. | `RESIDUAL_ACCEPTED_RISK` |
| JavaScript Argon2id provenance | `argon2id` 1.0.1, `sha512-rsiD3lX+0L0CsiZARp3bf9EGxprtuWAT7PpiJd+Fk53URV0/USOQkBIP1dLTV8t6aui0ECbymQ9W9YCcTd6XgA==` | [npm argon2id](https://www.npmjs.com/package/argon2id) | Read-only candidate provenance; browser/Node support, vectors, maintenance, and memory behavior remain Phase 9 work. | Not selected by the frozen policy; formal-audit absence is residual/release risk. | `RESIDUAL_ACCEPTED_RISK` |
| Node-native Argon2id provenance | `@node-rs/argon2` 2.1.0, `sha512-VBOWfM2u58/to3DFqTGJ2U5cJKQwmjN2zxzsQNZ5a2o8Z6aUrhvqQh8NdgotIF1Y0tMsBNtzOBDBdfvvkwJDSQ==` | [npm @node-rs/argon2](https://www.npmjs.com/package/@node-rs/argon2) | Read-only Node-native candidate provenance; browser closure, vectors, backend, and reproducibility remain Phase 9 work. | Not selected by the frozen policy; native zeroization and formal-audit absence are residual/release risks. | `RESIDUAL_ACCEPTED_RISK` |
| Frozen browser/Node Argon2id policy | `libsodium-wrappers-sumo` 0.8.4, `sha512-ql7hcgulKZ3ekfa2DGAogcCKsWU0diA/0nArz1CFzh93WQdb46/Kj18ka/Hifq6uA3Ush34Pc6vU/6HXeRwUkg==` | [jedisct1/libsodium.js](https://github.com/jedisct1/libsodium.js) | Candidate-only Node capability evidence; after `await ready`, a narrow adapter calls only `crypto_pwhash` with `crypto_pwhash_ALG_ARGON2ID13`, 32-byte output, unique 16-byte salt, and recorded `opslimit`/`memlimit`; it never exposes the sumo surface or uses `ALG_DEFAULT`. Browser vectors and reproducibility remain Phase 9 work. | JS/WASM memory zeroization is limited; no implementation or production claim is made. | `IMPLEMENTATION_PHASE_REQUIREMENT` |

The frozen libsodium-wrappers-sumo policy parameterizes browser/Node Argon2id use without claiming installation or production evidence. Browser vectors, reproducibility, backend execution, and truthful JS/WASM memory handling remain Phase 9+/release work. Missing dependency/network/native-binding evidence remains `ENVIRONMENT_DEPENDENT_VALIDATION`, not a Phase 8 blocker.

## 16. Phase 9 entry criteria and verdict

Phase 9 entry is separately authorized only for a bounded foundation after this accepted design is recorded. Phase 9+ must then execute exact vectors, cross-client interoperability, fuzz/property coverage, device/recovery/rotation/compromise tests, bridge crash safety, migration rollback/downgrade resistance, ciphertext-only backup/restore proof, candidate provenance/reproducibility/backend checks, and available provider/browser/CI/production validation. Concrete incompatibility, unverifiable artifacts, or irreproducibility block Phase 9 progression. Genuine owner decisions remain limited to sharing/public-link UX, recovery authority, migration window/UX, sync conflict UX, and any remaining 2FA policy.

Current verdict: **`PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`**. Phase 8 is `ACCEPTED`; Phase 9 is separately authorized but `NOT_STARTED`; Phase 15 remains `RELEASE_GATE_BLOCKED_ENVIRONMENT`. No Phase 9 foundation or runtime cryptography was executed by this correction.

## Sources and limitations

- `docs/product-discovery.md`: D-003 establishes client-side zero-knowledge content and minimum metadata; D-006 establishes compartment/device isolation and non-retroactive revocation; D-007 establishes versioned audited cryptography, per-file keys, verified recovery, and explicit historical re-encryption; D-008 establishes retention and truthful cryptographic-erasure limits; D-009 establishes encrypted derived data, unverified quarantine, server-blind sharing, bidirectional synchronization, local-bridge WebDAV, and encrypted backup/restore.
- `docs/architecture/current-server-responsibility-map.md`: current server-readable modes, metadata-dependent routes, scanning, WebDAV, persistence, cloud, backup, and lifecycle coordination are implementation boundaries, not target acceptance evidence.
- `docs/architecture/rootark-bielos-relationship-contract.md`: Root.ark and BielOS remain independently trusted systems with no shared identity, sessions, data, databases, keys, or automatic migration.
- `docs/validation/2026-08-13-rootark-continuation-evidence.md` and `docs/validation/2026-08-13-json-sqlite-parity-matrix.md`: focused local evidence is bounded and explicitly leaves current zero-knowledge behavior, full parity, live providers, OS WebDAV, migration, and production behavior unverified.
- `docs/security/current-findings.md` and `docs/security/phase-2-2-closure-audit.md`: prior security stabilization does not establish the future zero-knowledge architecture.
- Standards and provenance sources consulted for this correction: [RFC 5116 AEAD](https://www.rfc-editor.org/rfc/rfc5116), [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869), [NIST SP 800-38D GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final), [RFC 9106 Argon2](https://www.rfc-editor.org/rfc/rfc9106), [RFC 9180 HPKE](https://www.rfc-editor.org/rfc/rfc9180), [RFC 8949 CBOR](https://www.rfc-editor.org/rfc/rfc8949), [RFC 9052 COSE](https://www.rfc-editor.org/rfc/rfc9052), [RFC 9864 fully specified algorithms](https://www.rfc-editor.org/rfc/rfc9864), and active [draft-ietf-cose-hpke-26](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/). Primary implementation sources are [hpke-js](https://github.com/dajiaji/hpke-js), [panva/hpke](https://github.com/panva/hpke), [noble-curves](https://github.com/paulmillr/noble-curves), [argon2-browser](https://www.npmjs.com/package/argon2-browser), [argon2id](https://www.npmjs.com/package/argon2id), and [@node-rs/argon2](https://www.npmjs.com/package/@node-rs/argon2). These sources support review and provenance mapping; they do not constitute independent review or implementation evidence.

This is a reviewable design and threat-model record only. It does not change plan-tree, product decisions, issue state, runtime, tests, package files, dependencies, data, credentials, or remote state. Browser, CI, provider, OS-mount, and production behavior are not claimed.
