# Capability-based sharing contract

Status: partial implementation for issue #68. A bounded local-file capability API exists. A separate DEV-only, authenticated, ciphertext-only protected-sharing API is implemented for already trusted owner-compartment devices; public Zero-Knowledge link/key delivery remains disabled.

Related decisions: issue #68, the Zero-Knowledge baseline in `zero-knowledge-migration-contract.md`, and product decision D-009 in `../product-discovery.md`.

## Implemented first slice: scoped local-file access

Authenticated file owners with `listFiles` may `POST /share/capabilities` with `name`, `folderId`, `expiresInMinutes`, an **explicit** `permissions` array (`view`, `preview`, `download`), and optional `maxViews`, `maxDownloads`, or `password`. The response contains a one-time public bearer URL and token plus `{ capability: true, scope: { type: "file", folderId, fileName } }`. No other fields are accepted; unimplemented recipient restrictions and decryption-key inputs fail with HTTP 400. Creation still checks the current owner, file permission, expiry and absence of server-side encrypted-file metadata. Cloud-backed files return 409 instead of assuming a hydrated cache is an immutable resource.

The bearer uses a reserved uppercase `C` followed by 47 lowercase hexadecimal characters (188 bits of random content). Old automatically generated legacy bearer tokens remain lowercase. The reserved prefix forces a capability without valid `shareKind`, resource binding, or matching file identity to fail closed even if its metadata was lost or malformed. The capability record pins the folder and filename plus a SHA-256 digest of local filesystem device, inode, size, birth time and modification time; after file hydration and immediately before serving an already-opened file handle, all values must still match. A replaced or normally edited file requires a new grant. This is a local filesystem generation binding, **not** a cryptographic content or signed Zero-Knowledge version proof.

Public `/share/:token/...` requests reuse the existing operation allowlist, password sessions, expiry, preview/download quota reservations and final byte-stream authorization. `maxViews` and `maxDownloads` are optional, with `0` meaning unlimited. The authenticated issuer may `DELETE /share/capabilities/:token`; a different account cannot revoke it. SQLite records a revoked tombstone, and JSON removes the active record. Already issued bearer URLs then fail. Audits use a non-authorizing digest of the token; new capability audit events omit file names and folder paths.

### Boundaries that remain open

- Capability tokens are still stored as bearer identifiers by the legacy `public_links` persistence API and appear in the public URL. Logs outside this app (notably reverse proxies) must be configured separately not to record them. This slice does **not** implement a hashed-verifier-only database design or a secret-free URL.
- JSON quota updates are synchronous within one Node process but are not cross-process transactional; SQLite quota reservations are atomic. Do not claim multi-replica exact-count limits on JSON storage.
- Only one current local-file generation is supported. Folder/object sets, upload/add/list permissions, recipient identity requirements, durable cloud object IDs, cryptographically bound ZK versions and offline recipients remain unsupported.
- Encryption-enabled files remain blocked by the existing share creator and resolver. No decryption key or key envelope is accepted; there is no client-side recipient key transfer, device trust, epoch rotation or cross-device ZK sharing proof. Existing legacy links are unchanged and must not be described as Zero-Knowledge capabilities.

## Implemented bounded protected ciphertext sharing (DEV-only, ZK v2)

The opt-in ZK v2 protected-content server registers these routes **only** with a locally provisioned `Zk1ProtectedObjectStore` configured for *both* independently verified signed device history and physical I/O admissions. This is separate from `/share/*` and the legacy public-link database. It is not available when the protected-content bootstrap is disabled or the V2 trust requirements are absent.

`POST /zk-1/v1/share/grant` requires the authenticated owner account with `listFiles` and its trusted compartment, a fresh device-signed `get` operation that pins one **existing ciphertext object revision and SHA-256 digest**, a 32-byte random `grantId`, the exact recipient username and **already enrolled** recipient device ID, a UNIX-seconds expiry (at most 24 hours), and a separate Ed25519 signature by the authorizing device over `Root.ark/zk-1/protected-ciphertext-share/v1\0` plus deterministic CBOR of the bound grant statement. The signed grant includes account, compartment, keyring, ciphertext digest, version, epoch, manifest revision and digest, issuer device, recipient account and device, and expiry. The owner-signed `get` has its own independent witness/history authorization and durable replay nonce. The server verifies the recipient device is currently enrolled and active; it never invents a recipient key, device trust relationship or owner signature.

`POST /zk-1/v1/share/read` accepts `{ grantId, authorization, signatureBase64 }` under the recipient's authenticated account with `listFiles`. It requires a **fresh recipient-device-signed get** for the exact stored object/revision/digest and current manifest, then checks the owner grant signature against the independently verified *current* device history, recipient/account/device match, expiry, and non-revocation before returning only `{ id, revision, epoch, ciphertextBase64, shareStatementBase64, shareSignatureBase64 }`. It keeps the physical witness admission through HTTP egress. A grant ID alone does not grant access; forwarding to another account/device fails. A later object version never expands the grant. Changes in the key epoch or issuer-device revocation prevent use of the old grant.

`POST /zk-1/v1/share/revoke` requires the authentic owner account and creates a durable SQLite revocation tombstone. Grant and nonce history survive restart; replays cannot reset them. Grant IDs are randomly created client-side, 256 bits, opaque, and are never placed into URL paths in these APIs. Routes enforce the same no-store headers, rate limiter, and strict JSON body shape as protected-content operations. The new HTTP regression uses a real independent signed witness, trusted V2 manifest/history and on-disk ciphertext, covers wrong account, recipient/device substitution, tampering, original nonce replay, new object version, expiry, independent witness refusal, device revocation, explicit grant revocation and restart.

**Precise limits:** the recipient must *already* control a trusted signing device inside the owner's independently verified compartment and must acquire the appropriate CEK entirely out of band. This API does not provision cross-account device trust, exchange HPKE/CEKs, decrypt a file, produce a public URL, implement anonymous or offline recipients, deliver a browser recipient UX, or authorize folders, uploads, previews or further sharing. A recipient has the signed statement and ciphertext for independent verification, but the application has no integrated recipient client flow or authoritative owner-key pin discovery. There is no per-use quota and no cross-host distributed grant ledger. A concurrent revocation does not recall bytes already admitted and sent. The private SQLite grant table intentionally records signed ciphertext-identifying metadata and account names; separate privacy/audit retention policy is pending. Operator configuration, production rollout and a comprehensive independent security review remain prerequisites before broader claims.

## Current evidence and boundary

The existing public-link system still uses bearer links in `server.js` and `public-links.json`/`public_links`. The separate authenticated DEV-only ciphertext grant is bounded to a pre-enrolled device and has no independent recipient key delivery, so full public Zero-Knowledge sharing remains incomplete. Existing links remain explicitly legacy until separately reviewed compatibility or migration is approved.

The feature must build on the existing public-link authorization, revocation, storage-provider, and audit boundaries. It must distinguish authenticated account authorization from possession of an anonymous capability. It must not introduce a server-held universal decryption key.

## Security invariants

1. Every link has an explicit resource scope and an allowlist of operations. Authorization checks the requested operation, exact resource identity, current expiry/revocation/limit state, and any recipient constraint on every request.
2. A valid capability cannot perform an operation absent from its scope. Read/view, download-original, upload/add, and list are separate operations; an upload-only capability cannot read or list existing content.
3. Service authorization material and decryption material are separate. The server may validate a narrowly scoped bearer authorization, but file/compartment keys and plaintext remain client-side. Link key material is not sent in request paths, query strings, referrers, logs, analytics, or server audit records.
4. Resource/object/version/compartment scope and the crypto epoch or key-envelope reference are authoritatively or cryptographically bound. A stale key binding fails closed; it does not silently widen the link to a newer file or compartment key.
5. Expiry, revocation, exhausted use/download limits, malformed capability state, and unauthorized operation all fail closed with indistinguishable public responses where revealing state would help enumeration. Replays cannot reset limits.
6. Copying or forwarding a complete link can transfer only the exact capability already granted. It cannot add permissions, resources, a longer lifetime, or a newer key. The product must clearly explain that revocation cannot remove plaintext or keys a recipient already obtained.
7. Bearer secrets and verifier values never enter logs. Audit records may use a separate random, non-authorizing audit reference; it must not be the capability ID or be accepted as authorization. Audit records may also contain an opaque resource or compartment ID, actor/device, operation, result, time, and policy reason; they do not contain decryption material, filenames, plaintext, or key envelopes.

## Proposed bounded architecture

### 1. Capability record

Represent a capability as a server-authoritative record with a random opaque ID; a verifier for a high-entropy authorization secret; a stable resource/object set; an explicit operation allowlist; creation and expiry times; optional use/download limit and recipient constraint; key-envelope/crypto-epoch binding where protected content is involved; creator and revocation state; and versioned policy fields. Store no plaintext file key and no reusable bearer secret. Protect verifier comparison against timing differences and rate-limit failed attempts.

If a capability covers a changing object set, define whether membership is a fixed snapshot or a live folder scope before enabling it. A single-file capability must bind to stable object/version identity, not merely a mutable filename or path. The server validates the authoritative record on every operation and atomically records any count-limited use before serving or accepting content.

### 2. Separate authorization from decryption

Issue distinct authorization and decryption material. The server validates only the scoped authorization proof and returns ciphertext plus the crypto metadata needed by a recipient. The recipient decrypts locally using a key or key wrap that never reaches the server. For anonymous links, define a browser delivery mechanism that keeps decryption material out of HTTP requests and referrers; a fragment is a candidate to test, not an accepted implementation detail until browser history, copy/paste, password-manager, preview, and recipient recovery UX are reviewed.

Protected link creation must be disabled until the authorized client can construct, receive, and verify the server-blind key envelope end to end. Current server-key-readable links do not meet this condition. Do not add a fallback that sends a compartment key to the server or silently downgrades a protected file to a legacy link.

### 3. Operation enforcement and revocation

Route every capability request through one authorization service that resolves the capability, validates its scope and operation, validates expiry/revocation/constraints, and returns a narrowly scoped decision. Public view, download, preview, list, and upload routes must each request their own operation; checking only that “the token exists” is insufficient. Authenticated account sharing additionally checks the current account permission and device/session state, and capability possession does not override those checks.

Revocation prevents future service operations immediately and is independent of content retention. It cannot recall previously downloaded ciphertext, plaintext, or keys. Key rotation can make a recipient's old envelope stale for future versions, but does not erase copies the recipient already holds. A version change must not silently grant a new key or expanded resource scope.

### 4. Limits, audit, and failure behavior

Define maximum token length and entropy, failed-attempt rate limits, use/download counter semantics, clock source, expiry precision, and atomic behavior under concurrent requests. Limits are server-controlled and cannot be reset by a client replay. Store verifier and record data through the existing persistence boundary with migration parity, restart recovery, and JSON/SQLite behavior covered before runtime rollout.

Audit creation, permission changes, limit changes, revocation, denied operations, and successful restore/key-rotation handoffs without storing credentials or protected content. Return bounded generic errors to anonymous callers while preserving detailed internal audit reasons. Do not log full share URLs in application, proxy, analytics, browser, or error-reporting layers.

## Required proof before issue #68 can be called complete

- A route matrix proves each operation is allowed only for the exact capability scope and requested permission, including folder/object boundaries and filename/path reuse.
- Expiry, revocation, exhausted limits, malformed state, concurrency, replay, and persistence restart all fail closed.
- Token brute force is bounded; secrets and key material do not appear in logs, analytics, URLs sent to the server, referrers, or error responses.
- A protected recipient decrypts locally using the intended key envelope; inspection of server request, storage, database, and audit state proves the server never receives that decryption material.
- Stale epoch/key bindings fail closed; key rotation, device revocation, and capability revocation prevent future access within their stated boundaries.
- Forwarding a link grants no operations or resources beyond its declared capability, and the recipient-facing flow explains forwarding and revocation limits.
- Threat-model tests cover token leakage, forwarding, replay, stale keys, revoked devices, brute force, metadata leakage, storage-provider state, and authenticated/account-sharing boundaries.
- Link permission defaults, maximum lifetime/use limits, recipient restrictions, object-set semantics, recovery UX, migration treatment for existing links, and audit retention are approved before enabling the product path.

## Explicit non-claims

The two bounded APIs described above do not implement a complete protected public-link or anonymous recipient experience, key-envelope handoff, link UI, or migration of existing links. They do not make legacy server-readable links Zero-Knowledge, guarantee retroactive revocation of recipient-held data, or prove global distributed device revocation, proxy log hygiene, provider parity, or production readiness. Those claims require separate implementation, decisions and exact-head validation.
