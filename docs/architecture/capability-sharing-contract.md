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

`POST /zk-1/v1/share/revoke` requires the authentic owner account and creates a durable SQLite revocation tombstone. Grant and nonce history survive restart; replays cannot reset them. SQLite-backed egress leases coordinate processes using the **same** local SQLite file: the tombstone takes effect immediately for new reads, while a successful revoke ACK waits for all previously admitted lease rows for that grant to be released after HTTP `finish`/`close`. After a 10-second drain deadline, the server aborts its own outstanding sockets and waits up to one more second; a remote/orphaned lease forces 503 without unsafe TTL reclamation. If a concurrent SQLite writer lock (`SQLITE_BUSY`) or another database failure prevents the tombstone UPDATE, revoke returns retryable 503 **without claiming the grant was revoked**; invalid owner identity/missing grant remains 403. A partially written response that throws is destroyed, and its durable lease is never cleared merely because the sender threw or rejected. Grant IDs are randomly created client-side, 256 bits, opaque, and are never placed into URL paths in these APIs. Routes enforce the same no-store headers, rate limiter, and strict JSON body shape as protected-content operations. The HTTP regression uses a real independent signed witness, trusted V2 manifest/history and on-disk ciphertext, with a real SQLite writer-lock and partial-response transport test.

**Precise limits:** the recipient must *already* control a trusted signing device inside the owner's independently verified compartment and must acquire the appropriate CEK entirely out of band. This API does not provision cross-account device trust, exchange HPKE/CEKs, decrypt a file, produce a public URL, implement anonymous or offline recipients, deliver an integrated browser recipient UX, or authorize folders, uploads, previews or further sharing. The separate optional recipient client helper handles only authenticated ciphertext GET and a non-durable local receipt; the application has no integrated recipient UX or authoritative owner-key pin discovery. There is no per-use quota or cross-host distributed grant ledger. Durable leases work only when each process uses the **same physical SQLite database**, not independent database replicas/hosts, and orphaned leases require independently reviewed reconciliation. HTTP `finish` is an application egress boundary, not proof of receipt by the remote client; a concurrent revocation cannot recall bytes already handed to network buffers. Revocation tombstones are restart-durable but have no independently signed anti-rollback authority against a compromised local database. The private SQLite grant table intentionally records signed ciphertext-identifying metadata and account names; separate privacy/audit retention policy is pending. Operator configuration, production rollout and a comprehensive independent security review remain prerequisites before broader claims.

### Owner-to-recipient ciphertext redemption (opt-in client)

The successful grant creation ACK now additionally includes the already-existing owner-signed deterministic CBOR statement and its Ed25519 signature as shareStatementBase64 and shareSignatureBase64. The owner must **explicitly hand off** that envelope with grantId/expiresAt to the intended recipient; no grant discovery, public URL, decryption key or automatic sharing is added.

The opt-in RootarkZk1RecipientShare.redeemProtectedCiphertextShare helper uses the recipient's locally held **nonexportable Ed25519 signing CryptoKey**, an authenticated same-origin HTTPS session (or loopback HTTP in DEV) and mandatory readIndependentAuthority() supplied by the trusted caller. That callback must yield an independently verified **current** V2 scope, {revision, epoch, digest} head and active signer/recipient device roster from external history/CAS, never a roster inferred from the untrusted server reply. The client checks the exact canonical 17-field CBOR, owner signature against the independently pinned roster key, recipient account/device, immutable ciphertext version/digest, current epoch, manifest head and expiry, then signs a fresh recipient-device GET. After receiving the bounded HTTP ciphertext it compares the returned grant statement/signature byte-for-byte, verifies SHA-256, re-reads independent history/roster after network and crypto awaits, and finally checks the signed expiry before returning.

The frozen rootark-zk1-recipient-ciphertext-receipt/v1 contains the ciphertext as base64url, version, digest, grant ID and signed proof. It never includes a CEK or plaintext and explicitly marks durableCopyProven=false, serverRevocationProofVerified=false and authorizesPlaintextRelease=false. The server enforces live grant revocation and its physical witness admission at HTTP egress, but the client **cannot independently certify post-egress server revocation state or durable storage**. readIndependentAuthority is a required caller-provisioned trust dependency, not a promise that this module verifies signed history or CAS itself; without a real externally verified provider, owner grant and recipient device key, redemption must not be enabled in production.

### Local recipient file open using owner-approved CEK (DEV-OFF)

The opt-in Node helper `openProtectedRecipientShareFile` in `src/crypto/rootark-zk1-recipient-share-cek.js` combines the above authenticated ciphertext redemption with the **existing** owner-approved X25519/HPKE per-file CEK transfer (`rootark-zk1-owner-authorized-file-cek-transfer.js`). The owner must have completed the existing independent-owner and witness-committed V2 device enrollment/PoP, have proved possession of the real file CEK by opening the exact AEAD ciphertext, and handed its recipient-specific signed HPKE envelope to that device over a separately trusted channel. No server endpoint stores or unwraps the CEK.

The helper binds the owner-signed recipient grant and owner-approved CEK envelope to identical tenant/compartment/keyring, object ID, revision, ciphertext SHA-256, epoch, manifest revision/digest, and recipient device. It then uses the existing HPKE opener and file AEAD verifier, reads independently verified live head and device roster **again after both crypto awaits**, and releases only local plaintext to the authorized caller. Its result sets `serverRevocationProofVerified:false`, `externalCustodyProven:false` and `authorizesProductionIo:false`; the caller must zero the returned `data` buffer. The helper does not enroll a new cross-account user, deliver keys, prove live off-host custody, establish an independent history provider, authorize Android viewing or bypass an expired/revoked share. Explicit grant and key-envelope handoff plus a trusted recipient environment remain required.

### Portable owner-approved recipient offer (DEV-OFF)

The opt-in Node `createProtectedRecipientShareOffer` helper accepts a four-field signed grant ACK **claimed** to originate from the server, the owner's file CEK and exact ciphertext, independently verified current scope/head/device history, an explicit `issuerPin` containing `deviceId` and `authorizationPublicKey` (Ed25519 base64url), and an explicit `recipientPin` containing `recipientUsername`, `deviceId`, `authorizationPublicKey` (Ed25519 base64url) and `hpkePublicKey` (X25519 base64url). The owner must **independently authenticate and pin both identities and keys**, without deriving either from the proposed ACK or its share statement. An ACK's four fields alone do **not** prove server issuance: an active recipient device can sign a well-formed fake ACK, so the helper *fails closed* unless the grant issuer ID and Ed25519 key exactly match the separately owner-pinned **distinct** issuer and its current independently verified roster record. Merely being on the current V2 device roster is insufficient to act as an issuer. It verifies the owner's existing signed issuer grant against that trusted pin and live roster, its immutable object/ciphertext/epoch/digest, the recipient signing key pin, and the independent signed V2 enrollment/PoP and X25519 pin through the existing CEK sealing ceremony. It independently rechecks current authority after sealing and checks **both** signed grant and owner-approved HPKE envelope expiries at the final release fence, then returns a JSON-serializable `rootark-zk1-recipient-share-offer-dev/v1` containing the signed grant, recipient name/device, exact file metadata and owner-signed HPKE CEK envelope. It contains no plaintext or unwrapped CEK.

The recipient can import that JSON through `openPortableProtectedRecipientShareFile`, supplying their already authenticated share GET session, nonexportable device signing key, independently pinned owner/V2 approval and witness history, recipient HPKE private key, and monotonic sequence floor. It verifies the offer identity and grant before invoking the existing ciphertext redemption, HPKE and file AEAD checks. A grant revoked or expired before the HTTP read fails at server admission or at the client's signed-expiry check. The local offer is not itself revocable after the recipient has obtained the ciphertext and CEK. The helper does not automatically distribute the offer, authorize new accounts or devices, discover contact keys, independently prove a revocation ledger, or produce a browser UI. All flags remain DEV-OFF. Real independent custody, identity enrollment for accounts outside the owner's V2 roster, and a reviewed delivery channel remain external prerequisites.

### Local owner→recipient CLI using existing trust (DEV-OFF)

`scripts/zk1-recipient-offer-local.js` is a small CommonJS **file I/O shell around those existing reviewed helpers**, not a key manager, identity provider, grant issuer, verifier for external custody, account onboarding tool or production CLI. It does not create or discover trust, keys, server sessions, signed grants, owner recovery approvals or an external authority. The owner must first obtain the real authenticated four-field `/zk-1/v1/share/grant` ACK and independently pin the issuer and intended recipient. Both machines must independently provision the required current V2/witness/roster authority and keys. No example or fallback test authority is installed.

On the owner's workstation, put `grant-ack.json` and a **privately provisioned, trusted** `trusted-share.js` in an existing owner-only directory, then run:

```sh
node scripts/zk1-recipient-offer-local.js export --owned-dir /absolute/private-owner-dir --context-module trusted-share.js --grant grant-ack.json --offer portable-offer.json
```

The owner explicitly delivers only `portable-offer.json` through a separately trusted channel into the recipient's own preprotected directory. The recipient's **separate** trusted module and authenticated HTTP session then run:

```sh
node scripts/zk1-recipient-offer-local.js redeem --owned-dir /absolute/private-recipient-dir --context-module trusted-share.js --offer portable-offer.json --output recovered-private.bin
```

The private CommonJS module exports one async function `buildTrusted(role, artifact)`. In `export` mode `artifact` is the untrusted ACK and the module must return **only** the 11 existing helper inputs `{ recipientPin, issuerPin, readIndependentAuthority, ownerPrivateKey, ownerHeldCek, metadata, objectRevision, ciphertext, ciphertextRoot, authority, nowSeconds }`, all from the operator's already independently authenticated local sources, **never** from the proposed grant. In `redeem` mode `artifact` is the untrusted portable offer and the module returns **only** `{ redeemInput, authority, operatorMinimumSequence, deviceHpkePrivateKey, nowSeconds }`. `redeemInput` must contain the recipient's real account/device identity, a **nonexportable Ed25519 private signing CryptoKey**, `origin`, `grant: artifact.grant`, a real `readIndependentAuthority` provider and an **already authenticated** `fetchImpl` for the signed `/share/read` endpoint. The other fields are the real externally pinned owner/V2/witness proof and recipient X25519 key. The CLI delegates signature, HPKE, AEAD, current head, epoch and expiration verification to the existing modules; supplying no proven authority fails closed. A copied offer alone does not supply authentication.

The CLI accepts only basenames inside the preexisting owner-only directory; uses the existing local owner-workflow private directory, trusted module and native NTFS/POSIX checks; refuses overwrites and symlink outputs; creates the offer or recovered plaintext as a new owner-only file; clears the opened plaintext buffer; and prints **only** fixed status tokens. It never prints a username, filename, key, plaintext or server response. A write failure may leave a partial artifact in the *private* directory rather than unlinking an attacker-replaced pathname; inspect/remove that private artifact before retrying. The recipient retains any successfully recovered plaintext, so later revocation cannot revoke that already-released copy; future signed HTTP GETs remain subject to live server revocation. This DEV-OFF workflow is not automatic public sharing and is not enabled without an operator-supplied genuine authority.

### Explicit fixed object-set recipient import (DEV-OFF)

An operator may choose **one to eight distinct objects** by putting independently owner-issued portable offer files into the same preprotected recipient directory and writing a private `selected-set.json` with the exact shape below (each offer must come from the existing individual owner export and a separately trusted delivery channel):

```json
{
  "schema": "rootark-zk1-recipient-object-set-dev/v1",
  "entries": [
    { "offer": "first-offer.json", "output": "first-private.bin" },
    { "offer": "second-offer.json", "output": "second-private.bin" }
  ]
}
```

```sh
node scripts/zk1-recipient-offer-local.js redeem-batch --owned-dir /absolute/private-recipient-dir --context-module trusted-share.js --manifest selected-set.json
```

The manifest is only a **local selection**, not an owner signature or a new multi-object grant. The CLI checks the bounded manifest, distinct offer/object/grant identifiers and unique, unused private leaf names before any plaintext or HTTP read. It then calls the unchanged signed HTTP/HPKE/AEAD redemption and the independently provisioned trusted `buildTrusted("redeem", offer)` **separately for every offer**. The existing live authorization, expiry, recipient and owner checks apply per object. On full completion it prints `ZK_RECIPIENT_BATCH_REDEEMED_N_OF_N`; if a later item fails, it exits nonzero with `ZK_RECIPIENT_BATCH_INCOMPLETE_K_OF_N_INSPECT_PRIVATE_OUTPUTS`, where `K` counts only completely written outputs. Previously written plaintext files remain in the private directory, and a failed write may have left a partial leaf requiring manual inspection. No rollback, all-or-nothing delivery, public sharing, folder delegation, new server-issued set capability, or production authorization is implied.

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
