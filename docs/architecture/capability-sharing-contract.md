# Capability-based sharing contract

Status: architecture proposal for approved roadmap issue #68. The goal is approved; this document does not implement capability links or claim that existing public links satisfy the Zero-Knowledge design.

Related decisions: issue #68, the Zero-Knowledge baseline in `zero-knowledge-migration-contract.md`, and product decision D-009 in `../product-discovery.md`.

## Current evidence and boundary

The current public-link system is a bearer-link flow for a single file with existing expiry/use/password controls. Its routes and state are in `server.js` and `public-links.json`/`public_links`. Protected sharing does not yet have the capability model or server-blind key delivery required by issue #68. Existing links must remain explicitly legacy until a separately reviewed compatibility or migration plan exists; do not silently label or convert them as Zero-Knowledge links.

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

This contract does not implement a capability API, new link UI, recipient identity flow, protected public-link delivery, migration of existing links, or a specific expiry/default permission policy. It does not make legacy server-readable links Zero-Knowledge, promise retroactive revocation of recipient-held data, or prove device revocation, production proxy log hygiene, or provider parity. Those claims require implementation, approved product choices, and exact-head evidence.
