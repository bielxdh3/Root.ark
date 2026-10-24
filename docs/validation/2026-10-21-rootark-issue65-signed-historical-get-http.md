# Root.ark #65 — signed historical ciphertext GET, browser↔HTTP↔SQLite

**LOCAL EXPERIMENTAL INTEGRATION; NOT A NORMATIVE PRODUCTION AUTHORITY. NO-GO.**

Starting HEAD: `96aa80f`. This milestone joins the existing browser-only
AES-256-GCM encryption, nonextractable WebCrypto Ed25519 signing, authenticated
Express ciphertext endpoints and transactional append-only SQLite version
archive. It does not replace the normal Root.ark upload/download/sync UI.

## Wire semantics, compatibility, and authorization

The already signed 13-field `Root.ark/zk-1/protected-object-operation/v1\0`
CBOR authorization retains its exact binary field order/encoding, Ed25519
domain, scope, device, epoch, nonce, issue/expiry and current manifest
revision/digest checks. A legacy `get` remains `expected_object_revision:null`
and `ciphertext_digest:null` and reads the current projection.

A **historical** `get` requires **both** a positive
`expected_object_revision` and a 32-byte `ciphertext_digest`. The trusted
browser signs those exact fields; the authenticated server verifies the
signer's ACTIVE status in the live signed manifest referenced by its
freshly challenged witness head, even if the requested ciphertext was
encrypted in an earlier epoch. It then selects the exact immutable
`(scope,object_id,revision)` row and compares the signed digest with the
archived digest **and** SHA-256 of the actual stored bytes before egress.
Missing revision, mismatch, unsigned fields and partial historical selector
fail closed; no fallback to latest. No new unprotected/list history route.

Browser `signProtectedContentOperation` optionally accepts
`expectedCiphertextDigest` solely with a historical GET and snapshots it
before async WebCrypto. Browser `postProtectedCiphertextRead` refuses a
requested revision different from the signed revision **before HTTP**, hashes
the downloaded ciphertext against the signed digest and checks an independently
provided one-frame SHA-256 chunk root **before** AES-GCM opens its payload.
Returned metadata/CEK remain client-held. It still returns
`authorizesRelease:false`; only the separate server admission can admit I/O.

## Evidence and limitations

Focused tests: `test/issue-65-browser-signed-content-http.test.js` uses
WebCrypto Ed25519, independently verified server canonical CBOR, real Express
HTTP and a SQLite-backed server. It encrypts two versions with distinct CEKs,
reads the immutable original after overwrite, decrypts version two, runs six
concurrent HTTP readers of version one, tests missing revision, wrong signed
digest, replay, caller byte mutation, mismatched response root/epoch/revision,
pending witness, signed device revocation, and active new-epoch device access
to old-epoch encrypted bytes with the corresponding old CEK. The witness is
still a **synthetic signed adapter in the same process**, not an independent
mTLS authority. `test/issue-65-protected-ciphertext-version-retention.test.js`
checks the historical GET after reopening the disposable SQLite archive
without erasing nonce history and preserves prior transaction-corruption and
immutable-archive regressions.

The caller's ciphertext digest and expected root are **not authenticated by
the server as independently witnessed historical object commitments**.
Possession of an authorized device signing key permits selecting a previous
opaque revision, but does not grant access to a historical CEK. A compromised
DB owner can restore/forge both archive and digests unless an external
high-water and signed root catalogue are verified. The witness tests are
same-machine simulation; they do not prove distributed linearizability,
effective remote provider STOP or multi-host egress fences. A signed GET
does not replace revocation atomically coupled with provider admission.

The full #65 still requires independent production CAS/witness trust roots,
distributed GateAuthority and physical STOP, complete recovery consent/PoP,
multiple providers, real sync/WebDAV, versions/trash/backup/restore, reversible
migration and adversarial multi-host rollback tests. No push, merge, deploy,
production data/credential change, production DB write or cleanup of unknown
Docker volumes was performed.
