# Root.ark #65 — browser Ed25519 to authenticated ciphertext HTTP

**Status: experimental, development-only local integration. PRODUCTION NO-GO.**

The existing opt-in `/zk-1/v1/content/put` and `/zk-1/v1/content/read`
routes accepted signed operations, but there was no browser-ready counterpart
producing the server's exact signed CBOR contract. The new UMD module
`public/client/rootark-zk1-protected-http-client.js` supplies:

1. `signProtectedContentOperation` requires a nonextractable WebCrypto
   Ed25519 private CryptoKey and an **externally verified** scope, current
   manifest revision/digest, epoch and active device ID. It generates a new
   32-byte CSPRNG nonce, binds the exact object identity, expected revision,
   operation type, request window and SHA-256 digest of ciphertext (for PUT).
   It serializes the existing `Root.ark/zk-1/protected-object-operation/v1\0`
   signed message with RFC 8949 deterministic CBOR ordering, validated against
   the production-side `contentAuthorizationMessageV1` implementation.
   Caller-controlled binary fields and form scalars are captured before
   the first asynchronous WebCrypto operation.
2. `postProtectedCiphertextPut` sends only base64url-encoded sealed bytes and
   an Ed25519 signed request to the explicit authenticated HTTP route.
   The request uses `credentials:'same-origin'`, no-store and redirect denial.
   Browser calls may not override the page's origin. In test/Node contexts,
   plaintext HTTP is permitted only for loopback hosts. Responses are
   size-limited, exact-shaped and bound to the requested object ID.
3. `postProtectedCiphertextRead` requires an independently authenticated
   expected ciphertext root, expected object revision and an already locally
   held nonextractable AES-GCM CEK. It validates returned scope-local object ID,
   exact revision and epoch, then invokes the existing browser chunk-root
   inspector **before** locally decrypting ciphertext. It never trusts a root
   supplied by the HTTP server, returns no CEK to the server, and retains
   `authorizesRelease:false`. The current JSON ciphertext route contains a
   single bounded frame, not a general multi-chunk streaming protocol.

## Evidence

`node --test test/issue-65-browser-signed-content-http.test.js` exercises
the actual Express HTTP middleware and protected SQLite store, a separately
signed **synthetic in-process** witness adapter, WebCrypto Ed25519 from the
same v2 fixture device's PKCS8 material, actual browser AES-256-GCM, and
byte-for-byte canonical-CBOR signature verification against the server.
Covered adversarial cases: replayed nonce, wrong signing key, a later
cryptographically valid signed revocation, pending witness, forged response
ciphertext/root mismatch, old object revision, foreign HTTP origin, form/byte
mutation during async signing, and an encrypted 80 KiB+ payload (large HTTP
JSON response). All fixture files live in the operating-system temp
directory and are removed after the test. It does not use real customer data.

## Deliberately unproved

The `manifestRevision`, `manifestDigest`, `deviceId`, `epoch`, expected
object revision/root and signing CryptoKey are **caller-provided**. This module
does not attest their independently authenticated provisioning, browser
key custody, OS-backed key rollback resistance, current device status or
origin JavaScript integrity. The test's witness adapter is simulated in
the same process; its HTTP route is real, but this is not an independent
mTLS CAS/witness operation or a multi-host generation fence. The ordinary
Root.ark upload/download UI is intentionally unchanged. Loading this module
alone does not enable production ZK or change legacy server-readable routes.

Still required for #65: independently administered and provisioned CAS,
witness, status and GateAuthority with durable linearizable admission,
effect-point STOP across real network/provider I/O, anti-rollback high-water,
normative browser/device trust and recovery UI, both recovery paths,
multi-device sync, WebDAV, versions/trash/backups, local/S3/Google providers
and safe reversible legacy migration. No push, merge, deploy or production
activation was performed.
