# Root.ark #65 — signed read-back of a PUT with lost acknowledgement

**EXPERIMENTAL BROWSER CLIENT; NON-AUTHORIZING; PRODUCTION NO-GO.**

Starting HEAD: `98c25a5` (the observed amendment of `db093b4`,
same parent and commit message; this work did **not** rewrite that commit).

The module `public/client/rootark-zk1-uncertain-put-reconciliation.js`
adds a **new** operation independent of the already proven
`rootark-zk1-legacy-protected-copy.js` and does not change its fail-closed
behavior. A browser retaining the original ciphertext, its nonextractable
CEK, expected root, plaintext SHA-256 and active Ed25519 signing key can
investigate an uncertain PUT without retrying that PUT:

1. Copy current scope, metadata, object ID, previous revision, signing
   context, source ciphertext, expected ciphertext root and expected
   plaintext digest **before the first await**, then compute and compare the
   one-frame SHA-256 ciphertext chunk root locally. Reject mismatch without
   sending any HTTP request.
2. Compute the ciphertext SHA-256 and sign a new historical GET using
   `Root.ark/zk-1/protected-object-operation/v1` deterministic CBOR, a new
   32-byte nonce, the exact intended revision and ciphertext digest.
3. Use the existing same-origin authenticated `/zk-1/v1/content/read`
   route, active-device and current witness admission gate. The server
   returns only the exact archived revision and checks the digest against
   stored ciphertext. The browser checks expected ciphertext root and
   metadata **before** WebCrypto AES-GCM decryption.
4. Hash decrypted bytes, compare with the original owner-held plaintext
   digest, scrub temporary ciphertext/plaintext in success and error paths.
   Result has `clientReadbackVerified:true` but explicitly
   `independentDurableCommitProven:false`,
   `authorizesProtectedIo:false`, `authorizesCutover:false`.

It never calls `postProtectedCiphertextPut`, does not delete or
reclassify existing data, does not retry upon GET failure and does not
repair, mutate, seal, or version a provider. Input lengths are checked before
any allocation/copy, including raw `ArrayBuffer` and typed-array views:
maximum 4 MiB ciphertext and exactly 32 bytes for each digest and root.

## RED→GREEN / adversarial evidence

`test/issue-65-browser-signed-content-http.test.js` first failed RED due
to the missing reconciliation module. After implementing the helper it
passed GREEN with a **real Express HTTP listener, SQLite durable ciphertext
archive, nonextractable WebCrypto AES-GCM + Ed25519, canonical signed CBOR,
and a local signed but synthetic witness adapter**. The test deliberately
commits PUT revision 3 but drops its HTTP ACK, then proves GET read-back
of revision 3 while observing no second PUT. It rejects missing future
revision, incorrect owner plaintext digest, incorrect local ciphertext root
**before network**, substituted ciphertext in a 200 response, revoked device,
and mutable caller identity/ciphertext/root/digest changes after starting
verification. A plain browser UMD VM loads the module without Node `require`.
Existing signed HTTP PUT/GET and revocation cases remain covered. The
Express handler is backed by the same SQLite file, explicitly closed and
reopened after the uncertain write; read-back still succeeds and the
old lost-ACK PUT nonce remains rejected. The test counts **every real
HTTP PUT path**, not just the simulated lost-ACK wrapper, and verifies
that reconciliation generates no second write. A reviewer-confirmed P2
clone-before-bounds-check was reproduced RED with instrumented `.slice`
for an oversized ciphertext/root/plaintext digest; after checking the
original byte length before cloning, these tests pass GREEN. The
network-counter false-positive gap was also corrected.

## Non-goals / remaining blockers

A read-back from the same local SQLite database is **not** independent
durability, externally witnessed object-root publication, proof that a
lost-ACK write committed at a distributed linearization point, or physical
fencing across provider effects. A genuine concurrently revoked device
must fail even when the bytes exist. Another active device is not given
the lost signer CEK by this helper. The trusted owner must preserve CEKs
and expected hashes; this module does not turn externally supplied roots
into independently authenticated commitments. It does not change normal
sync/WebDAV/upload/migration/restore workflows or bypass the current
NO-GO for production.

Independent multi-host CAS/witness custody and durable anti-rollback
anchors, distributed admission/STOP of remote sockets, dual recovery,
provider-version/trash/backup coverage, and non-destructive product migration
still require implementation and operator-side verification. No production
data was read, changed, migrated or deleted; no unknown volumes were removed.
