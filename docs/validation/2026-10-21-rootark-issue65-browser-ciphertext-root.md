# Root.ark #65 — Browser WebCrypto ciphertext chunk root interoperability

**Status: local client-only primitive. NON-AUTHORIZING; no production rollout.**

The standalone `public/client/rootark-zk1-ciphertext-chunk-root.js` implements
the existing `Root.ark/zk-1/ciphertext-chunk-root/v1\0` commitment using only
browser WebCrypto SHA-256. It does not define a new ciphertext format,
encryption algorithm, key hierarchy, signature or authority.

Each ordered ciphertext chunk contributes its big-endian 32-bit index, byte
length and SHA-256 digest to the final transcript, preceded by a fixed domain
and big-endian expected chunk count. The resulting root matches the
pre-existing independent Node.js implementation
`src/crypto/rootark-zk-chunk-root-v1.js` and PostgreSQL `SEALED` verifier.
The builder stores only digests/lengths, not full ciphertext chunks, and
rejects empty/oversized chunks, count mismatch, ambiguous concurrent append,
post-finish reuse and unsupported backends. It snapshots caller byte views
before any asynchronous WebCrypto operation and wipes temporary payload copies.

An adversarial browser/Node interoperability test uses the pre-existing
browser-only AES-256-GCM per-file CEK module to encrypt a private name and
file bytes, divides the resulting **ciphertext envelope** into chunks, and
reconciles the client's commitment to the server's exact root. The test
decodes/decrypts only inside the client boundary and checks that raw filename
bytes are absent from the ciphertext wire. Cross-realm execution verifies
the browser bundle has no Node `Buffer` or `require` dependency.

**TDD evidence:** RED (missing browser module) and GREEN with
`npx --yes --package node@22 node --test` for the new root test and adjacent
browser file-content test: **6/6 PASS, 0 FAIL, 0 SKIP** (Node 22.23.3).

**Limits and outstanding acceptance obligations:** A SHA-256 ciphertext
root alone does not authorize storage, protected GET/egress, manifest
publication, device revocation or a true physical STOP. An independently
authenticated, currently ACTIVE device must sign/approve the intended root
under an owner-approved wire format and a live pinned CAS/witness protocol
with atomic one-use admission before any strict transport may act on it.
Neither the candidate Ed25519 approval experiments nor this builder prove
those authorities. No integration with normal upload/download, sync, backup,
S3/GDrive/WebDAV or real multi-host fencing is enabled by this artifact.
