# Issue #65: optional owner-backed ciphertext root provenance

The browser's historical ciphertext backup reader already verifies that HTTP
bytes match a caller-provided ciphertext root and that the GET authorization
names the exact historical revision and SHA-256 ciphertext digest. That root
comparison alone cannot establish who selected the root.

The opt-in `rootark-zk1-owner-ciphertext-root-checkpoint/v1` provides a
separate owner Ed25519 signature over deterministic CBOR with a dedicated
domain. Its exact fields bind scope, signer identity and key ID, current signed
manifest revision/digest/epoch, object identity/revision, historical ciphertext
epoch, 32-byte ciphertext root and issue time. The caller supplies a separately
trusted pinned owner public key and an owner-signed history checkpoint verified
with that same key and matching signed manifest revision/digest. Browser
verification mints an internal WeakMap-branded proof that cannot be made by
returning an untrusted JSON `verified: true` flag.

Passing this branded proof to `postProtectedCiphertextBackupRead` binds it to
the client's exact signed GET authorization and expected ciphertext root
**before any HTTP request**. Only then is `trustedRootProvenanceVerified`
`true`. The original no-proof read remains available with this flag `false`,
retaining compatibility with integrity-only callers. Historical object epochs
can differ from the current manifest epoch; both are independently signed and
checked. The output remains ciphertext-only and has no CEK.

## Boundaries

- Independent owner key provisioning and the freshness of the owner-signed
  manifest history are the caller's trust responsibility. Neither a server
  claim about a root nor an unpinned device key can satisfy signature checking.
- A former, later-revoked signer may still possess its signing key. This
  module **does not prove live device status**, online witness freshness,
  monotonic anti-rollback storage or current CAS/gate authorization. A
  checkpoint tied to an old manifest fails against a different current signed
  manifest; that is not equivalent to checking every later revocation.
- `authorizesProtectedIo`, `authorizesRecovery`,
  `authorizesRestore` and `durableBackupProven` remain `false`. This is
  origin provenance for already authorized ciphertext, not a restoration
  protocol, release authorization or external durability proof.

## Validation

Focused tests exercise independent Node canonical CBOR/Ed25519 equivalence,
plain-browser UMD, real authenticated HTTP GET, forged owner signatures,
cross-object/revision/epoch/root/manifest substitution, stale checkpoint after
a signed revocation-head change, denial before network I/O and the legacy
integrity-only path. No production deployment or independent online
revocation verification was performed.
