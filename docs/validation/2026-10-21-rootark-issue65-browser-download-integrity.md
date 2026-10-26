# Root.ark #65 — client-side ciphertext download integrity and decryption

**Status:** opt-in client-only byte verification, not a GET admission,
device/root authorization, production transport, provider or release.

The standalone browser/Node-compatible file
`public/client/rootark-zk1-ciphertext-download-integrity.js` verifies
an **already-received bounded ciphertext stream** against an expected
32-byte root supplied by its caller. Its deterministic transcript is
exactly `Root.ark/zk-1/ciphertext-chunk-root/v1\0`, shared with the
independent client SHA-256 root, Node and PostgreSQL SEALED verifier.
It requires canonical 0..N-1 chunk indices, exactly N frames, no duplicates,
truncation or unexpected frame fields, and a closed-world aggregate
ciphertext size cap of at most 4 MiB for the existing browser one-shot
file-envelope profile. Large-file streaming remains a separate design.

**TOCTOU and provenance boundary:** every frame and the expected root are
copied synchronously before asynchronous WebCrypto hashing. A WeakMap
binds each successful inspection to a *private* checked ciphertext copy.
Mutating the public `inspection.ciphertext` after verification or
fabricating `integrityMatchesProvidedRoot:true` on an arbitrary object
cannot change what the client decryptor consumes. The decryptor invokes
the existing browser AES-256-GCM `rootark-zk1-file-content` only with a
non-extractable CEK already held in that client; wrong account/compartment
AAD, tampered ciphertext and incorrect decryption keys fail closed.
The caller-provided expected root is **not** accepted as proof of active
device identity, owner consent, CAS/witness freshness, authorization epoch,
revocation state, or a consumed one-use replay permit. Returned inspections
always say `authorizesRelease:false`,
`trustedRootProvenanceVerified:false` and
`liveDeviceVerified:false`. Client-side decryption with a key already
held by a user does not grant a server permission to deliver ciphertext.

The no-Node browser-global build and Node CJS module use the same
WebCrypto compatibility API as existing `rootark-zk1-file-content.js`.
The browser script does not import server-only modules or use Node Buffer.

## Test-first validation

- RED: missing download verifier module (no new implementation existed).
- GREEN: Windows/Node **22.23.3** via the local npm cache,
  `npx --yes --package node@22 node --test` on this new test, the browser
  ciphertext-root test and existing browser file-content test:
  **11/11 PASS, 0 FAIL, 0 SKIP**.
- Includes encrypted file/private filename round trip, root/ordering/tamper
  rejection, missing/duplicate/oversized chunks, asynchronous mutable
  byte-array attack, forged inspector status, mutated public output bytes,
  cross-compartment AAD replay denial, and browser VM without Node.

**What remains unproven:** these tests do not exercise a real Root.ark
download route, strict physical STOP of GET, remote provider, TCP peer
buffer draining, identity enrollment/revocation, live witness, or
multi-host generation-fencing. No production API, HTTP handler, release
authorization or actual data path is enabled by this module. The
issue remains OPEN and **NO-GO for production**.
