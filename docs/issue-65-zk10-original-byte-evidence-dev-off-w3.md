# Issue #65 — original-byte evidence experiment (DEV-OFF, W3 source / W55 regression)

**Scope:** An isolated CommonJS verifier and disposable crypto tests. W3 source
`5d376ee24fb1e9d81a831a41dfb1d1157cafd023` and published PR #302
`5e852c149257588fa3700b32f418ef8efdb38cf6` descend independently
from `ce3d7ec4675a32455d844b60166ca32f627d3aca`. W55 imports only the
three new W3 experiment files onto the exact published PR #302 source.
Nothing is attached to an HTTP handler, multipart parser, staging directory,
WebDAV, backups, provider adapter or the live ZK10 cutover authority.
Production and R1 authorization remain **NO-GO**.

## Evidence actually checked

The owner statement is Ed25519-signed over a domain-separated canonical
record: immutable account ID, object ID, exact version ID, key epoch, SHA-256
and length of the **original opaque client bytes before server transformations**,
32-byte nonce, floor sequence/digest and a bounded time window. Owner public
key and DER/SPKI digest are supplied as independent **test configuration**,
not taken from multipart fields, JWT or a local database. Mutable Proxy wires,
unverified signatures, inconsistent versions/epochs, replayed nonces and byte
hash/size mismatches fail closed.

The test-only callback supplies a second pinned Ed25519 signer
for a nonce-challenged floor readback. The owner and floor signing keys must
be different cryptographic identities. Native `KeyObject.equals` rejects
identical public-key material even if a second `KeyObject` is constructed from
the same DER or its JavaScript `.export()` method is shadowed. Its
account/owner key, sequence, digest,
revocation state, TTL and signature must match the caller's fixed minimum.
No callback, readback, signer key, valid pin or retained minimum means denial.
The readback is repeated before body hashing and after assembly. Unknown floor
advances are rejected rather than accepting an unvalidated monotonic chain.
Hashing copies real native Buffer/Uint8Array ranges, rejects shared backing,
caller-shadowed length/region metadata and arbitrary Proxy sources, and never
returns raw bytes for provider I/O. The verifier permits at most 1 GiB of
evidence in up to 65,536 chunks of at most 16 MiB each.

The only positive result identifies a **syntactically and cryptographically
consistent, nonauthorizing signed-byte fixture** and explicitly reports
`authorizesIo:false`, `stagePermitted:false`,
`independentCustodyProven:false`, `offHostMonotonicFloorProven:false`
and `historicalCorpusComplete:false`. Successful test keys and a locally
injected signed callback are **not evidence** that a real operator owns or
retains an off-host floor. The module deliberately has no positive I/O
authorization, storage or production activation API.

## Outstanding independent blockers (not implemented)

- A production-provisioned owner signing root and secure owner/device lifecycle
  independent of the server and user-supplied HTTP fields.
- A real separately operated custodian, authenticated mTLS and accountable
  monotonic durable floor (including fork/replay control, crash restart and
  current revocation); these tests can only simulate a signer.
- Durable anti-replay across worker restarts, cross-process concurrency,
  horizontal replicas and failovers. The local nonce Set is intentionally
  limited to 8,192 entries and fails closed at capacity.
- An owner-signed **historical pre-upload** digest for existing legacy assets;
  an operator cannot reconstruct that prior consent from current server
  plaintext, source file hashes, or current provider metadata.
- A tamper-resistant, identity-bound immutable spool with OS-level ACL/handle
  checks and version-specific complete remote readback. This verifier returns
  no staged bytes; no provider operation is authorized by it.
- Complete historical corpus/version recovery, whole ZIP/account backups,
  background jobs and per-provider evidence. One signed object is not proof of
  account-wide migration or cutover readiness.

W55 TDD: a same-key custodian fixture was accepted before the fix (RED 8/9)
and rejected afterwards (GREEN 9/9) on Windows Node 22.23.3 NTFS,
Windows Node 24.14.1 NTFS and Ubuntu WSL Node 22.22.1. The Linux run also
passed 9/9 from a byte-for-byte copied ext4 workspace. Separate
cryptographic keys do not establish separate administrative custody; no
test here proves an independently operated custodian, real owner consent,
the complete corpus or R1 recovery. Independent SOURCE review of the exact
frozen SHA is required before any integration or publication, and this
experiment may not be used as production proof.

## 2026-11-09 — native SPKI identity correction (local follow-on)

Independent W42 SOURCE review found **P2** in W55's original candidate
`f3e1352064a0fcff893328b6ced4b6018a44de4c`: a valid Ed25519
`KeyObject` for owner A could override its instance `.export()` to return
SPKI bytes for unrelated key B. Configuration pinned to B then passed the
digest check while actual signatures were verified by A. The same flaw
affected the floor-signer pin. Native `KeyObject.equals` only compared owner
and floor against each other; it did not bind either to its independently
specified pinned identity. Therefore W55's 9/9 tests did **not** prove
trust-pin integrity, and its SHA is **SOURCE NO-GO**.

The follow-on corrects the SPKI extraction to call a captured native
`PublicKeyObject.prototype.export` function on the actual KeyObject, not a
caller-shadowable instance method. Its prototype is obtained from a local
fixed disposable Ed25519 public key that is never an accepted identity.
New adversarial owner/floor negatives were **RED** on the parent (owner
accepts unrelated pin), then **GREEN** after the correction. On the isolated
follow-on worktree, focused verifier tests are 10/10 PASS on Windows
Node 22.23.3/NTFS, Windows Node 24.14.1, and WSL Ubuntu Node 22.22.1 on
real ext4 (`/dev/sdd`); syntax and `git diff --check` also pass.

**Scope remains unchanged:** no live route imports the experiment; it
returns `authorizesIo:false` and `independentCustodyProven:false`. There is
no off-host floor, historical corpus proof, operating custodian or R1
authorization. The corrected exact commit still needs a **different**
independent SOURCE P0/P1/P2 reviewer and an explicit publication decision;
this local validation cannot itself issue release GO.

## 2026-11-09 — second independent P2: signer algorithm confusion

Peer W42 also found that the prior local fix `4e46859bba6c955c2a64638cfa1ffc3a0bfae332`
still consulted caller-shadowable `KeyObject.asymmetricKeyType`. A genuine
RSA-512 public key could falsely claim `ed25519`, while its RSA signature
occupied exactly 64 bytes and verified under Node's polymorphic
`crypto.verify(null, ...)`. Both owner and floor roles were affected. This
is a concrete algorithm-confusion **SOURCE NO-GO P2**, not a theoretical
warning, although no production I/O was authorized.

The subsequent isolated fix captures native `KeyObject.prototype.type` and
`AsymmetricKeyObject.prototype.asymmetricKeyType` getters from trusted Node
prototypes and invokes them on the real key object. The already captured
native `PublicKeyObject.prototype.export` continues to bind actual DER
to the caller's pinned hash. New RSA-512 owner/floor 64-byte signature
tests failed on the previous code and passed with the corrected getters;
genuine Ed25519 keys also pass despite malicious instance metadata shadows.
Focused verifier tests: **12/12 PASS** on Windows NTFS Node 22.23.3 and
Node 24.14.1, and **12/12 PASS** on WSL Ubuntu Node 22.22.1 real ext4
(`/dev/sdd`). This is still a DEV-OFF test-only module with no provider,
R1 or production authorization. A fresh peer must review the new exact
commit before any fast-forward of PR #302.
