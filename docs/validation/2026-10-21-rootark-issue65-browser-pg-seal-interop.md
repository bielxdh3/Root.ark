# Root.ark #65 — browser ciphertext commitment vs physical PostgreSQL SEALED

**Evidence boundary:** single-host, disposable PostgreSQL 18.6 integration
of **ciphertext bytes only** with browser WebCrypto. Not production ZK-1,
not a remotely distributed GateAuthority, not owner/device content approval.

## Verified round trip

The existing browser-only AES-256-GCM `rootark-zk1-file-content.js` creates
a per-file non-extractable CEK and encrypts a synthetic private filename,
media type and ~512 KiB binary payload. The new browser WebCrypto chunk-root
builder splits the **already-encrypted** envelope into 128 KiB pieces and
computes the exact domain-separated root that the Node and PostgreSQL
validators use. The trusted fixture GateAuthority writes each chunk under
its physical row lock; the independent `Zk1SharedPgSealedObjectStore`
verifies the ordered root/count and commits a SEALED marker. The test
reconstructs the ciphertext from physical PostgreSQL rows and decrypts
only in the client boundary, without passing the CEK or plaintext filename
to any SQL gateway. The expected root also matches the stored SEALED root.

Two adversarial cases demonstrate that a wrong/out-of-order client root is
rejected without creating a SEALED marker, and that an administrative SQL
mutation of an already SEALED ciphertext chunk leaves the old marker intact
but is detected by re-computing the **client-pinned** root. The corresponding
AES-GCM client decrypt also refuses the tampered bytes. Thus a server
cannot rely on a stale SEALED marker alone as a read-time integrity proof.

The fixture creates legacy non-strict `require_stop_proof=FALSE` scope
only for this cross-client format test. It must not be represented as
strict physical STOP, production distributed fencing or revocation proof.
There is **no** authenticated owner/device signature on the browser root
in this fixture; the trusted test caller supplies it to the sink. The
experimental device-approval modules still return `authorizesRelease:false`
and do not authorize publication. A real client/owner signature, active
device manifest and live independently pinned CAS/witness/nonce admission
are mandatory and not established here.

## Focused validation

`node lab/issue-65-packet-b/run-shared-gate-postgres.js`:

- **37/37 PASS, 0 FAIL, 0 SKIP**, exit code 0, Windows Node 24.
- Includes two browser-to-physical-seal cross-layer tests plus 35 existing
  shared-gate/STOP/role/TLS/SEALED/revocation regressions.
- `SHARED_GATE_PG_REAL_PASS loopback=true`;
  `SHARED_GATE_PG_CLEANUP verified=true` after identity/label verification.
- No real DB, cloud provider, migration, upload, release or deploy performed.

Next release gates remain independent client signature authority, physical
data-plane ownership for strict HTTP/GET, CAS/witness current-state/anti-
rollback, remotely distributed execution and provider-specific data-loss
proof. **Issue #65 remains open and NO-GO for production.**
