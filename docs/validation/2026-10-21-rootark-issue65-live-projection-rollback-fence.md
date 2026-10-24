# Root.ark #65 — reject mutable ciphertext projection rollback during live I/O

**Scope:** isolated experimental protected-content SQLite store; no normal
file route cutover, deployment, or production authorization.

## Confirmed runtime gap (TDD)

The store already maintained an append-only `zk_content_version` history
with byte digests, immutable update/delete triggers and startup consistency
checks. Nevertheless, the live `perform()` path used its mutable
`zk_content_object` projection directly for an ordinary latest GET, or
allowed a later authenticated PUT to overwrite that projection.

The RED test used a disposable SQLite fixture to alter only the current
projection **after** store startup. Three separate attacks were reproduced:

- Alter the current ciphertext bytes without changing the revision: latest
  GET returned malicious bytes; subsequent PUT could hide the mismatch.
- Rewind the projection to revision 1 with *authentic archived bytes* while
  the immutable archive still held revision 2: latest GET accepted stale
  content and a writer could attempt to advance from the forged revision.
- Delete the current projection while the immutable history survived:
  latest GET incorrectly reported missing content.

## Correction

Every selected-object GET or PUT now runs inside its existing SQLite
`IMMEDIATE` transaction and queries the **highest** immutable version for
that same scope/object, not the revision selected by the mutable projection.
Missing/mismatched projection, missing/mismatched archive tail, changed
revision or epoch, mismatched ciphertext bytes, or a digest mismatch cause
`ZK_CONTENT_VERSION_HISTORY_CORRUPT`, before any nonce or head-watermark
update, response bytes or version write. Exact parity resumes unchanged
legacy experimental behavior. Historical authorized GETs still require the
signed expected revision and digest.

The regression test `test/issue-65-protected-ciphertext-version-retention.test.js`
was RED for the changed bytes and separately RED for the authentic older
version rollback, then GREEN once latest-tail comparison was enforced.
The original version history/startup, protected I/O fence, signed-history
gate and CAS/witness end-to-end focused regressions passed.

## Residual security boundary

This catches a mutation of the mutable projection while the append-only
archive remains honest. A compromised database administrator who can also
**INSERT an attacker-generated higher archive revision and match the current
projection** (even without disabling the UPDATE/DELETE immutability triggers),
disable triggers, rewrite the entire archive, replace both SQLite and
its snapshots, or forge an external provider rollback is **not** defeated by
a local SHA-256 check. Hashes and SQLite triggers are not cryptographic proof
of writer identity or append authorization. Production still requires
independent trusted roots,
physically enforced remote GET/PUT/STOP and distributed monotonic fencing;
this local check is necessary but insufficient. Issue #65 stays **NO-GO**.
