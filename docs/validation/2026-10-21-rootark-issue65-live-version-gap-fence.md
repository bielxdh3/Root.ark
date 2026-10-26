# Root.ark #65 — reject live ciphertext archive gaps

**Scope:** experimental local zk-1 ciphertext SQLite store. No production
authorization, remote provider change, or migration.

## Confirmed failure and correction

The existing startup scan checked version continuity and the live I/O path
checked the current projection against the latest archived version. A
privileged SQLite writer could remove an older version **after startup**
(by first dropping the local immutable DELETE trigger), leaving the latest
archive record and current projection identical. A latest GET then succeeded
even though historic ciphertext had been lost; a new PUT could also build
on the truncated chain.

The adversarial regression intentionally removed revision 1 from an object
with revisions 1, 2 and 3 while leaving the current revision 3 untouched.
**RED:** latest GET returned bytes instead of rejecting incomplete history.

The protected store now checks the selected object's full revision span
inside the existing `IMMEDIATE` I/O transaction. The unique
`(scope,id,revision)` index and positive **integer** revision requirement
mean `COUNT = MAX = currentRevision` and `MIN = 1` prove that every revision
number from 1 through currentRevision is present. The check also rejects
noninteger revision values, because ordinary SQLite `INTEGER` affinity can
store `REAL` values despite a `CHECK(revision>=1)` constraint. That matters:
revisions 1, 1.5, 3 have `COUNT=3, MIN=1, MAX=3` while revision 2 is missing.

Both the latest GET and subsequent PUT now fail with
`ZK_CONTENT_VERSION_HISTORY_CORRUPT` before consuming the request nonce,
updating the local head watermark, emitting ciphertext, or writing a new
version. The fixture restores exact archived bytes and the trigger after
each simulated attack. Existing read and write behavior resumes after
restoration.

## Evidence

`test/issue-65-protected-ciphertext-version-retention.test.js`:

- RED: `Missing expected rejection: live latest GET must detect an erased
  historical ciphertext revision`.
- GREEN: 1/1 PASS after the transactional archive-span check.
- Extra GREEN case: deleting revision 2 and substituting revision 1.5 as a
  `REAL` row is rejected; the fixture verifies `typeof(revision)='real'`.

An independent read-only reviewer confirmed the original history-gap P2
and inspected the updated `getVersionSpan` check without identifying a
remaining bypass of that specific local continuity guarantee.

## Limitations

This is a local structural continuity check. A compromised SQLite operator
who can rewrite all archive rows, digests and projections coherently or
restore a previous entire database state can still roll back locally. The
new check does not cryptographically anchor version roots to externally
verified owner, CAS or witness commitments, and it does not fence a physical
remote socket, S3/GDrive operation, or external backup. Root.ark #65 remains
**NO-GO** until the separate operational and recovery guarantees are proven.
