# Issue #65 / PR #302 cryptographic backport — unpublished 2026-11-12

**DEV-OFF; RootSession OFF; MERGE NO-GO / RELEASE NO-GO.** This checkpoint
adds a local PR #302 candidate **after** reviewed `7baea943`; the two
independent SOURCE GO opinions on `7baea943` do **not** review the newer
composed SHA and cannot be inherited.

- The PR #301 `a4da7d25` / `9a541301` owner-checkpoint fixes were
  cherry-picked, retaining commit metadata. The shared
  `rootark-zk10-native-intrinsics-v1.js` was absent on PR #302; its exact
  reviewed PR #301 implementation was added as an explicit separate file
  dependency. This is a cross-branch **security backport**, not a PR merge.
- On the original PR #302 parent `7baea943`, four adversarial Node22
  Windows tests with genuine offline owner-signed Ed25519 A were **RED 0/4**:
  retargeted `crypto.verify`, mutable initially expected account B→A,
  owner signature A on unsigned checkpoint B via `Buffer.concat`, and
  a forged independently pinned public B SPKI via late
  `Function.prototype.call` rebind. These are distinct P2s, not simulated
  signatures. The new child reproduced **20 PASS / 0 FAIL** in owner
  checkpoint, multi-provider inventory, native exported public-key pins
  and offline enrollment tests, including the four new negatives and
  genuine owner A positives. Exact SHA peer review and hosted CI pending.
- The previous DEV-OFF dual-SQLite owner floor checks remain **local
  same-host evidence only**. No separate self-hosted custodian/operator,
  signed original NTFS root A and all ancestors, protected SID/UID namespace
  or externally monotonic release authority was provisioned.
- A physical Windows 10 CFAPI hydration test, Linux/ext4 fresh execution,
  true hard powercut and guarded product PREPARE/COMMIT are separate
  mandatory gates. No production cutover, push, PR merge or Draft change.
