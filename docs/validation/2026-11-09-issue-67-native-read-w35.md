# Issue #67 / PR #298 — W35 bounded native contained-read lab (NO-GO)

Source baseline: `b586ac3597f06aa1d8f91c62dc45e3a12a3123b7` (published Draft #298 at assignment). This experiment adds **only** two standalone native programs and disposable tests. It does not change `sync-client/rootark-sync-engine.js`, recovery authorization, or protected-history behavior.

## Problem and trust contract

In `readDurableRestoreProgress` around lines 394–409, JavaScript first `lstat`s an attacker-addressable pathname, then separately opens and reads it. That split permits containment, pathname and inode identity changes between operations. `scripts/issue-67-native-contained-open.cpp` already proves bounded **open**, but returns `fileContentRead:false` and closes its handles.

The new lab programs open validated components and read up to **65,536 bytes directly from the final held file handle** while keeping the physical root and all ancestor leases open. The CLI returns a base64-encoded copy of the fixture content. It does not parse or authorize restore manifests. `--fingerprint <absolute-root>` is a **bootstrap probe for laboratory fixtures**; a trustworthy production caller must supply its expected root identity from an independent, durable authorization and custody source, and maintain a trusted native root lease throughout the operation. Asking this program to fingerprint the same untrusted path immediately before `--read` is not authorization. The expected root ID is an **opaque trusted input contract**, not a trusted fact produced by the attacker-controlled filesystem.

Windows `--read <root> <relative-leaf> <trusted-48-hex-root-id>` walks a drive-absolute NTFS path one component at a time via `NtCreateFile(RootDirectory, FILE_OPEN_REPARSE_POINT)`. It checks each `FILE_ID_INFO`, non-reparse attributes, volume, inode link count, and revalidates while leases stay open. Handles deny `FILE_SHARE_DELETE` for ancestor renames and `FILE_SHARE_WRITE` on the leaf for ordinary currently-open writers. A conservative leaf DACL scan rejects allow-write ACEs other than file-owner, SYSTEM and Administrators; its policy is intentionally stricter than typical production ACLs. It reads only from that leaf handle, bounds size and EOF, and compares file timestamps/identity before and after the read.

Linux `--read <root> <relative-leaf> <trusted-32-hex-root-id>` uses `openat2` against held directory fds with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`. It keeps all directory fds, checks inode/device identities and parent name bindings at checkpoints with `fstatat(AT_SYMLINK_NOFOLLOW)`, and reads only from the final fd after bounded regular-file, single-link, current-owner and non-group/world-writable checks. Unsupported kernels/mount crossings fail closed. Unlike NTFS sharing restrictions, Linux directory fds **do not block rename** or owner writes.

## Local validation (disposable fixtures)

| Gate | Result |
| --- | --- |
| Windows MSVC `/std:c++17 /W4 /WX /EHsc` + `advapi32.lib` | PASS |
| Windows Node 22.23.3, physical `E:` NTFS | **7/7 PASS** |
| Ubuntu WSL2 ext4 `/home`, g++ 15.2 `-std=c++17 -Wall -Wextra -Werror -pedantic` | PASS |
| Ubuntu Node 22.22.1, `/home` ext4 | **7/7 PASS** |

Tests cover known good bounded/empty content, >64 KiB and wrong root ID refusal, traversal, symlink and NTFS junction to an external canary, double-link leaf refusal, untrusted writer ACL/mode refusal, NTFS case aliases vs ext4 case sensitivity, active writer coexistence, directory ancestor replacement during held read, and hard process death releasing handles. They only inspect safe synthetic content. The canary file remained unchanged and was never returned by the helper. **No kernel-level ETW/strace event measurement was available; zero external-canary OPEN/READ operations were not independently instrumented.** These results must not be represented as such a proof.

## Explicit NO-GO and residual P1/P2 boundaries

1. **P1 — root authorization is not established.** The CLI takes a textual expected fingerprint, and a malicious caller can obtain it by probing an arbitrary root. There is no trusted native root anchor connected to server authorization, no pinned lease crossing the JS/native boundary, no custody key, and no post-crash root continuity. No source CodeQL clearance may be inferred.
2. **P1 — no immutable reader/history snapshot.** Windows section mappings created before the native open may modify bytes despite denied `FILE_SHARE_WRITE`; owner/admin can write using other authority. Linux's active-writer test **demonstrably accepted content written after the fd was opened**. The pre/post metadata tests are detection heuristics, not a freeze, atomic historical record, or no-clobber protection.
3. **P1 — existing crash recovery semantics are not preserved.** Both prototypes reject `nlink=2`, whereas `readDurableRestoreProgress` currently permits exactly two links for a validated temporary recovery alias with cleanup. The primitive has no complete alias ancestry/custody proof and must not replace that flow.
4. **P2 — path and platform limits.** Linux name-binding revalidation has a race after its final checkpoint and excludes mount boundaries; Windows relies on NTFS share semantics and conservative ACE evaluation. Neither helper handles portable path encodings, root changes after the helper exits, ongoing writers, or untested physical Windows 10 systems.
5. **P2 — test observability.** Synthetic canary tests assert rejection and absence of leaked content, but cannot establish the stronger external canary **zero kernel OPEN/READ** requirement without additional instrumentation. Native binaries and test data are ephemeral and deliberately not committed.

Review only this local source SHA; require strict independent source review and a separate trusted-root authorization design before considering any production code change, publication, or CodeQL assessment.
