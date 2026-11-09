# Issue #66: Linux Node 22 N-API dirfd proof (test-only)

**Scope:** A small Linux/WSL ext4 physical proof that Node 22 can call native
`openat2`, `fdopendir` and `renameat2` through a C N-API addon. **System
RootSession and release remain NO-GO.** Branch starts at the exact integrated
contract `48e881c5bff6e67df2a58847e7963dfd7fb5395d`; the separately
reviewed C laboratory `8e0ccba222a713e1807cb9ad9f88217b03a3d3a8` is
reference material only. Neither referenced commit or worktree was edited.

Run in WSL Ubuntu on an ext4 HOME with Node v22 and system gcc/headers:

```sh
ROOTARK_ISSUE66_W3_NAPI_LAB=1 node --test test/issue-66-w3-posix-napi.test.js
```

Opt-in absent: all tests skip. The Node harness compiles only the checked-in
C source against `/usr/include/node/node_api.h`, using literal
`/usr/bin/gcc`, a small explicitly supplied environment, and a randomized
`0700` build directory under HOME on ext4. The resulting `.node` binary is
**outside the checkout** and never tracked. No npm runtime dependencies.
There is no installation or production module import.

## Narrow native behavior

The addon accepts **no JS-supplied directory path, fd or authority object**.
Only with the explicit lab opt-in, its native code obtains the OS `/` fd,
opens the passwd HOME dir using `openat2` and creates a private new
`.rootark-w3-napi-*` parent directory mode `0700`. The native side opens and
retains that parent dirfd, opens a `held` child, verifies ext4 and ownership,
then mints a random 128-bit **native-issued opaque test token**. The original
FD remains under a `DIR*` created by `fdopendir`, and `enumerate(token)`
uses **that exact same fd** (`rewinddir/readdir/dirfd`). Its present
enumeration limit is **16 fixture entries**; it does not implement the full
16,385-entry RootSession contract.

`read(token, exactLeaf)` rejects non-string tokens, forged/native-looking
objects, caller-provided numeric fds, empty/absolute/parent paths, separators,
symlinks, non-regular files and hardlinks. It opens exact child bytes via
`openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV`, reads
from that exact fd and returns an independent Node Buffer. The positive
Unicode filename `café-中-😀.bin` is transferred as UTF-8 without
normalization. This lab does not cover arbitrary invalid UTF-8 raw POSIX
filenames or casefold collisions.

Only for deterministic physical validation, native `swapToForeign` and
`restoreOriginal` perform `renameat2(..., RENAME_NOREPLACE)` on pinned
parent dirfd. During A→B→A, the old `DIR*` continues listing and reading A,
while B has a different marker and remains retained at `foreign-parked`.
No `unlink`, `unlinkat`, tree cleanup, signed DELETE or recovery commit
exists. The separate read-only `probeExistingMount` verifies `NO_XDEV`
rejects existing Linux `/proc` traversal from `/`; it **does not** inject a
bind mount under the retained directory.

## Evidence and remaining NO-GO

Physical TDD on WSL Ubuntu Linux 6.18.33.1, ext4 HOME, Node v22.22.1,
gcc 15.2.0: initial **0 PASS / 4 FAIL / 1 SKIP** without the C implementation,
then **4 PASS / 0 FAIL / 1 SKIP** with the addon loaded and called by Node.
The SKIP is a hostile same-UID concurrent bind-mount/parent-trust test:
`CAP_SYS_ADMIN` and independently protected custody were not available.

Even while this addon is loaded, the integrated
`sync-client/rootark-sync-native-root-session-contract.js`
`openNativeRootSession(true, addon)` still throws
`root_session_native_unavailable`, and
`requireNativeRecoveryAuthority(addon)` still throws
`root_session_unverified_authority`. The addon explicitly returns
`LAB_ONLY_NO_GO`; it cannot authorize any production recovery.

**Unresolved blockers:** passwd HOME and the underlying namespace/parent are
not independently attested or isolated from other same-UID actors. No writer
exclusion, cold reopen, secure anti-rollback custody, crash-safe journal,
full enumeration of 16,385 entries, hardlink threat closure, signed remote
DELETE policy, or real application integration is implemented. A `0700`
directory and random token do not defend against a hostile same-UID process.
The C source, compiler image and subprocesses, `.node` file, dependencies,
and pathname-based Node `require()` launch also lack independent
attestation; fixed gcc path and minimal environment only reduce exposure.
No native-code proof here establishes whole-process or filesystem authority.

**Decision:** source/review milestone only. Obtain fresh independent SOURCE
peer review; retain **PR #300 / RootSession / release NO-GO**.
