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
then mints a random 128-bit **native-issued opaque test token** from a
**separate** `getrandom` draw: the token is not embedded in, or computed from,
the directory suffix visible to the same UID. Each Node N-API environment
holds its own native session via a private `napi_property_descriptor.data`
pointer on each callback and a single `napi_add_env_cleanup_hook` for its
descriptors. The addon no longer uses the replaceable `napi_set_instance_data`
slot, so no file-static or externally owned instance-data slot is treated as
session authority across Worker threads. The original
passwd HOME lookup uses reentrant `getpwuid_r` with caller-owned storage
for concurrent Workers; this corrects a race in `getpwuid`, but it does not
attest to passwd/NSS contents.
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

An additional **test-only** native pagination experiment addresses the old
16-entry `enumerate(token)` laboratory cap without claiming a production
RootSession. `seedMany(token)` uses Linux `openat2` with native exclusive
no-follow creation relative to the same held directory fd to create exactly
**16,385** extra one-byte records; it fsyncs each opened file and the held
directory and refuses reseeding. `beginStream(token)` rewinds the native
`DIR*`; each `nextStreamPage(token)` returns at most 64 raw-name Node
Buffers, preserving exact `readdir` bytes without UTF-8 normalization, and
retains the directory cursor across calls until an explicit `done`. Invalid
tokens, calls after close, and interference from the legacy full-array
`enumerate` method fail closed. A physical test validates 16,388 unique
names (including the original Unicode name and alias), reads the last native
file, and enumerates the **same held A directory** after its pathname is
deterministically rebound to foreign B. Nothing in this lab reopens a
trusted root at cold startup, protects its owner-controlled HOME parent
from another same-UID process, or implements `unlinkat`, a durable recovery
journal or monotonic rollback protection. The N-API bridge is still
**LAB_ONLY_NO_GO** and cannot activate the production feature.

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
After resolving two source-review concerns (token/directory randomness reuse
and global state across Node environments), the focused addon suite is
**5 PASS / 0 FAIL / 1 SKIP** and the combined addon + unchanged RootSession
contract suite is **12 PASS / 0 FAIL / 1 SKIP**. The new tests physically
verify a directory suffix distinct from its native token and two concurrent
Node Workers with separate valid native sessions that reject each other's
tokens. The environment finalizer closes only its own descriptors.
The additional same-environment addon coexistence test loads a second native
module which installs its own instance data, while the first session remains
readable and closable. A source regression ensures no use of the shared slot.
On the corrected branch, WSL Node22/ext4 addon + RootSession-contract tests
yielded **14 PASS / 0 FAIL / 1 SKIP**; this only validates the lab scope.
The SKIP is a hostile same-UID concurrent bind-mount/parent-trust test:
`CAP_SYS_ADMIN` and independently protected custody were not available.
The later isolated `seedMany` + `beginStream` + `nextStreamPage` experiment
completed physical Ubuntu WSL Node22/ext4 TDD (the new test was RED before
the native methods existed) and the combined N-API + RootSession contract
suite with **15 PASS / 0 FAIL / 1 expected SKIP**. That is a bounded
test-only page-streaming result, not an independent 16,385-entry production
recovery or crash/power-cut authorization. Its exact commit still requires
independent SOURCE review before integration.
The test-token separation and per-environment state are narrowly scoped
correctness checks; a hostile same-UID process can still inspect another
process, mutate the trusted-by-test parent or race native fixture paths.

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
