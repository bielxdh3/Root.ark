# PR #300 / Issue #66 — held-source inbound publisher, **LAB ONLY**

**Exact starting PR #300 SHA:** `c928d894939014767f1a8669946eeca72b29a97e`.
This directory contains a concrete **Node 22 → native process** test-scope
bridge, not an `SyncEngine` adapter, operational Files On-Demand provider,
trusted `RootSession`, authorized FOD positive, or a production package.
The sources adapt previously tested #298 W21 held-file experiments. The
Windows #300 slice adds a second-process **late destination** collision
at the actual atomic publication boundary. The POSIX source is retained
byte-identical to its previously validated #298 W21 laboratory because
WSL is currently unavailable for a fresh exact-SHA physical run.

## Reproduce

Run explicitly from the repository root with Node **22**:

```sh
node --test experiments/issue66-w21-inbound-held-publish-lab/native-held-publisher.lab.cjs
```

The Node harness compiles from checked-in source with the absolute
system compiler to a newly created disposable OS temporary directory,
executes the native program, verifies exact categorical evidence and
deletes only its own compiler outputs. A platform-inapplicable case is
skipped. On **Windows**, its temporary volume must be physical **NTFS**
and `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` must
exist. On **Linux**, `TMPDIR` must point to a real **ext4** filesystem,
not WSL `/tmp` if that is tmpfs and not `/mnt/e` (DrvFS).

Each native program creates only disposable **synthetic** files. A distinct
Windows same-SID child process or Linux same-UID `fork` child moves the
original *source name* to a retained alias and installs a foreign inode
there. On Windows the child **also creates/fsyncs a second foreign
destination named `occupied-late`** after the parent's PREPARE, holding
its handle open during IPC. On Linux the child retains its replaced
source inode and the parent tests the regular atomic `EEXIST` retry
after its initial link. The parent
keeps its original source HANDLE/fd and destination-directory handle/fd
open, and calls a genuine kernel publication operation only after the
adversary acknowledged its changes.

### Implemented native kernel primitives

| Operation | Windows NTFS | Linux ext4 |
| --- | --- | --- |
| PREPARE | Retain source HANDLE + destination directory HANDLE; snapshot original `FileIdInfo` | Retain source `fd` + destination `dirfd`; snapshot original `st_dev/st_ino` |
| COMMIT no-replace link | `NtSetInformationFile(FileLinkInformation=11)` against held source and destination parent; `ReplaceIfExists=0` | `linkat(sourcefd,"",dirfd,leaf,AT_EMPTY_PATH)`, or unprivileged kernel `/proc/self/fd/N` fallback |
| Late foreign destination | Independent child creates after PREPARE; atomic collision `STATUS_OBJECT_NAME_COLLISION`; original foreign `FileId`/bytes preserved | **Not freshly tested**; previously verified original held-source link and `EEXIST` retry, without a distinct late-destination actor |
| Legal publication | A different absent leaf receives **the original held source** | A different absent leaf receives **the original held source** |
| Staging | `NtSetInformationFile(FileRenameInformation=10)` source HANDLE / directory HANDLE, no replace | Original-FD hardlink into held trash dirfd **without deleting source name** |
| Source-FD-bound destructive rename | Physical lab only; not yet RootSession / durable recovery | **Unsupported:** `renameat2` resolves a pathname, not an opened source fd |
| Durable ordering | Source bytes were written on disposable fixture; no production-verified directory flush or crash recovery | File `fsync` + directory `fsync` demonstrated; no independently durable owner PREPARE/COMMIT |

The output `WINDOWS_FOD_LATE_DESTINATION_PROTECTED` identifies
**physical native publication**, not operational FOD hydration. The
prior Linux lab returns `POSIX_NATIVE_FD_LINK_LAB_PASS` and
`POSIX_PREPARE_COMMIT_STAGE_LAB_PASS`; it is not evidence of a newly
executed PR #300 late-destination test. The Node test also passes a
hostile JavaScript Proxy to `openNativeRootSession(true, fake)`,
asserts `root_session_native_unavailable`, and verifies **zero Proxy
traps**. Thus the test-only bridge cannot be used as a fake root authority.

## Minimum *future* product integration

The existing `sync-client/rootark-sync-engine.js` `_apply` denies native
required inbound before journal admission and before
`publishInboundPayload` can reach the replace-capable JS
`fs.promises.rename(temp,target)`. `_materializeOnDemand` downloads
and validates signed content but delegates to `_apply` and therefore
cannot yet produce positive FOD hydration. Pin/picker and eviction also
depend on the same independently rooted session and durable checkpoint.

The native interface that **must exist before any positive activation**
would accept only native-minted opaque session and prepared-file tokens:

1. `acquire(original-A operator lease, immutable root/ancestor witness)`:
   validate a separately enrolled physical original-A and **every**
   ancestor before any attacker-addressable first pathname lookup; hold
   the exact OS objects across all subsequent operations.
2. `prepareInbound(session, verifiedSignedEnvelopeDigest, expectedLeaf)`:
   native-exclusive/opened file staging under an already-held parent,
   same-principal writer isolation or real immutable snapshot, exact
   directory and source identity, bounded data/flush. Nothing is
   authoritative merely because JavaScript passed a FileHandle or
   changed `nativeRootSession`.
3. `commitNoReplace(preparedToken, heldDestinationParent, exactLeaf)`:
   atomic link/rename **from the original held source**. A foreign late
   destination must produce a collision without replacing or unlinking
   anything. No JS `exists→rename`, pathname rollback or fallback.
4. `commitDurableRecovery(session, journal, snapshot, ownerCURRENT)`:
   ordered native flush and external monotonic PREPARE/COMMIT, cold
   re-acquisition and indeterminate-state retention. Only then may the
   signed operation be marked seen and hydration/pin/picker exposed.

The actual `ROOT_SESSION_CONTRACT` already lists the surrounding
required operations and its opener **always denies**. These sources
exercise only a tiny **non-authorizing** fragment of (2) and (3).
They do not provide independently administered root/ancestor custody,
separate service operator, mounted executable provenance, a guarded
native addon, source immutable-byte isolation, safe POSIX deletion,
native journal or independent signed CURRENT-floor checkpoint.

## Product and release gates

Do **not** change real positive FOD tests to expect denial to make CI
green. The existing `test/issue-66-native-inbound-deny-physical.test.js`
proves real signed Ed25519 ingress is blocked **before** a hostile
late-destination rename/link, with foreign bytes intact and no remote
dispatch. This is necessary security, **not** positive FOD delivery.
Windows 10 actual CFAPI hydration, Files On-Demand pin/picker success,
off-host independently operated custody, full W3/W26 and 16,385-name
stress, genuine hard power-loss, CodeQL on a *published exact SHA*, and
two independent SOURCE GO remain unproven by this slice.

**Verdict: lab-only component PASS where executed; full PR #300 / Issue
#66 PRODUCT, MERGE and RELEASE NO-GO. RootSession remains OFF.**
