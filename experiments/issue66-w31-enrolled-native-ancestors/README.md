# PR #300 / Issue #66: test-signed original-A ancestry, Windows NTFS lab

**LAB_ONLY_NO_GO. RootSession OFF. No production adapter, enrollment authority,
sync cutover, permission grant, or release approval.** This extends the W21
held-source publication experiment with independently *test-issued* identities
of the original physical object, rather than trusting whichever B happens to
be present at first local pin.

Run from repository root with **Windows Node 22 and physical NTFS**:

```powershell
node --test experiments/issue66-w31-enrolled-native-ancestors/enrolled-ancestors.lab.cjs
```

The isolated Node issuer subprocess calls the native `enroll` command and
generates an ephemeral Ed25519 keypair entirely within that issuer process. It
returns an exact byte-string receipt with the original `FileIdInfo` of the
volume-root HANDLE, every intervening directory, and the `source` file, and a
detached signature and public key. The main Node harness validates the
signature before launching `publish`, then passes the FileIds as expected
identities. **Signature verification is deliberately in the test harness,
not the native helper.** These keys are generated locally, by the same
Windows principal, with no off-host or separately administered key custody.
They cannot authenticate a production enrollment, even if the test passes.

Native `publish` starts at the drive root, then opens each exact lexical
component using `NtCreateFile` with `RootDirectory` set to the **retained
parent directory HANDLE**, `OBJ_DONT_REPARSE` and no-follow file flags.
It rejects all reparse points, non-NTFS volumes and non-fixed drive types. It opens and retains
the original `source` HANDLE in the same chain. Every opened FileId must
equal its exact enrolled ID **before** reporting `PINNED`. After the test's
external attack window, it reopens each native child from the already pinned
parent, compares all physical IDs and refuses a rebound name. Only then does
it perform an atomic, non-replacing `NtSetInformationFile` link of the held
source HANDLE into the held destination parent. No mutable JS `lstat`,
resolved path, or Node `rename` is used as a publication authority.

Two deliberate native sharing modes separate measurable properties:

- `movable` (`FILE_SHARE_DELETE`): a second same-SID process can replace
  `source` after PREPARE; comparing the native source name to the original
  enrolled FileId rejects that A-to-B drift before publication. A separately
  signed *original A* also rejects an entirely substituted directory B
  **before** the first native acquisition.
- `locked` (no `FILE_SHARE_DELETE` for **all ancestors and source**): the
  independent same-SID Node process physically attempts to rename both an
  ancestor directory and the original file. The NTFS kernel refuses each
  first A-to-B hop while the relevant native handles remain open; the native
  process then publishes the authentic original A through its retained HANDLE.
  These are concrete ordinary `fs.renameSync` attacks, **not a proof against
  every NTFS renaming mechanism or elevated writer**.

Native `no-replace` also rejects an occupied foreign `published` leaf while
preserving its bytes, and a modified signed receipt is refused before running
the publisher. The tests use a separate Windows Node PID with the same actual
SID, checked by the test when the attacker swaps A for B. All fixtures are
synthetic under distinct `LOCALAPPDATA` directories and are **retained** for
inspection; test build output is removed after the run.

## Physical validation on the local Windows NTFS host

- Windows Node **22.22.1**: W31 lab 7 subtests and enclosing suite,
  **8 PASS / 0 FAIL**. Valid native A, pre-pin foreign B rejection,
  post-pin source swap rejection, retained-parent no-replace collision,
  source and ancestor sharing vetoes, detached-signature tamper rejection.
- Existing W21 link/rename/late collision native lab and unchanged
  RootSession denial contract: **10 PASS / 1 expected Linux SKIP / 0 FAIL**.
- No WSL/ext4 validation of this Windows-only experiment. Windows `wsl.exe`
  probes were unresponsive at the time of the run.

## Boundaries still open

The initial drive-root open uses a local drive-letter pathname and is checked
against a test-enrolled root ID. That does not prove independent volume/mount
identity, an unforgeable enrollment origin, signer authenticity or permission
isolation. A malicious same-SID signer could certify B. In `movable` mode,
a complete A-to-B-to-A transition between identity observations is not
detectable from two equal FileIds alone; this lab does not claim otherwise.
`locked` mode prevents the *ordinary tested* A-to-B rename while the handles
exist, but is not persistent custody across process exit or power loss.

The test does not establish real outside-operator provenance, product
namespace handoff, hardened executable/DLL origin, Windows 10 CFAPI hydration,
unprivileged hostile writer isolation, anti-rollback CURRENT/Genesis,
signed durable PREPARE/COMMIT, powercut/crash recovery, 16,385-entry traversal,
or native service integration. Same-SID writers may also modify file content
without changing its FileId; no signed content binding is established here.
All are required before any RootSession gate
could be reconsidered. **Source/release/merge authorization remains NO-GO.**
