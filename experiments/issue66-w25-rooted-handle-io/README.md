# Issue #66 / PR #300 — W25 native rooted file-I/O proof (test-only)

**Scope:** A deliberately narrow, opt-in Windows/NTFS experiment; not a CFAPI
release change, not an ACL trust root, not a process launcher and not a fix for
CodeQL. Parent source baseline: `609564fa041cd903c6641368dd8df14d86f1442e`.

The test adds no native `.exe` or binary helper to the repository. It invokes a
checked-in PowerShell test script that compiles embedded C# interop with
`Add-Type` and uses `NtCreateFile` with an existing directory `HANDLE` as
`OBJECT_ATTRIBUTES.RootDirectory`. All **protected** file creation, writing,
flushing, reading and deletion in the experiment use native root-relative file
handles. The only pathname writes are the **adversarial simulation** (moving
the trusted directory and planting a distinct replacement canary) and
postcondition assertions. There is no fallback from a failed rooted operation
to a new absolute file path.

Run on a real Windows 10/11 NTFS host with Node 22:

```powershell
$env:ROOTARK_ISSUE66_W25_NATIVE_IO_LAB='1'
node --test --test-reporter=tap test/issue-66-w25-native-rooted-io-lab.test.js
Remove-Item Env:ROOTARK_ISSUE66_W25_NATIVE_IO_LAB
```

By default both tests skip. The opt-in script only accepts a randomized
`rootark-w25-native-rooted-io-*` test directory **directly under the current
user's LocalAppData**. It rejects arbitrary external paths and requires the
exact opt-in variable. This is *not* an endorsement of TEMP as a trust anchor:
the Windows `E:` checkout test initially failed closed when attempting to
write an owner-protected DACL (`UnauthorizedAccessException`); the isolated
disposable LocalAppData fixture permits the DACL operation. The fixture creates
an owner-only protected root; only test-created files are affected. The Node
runner cleans the complete scratch directory after each run.

## What a physical PASS demonstrates

1. Open the real NTFS directory with `CreateFileW` and retain its valid handle.
   Verify directory/non-reparse/NTFS via this handle.
2. Create `original.bin` relative to that directory with `NtCreateFile`
   (`RootDirectory`, one fixed filename, no reparse traversal). Write and flush
   its content through the opened file handle.
3. **Actually rename the directory while its handle remains open**, then
   create a new directory at its former pathname containing a same-name
   `FOREIGN_CANARY` file.
4. Open and read `original.bin` *relative to the old directory handle*: only
   the original content is returned. Delete the original file with
   `SetFileInformationByHandle(FileDispositionInfo)` on a rooted-opened handle.
   The different `FOREIGN_CANARY` remains unchanged.
5. Create/write/flush/reopen/read/delete `after-swap.bin` relative to the old
   handle. It appears exclusively in the moved original, never in the new
   same-spelled directory, and its cleanup does not touch the replacement.
6. No path, SID, ACL, file bytes, compiler errors or other internal data are
   printed. Success and rejection outputs use fixed categorical strings.

**Observed local Windows Node v22.23.3/NTFS:** 2 PASS / 0 FAIL / 0 SKIP on
the explicitly opted-in lab. Test 1 exercises the actual syscall sequence;
test 2 verifies that arbitrary TEMP scratch and disabled opt-in are rejected,
leaving a foreign canary unmodified. An eligible-looking, **nonempty**
LocalAppData directory containing an unrelated owner canary is also rejected
unchanged. Ten consecutive separate Node 22 opt-in executions passed. The
original #300 native ACL test trio remained 13 PASS / 0 FAIL without opt-in;
the two new lab tests were correctly SKIP. WSL Ubuntu Node 22: 2 expected
Windows-only SKIP / 0 FAIL.

## Still NOT established (release NO-GO)

- Initial, authentic root acquisition: opening the root by pathname could race
  *before* its first handle is obtained. There is no fully handle-rooted chain
  from a separately trusted owner/volume root here. An owner-only DACL does
  not exclude an adversary with the **same principal**, or an untrusted
  directory ancestor with `DELETE` rights.
- This result proves **non-escape of operations relative to the retained
  handle**, not persistence of the original *name*. A moved root can disappear
  from its discoverable pathname. A cold reopen under the old name can reach
  the replacement. No release ACK should rely on that without additional
  namespace custody/recovery semantics.
- A `FileStream.Flush(true)` is not proof that directory names, journal
  checkpoint, or directory rename are durable after a Windows power cut.
  Atomic no-replace publication and reboot recovery are unimplemented.
- The lab does not securely bind the actual image launched via `CreateProcess`
  or `spawnSync`. A pre-spawn digest/inode check on `.exe`, `cmd.exe`, vcvars,
  or `cl.exe` and a static filename do not prove what bytes executed under
  hostile pathname swaps. W2 executable helper files are untouched.
- No independently attested Visual Studio toolchain, official CodeQL hosted
  verdict, real multi-user hostile rename exploit, end-to-end CFAPI
  registration, or production native transport has been exercised.

**Decision:** valid *test-only* primitive for review and future design work;
**SOURCE/operational NO-GO** for promoting PR #300 until independently reviewed
native root acquisition, ACL custody, cold-reopen namespace binding, executable
identity, crash-safe publication and Windows hosted CI are proven.
