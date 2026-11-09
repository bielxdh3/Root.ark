# PR #300 — local native-toolchain hardening, 2026-11-09

**Release decision: SOURCE / OPERATIONAL NO-GO. No push, merge, deploy or
cutover.** This checkpoint records scoped test-harness improvements without
equating Windows native tests with authenticated executable bytes, DLL custody
or a safe Files On-Demand recovery release.

## Scope and exact ancestry

- Published `#300` remained `956b2515d3f5262b2bf8c6044be2bfd2db72dc9e`,
  OPEN/Draft. Its hosted formal CodeQL check was FAILURE, with a shell command
  warning in `test/issue-66-cfapi-acl-preflight-native.test.js` line 19.
- Existing local integration: `de43bd52ae439d8802c516988a55d2dbf537f0b9`.
- Native receipt argv scope: `b8e1590cc40560763f7248e669ce358d6af0ef26`.
- Literal ACL tool launch sites: `7a506eb3ac8642746f4c30a841c841d9da742fac`.
- Sanitized build environment: `24f8861f0eeb6dd7273f5d3daed9812e9b2f8763`.
- Conservative direct-`spawnSync` source guard: `18680c9a2c4e2fd796d75e0c93d4d73d5dd080a4`.
- Protected compiler working directory and explicit intermediate outputs:
  `cd16abe2578dab881d57ef5bdba7a1d1d47370f4`.

The latter five commits are local, descendants of `de43bd52` via `b8e1590c`.
They are not present in the remote PR. No release SOURCE GO is claimed.

## What changed

1. `runFixedTool` no longer accepts an executable lookup key. Native ACL test
   subprocess calls now contain literal `vswhere.exe` and `powershell.exe`
   absolute paths; tests assert these direct invocation sites.
2. The dynamic fixture receipt runner accepts only the fixed per-fixture
   argument shapes. The receipt still hashes before a pathname-based process
   launch: this is a partial harness safeguard, **not process image custody**.
3. The compiler subprocess now drops inherited compiler, linker, SDK and
   Visual Studio selectors case-insensitively, including `CL`, `_CL_`, `LINK`,
   `_LINK_`, `INCLUDE`, `LIB`, `LIBPATH`, `VCToolsInstallDir`, `VSINSTALLDIR`,
   `VCINSTALLDIR` and `VSCMD_*`, and starts with fixed System32 `Path` and
   `ComSpec` values. `vcvars64.bat` remains an unproven toolchain authority.
4. To avoid executable lookup in a writable TEMP current directory, MSVC
   compilation is launched from fixed `C:\Windows\System32`. The compiler
   writes `.obj`, `.pdb` and `.exe` into the disposable fixture directory by
   explicit output paths and rejects preexisting output names, including
   dangling reparse entries, before launching the toolchain.
5. The direct native ACL `spawnSync` regression now rejects every extra
   `spawnSync` binding reference, including comment-separated, optional-call
   and `.call` spellings. This is a source regression for one test file, not
   an analyzer of all ways to create a process or load code.

## Physical and source evidence

| Local SHA / scope | Windows Node 22 on E: NTFS | Ubuntu WSL Node 22 on `/dev/sdd` ext4 |
| --- | --- | --- |
| `7a506eb3` eight CFAPI files | 18 PASS, 0 FAIL | 11 PASS, 7 Windows SKIP |
| `24f8861f` eight CFAPI files | 19 PASS, 0 FAIL | 12 PASS, 7 Windows SKIP |
| `24f8861f` with intentionally bad inherited MSVC/SDK variables, three native files | 6 PASS, 0 FAIL | Not applicable |
| `18680c9a` changed direct-launch regression | 2 PASS, 0 FAIL | 8 PASS, 0 SKIP for three focused files |
| `cd16abe2` native builds and unit regressions | 14 PASS for five changed-area files, plus 7 focused receipt PASS | 11 PASS, 2 Windows SKIP for four changed-area files |

The `7a506eb3` independent SOURCE peer gave a **diff-only GO**, explicitly
with no process-image or hosted CodeQL assurance. The `24f8861f` peer found a
P2 false-green in the static source regression (`spawnSync /* gap */ (...)`
was not inventoried), so that exact SHA was **SOURCE NO-GO** for the full
local test-hardening range. The follow-on `18680c9a` targets that P2; the
later `cd16abe2` additionally addresses the untrusted `cwd` helper search.
An independent exact-SHA verdict for the final descendant remains mandatory.

## External/native lab not integrated

W25's `c45d272ba2bb43ba3be9ddf233e94b983405af55` has a reproducible
four-mode NT native handle/rename identity claim. Independent SOURCE review
classified it **NO-GO with two P2**: unpinned path-based scratch mutations
and recursive cleanup could affect a replaced directory under same-principal
ABA, and the standalone test does not independently verify an NTFS volume.
This research commit was not cherry-picked into the #300 candidate.

## Unresolved release security gates

- `test/support/issue-66-cfapi-built-artifact.js` still closes the verified
  executable handle before `spawnSync`; no demonstrated authentication of
  code pages **actually executed**. The same issue affects runtime DLLs,
  the Visual Studio compiler and `vcvars64.bat` chain. System32 paths and
  sanitized search are reductions in exposure, not image attestation.
- `sync-client/rootark-sync-engine.js` recovery still uses pathname-based
  directory enumeration, tracked-file reads and staged-marker promotion.
  Physical POSIX bind-mount A→B→A previously produced false acceptance;
  NTFS metadata/timestamps can be forged. Root/ancestor custody, hostile
  `FileSystemRights.Delete`, rollback, Unicode/casefold and cold reopen are
  not operationally solved by these test-only commits.
- Real Windows 10 end-to-end CFAPI, NTFS power-cut durability, independently
  protected ownership, full required-v2 crash recovery and hosted CodeQL on
  the final candidate are not verified.
- A local SOURCE GO for an isolated test patch does not authorize PR
  publication. The full source peer must cover the **exact final SHA** and all
  inherited release blockers; the hosted check must run on that same SHA
  only after all P1/P2 blockers are safely resolved.

**Preserve the draft PR, `Root/main`, all hostile fixtures and worktrees.**
