# PR #300 — integrated candidate verification, 2026-11-09

**Status: SOURCE / OPERATIONAL NO-GO. No publication or release.**

## Exact local candidate

The published PR #300 HEAD at the start of this verification was
`956b2515d3f5262b2bf8c6044be2bfd2db72dc9e` (OPEN/Draft).
Integration was created in an isolated worktree without a branch push:

| Commit | Change |
| --- | --- |
| `426d5e93f7b181aa8c055eb59b33f46c8f61cb3a` | Legitimate required-v2 recovery with more than 16,384 trash entries; **ABA NO-GO** |
| `98eeb658eb21c31fc2f59ce822556015ce564854` | Fresh test-only executable build receipt; **process-image NO-GO** |
| `d88d2d3cd46f857a95fdae1ef65f5f7f97e8a42a` | Absolute Windows cmd / PowerShell test tools; scoped test-only improvement |
| `1d59ea530b9eb11dd9baa8266a369f9be80ea4e3` | Prior source-backed executable-custody NO-GO checkpoint |

The integration had no cherry-pick conflicts. The sync engine and large-trash
test blobs are byte-identical to `426d5e93`, and the receipt and
absolute-tool test blobs match their corresponding original reviewed
commits. `git diff --check` and metadata checks passed. All four commits
have bielxdh3 as author/committer and one Codex coauthor trailer.

## Physical results of the integrated exact SHA

| Gate | Windows E: NTFS Node 22 | WSL Ubuntu real /dev/sdd ext4 Node 22 |
| --- | --- | --- |
| Six CFAPI ACL / native-build / receipt / fixed-tool test files | **15 PASS / 0 FAIL** | **8 PASS / 7 Windows SKIP / 0 FAIL** |
| Required-v2 hard process crash before PREPARE, 16,385 real retained trash entries | **1 PASS / 0 FAIL** | **1 PASS / 0 FAIL** |

The Linux target used an immutable `git archive` of exact integrated
`1d59ea53`, extracted on native ext4. Dependency files were linked from
an existing local Node 22-compatible installation for the single required-v2
test; no repository files were changed. The first **invalid invocation**
of `node --test-name-pattern` from nested PowerShell/WSL quoting accidentally
triggered whole-directory test discovery in a bare archive without
dependencies. It failed on missing modules, **not on a demonstrated
required-v2 assertion**, and is not counted as a product regression or a
security PASS. The corrected single-file, exact-title invocation passed.

An independent reviewer verified exact integrated SHA source, four-commit
ancestry, metadata and clean worktree, and returned **NO-GO for publication
because known P1/P2 security defects persist**. The passing large-trash
tests prove only legitimate input behavior, not anti-ABA custody.

## Unsatisfied mandatory requirements

1. `sync-client/rootark-sync-engine.js` retains pathname-based
   `fsp.opendir(trash)` alongside a separate held directory descriptor,
   pathname-based head reading and marker promotion. An independent physical
   POSIX bind-mount A→B→A adversarial test already demonstrated a
   false clean-recovery acceptance. NTFS file timestamps can also be
   restored to spoof ordinary identity checks. Handle-backed enumeration,
   parent/root/marker proofs, all tracked plaintext hash reads, durable
   journal and cold-reopen lifecycle are not integrated.
2. A build-receipt helper hashes an on-disk test EXE before releasing its
   descriptor, then executes the filename by `spawnSync`. The separately
   named CFAPI fixture tests also execute TEMP-built EXE files by pathname.
   This does not authenticate the image actually executed if an attacker
   replaces it between hashing and CreateProcess. Mutable batch compilation,
   compiler toolchain trust and later DLL loads are separate execution
   boundaries. Absolute System32 interpreter paths reduce one PATH hijack
   vector but do not establish process-image attestation.
3. Isolated Windows `NtQueryInformationProcess` class 44 experiments
   distinguished the original executable FILE OBJECT from a substituted
   leaf, using suspended processes always terminated before execution.
   The API compares file identity, **not authenticated mapped code bytes**.
   A further raw mapped-section comparison rejected even a legitimate
   executable in the presence of relocations, so no secure launcher is
   integrated or approved.
4. NTFS native `NtCreateFile(RootDirectory)` labs demonstrate useful
   file-handle rooted operations, but neither independent owner-approved
   root custody nor trusted ancestor ACL/DELETE-child authority, stable
   cold reopen, anti-ABA over every I/O, or power-cut durability is proved.
   An additional local lab's held-handle rename claim received peer
   **NO-GO P2 pending Windows share-mode reconciliation**.
5. Published #300 CodeQL was formally **FAILURE** with an uncontrolled
   absolute-path shell command annotation; the integrated local SHA has
   no hosted CodeQL or release checks. Do not suppress or call the alert
   resolved without evidence. Physical Windows 10 CFAPI and hostile
   origin/volume/toolchain custody remain unverified.

**Decision:** do not push or fast-forward this candidate, merge, deploy,
cut over, change `Root/main`, reopen #228, or remove adversarial RED
fixtures and native labs. A later decision requires a new exact-SHA
independent SOURCE GO, physical Windows Node 22/NTFS and WSL Node 22/ext4
proofs, fully authorized root/image custody and successful hosted CI/CodeQL.

## Later local test-only hardening (not a release gate)

The integrated chain was extended with the independently reviewed
`76c6a4cfd1031e124942607152042ad07d0fcf62`, which removes the
mutable `build.cmd` from the ACL fixture and adds a never-resumed native
image-section research probe. A further direct local child,
`06e65b93e54ad679bfe5577b43b94ea75157e7fd`, removes the
independent mutable `compile.cmd` execution paths in the deny-callback
and positive-shape native fixtures. Both now produce fresh expected
binaries through the allowlisted build-receipt helper, and a deliberately
present malicious `compile.cmd` canary is never executed.

The second child was verified with an exact-file RED before helper
integration (**2 native tests rejected with `UNTRUSTED_EXECUTABLE`**)
then GREEN. Windows E: NTFS Node 22 **16 PASS / 0 FAIL** for all seven
focused CFAPI suites; immutable `git archive` of the new SHA extracted
on Ubuntu WSL real `/dev/sdd` ext4, Node 22 **9 PASS / 7 Windows SKIP /
0 FAIL** for the same seven files. The new child has author/committer
`bielxdh3` and one Codex trailer, with clean worktree and diff.

This mitigates **writable temporary shell-script execution** and
unmediated fixture-name selection. However the common helper still
closes the hashed EXE descriptor before pathname-based `spawnSync`.
The receipts, PE-header validation, SHA-256 and pinned System32 shell
path do **not** authenticate the Windows image bytes or DLLs loaded
after process creation, nor exclude same-principal parent/leaf swaps,
compiler substitution, or a malicious preexisting mapped writer. The
product required-v2 ABA vulnerability, hostile ACL/owner custody and
formal CodeQL failure are unchanged. **Operational SOURCE NO-GO and
NO PUSH** persist; any future peer GO here is limited to test hardening.
