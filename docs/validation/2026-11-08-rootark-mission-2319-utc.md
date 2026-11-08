# Root.ark — mission execution checkpoint (2026-11-08 23:19 UTC)

This is a non-retroactive checkpoint. Prior source reviews, hosted runs and
historical snapshots retain their original SHAs and observations. A locally
tested commit does not inherit the CI result of a prior remote head.

## Remote PR heads and exact gates observed at 23:19 UTC

| Scope | OPEN/Draft PR head | Observed status / evidence still required |
| --- | --- | --- |
| Mission | [#251](https://github.com/bielxdh3/Root.ark/pull/251) `d911e4f5f4676809241b09d14130636aeaf10bbd` | CodeQL and Dependency Review SUCCESS. Security Regression [42532338633](https://github.com/bielxdh3/Root.ark/actions/runs/42532338633) remains IN_PROGRESS; Ubuntu full FAIL after the runner reported a shutdown/cancellation signal (not a proven assertion failure), Windows canonical and mandatory still running. Do not infer hosted GO. |
| #63/#68 | [#293](https://github.com/bielxdh3/Root.ark/pull/293) `49a9adfdc2e0cb910e08275fff79265c6841262a` | Transient real cross-process SQLite WAL terminal HTTP lease fixed by bounded 1-second terminal-only local retry; independent exact-SHA SOURCE GO and Win/WSL Node22 13/13 focused tests. Does not certify physical custody or global release. |
| #67 | [#298](https://github.com/bielxdh3/Root.ark/pull/298) `14bd5b2e5b4b9fdd93148f293d70c8d8c8d4a7cc` | Published S3 LIST-to-GET ETag/size/actual-byte binding and signed-history ZIP fail-closed fixtures; test-only historical no-clobber `O_EXCL` change. GHAS formal CodeQL is FAILURE with three HIGH alerts: `rootark-sync-engine.js:401`, `:2604` and `issue-67-historical-restore.test.js:310`. Physical NTFS rollback races remain NO-GO. |
| #66 | [#300](https://github.com/bielxdh3/Root.ark/pull/300) `3d0f687c19c7b5c017c74daf22d3a36fd7abc9fe` | Source-reviewed W2 eviction-ledger optimization + recovered P1 full-ledger-loss sentinel published by normal fast-forward. Integrated independent exact-SHA SOURCE GO. Focused Windows Node22 18 PASS/1 expected POSIX SKIP and broader 71 PASS/7 SKIP; native ext4 Ubuntu Node22 19 PASS/0 SKIP and broader 72 PASS/6 SKIP. New-hosted CI in progress; CFAPI remains nonauthorizing, without real Windows 10 positive hydration. |
| #65/R1 | [#302](https://github.com/bielxdh3/Root.ark/pull/302) `ac734c130bf7a496db847481fa59ba07ee7a2cb5` | Owner-history signed byte-snapshot TOCTOU fix and strict ingress DEV-OFF remain published. GHAS formal CodeQL is FAILURE with one HIGH on test-only snapshot filesystem race. Subsequent local test-only candidate `ce3d7ec4675a32455d844b60166ca32f627d3aca` is not published or certified by hosted analysis. No external owner signer/custody floor. |

## Security findings and precise dispositions

- **#66 P1 found and corrected in the published source scope.** A lost entire `.rootark-sync-evictions` directory following a durable PREPARE and filesystem stage used to look like an empty ledger. If exclusion policy then reset, reconciliation could sign a remote DELETE. W8's `137ba07a` fixes this with `evictionLedgerRequired` persisted before PREPARE and a missing-ledger rejection before reconciliation; the corrective source was integrated as exact `3d0f687c` and independently reviewed. Negative tests use a real protected `SyncObjectStore` and assert no outbound signed DELETE. This is not a separately anchored off-host monotonic floor.
- **#66 separate batch NOT published.** Local `d9c66e953f452105f8919e154a5d393fee1d8305` reduces journal rewrites, but independent review found a distinct P2: signed remote-only admission can be lost if an invalid following record or crash occurs before batch durability; expired historical replay is then denied. Keep this branch NO-GO until independently corrected and re-reviewed. The published `3d0f` deliberately excludes it.
- **#67 remains a recovery NO-GO.** Disposable native NTFS `CreateFileW` share-mode-0/FileIdInfo experiments prevent cooperating process writers while the handle lives, but cannot prove path/ancestor namespace exclusion, durable journal/ACL recovery after crash or absence of all races. Do not wire `restoreFileSet`, claim `recovered:true`, or treat scanner warnings as cosmetic.
- **#302 local code-scanning work remains gated.** The earlier local `9d9a8198` test snapshot refactor was rejected because on Windows a leaf symlink could be opened outside the disposable root before FD verification. Another local candidate `ce3d7ec4` rejects nonregular/symlink Dirent before opening and tests zero external canary opens/reads on Windows and WSL; the formal CodeQL outcome on its exact SHA is not available and SOURCE review is still pending at this checkpoint.
- **#63/#242 still lack complete certification.** The historical 128-revision owner-initiated encrypted-index replacement candidate is local and undergoing adversarial review for persistent destructive opt-in between operations. Physical authenticated immutable version custody and TURN/cross-NAT end-to-end checks for P2P are absent. Android Keystore/SELinux and real enrollment on a physical device are also not certified.

## Dependency flow — source progress versus release

~~~mermaid
flowchart TD
  P293["#293 Draft: signed sharing / historical search"] --> G
  P298["#298 Draft: ZIP/restore; CodeQL HIGH and NTFS NO-GO"] --> G
  P300["#300 Draft: eviction ledger P1 fixed / CFAPI deny-only"] --> G
  P302["#302 Draft: strict ZK10 DEV-OFF / CodeQL HIGH"] --> G
  OWNER["Owner-signed ORIGINAL bytes before upload, version and revocation"] --> G
  CUST["Independent off-host monotonic custody / R1 floor"] --> G
  PHYS["Physical Win10 CFAPI, Android, TURN and complete recovery"] --> G
  CI["Independent exact-SHA review and ALL mandatory hosted gates"] --> G
  G{"Every real release gate proven?"}
  G -->|"No — current state"| HOLD["OPEN/Draft; NO merge, deploy, R1 cutover or Ready assertion"]
  G -->|"Only on future independently verified evidence"| REVIEW["Separate explicit release authorization required"]
~~~

## Source and history preservation

Literal remote `Root/main` was `d5fbc110944a5437dbd5e9175f39dd97f5e433bc`
in this check. Historical chain #231–#236 had already merged before this
mission; [#228](https://github.com/bielxdh3/Root.ark/pull/228) remains
CLOSED/unmerged and untouched. Keep these five scoped PRs Draft, do not force push,
merge, deploy, authorize ZK10 I/O, reset, clean or alter `Root/main`.

The shared Git configuration has a stale `core.worktree`; every modification
must pass explicit per-worktree `--git-dir` and `--work-tree` checks to avoid
writing into unrelated recovery/Android worktrees. This checkpoint changes
documentation only and cannot certify production.

## Publication after this 23:19 observation

The independently reviewed test-only `ce3d7ec4675a32455d844b60166ca32f627d3aca`
subsequently advanced PR #302 by normal fast-forward, with the remote branch
and GitHub PR head both verified at the new SHA; the PR remains OPEN/Draft.
Native Windows Node22 and Ubuntu WSL Node22/ext4 ran the exact three strict
ingress and disposable external-canary tests successfully (3 PASS, 0 FAIL,
0 SKIP each). Its independent SOURCE GO is scoped to the regression fixture:
this is not an endorsement of adversarial concurrent Windows ancestor renames,
production ingress, owner custody, or ZK10 I/O. Hosted CodeQL and other
required checks for the *new* SHA were not completed at the publication check.
