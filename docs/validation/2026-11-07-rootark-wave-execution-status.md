# Root.ark — execution checkpoint, 2026-11-07

**Snapshot, not release certification.** Revalidate remote SHA, GitHub checks and independent review immediately before any action. This document supersedes earlier **current-state** numbers, but never deletes historical evidence in `docs/rootark-main-execution-mission.md`.

## Canonical state and authorized procedure

- Remote branch literal `Root/main`: `d5fbc110944a5437dbd5e9175f39dd97f5e433bc`. Five confirmed normal merges on that path: #252, #253, #255, #256 and #258; no later merge in this checkpoint.
- GitHub OPEN PRs: **47 (20 Ready, 27 Draft)**. Earlier count 49/30 Ready is a historical snapshot only. A review compared **all 39 open PR-to-PR dependency edges**: 29 parent-current-HEAD ancestors, **10 divergent**: `273→261`, `286→278`, `292→278`, `295→292`, `296→294`, `298→295`, `299→284`, `300→295`, `301→251`, `302→251`.
- Existing PRs are the consolidation targets. **Approximate ten-PR target, not achieved:** #293 search, #291 Android, #295 picker/FOD, #300 CFAPI, #288 recovery, #298 #66/#67 integration, #296 sharing, #299 WebRTC, #302 ZK10/R1 and #306 boot. Others cannot be closed merely because a target has similar file names; prove exact ancestry or materialized source/test equivalence in a *merged* canonical target first.
- Human authorizes **normal GitHub merges** only when the exact final SHA has independently favorable P1/P2 review, **all applicable hosted mandatory checks GREEN**, and current `Root/main` composition is verified. No force push, destructive rebase/reset/clean, direct edit of `Root/main`, deploy or cutover. `PR #228` was already closed unmerged by its owner on 2026-11-02 and remains untouched.

## Dependency and security gates

~~~mermaid
flowchart TD
  M["Root/main d5fbc110; five confirmed merges"]
  S["#63 / #68: #293 + owner-signed HPKE grant bundle"]
  A["#64: #291 Android offline floor + session cache"]
  P["#66/#67: #298 pin, FOD, signed CAS, restore, backup"]
  C["#66: #300 Windows CFAPI native boundary"]
  W["#242: #284 → #299 WebRTC broker/resume"]
  Z["#65: #251/#301/#302 bridge + independent R1 custody"]
  B["#306 boot fail-fast"]
  G{"Exact SHA independent GO and all required hosted gates GREEN?"}
  HOLD["Draft / no merge; preserve evidence and worktrees"]
  MERGE["Normal protected merge, then verify new main and child SHAs"]
  M --> S & A & P & C & W & Z & B
  S & A & P & C & W & Z & B --> G
  G -->|No| HOLD
  G -->|Yes| MERGE
~~~

| Scope | Verified source / present HEAD | Current blocking gate |
| --- | --- | --- |
| #63 protected search | #257 `dcaa636a` is **Ready** after exact-SHA peer GO; 10/10 focused and formal hosted Windows/Ubuntu/PG18/CodeQL/dependency PASS. #293 `4ea7f7cd` is Ready; proposed #63+#68 combined `d03cfd1e` remains local, independent source-level GO. | Current-main hosted regression remains queued; #293 combined WSL full capability startup/CodeQL not certified. #63 remains open. #257 not merged. |
| #68 ZK sharing | #294 `e2b7c035` Draft with owner-verified local ACK fix; #296 `9fa36409` Draft; local combined #293/#68 SHA `d03cfd1e` includes HPKE/AEAD, signed history, zero-byte and bounded multi-object behavior. | #294 formal CodeQL queued; complete combined exact-SHA hosted suite absent, physical owner custody not provided. Partial batch success is documented and not falsely called atomic. |
| #64 Android | #291 published Draft `012c73e75a5c687d4c2a0538b4019d3a447f2e6f`: nine source-reviewed owner floor/native lock/FD/importer artifacts plus #291 ciphertext session cache; independent exact-SHA source GO, JDK17 Kotlin and Node22 focused tests PASS. | Hosted checks queued; actual Android hardware Keystore, FD lifecycle/SELinux, real enrollment and independent monotonic R1 floor not proven. Grant provider remains null. |
| #66/#67 pin/recovery | #298 published Draft `4237477f657c92d4af4346f1eb909cf8a7fbdd5b`: reviewed fail-closed ZIP source coverage (Win Node22/WSL22 GREEN). Earlier combined local `afb97777` and correction `90f95ca1` had Windows/Ubuntu green unit tests **but independent P2 NO-GO**. | Signed pinned `docs/A.txt` can be replaced by directory and cloaked with case-distinct `docs/a.txt` under `selectedPaths`/`excludedPaths`, changing snapshot/journal. New independent *unfiltered physical pin preflight* and tests required, then compose onto new #298 HEAD. ZIP is not full-account signed inventory or off-host R1. |
| #66 native CFAPI | #300 `9f3e3ffa` Draft; local deny-only bridge `b398bed3` plus timeout fix `37376e16` tested Windows SDK26100/native mock and WSL. | Reviewer found P2 orphan noncooperative fail-ACK promises exceeding max active budget and requestKey descriptor/getter mismatch. Local repair in progress; no actual Windows10 CFAPI registration, positive hydrated bytes or physical proof. |
| #242 WebRTC | #284 published Draft `d73c06ac`; local #299 integration `6bc68184` composes ACL snapshot, prehash signaling, resumed 1:N transfer and Edge tests. | Independent peer found P2: room creation calls costly `authorizeObject` before cheap room capacity limit, even if eventual 429. Repair and new exact peer required. App lacks coherent serialized owner/all-guests ACL authority; TURN/cross-NAT not validated. #254 remains Draft under its research-only issue constraint. |
| #67 CodeQL restore | #288 `e385281f` Draft, scoped signed multi-object historical CAS/retention tests pass. | Formal CodeQL **FAILURE** with one high `sync-client/rootark-sync-engine.js:401` `lstat→open` race warning; safe source refactor + independent SHA review and hosted recheck pending. Do not dismiss/suppress scanner. |
| #65 ZK10 + R1 | #301 `4815e8a` owner-signed SyncV2↔ZK1 mapping DEV-OFF, #302 `9e3d31` signed lease/two local stores DEV-OFF, #251 roadmap Draft. | Real independent off-host monotonic custody, owner approval/provisioning, backup/account completeness, physical gates missing. #301 canonical Windows had one red run but a separate **same-SHA** successful 3350-test run, so root cause unproven; red remains red. No ZK10 cutover. |
| Cross-cut #306 boot | `fe8f9a15` Draft, independent source GO, Windows/Ubuntu22 local boot fail-fast regression PASS. | Hosted CodeQL/security/dependency still queued; no merge. |

## CI, worktree provenance and remaining execution

- The hosted `Root/main` runs `42380131258`, `42380131280`, `42380131359` and many current PR runs were **queued at the earlier snapshot**. Later the Security Regression Ubuntu job began/passed while Windows jobs remained queued; CodeQL reached SUCCESS and Dependency Review remained queued. GH Actions may operate globally while individual jobs remain unscheduled. No legitimate all-green inference; no mass reruns or bypass. Billing/scheduler cause unproven. A safe next action outside code is owner billing/usage or GitHub Support with exact run IDs.
- A shared `E:/servidor/.git/config` `core.worktree` points at another old ZK65 worktree. During #291 composition, **nine untracked** Android owner-floor/fixture files in `E:\servidor\.worktrees\zk65-recovery-journal-20261024-chatgpt` were inadvertently overwritten by a Git command lacking explicit worktree context. Prior bytes are **unknown**; files were preserved, not reset/cleaned or spuriously declared restored. Every Git mutation must use per-worktree `--git-dir` AND `--work-tree`; an isolated worktree created with `--no-checkout` also requires `read-tree HEAD` to populate its own index before `checkout-index`.
- Local AI Memory `127.0.0.1:49374` connection refused; source, reviewed commits and GitHub checks remain authoritative. Tests on this PC (Windows 11) **do not** constitute physical Windows 10 CFAPI validation. Android SDK compilation is **not** physical-device evidence. Edge local transfer is **not** TURN/cross-NAT proof.
- The remaining roadmap is not finished: owner-signed historical multi-object recovery, whole-account source inventory/retention and revocation, #63/#64/#66/#67/#68/#242 integration, independent R1 genesis/monotonic floor and real platform checks remain live gates. Keep their issues open, preserve worktrees, update this checkpoint only with new verified evidence.

Links to original mission and exact review details are maintained in [the main mission](../rootark-main-execution-mission.md) and [its PR #251 checkpoint](https://github.com/bielxdh3/Root.ark/pull/251#issuecomment-6708652569).
## Later verified publication and CI update — 2026-11-07

This section supersedes **current statuses only**, not the historical test and review evidence above.

| Track | Published and source-reviewed state | Pending/blocked |
| --- | --- | --- |
| #63+#68 | Existing [PR #293](https://github.com/bielxdh3/Root.ark/pull/293) advanced by normal fast-forward to `d03cfd1e283acb876f99bbf03db976b90959eb72`; **Ready→Draft** before publication; independent prior exact-SHA source GO. Genuine signed share/ACK, HPKE/AEAD, zero-byte, scoped grants and 1–64-revision private search remain in one functional branch. WSL22 `/mnt/e` fixture startup 6 failures before assertions was rechecked using tracked-source-only disposable ext4 `/tmp`: **12/12 focused #68 PASS**, Node22, exit 0; no product edits to make it pass. | New-head hosted checks and #294 formal CodeQL ACK gate not all complete. Production owner custody/physical acceptance missing. |
| #66+#67 | Existing [PR #298](https://github.com/bielxdh3/Root.ark/pull/298) advanced twice via normal fast-forward to final `4fddeefb090c47371394bc753cc22077225adb65` (parent backup ZIP peer-GO `4237477`). Independent exact-SHA composition SOURCE GO. Linux Node22 combined **128 PASS/0 SKIP**, Windows22 focused **44 PASS/8 POSIX SKIP + 53 PASS** historical/preview/FOD; peer Windows22 pin/ZIP 35PASS/8SKIP and Linux signed CAS 32PASS. Filter-independent real inode/alias guard before journal/snapshot; ZIP source omission fail-closed preserved. | New-head hosted checks pending; actual physical Windows10 native FOD, account-wide signed backup inventory, off-host R1 custody unverified. Draft only. |
| #66 CFAPI | Existing [PR #300](https://github.com/bielxdh3/Root.ark/pull/300) fast-forwarded to `03cac3a9f33975af403c231ce4ffc62e4e7a4d52`. Independent P1/P2 source GO for deny-only native ABI+JS bounded callback/ACK; Windows MSVC SDK self-test 23PASS, WSL Node22 21PASS/2 expected skip. | No native OS provider registration, physical Win10, positive hydration, independent CEK authority or assured kernel fail-ACK fallback; Draft, hosted gates not complete. |
| #63 baseline | Existing [PR #257](https://github.com/bielxdh3/Root.ark/pull/257) `dcaa636a20` promoted **Draft→Ready** after peer exact-SHA GO, 10/10 focused, all PR-head hosted gates PASS and clean `merge-tree` with `Root/main`. | Not merged while current main hosted regression/Dependency Review incomplete; broader #63 issue remains open. |
| #67 recovery CodeQL | [PR #288](https://github.com/bielxdh3/Root.ark/pull/288) `e385281f` still Draft with formal high alert at `rootark-sync-engine.js:401`. Local fd-first candidate `cb454f16` got peer **NO-GO P2** because Windows Node22 lacks O_NOFOLLOW; subsequent Windows pre-lstat mitigation `7442a053` local and tested, pending new exact SHA peer. | Native reparse-safe Windows open and formal CodeQL alert resolution not proven; no push or dismiss. |
| #242 WebRTC | [PR #284](https://github.com/bielxdh3/Root.ark/pull/284) published `d73c06a` remains Draft. #299 child combined local `6bc68184` and capacity repair `29c2459` found new real HTTP response-disconnect P2. New child local `78b83c5` adds real socket-close cleanup with Win/Ubuntu tests, pending peer; parent-only port local `914279` lacks final close fence. | Source peer on new child SHA, parent backport+peer, hosted checks and TURN/cross-NAT/owner+guest serialized ACL authority absent. No pushes of pending local P2 chain. |

**Overall PR total:** 47 open at latest check, approximately **19 Ready / 28 Draft** after #293 returned to Draft. `Root/main` remains `d5fbc110944a5437dbd5e9175f39dd97f5e433bc`, with five verified normal merges only. Main CodeQL `42380131359` **SUCCESS**, Security Regression `42380131258` **IN PROGRESS** (Ubuntu success; Windows jobs still unresolved), Dependency Review `42380131280` **QUEUED**. Exact latest status must be re-read before any merge; no bypass or speculative all-green claim.
