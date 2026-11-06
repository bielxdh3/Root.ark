# Root.ark — Main Execution Mission (2026-11-05)

Status: **ACTIVE**. Owner approved starting immediately on 2026-11-05 (America/Porto_Velho). This is an execution ledger, **not** release/deploy authorization.

## Objective
Complete relevant Root.ark security and reliability work first, then the remaining useful product roadmap, carrying forward exact-HEAD evidence rather than restarting old work. Favor real, reproducible defects, minimal dependencies and proportional tests; avoid hypothetical edge-case blockers and scope drift.

## Prioritized flow

1. **Security foundation:** [#203](https://github.com/bielxdh3/Root.ark/issues/203) current-HEAD triage with real reproduction and narrowly scoped fixes -> README R2 hardened execution/production profile -> [#94](https://github.com/bielxdh3/Root.ark/issues/94) confirm topology and only add shared/edge rate limiting if multi-process deployment actually requires it.
2. **Integrity and recovery:** [#67](https://github.com/bielxdh3/Root.ark/issues/67) protected snapshots and recovery + README R3 restore evidence + README R5 independently test each used external adapter -> README R1 independent key custody, external durability, configuration and authorized ZK-1 cutover certification. None of this grants deployment automatically.
3. **Core product:** [#68](https://github.com/bielxdh3/Root.ark/issues/68) capability-based sharing -> [#66](https://github.com/bielxdh3/Root.ark/issues/66) Files On-Demand and selective sync.
4. **Nonblocking later work:** [#63](https://github.com/bielxdh3/Root.ark/issues/63) advanced protected search; [#64](https://github.com/bielxdh3/Root.ark/issues/64) native Android; [#242](https://github.com/bielxdh3/Root.ark/issues/242) PrivyDrop/PairDrop/Magic Wormhole feasibility. README R4 scanner and suspicious-file isolation stays a real obligation, scheduled according to demonstrated risk after foundation work.

**Explicitly removed from scope:** README R6 integration into BielOS/BLS and any Virki integration. Do not manufacture an integration task. The former 60/20/20 agent allocation was a one-off and is revoked.

## Mission execution contract

- On every new task, read the current skills and instructions (Superpowers, PONYTAIL, UI-UX-PRO-MAX only when applicable), the current linked issue, actual source, test evidence and current HEAD. Consult available AI Memory to avoid rework, but source and GitHub state win over historical notes.
- One coherent bounded goal at a time, worktrees in E:, no modifications to other worktrees or user data, no force push/rebase/reset/clean. Split independently executable work only when it *reduces* total time; no fixed agent allocation.
- Reproduce actionable issues (TDD RED/GREEN for behavior changes), implement the smallest safe fix, use no unnecessary dependencies, run meaningful affected tests plus one appropriate final gate, independently review relevant high-risk changes, verify exact-head CI before claiming green.
- Do not chase improbable security narratives without real plausible preconditions, exploitability and consequence; do not hide confirmed vulnerabilities either. Preserve ZK, auth, ACL, storage, restore, users and history.
- Record precise issue/PR/branch/SHA/tests/blockers after each completed step. No deploy, activation, destructive migration or global ZK cutover without explicit permission. Merge only through authorized protected normal merge after genuine gates.

## Starting snapshot — verify on resumption

- GitHub `Root/main` = `ea0445df8ccd8f17da2c70572786d298491fd2c2` (#250); #249 also merged; #65 closed/completed.
- Open issues: #63, #64, #66, #67, #68, #94, #203, #242. No open PRs at time of inspection.
- **First implementation focus: #203**, based on *current* source and evidence, not blindly treating October findings as live.

## Progress ledger

- **2026-11-05 — Plan initiated.** Initial SHA and live issue/PR states verified through GitHub. Work on #203 not yet certified; no vulnerability or test result claimed from this plan alone.
