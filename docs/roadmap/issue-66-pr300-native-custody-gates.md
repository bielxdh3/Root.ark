# Issue #66 / PR #300 — native root custody execution gates

**Status: RELEASE NO-GO.** This is an execution and evidence map, not
permission to enable recovery, merge PR #300, deploy, or change `Root/main`.
RootSession remains unconditionally unavailable for production. The local
feature-denial seam in `sync-client/rootark-sync-native-root-session-contract.js`
is an intentional security boundary, not a test workaround.

## Required sequence

```mermaid
flowchart TD
  S[Draft PR 300: no cutover] --> I{Native executable, DLL and compiler provenance attested?}
  I -- No --> N[Keep RootSession closed; RELEASE NO-GO]
  I -- Yes --> O{Original root identity pinned by an independent custodian BEFORE any mutable-name preflight?}
  O -- No --> N
  O -- Yes --> A{Root and every ancestor acquired and held by an independent custodian?}
  A -- No --> N
  A -- Yes --> P{A distinct untrusted UID/SID fails real reads and writes through every ancestor?}
  P -- No --> N
  P -- Yes --> H{Hold and validate OS handle/fd identity for all I/O?}
  H -- No --> N
  H -- Yes --> B{Bound cold metadata reads to opened-inode versions and finite resource budgets?}
  B -- No --> N
  B -- Yes --> T{Native create/read/enumerate/rename/unlink, stage, journal, rollback and commit under the same root?}
  T -- No --> N
  T -- Yes --> X{No legacy pathname fallback for signed directory relocations or deletes?}
  X -- No --> N
  X -- Yes --> D{Flush ordering, cold reopen and independent anti-rollback floor proven?}
  D -- No --> N
  D -- Yes --> C{Cold PREPARE and COMMIT bound to original physical identity and signed CURRENT floor?}
  C -- No --> N
  C -- Yes --> M{Cold PREPARE signs original named/anonymous publication mode and enforces exact stage topology?}
  M -- No --> N
  M -- Yes --> F{Real hostile same-SID/UID A-B-A, Unicode, 16385+ entries, power loss and recovery passed on both OSes?}
  F -- No --> N
  F -- Yes --> E{Signed ingress/egress and independent server-side revocation and replay fencing proven?}
  E -- No --> N
  E -- Yes --> R{Exact SHA independent SOURCE GO and hosted required checks green?}
  R -- No --> N
  R -- Yes --> G[Only then request release-policy approval; do not auto-merge]
```

The arrows are **conjunctive gates**, not alternative tests. A positive lab
proof does not unlock the next gate without its own source-backed evidence.

## 2026-11-11 late continuation — physical lab publication and crypto P2 boundaries

This is the **newest checkpoint**, superseding only the stale "current HEAD"
claims in historical checkpoints below. It does not supersede their physical
test evidence or permit release. GitHub was queried after the PR #298 lab-only
fast-forward; `Root/main` remained `202146bb73ca8577a0a4017c4556cb8b1e9588a6`.

| PR | Published HEAD / scope | Latest separately bounded evidence and open gate |
| --- | --- | --- |
| #298 | `73c2be30a1fbfd95f346d94337e8d09a972138ec`, OPEN/Draft, **normal FF** from `ce393b75` | Two independent exact-SHA SOURCE GO apply **only to 11 experimental lab files**. Physical NTFS/Win11 Node22 and WSL/ext4 Node22 cases each reported 7/7; lab demonstrates actual separate-process same-SID/UID source/ancestor replacement and held HANDLE/dirfd no-replace. Windows 10 CFAPI and production root custody are NOT proven. **Distinguish two GitHub checks:** the CodeQL *workflow* run `43118997507` and its Analyze job `130854325688` completed **SUCCESS**, but the distinct **GitHub Advanced Security `CodeQL` PR check-run `130855351016` concluded FAILURE** with 20 high-severity new alerts (`js/file-system-race`: 19 in deliberately adversarial experiments, 1 historical test). A successful query execution/upload does NOT make the security-alert gate green. Investigate and resolve without hiding production findings or rewriting deliberately RED tests. |
| #300 | `984a62ef8ca2bee00b8bf296086da3e10d5b7761`, OPEN/Draft (documentation only) | Real `RootSession` remains unconditionally disabled. Prior `a598eb47` hosted Security Regression had **49 Windows** and **59 Ubuntu** positive FOD/pin/picker failures; neither lab publisher nor docs cure them. |
| #301 | `e1ca644b6aaaa48d87534895575d8576cfced077`, OPEN/Draft | Later *unpublished* chain now reaches **local `7da07252eec87ad8a2451bf5f21665ae74e1900d`**. Exact parent `25b2649c` physically failed two new P2 oracles in Windows Node22: dynamic `Object.freeze` fabricated the native Hash facade/SMT root, and inherited `Array.prototype[0]` setter authenticated signed compartment A while applying B. Capturing the early freeze intrinsic and removing array prototype **before first write** gave targeted 2/2 GREEN and related 34/34 Windows tests. WSL tests on this new SHA and two independent exact-SHA SOURCE GO remain pending; prior reviews of `25b` were NO-GO. Published `e1ca` Security Regression failed one old issuer Proxy test expecting descriptor reads, although hardened source correctly rejected Proxy before traps; correct test realism without making real positives negative. |
| #302 | `e0af83970f2efa3c0798772c001e17f1dd49cade`, OPEN/Draft | Later *unpublished* chain reaches **local `be3170e33b5f8f848c3c917eed9117e21bd75e5d`**. A SOURCE NO-GO on prior `34b4d39e` identified mutable `WeakMap.prototype.get` substituting unsigned byte intent B for real owner-signed A, and mutable `Set.prototype.has` permitting nonce replay after a signed CURRENT callback. Both attacks physically RED on `34b` and GREEN on local child in Windows Node22, along with full **70 total / 66 PASS / 4 SKIP / 0 FAIL** Windows suites. The child pins native Set/WeakMap constructors and methods. Exact-child WSL GREEN and two independent SOURCE GO have NOT been obtained; DEV-OFF dual SQLite remains same-host and NONAUTHORIZING. |
| #306 | `b13b29f9662d5f9036431e53235b9cdc132f0944`, OPEN/non-Draft | Earlier applicable checks green but no formal APPROVED review and base behind current `Root/main`; not merger-ready. |

**Environment limitation:** New Ubuntu WSL child-test invocations stalled while
`wsl.exe` was starting, including a trivial process probe; do not report their
missing exit codes as PASS or FAIL, do not terminate unrelated app processes or
restart Docker/WSL without diagnosis. Earlier completed WSL tests on prior
SHAs stay valid **only for their own exact SHAs**.

**Evidence planes remain all-required and distinct:**

1. **Laboratory:** disposable RED and held-inode/HANDLE no-replace demos;
   independent SOURCE GO for #298 experiments does not authorize runtime I/O.
2. **Native product:** first-pin independently enrolled original root and ALL
   ancestors, OS-held identity, writer-isolation, durable no-clobber PREPARE /
   COMMIT, cold `required-v2`, positive CFAPI FOD hydration/pin/picker and
   signed ingress/egress. **NOT IMPLEMENTED / NOT PROVEN.**
3. **Independent self-hosted custodian:** different operator/host retains
   monotonic owner-signed CURRENT, lease serial, replay/revocation and original
   physical identity; local test-supplied callbacks and dual SQLite DEV-OFF
   remain **nonauthorizing**. **NOT PROVISIONED.**
4. **Release/merge:** Windows **10** CFAPI physical proof, true power-loss /
   recovery, isolated writers, two SOURCE GO for exact publishable SHA,
   hosted canonical/mandatory/CodeQL green and owner approval. **NO-GO.**

No merge, deploy, force-push, `Root/main` mutation or production activation
is authorized by any of the above. **Issue #66 incomplete · RootSession OFF ·
MERGE NO-GO · RELEASE NO-GO.**

## 2026-11-11 continuation — completed Windows CI evidence and unpublished fixes

The live GitHub API was rechecked after the 21:00Z checkpoint immediately
below. All five published PR HEADs and the `Root/main` ref remained unchanged;
the four detached worktrees below were **clean**, not pushed or merged.
This checkpoint supersedes the still-in-progress Windows #300 CI description
below, but does not retroactively alter its test evidence.

| Evidence plane | New observed fact | Remaining gate |
| --- | --- | --- |
| Hosted #300 `a598eb47` | Security Regression `43094656916` completed **FAILURE**: Ubuntu 3,780 tests / **59 FAIL** (34 FOD, 25 pin); Windows canonical 3,781 tests / **49 FAIL** (34 FOD, 12 pin, 3 picker); Windows mandatory and syntax/test aggregation also FAILED. CodeQL `43094498755` SUCCESS. | These are real *positive* behavior failures under the S0 native-required deny. No tests may be weakened to expect denial; RootSession still throws unconditionally. |
| Hosted #301 `e1ca644b` | CodeQL `43100369591`, PG18 `43100369434`, dependency review `43100369516` and provider/Android `43100369316` SUCCESS; Security Regression `43100369644` was **in_progress**, not green, at the continuation query. | CI for a later child cannot inherit checks from this SHA. |
| Hosted #298 `ce393b75` and #302 `e0af8397` | Security Regression `43097069140` and `43096175973` completed `startup_failure`, **0 jobs**, both `workflow_dispatch`; CodeQL and PG18 PR runs remained QUEUED with 0 jobs. Workflow `security-regression.yml` itself was active. | A zero-job infrastructure/dispatch failure is not a source-test failure and is not evidence of success. Do not rerun active jobs or assert a GitHub incident without diagnostics. |
| #298 local `67c850c11e56b945309aae75973ca0813257c392` | Separate **expected-security-RED** evidence: three actual pathname-resolved `link`/`rename` operations and two legitimate controls per OS; no production code change. | Requires native fd/HANDLE-rooted replacement and own two SOURCE GO for any evidence-only publication. |
| #301 local `afde24320661902b5bdd2c1cefadbc19229dfe6f` | Two local commits after `e1ca644b`: pin captured native createPublicKey/hash/verify/sign before hostile `Symbol(kHandle)` getters and bound owner-key history. Targeted Win22 and WSL22 suites each **43 PASS** as previously executed. | Await two independent SOURCE GO on the full child delta before any normal fast-forward. No production key authority is established. |
| #302 local `47c95899a66917b87c8b43d4a23014321d9aa9eb` | Three same-realm DEV-OFF crypto factory/verify mutations reproduced RED on its parent; local fixes reported Win22 **47 PASS/4 SKIP**, WSL22 **50 PASS/1 SKIP**. | Await two independent SOURCE GO before fast-forward; dual SQLite on one host is **not** external independent custody. |

The still-unpublished documentation child `30657c469d20222ccb2e9af126ef44da7236f47f`
is the immediate parent of this continuation. Neither documentation nor the
security-RED experiments cure missing native physical custody. **Four separate
required evidence planes** remain laboratory, native product, independent
self-hosted off-host operator, and release/merge. Windows **10** CFAPI,
physical power-loss recovery, separately administered original-A enrollment
of all ancestors, and a genuine positive FOD hydration path remain unproven.
**RootSession OFF · MERGE NO-GO · RELEASE NO-GO.**

## 2026-11-11 21:00Z — newer cross-PR source/CI checkpoint (supersedes earlier current HEAD snapshots)

This checkpoint records observed **published** refs, not approval to merge,
deploy, remove Draft, or open `RootSession`. It supersedes older current-HEAD
tables further down; those earlier test and incident descriptions remain
historical evidence. `Root/main` is still
`202146bb73ca8577a0a4017c4556cb8b1e9588a6`.

| PR | Published HEAD / draft state | Independent scope and CI evidence at this checkpoint |
| --- | --- | --- |
| #298 | `ce393b75b676119d7ac6f2e74e17a43421bd6cf9`, OPEN/Draft | Earlier strict stage restoration fixes passed Win22/NTFS and WSL22/ext4; full PR **NO-GO**. Security Regression run `43097069140` completed `startup_failure` with no execution jobs. CodeQL `43097027050` and PG18 `43097027060` were queued, not green. |
| #300 | `a598eb470be7b9871fe7e905aa76ea64ab98d60c`, OPEN/Draft | Documentation-only descendant of S0 deny; CodeQL `43094498755` SUCCESS. Security Regression `43094656916` in progress: Ubuntu full TAP **3780 tests, 3473 PASS, 59 FAIL, 248 SKIP**, including 34 positive FOD and 25 pin failures; Windows canonical and mandatory results still running/unconfirmed. The negative S0 physical opt-in tests were SKIP hosted. |
| #301 | `e1ca644b6aaaa48d87534895575d8576cfced077`, OPEN/Draft | New direct cutover history P2: signature A / digest B split-read reproduced RED on the former `50d76c68`; data-descriptor snapshot and one frozen wire now GREEN. Win22/NTFS **40/40 PASS**, WSL22/ext4 **40/40 PASS**, including real Ed25519 owner rotations and synthetic mapping authority. Two independent SOURCE GO for this *delta*; normal FF published. New exact-SHA hosted checks still in progress/queued (Security Regression `43100369644`, CodeQL `43100369591`, PG18 `43100369434`). |
| #302 | `e0af83970f2efa3c0798772c001e17f1dd49cade`, OPEN/Draft | Prior native KeyObject clone fix passed local crypto tests, but new same-realm dynamic `crypto.createPublicKey` and `crypto.createPrivateKey` replacement during hostile `Symbol(kHandle)` getters was reproduced as **two DEV-OFF P2 RED** scenarios on Win22 and WSL22. The published source is not cleared. Security Regression `43096175973` completed `startup_failure` with zero execution jobs; CodeQL `43096131770` and PG18 `43096131753` queued. |
| #306 | `b13b29f9662d5f9036431e53235b9cdc132f0944`, OPEN/non-Draft | Applicable earlier hosted checks succeeded on that SHA, but GitHub contains **zero APPROVED reviews** and its merge base predates the current `Root/main`; no formal merge approval. |

Additional PR #298 *local/unpublished* artifact
`67c850c11e56b945309aae75973ca0813257c392`
(parent `ce393b75`) isolates three **expected-security-RED** kernel
pathname-swap observations in `experiments/issue-67-pr298-unbound-name-evidence/`:
progress `link` can publish a substituted foreign inode, `stageExisting`
`rename` can move a foreign inode, and historical `_apply` can hardlink a
foreign local inode (the subsequent signed SHA gate denied remote push).
Physical disposable tests reported 5/5 on each Windows Node22/NTFS and WSL
Node22/ext4 (two legal controls plus three reproductions). These use a
same-process pre-syscall interposition followed by actual filesystem calls,
**not** an independently hostile SID/UID or proof of original-root custody.
The artifact awaits exact-SHA peer review; neither a later `lstat` nor an
`O_EXCL` name-only fallback resolves these identity races.

**Conjunctive separation:** laboratory FileId/inode probes and same-process
RED tests; native product authority with first-pin independent original-A,
held root+ancestor handles and no-replace PREPARE/COMMIT; separately
administered 100% self-hosted off-host CURRENT/floor/lease/revocation; and
formal release approvals are **four distinct, all-required evidence planes**.
No product FOD positive hydration may be claimed while S0 denies it. No
DEV-OFF SQLite cryptographic correctness grants remote custody or replay
authority. Real Windows **10** CFAPI and physical **power-loss/recovery**
remain unperformed; Windows 11 and process hard-exit are not substitutes.
**MERGE NO-GO · RELEASE NO-GO · RootSession OFF.**

## 2026-11-11 — current published branches, CI, and mutually independent release gates

This later GitHub snapshot supersedes all earlier **current/as-of** statements
below, without erasing their original test histories. PR #300 is **OPEN/Draft**
at exact published HEAD `b774ce13398e2486fd08e3ff7b47d53d66c046c2`;
PR #301 is OPEN/Draft at `50d76c686f7d47799344ea8994fd0b8adb3293cc`;
PR #302 is OPEN/Draft at `9096cfa75598f23cd640242febe4118e0df64acd`.
The untouched `Root/main` ref is
`202146bb73ca8577a0a4017c4556cb8b1e9588a6`. No merge, deploy,
production cutover, forced push or `RootSession` activation occurred in this
checkpoint.

| Published exact SHA | Hosted checks confirmed | What is **not** proven |
| --- | --- | --- |
| PR #300 `b774ce13` | CodeQL run `43058440999` **SUCCESS**. Security Regression run `43058657386` **FAIL** in Ubuntu full, Windows canonical, mandatory release and downstream syntax/tests aggregation. | S0 fail-closed inbound denial is not positive FOD hydration, atomic no-replace publication, original-A native custody or release authorization. |
| PR #301 `50d76c68` | Security Regression `43058539434`, CodeQL `43058539486`, Dependency Review `43058539491`, PostgreSQL 18 `43058539312` and targeted provider/Android `43058539532` all **SUCCESS**; individual Ubuntu/Windows canonic and mandatory checks also reported SUCCESS for that SHA. | Source-level cryptographic role separation is not an independently operated mapping CURRENT, physical original root enrollment, or cold-replay authorization. |
| PR #302 `9096cfa7` | CodeQL `43056966865`, Dependency Review `43056966940`, PostgreSQL 18 `43056966851`, Ubuntu full and Windows mandatory release jobs **SUCCESS**. Security Regression `43057146979` **FAIL**: Windows canonical and its syntax/tests aggregator failed; the canonical job logged one `ERR_ASSERTION` in `test/issue-65-zk10-external-floor-custodian-w4.test.js` test *partial wall-clock rollback during signing cannot hide an elapsed owner lease*. | DEV-OFF same-host dual SQLite is not an independent off-host custodian. Passing Ubuntu/mandatory jobs cannot override the failed exact SHA Windows canonical or a separate SOURCE NO-GO. |

The new PR #300 S0 code was published by normal fast-forward (`226652ff`
source, then documentation HEAD `b774ce13`) after its bounded physical
RED→GREEN tests and reviews. Native-required inbound CREATE/UPDATE/MOVE
now reject **before** legacy `publishInboundPayload()` or signed journal
admission. This closes the observed late foreign-inode overwrite attempt
**only by denying the positive native-required operation**. It does not
replace the JavaScript publisher with a native atomic no-replace operation.
In the hosted full suite, the previously red positive FOD assertions remain
red and additional positive hydration/picker expectations now reject at the
new S0 guard. Do not change the positive tests to expect denial or claim
successful feature delivery. Legacy non-FOD `fsp.rename` remains a separate
same-principal destination race.

**Four separate trust/evidence planes (all required for release):**

1. **Laboratory:** W3 Linux/ext4 held dirfds and W26 Windows/NTFS retained
   HANDLEs, native no-replace stage, adversarial inode/ancestor checks and
   narrow cold witness tests are nonauthorizing. Tests on Windows **11** do
   not prove Windows **10** CFAPI. A process hard-exit is not a physical
   powercut, and an opt-in PREPIN rejection is not an original-A enrollment.
2. **Product:** a real native, independently rooted `RootSession` must hold
   the original root and every ancestor (FileId/inode, owner, ACL/mode,
   reparse/mount chain), perform signed inbound/outbound stage, no-replace,
   PREPARE/COMMIT, cleanup and cold `required-v2` replay through retained
   native handles, without a legacy JavaScript rename/unlink fallback.
3. **Independent self-hosted custodian:** a separately administered UID/SID
   and machine/host must enroll the original-A physical identity **before**
   any hostile mutable-name preflight, protect independently monotonic owner
   CURRENT/floor/epoch/lease/revocation, and bind the actual physical origin,
   owner-signed SyncV2↔ZK mapping and signed ingress/egress. PR #301's
   mapping proof, PR #302's DEV-OFF floor and PR #300's lab FileId cannot
   be treated as interchangeable signatures or automatically joined across
   divergent branch histories.
4. **Release/merge:** fresh independent SOURCE GO on the **published SHA**,
   correct author/trailer metadata, hosted CodeQL and all mandatory full CI
   checks, Windows 10 real CFAPI, hostile-process tests, crash/cold replay,
   real hardware powercut and explicit operator custody must all be proven.
   A green check on an ancestor or a narrower DEV-OFF/lab suite is not GO.

**Status: PR #300 MERGE NO-GO · RELEASE NO-GO · RootSession OFF.**

## 2026-11-11 — verified current publication and independent authority gaps

This entry supersedes earlier *as-of* snapshots below for current branch
provenance; historical experiment evidence remains intact. The published
PR #300 HEAD is `23cc31b69c5efb6f218eb74e556b49e297e79297`
(`OPEN/Draft`), fast-forwarded from `dceeb9c3179bae28a4065583f754277ee31ba71c`
after two independent **SOURCE GO** reviews on the exact integrated SHA.
`Root/main` remained `202146bb73ca8577a0a4017c4556cb8b1e9588a6`.
The two new commits fix the *advisory metadata inventory* contract, not
native storage authority: custom-adapter records are detached as bounded
JSON-only values, with explicit id/path types, no callable coercion, no
getter/Proxy execution, and a reconstructed metadata-only output with no
ciphertext or authorization envelope. Windows Node 22/NTFS and WSL Node
22/ext4 each completed the exact integrated metadata test file **13/13
PASS**; Node syntax and Git diff checks passed. A pre-fix hostile
`toString` callback executed while the corrected path denies with
`invalid_inventory` and zero callback executions. The DTO's 128 KiB,
4096-node/key bound does **not** prove constant memory when V8 prepares
an enumeration of an already enormous custom JavaScript object.

Hosted CodeQL run `43048299591` on exactly `23cc31b6` completed
**SUCCESS**. Hosted Security Regression run `43048466075` was launched
for this exact SHA and its Ubuntu Node 22, Windows canonical and Windows
mandatory jobs were **in progress** at this snapshot; do not claim those
results before checking completion. At predecessor `dceeb9c3`, the Ubuntu
full suite reported **3,509 PASS / 18 FAIL / 244 SKIP**. Those failures
include positive FOD/native-session scenarios: `RootSession` remains OFF
and old path-based fallback must not be activated to satisfy CI.

The operational inbound publisher, `sync-client/rootark-sync-engine.js`
`publishInboundPayload()`, still executes replace-capable `fsp.rename`
after a separate destination-absence check. A new **unpublished,
non-destructive RED** test in worktree
`issue66-w14-inbound-collision-red-dce-20261111` planted a foreign inode
at that exact boundary and intercepted the attempted destructive rename
on real Windows NTFS and WSL ext4 (**0 PASS / 1 FAIL** each). Both foreign
inodes, exact canary bytes, local snapshot and signed-operation ACK state
were preserved. This demonstrates a live P2; it is not a native
no-replace **GREEN**, and the intentionally RED fixture was not
committed or published as a fix.

The W26 opt-in `PREPIN_COLD_ORIGIN_REQUIRED` negative lab is already
published in `dceeb9c3`: owner SID inspection requires native
`READ_CONTROL`, and separate plain-B/junction-B attacks denied the
untrusted pre-pin directory (Windows Node22/NTFS **25 PASS**). It still
cannot attest the physical FileId of original A **before the first native
pin**; `NORMAL` may pin a hostile same-SID B. The PR #301 logical
SyncV2/owner-signed ZK mapping and PR #302 DEV-OFF monotonic floor have
distinct signing domains and divergent branch bases. The PR #302 hosted
Security Regression on exact `dcd65b6b` finished **SUCCESS** in Ubuntu,
Windows canonical, mandatory gates and syntax, with CodeQL/PostgreSQL18/
dependency review green. This neither provisions an off-host custodian
nor creates a valid cold physical-root authority in PR #300.

**Still blocked:** independent original-root and all-ancestor enrollment
before hostile namespace access; distinct-principal same-SID/UID writer
isolation; native HANDLE/dirfd stage/publish/retire with no-replace;
signed origin/current-floor/PREPARE/COMMIT cold recovery and owner-signed
ingress/egress; real Windows **10** CFAPI and physical powercut evidence.
**RootSession OFF; MERGE NO-GO; RELEASE NO-GO.**

### 2026-11-11 — S0 native-required inbound containment (local integration)

The unpublished integrated candidate `226652ff8504477c2fba2b7d4d2d35de0886528b`
combines reviewed roadmap checkpoint `a2327a8c` with S0 inbound fence source
`21c7824e` on the published `23cc31b6` base. The S0 private,
non-overridable `denyUntrustedNativeInboundPublish()` fence rejects **all**
native-required signed inbound CREATE/UPDATE/MOVE before `journal.observeAdmission`,
user-payload parent creation, staged publication or legacy replace-capable
`fsp.rename`. Signed native-required DELETE is already denied by its own
earlier fence. Successful signature/AEAD checks and an apparent caller-supplied
native session **never** authorize JavaScript publication: the current
`openNativeRootSession(true)` throws, and the new guard still fails if a future
opener were to return. Metadata-only browsing and legacy non-FOD operations
retain their separate behavior. Cooperative root-lock bookkeeping may precede
the fence; there is **no** claim of zero operating-system I/O.

The source parent without S0 was RED on Windows Node22/NTFS and Ubuntu
WSL Node22/ext4. The physical negative test uses a second **same-principal
process** to create and `fsync` a foreign inode at signed-ingress time,
keeps an original file descriptor open, verifies `dev/ino` and original
bytes **through that descriptor**, and intercepts would-be unsafe JS
rename/link. With S0 integrated, the four focused tests passed **4/4 on
Windows 11/NTFS Node22.23.4** and **4/4 on Ubuntu WSL/ext4 Node22.22.1**:
no inbound temp, no target rename/link, no journal admission or snapshot
change, no push/ACK, and no foreign canary mutation; authenticated browse
and legacy non-FOD positive CREATE still work. These are *denial* tests,
not a positive native FOD hydration implementation or Windows 10 CFAPI gate.

```mermaid
flowchart LR
  S[Authenticated inbound envelope] --> Q{Native-required root recovery?}
  Q -- Yes --> D[Fail closed before inbound journal or payload mutation]
  Q -- No --> L[Legacy JS path; NOT independent native custody]
  D --> N[No positive FOD, MERGE or RELEASE GO]
  L --> N
```

The legacy non-FOD `fsp.rename` remains replace-capable under a hostile
same-SID/UID destination race. S0 makes **native-required** ingress inert,
not the entire engine race-free; it does not enroll original-A FileId before
the first native pin, construct a product native publisher, fix PREPARE/COMMIT
or prove physical powercut. This local candidate still requires two
independent SOURCE reviews of the **final composed SHA**, fast-forward
publication and hosted CodeQL/Windows/Ubuntu checks of that published SHA.
The predecessor `23cc31b6` CodeQL succeeded, while its Ubuntu full
validation completed **3,514 PASS / 18 FAIL / 244 SKIP** (positive FOD
gates); Windows jobs were not final at this documentary snapshot. Do not
inherit predecessor results or claim that S0 resolves the 18 functional
failures. **LAB/DENY ONLY; MERGE NO-GO; RELEASE NO-GO.**

## 2026-11-11 — current live integration and release boundary

The last independently verified published PR #300 HEAD before this W26
integration was `057241e030078190147492429782b973746c31d2`; PR #300 was
**OPEN/Draft**, and `Root/main` remained at
`202146bb73ca8577a0a4017c4556cb8b1e9588a6`. Hosted CodeQL on that
**exact published HEAD** was **SUCCESS / zero annotations** (check
`130551922365`, run `43028837873`). The hosted Security Regression
`43028889030` returned **Ubuntu Node 22 FAIL**: 18 failed assertions, all
in the positive `issue-66-device-pin` suite; errors include missing native
`RootSession`, an irreversible FOD required-mode fence, and a post-rename
`fsync` EIO wrapped as an indeterminate snapshot. These cannot be made
green by authorizing legacy fallback, replacing the native session with a
mock, or converting positive product tests into expected denials. Windows
canonical and mandatory release jobs were still running at this snapshot;
their final outcome must be checked against the exact future published SHA.

The W3 retained-live-ancestry/`0700`-to-`0777` physical RED→GREEN fix was
independently SOURCE-approved and published in `b6775945`; the complete
Ubuntu WSL/Node22/ext4 native W3 suite passed **38 / 41**, with three
expected skips and no failures. A separate duplicate W3 worktree was
preserved and **not** integrated. The three suspected legacy journal
hardlink expectations were independently rechecked on `057241e0` and were
already correct (`invalid_sync_journal`); 16/16 relevant WSL tests passed,
so no speculative journal change was made.

The W26 NTFS experiment's four reviewed source commits
`cddceb7e → 5ca10105 → 03fdabaf → cd206fbb` were cherry-picked **without
conflicts** onto `057241e0` in a new isolated integration worktree, producing
local experimental head `e1e8b548fcf6aef9e8d73a68b55d89873d05f3e1`
before this documentation addendum. Two independent source auditors
confirmed identical W26 test/PowerShell blobs to `cd206fbb`, correct
author/committer/trailers and no introduced P1/P2 **inside the bounded
post-first-native-pin lab**. Physical Windows 11/NTFS Node **22.23.4**
W26 suite passed **22/22** on two captured repeat runs; an earlier first
integrated run had **21/22**, but its individual failing assertion was not
retained, so intermittent test instability is **not claimed resolved**.
The WSL/ext4 W3 regression on the integrated tree was **38 PASS /
3 expected SKIP / 0 FAIL**. This is local laboratory evidence, not a
hosted CodeQL/CI result for the future published integration SHA.

The W26 *original-A provenance* gap is unchanged and release-blocking:
PowerShell's `DirectoryInfo` clean-scratch preflight does **not** retain
the original directory HANDLE/FileId across `Add-Type`; an ordinary
same-SID directory **B** installed before the **first native** acquisition
can be self-pinned and accept `NORMAL` writes. Post-pin native handle/
FileId validation, parent-relative `NtCreateFile` for held/signals and
four real A→B attacks (junction/plain × ACK/no ACK) prove only that an
already pinned A is not redirected. They do **not** attest the initial A,
exclude same-SID ABA, establish owner custody on cold restart or authorize
product `RootSession`. The signed owner monotonic floor still needs
independently protected custody and cold replay evidence. Windows 10
**real CFAPI**, physical hardware powercut and native product-level
signed entry/exit operations remain separate unsatisfied gates.
**LAB_ONLY_NO_GO · MERGE NO-GO · RELEASE NO-GO · no production activation**.

### Native pre-first-pin denial rehearsal (local post-`a73b4a3` candidate)

An opt-in, negative-only W26 `PREPIN_COLD_ORIGIN_REQUIRED` scenario now
uses a real same-SID second process to replace the disposable original
scratch A with either a **plain NTFS directory B** or a **junction B**
**before** the first native scratch acquisition. The laboratory refuses
all writes when the independently owner-enrolled original-A FileId and
signed external floor are missing. Original A remains empty, foreign B
retains only its exact physical canary, and production `RootSession` stays
unavailable. This scenario does **not** protect `Run(NORMAL)` from an
early ordinary-B swap and does **not** compare the originally enrolled
native A FileId to B: no such trusted original record has been provisioned.

Independent SOURCE review found P2 in the initial version: its read-only
scratch HANDLE did not request `READ_CONTROL`, so `GetSecurityInfo` could
fail with ACCESS_DENIED and still produce the generic expected denial.
The corrected lab requests `READ_CONTROL` **only** for the scratch owner
read, and a distinct test oracle is emitted only after a successful native
owner-SID query that confirms the scratch is owned by the **same SID**.
The plain B test requires that oracle; junction B is rejected earlier by
native no-reparse opening and must not claim its owner was read. Requiring
the successful SID oracle on the pre-fix source produced physical **RED
0 PASS / 2 FAIL**; the corrected source yielded targeted **2 PASS** and
the complete Windows Node 22.23.4/NTFS opt-in W26 suite **25 PASS /
0 FAIL / 0 SKIP**, log preserved in `.evidence`. These tests measure
**zero foreign mutations**, not zero read-only kernel I/O. This is a
lab-only denial proof, not a release gate promotion; exact-SHA SOURCE
review and hosted CodeQL/CI are still required before publication.

## Current bounded milestones

| Milestone | Evidence and what it means | Remaining gap |
| --- | --- | --- |
| Cooperative Files On-Demand root marker | A held marker descriptor rejects FIFO, symlink, hardlink, invalid bytes, concurrent growth and downgrade in tested clients. `O_NONBLOCK` avoids FIFO blocking. | The same SID can delete/replace/rollback the marker and its ancestors; it is not independently monotonic. |
| Linux staged genesis reader | Root/trash/head descriptors are retained through Linux `/proc/self/fd` traversal, enumeration and bounded head reads; successful real ext4 required-v2 recovery with 16,385 legitimate entries. | Initial root lookup, procfs trust, mount/ancestor attacks, destructive mutations, and independent custody remain open. |
| Native N-API page streaming (lab only) | `openat2` and held `DIR*` support 64-name raw-Buffer pages. Exactly 16,385 seeded entries plus Unicode, alias and invalid UTF-8 names are compared by full bytewise namespace; A→B→A retains the original directory. Native stress writes require explicit extra opt-in. | Parent remains writable by same UID; no owner-authorized production root, cold reacquisition, attested binary, journal or commit. |
| Native fixed-leaf staging and publication (lab only) | New `stageProof`/`publishProof` rehearse exclusive held-dirfd stage, fixed PREPARED journal, file/directory fsync, `renameat2(RENAME_NOREPLACE)` and exclusive COMMITTED marker. A rebinding to B does not redirect a publication on pinned A; a colliding foreign destination stays intact and a separate same-UID writer's pre-commit corruption is rejected. | The canaries/journal are not owner-signed or independent, and a same-UID writer may race between syscalls. No trusted `unlinkat`, production journal, rollback, cold reopen, monotonic floor or power-cut proof. |
| Linux required-v2 ledger read and bounded names | `54067c2d` uses held nofollow root/ledger descriptors, procfd-relative enumeration and bounded 8 KiB record reads. A physical WSL/ext4 test reproduced foreign-ledger enumeration RED before this change and passed after it. `77e1736b` streams ledger names with an explicit 32,769-entry ceiling instead of allocating an unbounded `readdir` array; Windows and WSL focused tests passed. | These are legacy read-hardening gates, **not** independent root trust. Initial acquisition, same-UID A→B→A, Windows journal writes/promotion and POSIX path-based stage/rename/cleanup remain unsafe under the full adversary. No full product native recovery or external monotonic floor. |
| Linux legacy ledger PREPARE/COMMIT and retirement hardening | `0f80974a` pins Linux root/ledger descriptors for record writes, HEAD replacement and fsync. Before the fix, a physical same-UID directory swap wrote PREPARE/COMMIT/HEAD to an attacker directory; after the fix, PREPARE/COMMIT swap cases passed. `5e927dc5` anchors archive retirement to the original read inode and unlinks through its held dirfd; a physical pre-fix test intercepted an attempted foreign unlink through a substituted archive symlink. The initial archive test had a P2 false-green in its interceptor; `c5d56592` now resolves physical parents for both procfd and pathname unlinks and requires exact invalid-snapshot denial. Both focused malicious and legitimate cases passed on WSL/ext4; the exact test child received bounded independent SOURCE GO. | This is **only legacy Linux path containment**, not trusted native recovery. Same-UID A→B→A, leaf substitutions between identity check and unlink, protected parent custody, independent rollback floor, stage/genesis promotion, Windows native handles, powercut/durability and hosted CodeQL are unresolved. |
| Linux legacy genesis creation/publication and archive cold-fence | `cc7daca6` pins nofollow root/trash/ledger FDs for staged genesis creation, enforces exclusive hard-link publication (no overwrite of foreign `head.json`), verifies inode/content identity and flushes both directories; physical WSL adversarial and legitimate recovery tests passed. `b3b5e591` prevents a cold open from ignoring orphan archives after a full checkpoint; original parent was **RED** (accepted orphan) and child **GREEN**. `d5805da8` adds a real hard-exit + new-process denial test; `7ff6dade` tightens that test to compare the exact archived PREPARE and all record names/bytes, not merely nonempty directory contents. | These are **bounded cooperative Linux recovery fences**, not independent custody. The exclusive link creates a two-name crash window that intentionally fails closed rather than automatically resolving. Same-UID A→B→A, protected parent and owner-signed floor, native remove/stage/publish in Windows, independent rollback witness, powercut and formal CodeQL final-SHA evidence remain open. |
| Windows legacy archive cold-open and genesis non-overwrite | `e2297926`: Windows archive cold-open RED (accepted orphan), then 3 PASS Windows + 2 PASS WSL and one genuine subprocess-exit/new-process PASS per platform. `1b4fc52f`: Windows genesis rename RED overwrote a competing head; exclusive NTFS hard-link publication then 3 PASS Windows, 1 PASS Windows after-link process exit, 2 PASS WSL regression. | These are cooperative pathname compatibility fences only. Hostile same-SID root/ancestor/leaf rebinding, independent ACL custody, native NTFS/CFAPI handles, monotonic rollback floor, directory powercut and Windows 10 release gate remain unproven. |
| Windows bounded held genesis source | `88a88b68`: replaces the residual pathname `readFile` of the staged genesis with a retained file handle, size-limited 8193-byte read, pre/post fstat and pathname checks, retained FD through exclusive link; Windows positive staged read, genuine 8193-byte growth at the held-open boundary, competing head and hard-exit tests passed. | The initial path still lacks protected same-SID custody; held source bytes and same-inode checks do not supply owner-signed root authority, cold NTFS durability, CFAPI or powercut proof. |
| Windows legacy archive-retirement identity | `76a838de`: retains the Windows ledger's dev+ino across read, validates that the directory being renamed and the archive before each unlink match that inode. A real NTFS substitution at rename caused the old code to **attempt** a foreign unlink (intercepted before destruction); the corrected code passed two adversarial swaps, including one after rename just before cleanup, plus legitimate checkpoint/crash recovery and a real two-process hard-exit. | Protection applies to observed swap windows **only**: Windows Node path-based unlink can still race against a hostile same-SID A→B→A after the last check. Independent NTFS RootDirectory/ACL custody, atomic identity-bound removal, powercut durability, rollback floor and native CFAPI remain NO-GO. |
| Windows and Linux held-ledger record-leaf identity | `c2e8e9b4` binds each Windows PREPARE/COMMIT/HEAD record's original validated BigIntStats to the later archive cleanup, rejecting a changed inode/version before unlink. `61669b06` does the same for Linux using bytes and BigIntStats from the exact held record FD, checking the original directory-relative leaf before `unlink`. On both OSes, the old code physically attempted a foreign COMMIT unlink (intercepted without destruction), while each child passed real adversarial COMMIT/PREPARE/HEAD substitution and legitimate recovery checks. Both exact code SHAs received bounded SOURCE GO and were fast-forwarded locally. | **Neither filesystem provides an atomic unlink of the verified inode using these Node pathname APIs.** Hostile same-SID/UID A→B→A or replacement immediately after the final leaf check remains unsafe without independent root/parent custody or verified native deletion. No production authorization, rollback witness or powercut proof. |
| Genesis exclusive *stage* and post-publication stage-leaf retirement (Windows+Linux legacy) | `afa4cb5e` replaces destructive temporary→reserved-genesis `rename` with no-replace `link` and fail-closed two-name crash semantics; parent `c9be3dc7` physically attempted a foreign-stage overwrite on both platforms (**RED**, intercepted). Initial `afa4` SOURCE NO-GO found a stale crash hook and unsafe failed-temp cleanup; `022e5c46` fixes both, leaves error-path .tmp evidence inert and received narrow SOURCE GO. `a18d2cce` is the clean rebased follow-up: it rechecks the original linked stage leaf just before final unlink on NTFS and the held-trash dirfd on Linux. Parent physical RED on both OSes caught would-be foreign stage unlinks; exact composed Windows+WSL five focused tests each passed. Both reviewed code deltas are integrated locally, not remotely. | Successful temporary/stage unlink remains **name-based and non-atomic** under same-UID/SID writable ancestors. There is no trusted native RootSession, independently owned parent, stable cold-restart custody, owner-signed antirollback floor, CFAPI release guarantee or powercut proof. SOURCE GO is strictly for cooperative legacy fences, not production/adversarial-root recovery. |
| Root-owned ext4 read-only fixture | Ordinary UID writers cannot mutate the existing root-owned marker/leaf; retained descriptor and fresh-process reads were tested. | Cannot authorize writable recovery; root provisioning, device/issuer trust and monotonic floor are not established. |
| Windows / NTFS / CFAPI (Win11 exercised; Windows 10 unproven) | Windows Node22 CFAPI and recovery compatibility tests are available; the Windows read-handle laboratory proves narrow original-byte continuity. Prior physical host evidence includes Windows 11 Pro build 26300, **not** a verified Windows 10 CFAPI release gate. | Windows 10 end-to-end physical validation, same-SID native NTFS handle-bound acquisition, writes, rename, unlink, directory durability, CFAPI image/DLL custody and powercut proof are absent. |
| Windows exact opened-inode removal after hostile leaf replacement (lab only) | `9302e3da` extends the opt-in NTFS `NtCreateFile(RootDirectory)` proof: after opening a fixed leaf HANDLE, the lab physically moves the original inode and creates different same-name files inside the held A and the pathname-replacement B. `SetFileInformationByHandle(FileDispositionInfo)` removes **only the original opened inode**, keeping both foreign files intact. Windows Node22 NTFS 2 PASS, WSL 2 expected SKIP. | Adversarial order is deterministic within one same-SID process, not a concurrent external writer. Initial root acquisition and test fixture pathname setup remain untrusted. No independently protected ancestor, production Windows RootSession removeEntry, Windows 10/CFAPI, monotonic rollback or powercut proof. Linux `unlinkat` by name remains non-atomic against writable same-UID parent. |
| Native deletion admission contract (still fail-closed) | `74ff83b4` requires Windows `SetFileInformationByHandle` on the originally opened file HANDLE and independently trusted ancestry. POSIX `unlinkat` now explicitly requires independent same-UID writer exclusion on the parent and ancestors. Frozen guards reject `stat→unlink` as identity authority. Contract RED before guards, then Windows Node22 **8 PASS** and WSL Node22 **8 PASS**, with bounded independent SOURCE GO. | This is a declarative native API requirement, **not** a loaded production implementation. No external root custodian, antirollback floor, powercut validation or Windows 10/CFAPI release authority exists. `RootSession` remains unconditionally unavailable. |
| Failed metadata publication and legacy-name compatibility fences | `a36e4ec1` removes unsafe failure-path `rm(temp)`/`unlink(temp)` in operational snapshot/HEAD and journal writes: physical Windows NTFS and WSL/ext4 RED proved would-be foreign-temp deletion (intercepted before destruction), then focused GREEN. Initial SOURCE NO-GO: broad new temp prefix exclusion could hide a previously tracked user filename and create false missing-file reconciliation. `ff41222e` protects historical root names before signed operations and supports root-local custom metadata paths; `ddc8484f` extends the historical fence to **nested** names that the portable validator newly reserves; `bcc47828` adds a direct already-open `_reconcileLocal` regression. Both scanners exclude inert orphan state files, and tests confirm legitimate cold recovery with debris. | Names formerly legal in historical snapshots now require an explicit **fail-closed migration**; they are not silently deleted. Failed temp files intentionally remain as untrusted evidence, with no unverified cleanup/GC, and can exhaust space over time. Successful journal/snapshot rename and other mutable-name cleanup remain unsafe under hostile same UID/SID without protected ancestor custody. No production root session, powercut, CFAPI or rollback authorization. |
| Linux post-rename metadata durability and cold replay | `d1a3e47f` proves (in injected post-successful-rename parent directory `FileHandle.sync` EIO schedules) the snapshot v2, PREPARE HEAD and journal replay paths; `0d969b4b` adds physical completed-v2 checkpoint plus **a separate Node22 cold process**; `02600fbe` closes peer-found false-green (only one directory CREATE allowed) and false-red (await subprocess `close`). `3458a440` fixes a new **RED**: after an actual v2 snapshot rename and injected fsync EIO, legacy code resumed `_reconcileLocal`; now `invalid_snapshot` aborts the entire pass before signed reconciliation and retains original EIO cause. Composed Node22 WSL ext4 **6 PASS** and Windows NTFS focused nonregression **5 PASS**. | EIO is injected into a real opened directory handle's `sync` method, **not** an actual kernel fsync/hardware power failure. Earlier reopen checks were separate objects; only the final checkpoint test used a truly separate OS process. This is legacy cooperation, not same-UID/SID identity-bound remove, independent custody, signed rollback witness or a release GO. |
| Four formal CodeQL filesystem-race root causes and physical marker rebound | On old remote `d3a91c92`: marker `lstat`→pathname `readFile`, held trash then pathname `opendir`, test fixture `stat`→pathname `readFile`, and privileged owner test `lstat`→pathname marker `readFile`. Local held-FD marker/genesis and test-file handles address these specific reopen races without suppression. Child `9fe36d47` physically swapped equal-byte marker inodes and failed old remote Windows+WSL RED, while held-FD local passed; independent SOURCE GO. Child `23a0746e` removes an analogous stat/read-by-name from the proof itself, Windows+WSL focused 3 PASS each; SOURCE GO. | These are bounded local source fixes, not a hosted CodeQL PASS for the unpublished SHA; protected parent acquisition, same-SID/UID ABA, owner-signed rollback floor and native root authority remain absent. |
| Inbound authenticated payload publication failure | Parent `9fe36d47` attempted to delete a physically substituted foreign temporary after injected rename EIO (Windows/WSL RED, interceptor saved bytes). `a5cab02a` removes both unsafe inbound/MOVE `rm(temp)` sites and uses exclusive inert reserved names. Its first peer review found P2 `EXDEV` on nested mount targets; `da06918a` stages in the target directory, preserves normal/move recovery and handles nested regular-file orphans in required-v2 cold scan. Second peer review returned narrow cumulative GO. Previous full FOD suite: Windows Node22 39 PASS/1 SKIP, WSL Node22 40 PASS; follow-up nested required-v2 1 PASS each platform and focused FOD 3 PASS each. | No physical nested bind-mount cross-device test and no crash injected during inbound write; `rename` remains name-based under hostile same UID/SID. Orphan accumulation requires separately authorized custody-safe cleanup; source tests, synthetic errors and cold hard-exit are not powercut evidence. |
| W3 opened-inode native publication (Linux lab, NOT RootSession) | Child `29ccf0da` retains the exact exclusive stage FD through publication. An unprivileged `linkat` from kernel procfd into the pinned held directory creates the destination with atomic no-replace semantics; foreign same-byte source substitution and EEXIST retry were both physical RED on the parent, GREEN in the child. A native-internal late stage-name replacement after the preflight also proved that the published destination remained the ORIGINAL opened inode. WSL Node22/ext4 W3+contract 23 PASS/3 SKIP; Windows Node22 RootSession contract 8 PASS; SOURCE GO. Later local laboratory child `03b65966` adds a separate **opt-in** O_TMPFILE stage (without O_EXCL), retained FD and no-replace linkat, producing a final `nlink=1` inode with **no stage pathname to retire**. Real WSL Node22/ext4 RED before anonymous staging, then **27 PASS/3 SKIP** W3+contract, including foreign destination collision, a separate Node process.exit(74) before link and native _exit(73) after directory fsync but before COMMIT. Windows RootSession contract 8 PASS. | The older visible-stage mode deliberately leaves two names with nlink=2 (generic read denies it), while the anonymous mode has nlink1 and is readable in the LAB; neither is product-root custody. Before link, an orderly child-process exit leaves PREPARED with no recoverable unnamed payload; after link/before COMMIT it leaves published bytes plus PREPARED but no COMMIT, which must not authorize replay. No independent same-UID/SID writer isolation, trusted cold reacquisition, signed monotonic checkpoint, production NTFS equivalent, CFAPI or powercut proof. The newer candidate needs exact independent SOURCE approval before FF/push. |
| FOD absent-destination publish race — unresolved P2 | On published `ca1d24e0`, `publishInboundPayload` (engine ~758-770) calls replace-capable `rename(temp,target)` after a separate target preflight (`_apply` ~3792 and ~3828). An isolated RED test physically plants a distinct foreign destination inode with `wx` at the real publish boundary; both Windows Node22/NTFS and WSL Node22/ext4 observed the unsafe rename attempt. Destruction was intercepted; foreign bytes remained intact. | Not fixed by the published temp-cleanup/EXDEV patches. Atomic no-replace target publication must be joined to held-inode stage identity and custody-safe retirement without leaking aliases. JS `exists`/`lstat` checks alone remain TOCTOU, while `link`+unsafe unlink would merely move the destructive race; leave production authorization fail-closed until a proven native custodian exists. RED is isolated and not an integrated passing test. |
| Hosted CI and CodeQL: current stacked-base mismatch | The reviewed chain was published once by normal fast-forward from `d3a91c92` to `ca1d24e0`; PR #300 is still OPEN/Draft and `Root/main` was not changed. GitHub shows zero Actions runs and zero check-runs on `ca1d24e0` at this checkpoint. The **current PR base** is `cdx/issue66-picker-pin-integration-prime-20261107` (`5bac9e8e`); its `.github/workflows/codeql.yml` and `security-regression.yml` allow `Root/main` or `cdx/zk65-split-pr*` but not the current base, so the previous hosted CodeQL failure on `d3a91c92` does not establish the new SHA's result. | Getting a fresh hosted CodeQL check requires an explicitly authorized change to the stack-base workflow trigger or PR-base routing, not a redundant push of identical HEAD or a head-only workflow edit. Do not mark CodeQL formally cleared. Retargeting/altering upstream without approval would change the stack scope. |

The four remote CodeQL HIGH annotations were recorded at `rootark-sync-engine.js`
old lines 77 and 706–707, and two issue-66 tests. Local held-marker,
held-genesis, held-ledger and test-handle changes address narrower code paths,
but **formal CodeQL still reads FAILURE** on `d3a91c92`; none of the local
SHAs received a new hosted evaluation. A read-only independent review also
confirmed that adding `unlinkat(dirfd, leaf)` to a same-UID-writable laboratory
root would remain unsafe: a hostile process can replace `leaf` after an
inode/content check and before name-based unlink. No such destructive
implementation was integrated.

## Next implementation milestones (ordered; not yet authorized for production)

1. **Independent parent and root authority.** Establish a protected owner
   service or OS custodian whose writable namespace and rollback witness
   cannot be mutated by the untrusted sync principal. Bind a signed owner
   scope/digest to a protected root identity. Prove cold reacquisition and
   concurrent-writer exclusion. A `0700` same-UID directory, a random token,
   a JS lock, and a pre-open pathname hash are insufficient.
2. **Complete native transaction API.** Implement and review the contract's
   `openRootFromTrustedParent`, `openChildDirectory`, `enumerateDirectory`,
   `openContainedFile`, `readOpenedFile`, `createExclusiveFile`,
   `renameNoReplace`, `removeEntry`, `syncOpenedFile`, `syncDirectory`,
   `reacquireRoot`, `commitDurableRecovery` and `close` under the same pinned
   root. On Linux use native `openat2` with `RESOLVE_BENEATH`,
   `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_XDEV`, `renameat2(RENAME_NOREPLACE)`,
   `unlinkat` and directory/file `fsync`. On Windows use independently
   protected NTFS ancestors, `NtCreateFile` relative to `RootDirectory`,
   held HANDLE enumeration, stable file/volume IDs and proven flush ordering.
3. **Durable recovery protocol.** Stage and journal on trusted descriptors,
   verify signed owner policy, commit only after ordered durable markers and
   independent monotonic floor promotion; fail closed on indeterminate
   commit/replay. Cover per-phase crash, process restart and real powercut.
4. **Physical adversarial matrix.** Run competing processes with the **same**
   UID/SID, real A→B→A during every operation, symlink/reparse, mount/bind,
   hardlink/Unicode/raw POSIX naming, 16,385+ legitimate records,
   forbidden collisions and under-load cold reopen; prove there is no
   foreign-file deletion, cross-root replay or false-green cleanup.
5. **Supply-chain, independent review and release.** Attest exact native
   binaries, loaded DLLs, compiler and image provenance. Obtain independent
   SOURCE GO for the exact integrated SHA and formal hosted CodeQL/mandatory
   CI success. Separately request the PR's merge/deploy/cutover policy.

## Operational guardrails

All work for this checkpoint is in isolated worktrees and may be
fast-forwarded **locally** only after an independent SOURCE GO. No push,
remote merge, deploy, cutover, force-push, `Root/main` mutation, root-owned
fixture cleanup, or privileged reprovisioning was authorized in this round.
Use local Windows Node22/NTFS and Ubuntu WSL Node22/ext4 tests before a
future authorized GitHub Actions run to conserve metered Actions minutes.

## 2026-11-10 W26 — Windows NTFS source-HANDLE no-replace publication (laboratory only)

The Linux W3 `O_TMPFILE`/held-FD lab is **not** a Windows backend. The new
Windows W26 opt-in laboratory candidate (`0cc48337` + `d221765d`) instead
uses `NtCreateFile` with `RootDirectory` and `FILE_CREATE` to hold the
original staged file HANDLE, writes and calls `FlushFileBuffers`, then uses
`NtSetInformationFile(FileRenameInformation, ReplaceIfExists=FALSE)` relative
to the same held directory HANDLE. No `stat→rename` admission or source
pathname unlink is treated as atomic authority. Unlike Linux's original
two-hardlink lab, successful native rename retires the source name without
creating another hardlink alias. This is still only a fixed-leaf disposable
fixture in LocalAppData, not a Windows production RootSession.

Physical Windows Node22/NTFS: **5 PASS** for normal original-inode publish,
exact `STATUS_OBJECT_NAME_COLLISION (0xC0000035)` with foreign destination
intact, late equal-byte foreign stage substitution leaving the original
opened HANDLE as the published inode, and replacement of the original root
path **before** opening the staged child (retained root A receives the
publication while replacement B remains intact). Disabled and populated
scratch cases reject without mutation. Combined Windows RootSession
contract: **8 PASS**. WSL Node22: **5 expected SKIP** for Windows-only lab.
No 16,385-record stress was repeated. These experiments were sequential
physical substitutions in user-owned scratch, not simultaneous hostile
processes, and `ROOT_SWAP` does not prove renaming a directory while its
child HANDLE is open. The collision code, original `FileIdInfo` and foreign
bytes were checked, not merely a generic nonzero native error.

**Outstanding gates:** the normal operational SyncEngine FOD path still
uses replace-capable pathname rename and has an isolated Windows/WSL RED;
W26 cannot be connected without independently trusted root/ancestor
custody, same-SID writer exclusion, safe PREPARE/COMMIT and cold replay,
antirollback witness, Windows 10/CFAPI validation and real powercut.
Formal CodeQL on the current stacked PR head still lacks a triggering
base-workflow run. The new W26 candidate requires SOURCE GO of the exact
SHA before integration or publication. **Merge NO-GO; release NO-GO.**

### W26 follow-up — explicit PREPARE → native rename → COMMIT interruption windows

Local child `caa6eb52` (parent docs `827ba856`) extends the same disposable
NTFS HANDLE-only lab with a separate opt-in hard-stop flag. The positive
`TXN_COMPLETE` sequence exclusively writes/flushed `prepared.bin`, publishes
the original opened stage HANDLE without replacing the target, then
exclusively writes/flushed `commit.bin`. A PowerShell child process is killed
with native `TerminateProcess(exit=74)` **before** the rename: staged bytes
and PREPARED survive, with no published target or COMMIT. Another isolated
child is killed with `TerminateProcess(exit=73)` **after** native rename,
but before COMMIT: the original staged name is gone, published bytes and
PREPARED survive, and COMMIT is absent. The native process exit is not a
powercut; Windows NTFS directory metadata durability and cold replay remain
unproved. Physical Windows Node22 W26 **9 PASS**, with **8 PASS** for the
separate RootSession contract in the preceding regression cycle; no 16,385
seeding. Windows-only W26 tests skip on WSL. Neither the PREPARED nor the
COMMIT marker is a trusted owner-signed recovery authority; this lab has
**no recovery engine**. Exact `caa6eb52` SOURCE approval remains mandatory
before FF/push. Product FOD late-destination overwrite, external root
custody, antirollback, hosted CodeQL and Windows 10 CFAPI remain **NO-GO**.

### W26 follow-up — independent-process read-only cold phase inspection (LAB only)

An opt-in `COLD_INSPECT` process now reopens a pre-existing disposable W26
scratch under LocalAppData without staging, renaming, deleting or granting
recovery rights. Native `NtCreateFile(RootDirectory)` opens only fixed leaves
from a newly held NTFS directory HANDLE; reads are bounded to 129 bytes and
bound to the same opened file identity. `FileIdInfo`, `FileStandardInfo`
(regular file, nlink=1, size) and `FileBasicInfo` (version) are compared
before/after each read. It distinguishes PREPARED-only, published-but-NOT-
committed and COMMIT-observed phases after real child process termination,
and denies corrupt markers and a foreign hardlink. A separate
`ROOTARK_ISSUE66_W26_COLD_INSPECT_LAB=1` opt-in is mandatory.

Physical Windows Node22/NTFS: targeted cold cases **3 PASS / 0 FAIL**,
including same-SID marker corruption and an additional hardlink; the W26
suite was **12 PASS / 0 FAIL** before the final read-version comparison,
with all three new cold cases revalidated afterward. RootSession contract
Windows Node22 **8 PASS**, WSL Node22 **8 PASS**. Earlier November 9 physical
evidence and 16,385-name stress were reused, not repeated. No cold
classification authenticates the root: a same-SID writer can replace an
unsigned, byte-identical fixture; no protected root/ancestors, independent
floor, binary attestation, Windows 10 or powercut durability is proven.
**MERGE/RELEASE NO-GO** still applies independently of these results.

### 2026-11-11 — private-lock, journal and signed retry safety chain published

The PR #300 head advanced by **one normal fast-forward push** from
`e82d88606002f0da943f1fda57a604b203e9c539` to
`4d9b19bff36a2ab2e19814c6c7b8734da8e58d38` (17 linear commits).
`Root/main` remains unmodified; PR #300 remains OPEN/Draft. All new commits
have the required bielxdh3 author/committer and one Codex co-author trailer.
Two independent SOURCE reviewers found no remaining P1/P2 **within the
reviewed 17-commit scope**; that is not a production or hosted-CI approval.

The chain tightens the required-v2 private root mutation lock: every private
mutation path must hold a live physical root lock, stale AsyncLocalStorage
leases cannot outlive it, and started/unawaited or already-settled failures
cannot silently release it. Separate explicit write-hazard marks quarantine
the lock after possible `mkdir`, rename, snapshot or journal side effects,
including failures reported after a completed syscall. Cold WebDAV
translation, historical signed atomic-batch journal acknowledgements and
native-required DELETE retries now obey these negative fences. W26 adds a
**read-only, native HANDLE-relative cold-phase inspector** for lab-created
PREPARE, PUBLISHED-without-COMMIT and COMMIT states; no recovery authority is
granted by the inspector.

The final signed-outbound regression intentionally uses two **genuine Ed25519
signed** operations. A replaceable `adapter.push` getter used to mutate the
caller-owned CREATE into a valid DELETE **after** the last envelope check:
the old `8a3c44f1` failed physically on Windows Node22/NTFS and Ubuntu WSL
Node22/ext4 (the DELETE reached the disposable adapter). The new
`4d9b19bf` resolves any getter **before** its final check, validates and
detaches the exact signed operation, compares its digest to the pre-await
original, denies DELETE on that same detached object and dispatches only the
detached copy. A signed legitimate CREATE still writes a disposable fsynced
record and retains its verified authorization bytes. Physical tests of the
final code: full FOD **Windows 72 PASS, 1 POSIX-only FIFO SKIP** and **WSL
73 PASS**; targeted atomic signed batch **4 PASS** on each platform; the
new attacker/control test **1 PASS** each. W26 cold lab tests **3 PASS**
after its ABI fix, and the final published W26 implementation was also
revalidated in its complete Windows Node22/NTFS suite: **12 PASS / 0 FAIL**.
The November 9 stress proof of 16,385 entries was not rerun: these changes
did not alter that physical enumeration contract.

Hosted CodeQL on the published **code SHA** `4d9b19bf` completed SUCCESS:
run `42950460806`, `Analyze JavaScript / TypeScript` check `130293268788`
SUCCESS and separate formal `CodeQL` check `130294051622` SUCCESS. This is
exact-head code evidence, not automatically inherited by a subsequent docs
or code commit. Only these triggered checks were verified; other required
platform/release gates must be evaluated separately at their exact SHAs.

**Unclosed gates:** the operational inbound publisher still uses a
replace-capable JavaScript pathname `rename` and has an isolated adversarial
foreign-destination overwrite RED. W3/ext4 and W26/NTFS remain disposable
laboratories, not signed or independently acquired RootSession custodians.
There is no trusted protected root and entire ancestry, no independently
excluded same-UID/SID hostile writer, no owner-signed monotonic recovery
floor, no attested native product service with durable PREPARE/COMMIT and
cold-reopen authority, no real hardware power-cut proof, and no Windows 10
CFAPI release evidence (the exercised workstation was Windows 11 build
26300). Native no-replace and identity-bound deletion must never be
approximated with stat/exists→pathname rename/unlink. `RootSession` stays
unconditionally OFF. **MERGE NO-GO and RELEASE NO-GO.**

### 2026-11-11 — cold snapshot/journal inode continuity and signed directory negative gate

The next implementable follow-up hardens **cooperative cold admission** and
rejects another path-based mutation that bypassed `RootSession` denial. It
does **not** promote any JavaScript FileHandle into a native custodian.

1. **Snapshot cold read:** `SyncEngine._open()` no longer does
   `lstat(snapshot)` followed by `readFile(snapshot pathname)`. It opens the
   index with nofollow/nonblocking flags where supported, keeps the original
   file handle for its entire read, checks a regular single-link inode with
   a nonzero file ID, and compares dev/ino/size/mtime/ctime against both the
   visible name and retained file handle before/after the byte read. An
   attacker physically swapping the index to a different valid JSON file
   after the original stat was **RED on Windows Node22/NTFS and WSL
   Node22/ext4** before the change, then **GREEN** with `invalid_snapshot`.
   The original and foreign files remained physically distinguishable.
2. **Signed journal cold read:** `SyncJournal.open()` opens the journal once
   and reads from the original held handle with analogous version/identity
   comparisons. An ENOENT **after** opening is invalid rather than consent
   to create an empty journal. A failed open restores the previous in-memory
   state. Physical same-name substitution to a different valid JSON journal
   containing a forged `seen` receipt was **RED on both systems** before
   the change and **GREEN** afterward with `invalid_sync_journal`, retained
   root lock and no remote write. This protects a check/read window but
   cannot authenticate an already-foreign inode at first open or prevent
   same-UID/SID A→B→A without a protected parent and signed recovery floor.
3. **Signed directory UPDATE:** required-v2 had denied physically cached
   signed `MOVE` and `DELETE` but accepted Ed25519-authenticated directory
   `UPDATE` with a different path. That route renamed an entire cached
   subtree using legacy `fsp.rename`, despite native custody being OFF.
   A real directory with an independently fsynced child sentinel was
   accepted by the vulnerable legacy UPDATE path in RED Windows/WSL runs;
   that path calls the kernel rename. The new module-owned
   negative gate rejects **every** native-required directory UPDATE before
   journal admission, rather than testing source absence and introducing a
   second `exists → rename` TOCTOU. Both platforms now reject it with
   `root_session_native_unavailable`, leaving the original subtree, durable
   journal/snapshot bytes and remote store intact. A normal directory CREATE and
   standalone signed CREATE continue through their existing bounded paths;
   non-native legacy operation semantics were not intentionally changed.

Final material regression evidence for the above source changes:
**FOD Windows Node22/NTFS 75 PASS / 1 FIFO SKIP; WSL Node22/ext4 76 PASS**;
targeted signed atomic batch **4 PASS** on each; additional cold-journal
open/receipt/atomic-update regression groups passed together with FOD
(Windows **99 PASS / 1 SKIP**, WSL **100 PASS** before the separate directory
UPDATE denial, which does not change journal parsing). Syntax and diff
whitespace checks passed. These are real filesystem tests with controlled
same-principal substitutions and verified disk bytes, **not** verified
independent concurrent-writer exclusion or physical power interruption.

The previous exact published head was `f0d573637952b642c4c34c2f30bb5c27f2ffe6e7`
with hosted CodeQL SUCCESS. **Never transfer that verdict to this new
source commit:** independent SOURCE/evidence review and hosted CodeQL must
both be verified on the exact new published SHA before calling its code
gate green. All remaining W3/W26 product-integration, native no-replace,
same-SID/UID writer exclusion, protected ancestors, owner-signed monotonic
floor, Windows 10 CFAPI, power-cut and mandatory release checks remain
independent **NO-GO** gates. No release or merge authorization follows.

### 2026-11-11 — bounded cold metadata reads and directory UPDATE proof

The subsequently published `271a7727` (direct child of `79a0da11`) fixed a
test-only held-inode canary, but GitHub's **formal** CodeQL check
`130311529941` on run `42955874978` was **FAILURE** even though the
`Analyze JavaScript / TypeScript` job `130310716545` completed SUCCESS.
The branch alert was **#515, `js/file-system-race`** at the physical signed
directory UPDATE test's later `open(sentinel)`; its original creation had
already recorded `fstat` of the same path. Do not call this SHA CodeQL-green.

The next isolated code candidate `17eebd8232621644d91bce6be85bbc79b2667af1`
retains the original exclusive `wx+` sentinel FileHandle across the signed
negative UPDATE. It reads at an explicit offset on that **same** handle and
rechecks its original dev/ino/size, plus the name's currently visible inode.
It also counts attempted directory renames **before the syscall**: a Windows
sharing or EBUSY failure cannot supply an accidental false-green denial.
The old post-validation reopen is gone without CodeQL suppression.

The same candidate removes two unlimited `FileHandle.readFile()` calls from
cold required-v2 snapshot and signed journal admission. The reader now uses
bounded positional reads from the originally opened inode, with a maximum of
the `fstat` size plus one extra byte to detect post-check growth and a
separate **256 MiB per-control-file resource ceiling**. Changed size,
version, inode or excessive input fails closed; it does not manufacture
recovery authority. Actual same-inode sparse expansion after the initial
inspection was **RED on the preceding source** (two tests per platform,
unbounded method observed) and **GREEN** on the candidate with no unbounded
read. That ceiling is a deliberate availability boundary: larger historical
metadata files require a separately reviewed migration/read policy rather
than bypassing the safety limit.

Physical candidate evidence: Windows Node22/NTFS FOD **77 PASS, 1 FIFO SKIP**;
Ubuntu WSL Node22/ext4 FOD **78 PASS**; cold growth/negative UPDATE targeted
**3 PASS each**; Phase16 cold restart/eviction targeted **4 PASS each**.
No 16,385-record enumeration stress was repeated because the mutation
concerns control-file consumption, not namespace enumeration or native
publisher behavior. The candidate requires exact-SHA independent SOURCE
review before integration and fast-forward, and **formal hosted CodeQL must
be reevaluated on the subsequently published exact final HEAD**, not borrowed
from its parent. These changes cannot remove the known replace-capable
inbound pathname rename, grant independent root/ancestor custody, prove
same-UID/SID writer isolation, monotonic signed rollback protection,
Windows 10 CFAPI, hardware power-cut durability, or native product
PREPARE/COMMIT recovery. **MERGE NO-GO; RELEASE NO-GO; RootSession OFF.**

### 2026-11-11 — external-process no-replace collision probes (W26/NTFS and W3/ext4)

The published baseline `63dec688a6218e6b60a19b8b7fe3063d00977fa0`
passed formal CodeQL (`42958828896`, separate `CodeQL` check
`130321352433` SUCCESS and Analyze `130320252919` SUCCESS). The additional
external-writer tests below are a **new unpublished candidate** and must
receive their own exact-SHA SOURCE review and hosted CodeQL after publication.

The Windows W26 opt-in HANDLE lab now has a strictly separate
`ROOTARK_ISSUE66_W26_EXTERNAL_WRITER_LAB=1` switch for `EXTERNAL_COLLISION`.
An actual second Node process, inheriting the same Windows SID, waits until
the PowerShell/C# native publisher has acquired its directory and original
stage HANDLEs. The child then **exclusively creates, writes, fsyncs and
closes** a foreign `published.bin`, and acknowledges the completed physical
write before the publisher calls native `NtSetInformationFile` with
`ReplaceIfExists=FALSE`. The syscall returns exact NTFS
`STATUS_OBJECT_NAME_COLLISION (0xC0000035)`; the retained original stage and
distinct foreign destination inodes and bytes remain unchanged. The test
checks both inodes through their own opened file descriptors, and the opt-in
denial test confirms no held directory is created with the switch off.
**Windows 11/Node22/NTFS full W26 suite: 14 PASS / 0 FAIL.**

On Ubuntu WSL Node22/ext4, an actual separate **same-UID** Node child creates
and fsyncs the destination after W3 has staged its original retained inode.
The native `linkat` from the original opened stage FD returns the expected
`NATIVE_TXN_NO_REPLACE_CONFLICT`; retained stage and foreign FDs retain
distinct inode identities, bytes and version after the attempt. This is a
deterministic separate-process adversarial interleaving: the child finishes
writing before the native link. **W3 full non-stress suite: 20 PASS / 0 FAIL,
3 expected SKIP.** The 16,385-record stress and privileged bind-mount
fixture were not rerun, since neither native primitive was changed.

These are **laboratory no-overwrite proofs, not same-SID/UID exclusion**.
Each process still shares a writable test principal and the initial ancestor
lookup is not independently authenticated; the probes neither prove
unbounded live contention/A→B→A under every syscall nor supply a trusted
publisher, permanent signed PREPARE/COMMIT, monotonic recovery witness,
Windows 10 CFAPI, power-cut durability or cold independent root reacquisition.
The actual SyncEngine inbound path still has replace-capable pathname rename.
The native experiments remain **LAB_ONLY_NO_GO**, RootSession stays OFF,
and **MERGE/RELEASE remain NO-GO**.

### 2026-11-11 — cold journal bootstrap: no replace-capable publication

A new local required-v2 regression found a separate **first-open journal
bootstrap** race. The old `readHeldJournal()` correctly rejected a previously
rebound journal inode, but its `ENOENT` branch called `durableWrite()`: the
ordinary temp-to-final `rename()` can overwrite a foreign journal created by
a same-principal writer **after the missing-file observation**. A physical
fixture created and fsynced a foreign journal inode at that exact point and
intercepted the would-be replace-capable rename *before destruction*. The
previous source was **RED on Windows/NTFS and Ubuntu WSL/ext4**.

The replacement cold-only initializer now creates the final journal leaf
with `O_CREAT | O_EXCL | O_NOFOLLOW`, writes and fsyncs the originally opened
inode, checks its `fstat` identity/version against the current name, and
syncs the directory where supported. An occupied name fails
`invalid_sync_journal` rather than replacing its owner; the root lock remains
quarantined. If initialization is interrupted, incomplete control-file bytes
must reject cold reopen rather than invent signed receipt authority. Normal
subsequent journal updates still use their existing fsynced atomic-update
path. **GREEN**: focused regression **1 PASS** each on Windows Node22/NTFS
and WSL Node22/ext4; combined FOD + journal open/temp/update suites
**Windows 100 PASS / 2 SKIP**, **WSL 102 PASS / 0 SKIP**.

This is a negative single-leaf collision fence, **not** independent custody
of the root and ancestors, hostile same-SID/UID isolation, antirollback,
power-cut recovery, a general no-replace implementation or an authorization
to activate `RootSession`. The precise new SHA requires independent SOURCE
review and hosted CodeQL after safe publication. **MERGE/RELEASE NO-GO.**

### 2026-11-11 — original PREPARE and COMMIT custody rehearsals, bounded signed floor

This work combines three **non-production** source paths. None connects to
`SyncEngine` as a trusted `RootSession`; its native recovery activation point
continues to reject unconditionally. The public branch previously stood at
`81fe58c2bcaf46856f1e03c6eb2636a67f1a8511`. All new results below
must be reviewed again at the **exact integrated SHA** and subjected to its
own hosted CodeQL/mandatory CI, not inherited from baseline `81fe58c2`.

**W3/Linux Node22/ext4:** source commits `a457dd3361038981a163ea07c521c10af53cdae3`
and `d6594fdf16e4be55aa0c6e4934c77a68291bbab7` retain both the original
staged inode FD and the exclusive, fsynced PREPARE journal FD. The native
publisher now checks original-vs-current journal `dev/ino`, regular-file
type, link count, exact PREPARE bytes and a version pinned **after initial
fsync** (`mtime/ctime`, including nanoseconds), with an additional native
fd-relative identity/version check after no-replace publication and before
writing COMMIT. Physical RED on the parent: a second same-UID process
substituted a different journal inode with equal bytes and the old code
committed. The first candidate was SOURCE **NO-GO** for missing same-inode
version checks and a post-link swap window; both received follow-up code,
new physical tests and independent **SOURCE GO for the bounded laboratory
scope** at `d6594fdf`. Windows-style `exists->rename` is not emulated;
Linux publication remains `linkat` from the original retained inode under
held ext4 directory FD. WSL Node22 W3 full non-stress suite:
**24 PASS / 3 expected SKIP / 0 FAIL**. The two additional tests exercise
named and anonymous `O_TMPFILE`: a separate process changes and restores
the **same** journal inode (version must still fail), and an opt-in
kernel-level journal rebind **after** publication must deny COMMIT. A
published-without-COMMIT inode stays visible and nonauthorizing. These
rechecks cannot eliminate the last-check-to-COMMIT race for an active writer
with the same UID: only independent parent custody can do that.

**W26/Windows Node22/NTFS:** source commit
`77f02bd2327de9275e42da71d3c24f46a934719b` binds the native
PREPARED_V2 and COMMITTED_V2 marker bytes to the **original** native
`FILE_ID_INFO` (volume serial and 128-bit FileId) of the held root and
opened stage. Its new-process cold inspector opens each leaf relative to a
held native directory HANDLE, verifies bounded bytes and original native
File IDs, and denies even if a hostile same-SID writer replaces the
published inode with a **different FileId containing identical bytes**.
The previous source returned a false `COMMIT_OBSERVED` on that real attack;
the child denies and retains both original/foreign inodes. Physical full
W26 suite **15 PASS / 0 FAIL**; independent **SOURCE GO** for this limited
source. `PREPARED_ONLY`, `PUBLISHED_NO_COMMIT` and `COMMIT_OBSERVED` are
read-only laboratory classifications, not a signed native replay permit.
Native no-overwrite uses NTFS `NtSetInformationFile` with
`ReplaceIfExists=FALSE`, never a JavaScript pathname rename.

**Owner/witness/floor reference verifier:** isolated candidate
`2ada620d91f2a4380a59083eb9dc86083ec016ab`, followed by input-budget
hardening `548fb526192694965da9c7e2bcd29edd638d2670` and
`cdeeba5c5917410151be12634cde2bf51354bba4`, with final intrinsic
Buffer length and strict UTF-8 fix `71b07b2ef0033733327323358f9a4f083ad40a15`
(rebased `baa9c27c`), verifies separately
signed Ed25519 owner provisioning, current root-commit witness and
monotonic floor (distinct keys), a fresh nonce in both independent
receipts, exact scope/root digest/epoch/sequence/physical file identity,
and PREPARE/COMMIT digests. It returns **only a frozen nonauthorizing
observation** (`authorizesIo:false`, `authorizesReplay:false`). The
reference accepts **canonical byte buffers of at most 8192 bytes before
JSON parsing**; no arbitrary JS-object descriptor enumeration is allowed.
Valid but stale floor, nonce replay, incomplete COMMIT, oversized or
noncanonical bytes, malformed keys, and a real same-byte foreign inode
are rejected. Lab verification test **1 PASS on Windows Node22/NTFS and
1 PASS on WSL Node22/ext4**; signers and physical readback are test-owned,
not remotely or OS-independently attested. An initial witness implementation
had SOURCE **NO-GO** for unbounded enumeration before its claimed budget;
later commits replace that interface. This verifier is NOT wired as a
product authority and cannot make a local writable journal monotonic.

**Concrete unblock requirements:** provision a separately protected native
service **and all ancestor directories** under a distinct OS principal;
prove user-token access denial by a second hostile process, not by checking
ACL bits alone. On Linux this entails a root/independent-UID-owned helper
with credential-verified AF_UNIX and `openat2`/`renameat2` under retained
dirfds; on Windows an independently installed service identity, protected
DACLs over the full ancestor chain and HANDLE-relative NTFS operations
must exclude the interactive SID. This Windows session is not running as
SYSTEM, and no independently installed Windows service or production Linux
custodian was provisioned or exercised. An opt-in root-owned WSL **test
fixture** is now physically exercised below, but is not a deployed,
independently attested service. After provisioning, a separate current owner-signed
monotonic witness store and challenge must bind cold PREPARE/COMMIT,
physical inode/root identity, original bytes, replay floor and exact
principal to trusted persistence beyond writable sync files. Do not
equate an in-process N-API addon, 0700 same-UID fixture or test-generated
signing keys with such an authority.

Additional external release requirements still include genuine Windows 10
CFAPI hydration/OS callback validation, real hardware power-loss durability
and recovery, supply-chain attestation, same-SID/UID hostile concurrent
A-B-A/mount/reparse pressure under an independent service, and all hosted
Windows/Ubuntu mandatory release gates at the exact published SHA.
The operational `SyncEngine` inbound publisher still has a replace-capable
JavaScript pathname `rename`; W3/W26 do **not** make it safe merely by
existing in the repository. **MERGE NO-GO; RELEASE NO-GO; RootSession OFF.**

### 2026-11-11 — cross-platform native integration, new-process ext4 cold custody, and distinct-UID isolation proof

The previously isolated W3, W26 and witness lines were integrated **after**
the published `91c4e75c` cold journal bootstrap without resetting or
replacing their original commits/worktrees. The combined native/witness
commit chain is `a0b293d1` → `eaf7cb18` → `476b0362` → `8889188c` →
`a50bfeb1` → `40061a7d` → `baa9c27c` → `50c3b9c3`.
This preserves the source-to-integrated SHA provenance, the real NTFS
`NtSetInformationFile` no-replace publisher, and the separately signed
owner/witness/floor **nonauthorizing** reference. The resulting integrated
HEAD `50c3b9c32f3e82369427545a9d7860fea1db1549` received two bounded
independent SOURCE GO reports with zero new P1/P2. Physical exact-tree
tests: Windows Node22 NTFS W26+signed witness **16 PASS / 0 FAIL**, WSL
Node22 ext4 W3+signed witness **25 PASS / 3 expected SKIP / 0 FAIL**.

The next source commit `7da2fd9578d97413a15a9b4752a51f12a4882bef`
implements a further **Linux-only opt-in native laboratory** milestone.
W3 PREPARE now stores and retains an exclusively created, fsynced native
`PREPARED_ID_V2` sidecar with the held directory's `st_dev/st_ino` and
original staged inode `st_dev/st_ino`, and verifies its ORIGINAL held FD,
namespace occupant and file version both before no-replace `linkat` and
after publication before COMMIT. `cold_inspector.c` runs in a **new native
OS process** and walks an explicitly fixed sandbox suffix below passwd
HOME using `openat2` with `RESOLVE_BENEATH`, `NO_SYMLINKS`, `NO_XDEV`.
It reads bounded marker bytes from held FDs, compares inode/version and
current name, checks the original sidecar's exact canonical IDs, and returns
only `PREPARED_ONLY`, `PUBLISHED_NO_COMMIT`, `COMMIT_OBSERVED` or denial.
There is **no cold replay** and no native authority emitted by this inspector.

Physical RED→GREEN on WSL/ext4: a parent without the native identity sidecar
failed the new cold phase proof (missing original inode ID), then the new
native commit passed; an original cold inspector accepted the same inode's
`COMMITTED_V1` prefix followed by `\0FOREIGN` (**RED**), then the corrected
bounded byte comparisons and NUL rejection passed (**GREEN**). A second
real same-UID process parked the original PREPARE identity sidecar and
installed a **distinct byte-identical inode**; native publication denied
before creating COMMIT, and both original and foreign FDs/bytes survived.
Another physical child exited with code 75 **after fsynced PREPARE but
before sidecar**; a new inspector denied the torn transaction. A native
post-link `_exit(73)` produced `PUBLISHED_NO_COMMIT`, never COMMIT. An
independent same-byte foreign **published** inode with an intact COMMIT also
caused cold denial. WSL Node22/ext4 complete W3+signed-witness non-stress
run at `7da2fd95`: **31 PASS / 3 expected SKIP / 0 FAIL**; test-only
stress 16,385+ entries was not repeated.

Additionally an explicitly gated **privileged WSL test process** created a
genuine root-owned ext4 fixture under `/root` (`0700` for both protected
test ancestors and final directory), held the original descriptors,
published an anonymous `O_TMPFILE` stage no-replace, and verified cold
COMMIT as root. A separate real OS child dropped to UID/EUID **1000** via
`runuser` and attempted **read**, **exclusive create**, **overwrite**,
**rename ancestor**, and **create symlink** at both PREPARE and committed
phases: **all five operations per phase were denied by the kernel with
`EACCES`/`EPERM`**. WSL22 root-principal isolated test **1 PASS**. This
establishes distinct-UID isolation in a disposable root-owned **laboratory
root**, not a persistent trusted service; it does **not** exclude a host
administrator, separately privileged process or the same UID as the
custodian. The Windows same-SID isolation gate is still outstanding.

These are closer physical proofs of a coherent native transaction, but
**none** independently attests the native executable, protects persistent
all-ancestor custody through reboot, verifies a current remote monotonic
operator floor, supplies a production RootSession or eliminates arbitrary
hostile same-UID TOCTOU while the root is writable by that principal. The
Linux sidecar contains native inode numbers but is **not signed**; a writer
with the custodian's privileges can forge it. No real hardware powercut,
Windows 10 CFAPI callback, native Windows installed service or exact-head
hosted mandatory release matrix has been proven by these lab results.
`sync-client/rootark-sync-engine.js` still contains the legacy inbound
replace-capable pathname `rename`; it is **not** made production-safe by
these experiments. **MERGE NO-GO; RELEASE NO-GO; RootSession OFF**.

**Independent P2 resolved — named-stage cold replay classification.** The
initial `7da2fd95` inspector correctly classified anonymous `O_TMPFILE`
publication but conservatively rejected *every* successful **named-stage**
publication because `linkat` retains the original stage pathname and the
published name as two hardlinks to one inode. This was a **SOURCE NO-GO**
from an independent reviewer, despite no false COMMIT. Follow-up source
`3f26295b` now requires the opened stage and published file to match the
**same original** dev/ino and PREPARE sidecar, and requires `st_nlink==2`
on both descriptors. Anonymous stages still require no stage pathname and
exactly one published hardlink. An extraneous third alias, a same-byte
foreign stage inode, or a changed FileId fails closed; no unlink/cleanup
is performed. The native bridge also provides a **separately opted-in
named-stage post-link `_exit(73)`**, allowing a second process to observe
`PUBLISHED_NO_COMMIT` through the exact retained original two-link inode.
The preceding inspector returned status 41 for a real valid named COMMIT
(physical **RED**); the corrected inspector returned `COMMIT_OBSERVED`
on the same scenario and denied a byte-identical foreign alias (**GREEN**).
Three focused named-stage tests **3 PASS** on WSL22/ext4. New combined
physical W3+signed-witness suite **34 PASS / 3 expected SKIP / 0 FAIL**;
distinct-principal root-owned ext4 kernel isolation **1 PASS**. The
isolated RED worktree and its fixtures remain preserved. All classifications
remain `LAB_ONLY_NO_GO`, including successful named two-link COMMIT, until
an independent custodian can safely retire the stage and enforce a signed
monotonic cold floor. Native W3/W26 experiments are **not** imported by
the operational publisher. **MERGE/RELEASE NO-GO, RootSession OFF.**

**Second independent P2 resolved — original publication-mode binding.**
The follow-up reviewer identified a distinct cold attack on the preceding
`87f2bd04` state: after a successful named-stage COMMIT, a same-UID writer
could remove the original stage name. Its published inode then changed
from `nlink=2` to `nlink=1`, while PREPARE sidecar and COMMIT marker bytes
remained intact. The old inspector inferred the **anonymous** modality
from the missing stage name and incorrectly returned `COMMIT_OBSERVED`.
That was reproduced on real WSL/ext4 with an opened original inode,
the actual `unlink` of the disposable named stage and the original
intact COMMIT: previous code **RED** (`status=0`, expected deny 41).

Source `ab4a91a0863140017d95e625c2719e5c979b8cfd` now persists a
one-byte **`N` (named) or `A` (anonymous)** original publication mode
alongside the root/stage `st_dev/st_ino` in the exclusively created,
fsynced PREPARE identity sidecar. The native current-session publisher
retains and validates the original sidecar inode/bytes/version across
publication, and the separate cold process compares exact canonical
sidecar bytes and enforces the **original mode**, never the mode inferred
from a mutable leaf. Named mode requires the original stage name and
published inode with the correct `nlink=2` topology; anonymous mode
requires stage absent and published `nlink=1`. The former false COMMIT
now returns 41; correct named and anonymous COMMITs remain valid *lab
classifications only*. The privileged fixture's test name was corrected
to accurately describe a **different-UID** writer, not same-UID exclusion.

Focused physical regression **GREEN 2 PASS** for named mode and actual
alias removal; full WSL Node22/ext4 W3+signed witness **35 PASS / 3
expected SKIP / 0 FAIL**; root-owned distinct-UID adversarial lab
**1 PASS**. Both original RED worktrees, prior SHAs and all test fixtures
were kept. The PREPARE `N/A` byte is **not an independent signature**;
a same-UID writer with access to the entire unprotected test namespace
could forge the sidecar and other markers. Only a differently owned
persisted custodian, owner-signed external monotonic floor and sealed
root/ancestor identities can make this authoritative. **No native
RootSession activation, no merge/deploy/cutover, RELEASE NO-GO**.

### 2026-11-11 — staged foreign alias witness follow-up (local candidate)

The earlier **local-only** `09465635` fixture retained original and foreign
FileHandles but still linked a **mutable stage pathname** and subsequently
unlinked that pathname. A same-UID/SID writer could replace the stage alias
before either operation: the link could publish a different inode, and the
unlink could remove the attacker's alias. The companion local `5ee93025`
roadmap description did not establish a source-safe production publication.

The new candidate is based directly on PR #300's published `18ee8bdb`.
It keeps the stage and published names as hardlinks (expected `nlink=2`),
**never unlinks a mutable stage path**, and verifies that the published FD
has the same `dev` and `ino` as the retained foreign FD. The test also
reads and `fstat`s the original, foreign and published **same held FDs**
before/after their exact-byte checks. A separate adversarial case rebinds
the stage pathname to a different inode containing identical bytes and
requires the local lab guard to reject with
`lab_publication_identity_mismatch`.
After the exact-head hosted CodeQL flagged the test's *open after stage rename*,
the foreign inode is now first created exclusively at `published.bin` and
retained there. The original stage is then parked and an atomic **no-replace
hardlink from this already-published foreign inode back to the empty stage
name** creates precisely two foreign links. This is an adversarial final-state
identity test, **not** a reenactment of a legitimate `stage→published` publish
syscall; that forward direction is covered by a separate positive scenario.
The guard must still reject two physical aliases with the same bytes and
the correct `nlink=2` because neither matches the ORIGINAL retained stage.
The original expected inode also holds **two real links** (`preservedName`
and `original-held-peer.bin`) before any alias switch: this prevents a false
GREEN from a guard checking only the link count while omitting inode identity.
Both candidate source and target must therefore pass nlink checks, with
**distinct** dev/ino values providing the only rejection reason.

The peer-reviewed false-GREEN was reproduced by removing only the guard's
`dev/ino` comparison in a disposable copy of the test: **RED 0 PASS /
1 FAIL** (`Missing expected rejection`) on Windows Node 22.23.4/NTFS
and WSL Node 22.22.1/ext4. The unmodified identity guard is **GREEN
1 PASS / 0 FAIL** on each. The temporary mutated test copy was deleted,
while native evidence fixtures remain retained; none of these results
authorizes recovery or resolves the current hosted CodeQL until the exact
corrected commit has been published and scanned.

The unchecked-guard negative control was **RED 1 PASS / 1 FAIL** (`Missing
expected rejection`) on both **Windows Node 22.23.4 / NTFS** and **WSL
Node 22.22.1 / ext4**. After the held-inode check, the targeted witness
suite was **GREEN 2 PASS / 0 FAIL** on both platforms. For WSL, `TMPDIR`
was set to a verified ext4 path under `/home` (the default `/tmp` was
tmpfs). These are disposable **nonauthorizing laboratory tests**;
they do not exclude concurrent same-principal namespace mutation or
provide atomic native publication. Independent SOURCE review, published
exact-head CodeQL/CI and production custody remain pending. **RELEASE
NO-GO**.

### 2026-11-11 — independent source P2: staged symlink can falsely pass held-inode test

Independent SOURCE review of local commit `d481a4fd` found another lab
false-positive: on POSIX, a hostile same-UID writer can rename the retained
foreign stage to `foreign-preserved.bin`, place a symlink back at the stage
name, and hardlink the **symlink inode** into `published.bin`. Opening the
published path with `"r"` **follows** the symlink to the original held foreign
inode; the old guard accepted matching `dev`/`ino` and equal bytes even
though no second regular-file hardlink had been published.

The new deterministic disposable physical test confirmed this as **RED**
on WSL Node 22.22.1 **ext4**: **2 PASS / 1 FAIL** (`Missing expected rejection`),
with `lstat(published).isSymbolicLink() === true`. The candidate now opens
published paths with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` (where supported),
rejects symlink/nonregular publication via a supplementary lab-only `lstat`
identity check, and demands **exactly two links for both the retained
source and published file FDs** with equal `dev`/`ino`. All bytes and
before/after file identities in the attacked fixtures come from retained
FDs. No hostile stage pathname is unlinked.

Physical targeted WSL/Node22/ext4 is **GREEN 3 PASS / 0 FAIL**. Physical
Windows/Node22/NTFS hardlink checks are **GREEN 2 PASS / 0 FAIL**; the POSIX
symlink-inode adversarial scenario is explicitly **SKIPPED on Windows**,
and no Windows reparse-point or symlink-privilege outcome is claimed. The
Windows `lstat` fallback is only laboratory evidence and cannot provide an
atomic race-free directory entry guarantee under same-SID mutation.
This candidate requires fresh independent SOURCE GO and hosted exact-head
CodeQL/CI if published. **Lab nonauthorizing; RELEASE NO-GO.**

### 2026-11-11 — W3 live native all-ancestor chain and original 0700 permission drift

The W3 POSIX native laboratory now retains the original `/` anchor, every
literal passwd HOME component and the disposable fixture-parent fd while
retaining the original `held` DIR*. Each stage, publication and pre-COMMIT
gate reopens named children from **their originally retained parent fd** with
`openat2` no-follow/no-cross-mount constraints; it compares the opened inode
identity to the original descriptor. A physical second same-UID process
renaming the fixture parent and creating another directory/held was accepted
by the predecessor (**RED**) and is now rejected without COMMIT. Symlink
replacement and a deterministic post-link/pre-COMMIT parent rebind also
reject, without deleting an untrusted pathname.

An independent source review found that checking only `dev/ino` could still
allow same-inode permission weakening. An additional physical WSL22/ext4
test changes the retained parent from owner-only `0700` to `0777` from a
separate same-UID process: prior integrated ancestor source **RED 0 PASS /
1 FAIL** (it published anyway). The follow-up stores and rechecks the
original `st_uid` and mode bits of **every ancestor**, plus the private ext4
parent's strict `0700` contract, before staging, publishing and COMMIT.
Physical child **GREEN 1 PASS**, and the complete W3 Node22/ext4 suite
with **no 16,385-inode stress rerun** is **38 PASS / 3 expected SKIP /
0 FAIL**. After proving the hostile `0777` state, the test resecures
**the same opened parent inode** by `fchmod(fd, 0700)` in `finally` before
closing the descriptor, leaving the fixture and its original bytes preserved
without a world-writable directory. This W3 fix received independent
SOURCE GO and was published in `b6775945`; hosted checks belong to their
own exact published SHAs, as reconciled in the live status above.

This is **live, cooperative LAB_ONLY_NO_GO**, not a persistent independent
custodian. The cold inspector acquires its own namespace after the original
descriptors die; a same-UID actor can still do ABA between checks, tamper
with the source or change the process mount namespace. It cannot attest a
signed owner floor or authorize `RootSession`. Real Windows 10 CFAPI,
Windows native all-ancestor custody, separate-principal isolation and
hardware powercut gates remain open. **MERGE NO-GO; RELEASE NO-GO**.
