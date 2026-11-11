# Root.ark Plan Tree

Last reconstructed: 2026-07-25 (historical baseline)
Latest application-code snapshot for this closure: 2026-10-16 after PR #201 merged at `341804fa2bfd02dcd50f2d1bde560cb677fc27fd`. The [2026-10-16 pre-publication snapshot](validation/2026-10-16-rootark-prepublication-closure.md) records GitHub state and validation evidence queried after PR #199; it is historical and does not describe PR #201 or later commits. Track the final exact `Root/main` SHA and local validation for the documentation-only closure publication in the [final closure PR #202](https://github.com/bielxdh3/Root.ark/pull/202).

Repository: bielxdh3/root.ark

PRs #195–#201 are merged. This milestone includes the aggregate chunk-upload quota follow-up test (#199), the Windows WebDAV journal rename retry (#200), and the closure ledger/evidence reconciliation (#201). The [pre-publication snapshot](validation/2026-10-16-rootark-prepublication-closure.md) contains exact branch-head release-gate results and the remote Windows-job outcomes for #199–#200; those results do not transfer to later SHAs. PR #97 is merged as partial selective-sync work; issue #66 remains open. Use the [final closure PR #202](https://github.com/bielxdh3/Root.ark/pull/202) as the durable record for the exact final default-branch SHA and local validation.

Historical sections below preserve their original evidence and claims; they are not current live status. Validation statements are tied to their named SHA and do not transfer to later commits.

2026-11-11 late continuation — **newest execution checkpoint**: confirmed
`Root/main` `202146bb73ca8577a0a4017c4556cb8b1e9588a6` unchanged. PR #298
was advanced by ordinary FF to `73c2be30` after **two independent SOURCE GO
limited to 11 LAB experiments**; OPEN/Draft, with held-HANDLE Windows11/NTFS
and Linux/WSL/ext4 no-replace experiments 7/7 per OS. On published #298,
the CodeQL Action workflow `43118997507` and Analyze job `130854325688`
are **SUCCESS**, but the SEPARATE GitHub Advanced Security `CodeQL` PR
check-run `130855351016` is **FAILURE** with 20 new high-severity
`js/file-system-race` alerts (19 in lab experiments, 1 in a historical test).
The scanner running successfully is not the security-alert gate passing;
other mandatory jobs must be examined, and **no native product implementation**
was released. PR #300 remains OPEN/Draft `984a62ef` (prior docs-only FF);
PR #301 remote remains OPEN/Draft `e1ca644b`; PR #302 remains OPEN/Draft
`e0af8397`; PR #306 remains OPEN/non-Draft `b13b29f9`, without APPROVED.

PR #301 has **unpublished** local child `7da07252` (parent `25b2649c`):
two physically RED Windows P2 regressions, fake Hash facade via mutable
`Object.freeze` and inherited numeric array setter signed A / applied B,
now Windows targeted 2/2 and related 34/34 GREEN; **exact-SHA WSL and two
independent SOURCE GO pending**. PR #302 has **unpublished** local child
`be3170e3` (parent `34b4d39e`): callback-poisoned WeakMap ticket relookup
unsigned B and Set nonce replay physically RED Windows on parent, patched
with early native methods; full Windows Node22 70 tests / 66 PASS / 4 SKIP.
**Exact-child WSL and two independent SOURCE GO pending.** Current WSL
process launches are stalled; do not silently inherit prior successful WSL
results. PR #301 published `e1ca` Security Regression 1 old issuer Proxy
oracle FAIL; PR #300 published earlier `a598` had 49 Windows and 59 Ubuntu
positive FOD/pin/picker failures. All #298 native file linkage results are
**LAB ONLY**; writable `RootSession` still unconditionally denies product
recovery. First-pin original-A independent root+ALL ancestors, real
same-UID/SID writer isolation, no-replace PREPARE/COMMIT, owner-signed
off-host CURRENT, CFAPI physical Windows **10** and real powercut remain
unproven. Four evidence planes in latest
`docs/roadmap/issue-66-pr300-native-custody-gates.md` are conjunctive.
**ISSUE #66 INCOMPLETE · MERGE NO-GO · RELEASE NO-GO · RootSession OFF.**

2026-11-11 continuation — **newest live CI checkpoint**: all published HEADs
remain #298 `ce393b75`, #300 `a598eb47`, #301 `e1ca644b`, #302 `e0af8397`,
#306 `b13b29f9`, with unchanged `Root/main` `202146bb`. #300 exact Security
Regression `43094656916` is now completed FAILURE: **59 Ubuntu positive
FOD/pin failures and 49 Windows positive FOD/pin/picker failures**; CodeQL
SUCCESS is insufficient. #301 new published checks CodeQL, PG18, dependency,
provider/Android SUCCESS, but Security Regression `43100369644` remained
in_progress at this check. #298/#302 Security Regression `startup_failure`
with zero jobs is neither passing nor failing code coverage; other workflows
are queued. Four isolated unpublished children remain protected: #298
`67c850c` evidence RED, #300 `30657c46` docs, #301 `afde2432` native crypto
intrinsics fix, #302 `47c95899` DEV-OFF crypto fix; exact-child SOURCE pairs
are still required before any FF. **Native positive FOD/root original-A,
independent custodian, Win10 CFAPI and real powercut remain unproven.**
**RootSession OFF · MERGE NO-GO · RELEASE NO-GO.** See latest roadmap section.

2026-11-11 ~21:00Z — **newer verified cross-PR checkpoint** (supersedes
subsequent older "current" notes): PR #298 `ce393b75` OPEN/Draft,
#300 `a598eb47` OPEN/Draft, #301 `e1ca644b` OPEN/Draft (two exact-SHA
SOURCE GO for narrow crypto split-read fix, 40/40 local Win22 and 40/40
WSL22 ext4, FF published), #302 `e0af8397` OPEN/Draft, #306 `b13b29f9`
OPEN/non-Draft with 0 GitHub APPROVED reviews. `Root/main` remains
`202146bb73ca8577a0a4017c4556cb8b1e9588a6`. #300 exact CodeQL
`43094498755` succeeded but Ubuntu canonical still reports 59 positive
FOD/pin failures on run `43094656916`, Windows result pending. #298
`43097069140` and #302 `43096175973` Security Regression completed
`startup_failure` with **no jobs**, not a code-test verdict; their CodeQL
and PG18 runs still queued. Fresh #301 e1ca hosted checks are pending,
not inherited from green 50d. Three real pathname-dependent #298 RED
reproductions were isolated in **unpublished evidence commit** `67c850c`;
PR #302 also has two local dynamic crypto factory / `Symbol(kHandle)`
P2 RED scenarios requiring remediation. The four separate laboratory,
native product, off-host self-hosted custody and release gates remain
conjunctively unmet. No positive native root-session FOD path, independent
original-A/ancestor ownership, Windows 10 CFAPI or physical powercut
proof. **MERGE NO-GO · RELEASE NO-GO · RootSession OFF.** See the
`docs/roadmap/issue-66-pr300-native-custody-gates.md` top checkpoint.

2026-11-11 — **latest verified PR HEADs, authoritative over older
"current" entries below:** #300 `b774ce13398e2486fd08e3ff7b47d53d66c046c2`
(OPEN/Draft), #301 `50d76c686f7d47799344ea8994fd0b8adb3293cc`
(OPEN/Draft), #302 `9096cfa75598f23cd640242febe4118e0df64acd`
(OPEN/Draft); `Root/main` unchanged at
`202146bb73ca8577a0a4017c4556cb8b1e9588a6`. PR #300 exact HEAD
CodeQL `43058440999` SUCCESS, Security Regression `43058657386`
FAIL (FOD/native-positive CI remains unimplemented); S0 deny-before-inbound
is fail-closed **not** functioning native hydration. PR #301 exact HEAD
CodeQL/Ubuntu22/Windows22 canonical/mandatory/PG18/dependency/provider
checks SUCCESS, but logical owner CURRENT mapping is not independent
off-host/physical FileId custody. PR #302 exact HEAD CodeQL/Ubuntu22/
Windows mandatory/PG18/dependency SUCCESS, but Windows canonical single
`ERR_ASSERTION` in a partial-clock-rollback owner-lease test and aggregator
FAIL. DEV-OFF same-host SQLite does not authorize production. Native no-replace
publication, original-A pre-first-pin enrollment, separate UID/SID custodian,
PREPARE/COMMIT and signed floor cold replay, real Windows 10 CFAPI and
physical powercut remain unproven. See
`docs/roadmap/issue-66-pr300-native-custody-gates.md` for full conjunctive
gate/CI table. No merge or deploy; **MERGE/RELEASE NO-GO**.

2026-11-11 — **live PR #300 #66 checkpoint, not release authorization:**
published HEAD `23cc31b69c5efb6f218eb74e556b49e297e79297` remains
OPEN/Draft; `Root/main` stayed `202146bb73ca8577a0a4017c4556cb8b1e9588a6`.
Two exact-SHA SOURCE GO reviews approved advisory-inventory boundary
sanitization; Windows Node22 and WSL Node22 inventory tests each passed
13/13. CodeQL run `43048299591` succeeded on the published SHA;
Security Regression `43048466075` was still running and must be checked
separately. The product FOD inbound `fsp.rename` destination-collision
P2 remains confirmed physical RED on Windows NTFS and WSL ext4; its
non-destructive attack fixture is preserved unpublished. `RootSession`
remains OFF. Independent original-A enrollment, native no-replace
publication, owner-signed monotonic cold floor, crash/powercut and real
Windows 10 CFAPI remain unproven. PR #302 exact `dcd65b6b` hosted
Security Regression is green but its custodian is DEV-OFF, not external
authority; PR #301 cryptographic signer-role changes require their own
exact-SHA review/CI, not reuse of PR #300 checks. **MERGE/RELEASE NO-GO.**

2026-11-11 — **S0 denial is not a native FOD implementation:** local composed
PR #300 candidate `226652ff8504477c2fba2b7d4d2d35de0886528b` includes
the private fail-closed `SyncEngine._apply` native-required signed inbound
guard before journal/payload mutations. A hostile same-principal second
process inserts an exclusive `fsync`ed foreign inode after authentic Ed25519
verification; four focused negative tests each passed on Windows Node22/NTFS
and WSL Node22/ext4 in the composed tree, with retained original FD and no
rename/link/temp, journal admission, snapshot change or remote push. Browse
and signed non-FOD legacy CREATE remain operational; other native-required
operations are intentionally unavailable. Linux/Windows product native
publisher, independently enrolled original-A and ancestors, owner-signed
off-host floor, real Windows 10 CFAPI and physical powercut are **still
missing**. CodeQL/hosted CI on this local SHA have **not** been run;
predecessor `23cc31b6` had CodeQL SUCCESS but Ubuntu 18 positive FOD FAIL.
The legacy JS rename remains overwrite-capable outside S0. **No merge,
deploy, RootSession activation or release authorization.**

2026-11-11 — Issue #66 / PR #300 W26 integration status: current bounded
native NTFS evidence is recorded in
`docs/roadmap/issue-66-pr300-native-custody-gates.md`. Four post-native-pin
W26 test/lab commits were integrated without conflicts above published
`057241e0`; local tree `e1e8b548` received two narrow independent SOURCE
GO reviews, Windows 11 NTFS/Node22 completed two **22/22** repeat runs
after one unclassified 21/22 result, and WSL/ext4 W3 remains **38 PASS /
3 SKIP**. Root/main is untouched; PR300 remains Draft. Formal CodeQL
**0 alerts** applies to the prior published `057241e0`, **not** to the
new candidate. The initial original-A identity prior to first native
pin, independent cold custodian and signed floor, Win10 CFAPI and real
powercut remain release blockers; the post-pin lab never authorizes
RootSession, merge or deploy.

2026-11-11 — laboratório W26 de aquisição fria pré-pin, ainda não
publicado: uma alteração opt-in testa A→B antes do primeiro HANDLE nativo,
para B comum ou junction, e exige recusa sem escrever no diretório
estrangeiro enquanto inexiste FileId original atestado por custodiador
independente. A primeira revisão SOURCE detectou falso verde por ausência
de `READ_CONTROL` no HANDLE usado por `GetSecurityInfo`; contraprova RED
0/2, correção exigindo leitura real do SID no B comum, e suíte Windows
Node22/NTFS 25/25 PASS. O modo NORMAL permanece vulnerável à substituição
pré-pin: isso não é prova positiva de identidade A, nem autoriza merge,
RootSession ou release. A nova revisão SOURCE/CI pertence ao novo SHA.

2026-11-11 — Issue #66 / PR #300, W22 inert remote-only source:
pre-rename `EIO` em checkpoint da snapshot ou ACK do journal deixa
um `.tmp-<pid>-<uuid>` físico não autorizador. O temporário deve ser
preservado: excluir por pathname depois da falha poderia apagar um inode
estrangeiro substituído por escritor do mesmo UID/SID. O classificador W22
de raiz vazia **rejeita** esse nome com `unsafe_path` antes de qualquer
ACK/replay; não existe prova nativa independente que autorize o descarte.
Os dois testes legados que prometiam retry automático foram alterados para
provar os mesmos inodes/bytes originais por descritores retidos, journal
observed/seen, snapshot anterior, nenhum push/DELETE e ausência de
autorização fria. Testes físicos RED anteriores: 2 falhas no WSL22;
GREEN WSL22/ext4: **15 PASS / 0 FAIL** no arquivo W22 completo, incluindo
recuperação legítima sem órfão após saída abrupta de processo. Não é
recuperação operacional de órfão hostil: requer custódia nativa protegida
para reconciliação independente. Os testes não ativam `RootSession` nem
transferem resultado à CI hospedada de outro SHA. **MERGE/RELEASE NO-GO**.

2026-11-06 — Issue #66, etapa parcial em revisao: inventario de metadados
autenticado, paginado e limitado por resposta, com cursores invalidaveis por
mudanca na biblioteca e isolamento por conta. Adapter e SyncEngine expõem
navegacao apenas informativa e leitura completa por objeto permanece a fronteira
de verificacao assinada. 13/13 testes focados de inventario e sync seletivo
passaram localmente em Windows, antes da publicacao da PR. A implementacao
normal de `syncOnce` ainda usa LIST completo. A issue continua aberta para
integracao de sync paginado, placeholders nativos e garantia de eviction com
escritor externo.

Revisao de escala da PR draft #255 (2026-11-06): o custo de uma leitura,
attestation, ordenacao e hash completos por pagina era concreto (10 mil
objetos; as primeiras 10 paginas custaram 23,595 s, 78,29 MiB de estado).
Um cache somente de metadados, para uma conta, inicialmente limitado a 16 MiB, com
invalidação por identidade do arquivo persistido e lock de escritores,
passou teste adversarial de segunda instancia de armazenamento e trava
externa. No mesmo fixture, o conjunto completo de 157 paginas levou
2,625 s, sendo 2,337 s no primeiro acesso. Esta otimizacao continua
sem usar metadados para admissao criptografica.

Revisao independente adicional da #255 confirmou caso adversarial
de biblioteca com 10 mil objetos e metadados longos: indice de
20,50 MiB superava o teto de 16 MiB e fazia a rota reler todo o
estado a cada pagina. O teto passa a 32 MiB **serializados** por
conta/instancia; excedê-lo gera 507 `metadata_index_too_large` com
marcador de erro invalidado por mudanca do arquivo, nunca fallback
O(N²). Um teste RED→GREEN com teto artificialmente baixo verifica
erro estavel, ausencia de releituras em retries, isolamento entre
contas e invalidação por outra instancia. Benchmark 10 mil objetos,
indice 20,50 MiB, JSON 149,62 MiB: 167 paginas, 4,288 s total,
sendo 3,586 s no primeiro acesso. Bibliotecas acima do teto exigem
indice persistido em trabalho separado; #66 continua parcial.

Revisao final adicional da PR #255: um unico slot de cache era
compartilhado entre indice positivo e marcador de excesso. No fluxo
A (indice grande, 507), A (507), B (indice pequeno, 200), A (507), a
ultima chamada relia o estado completo sem nova escrita. Marcadores
negativos agora ficam num LRU independente de ate 32 contas, por
identidade duravel e teto vigente. Teste adversarial RED→GREEN: na sequencia A→B→A, a contagem
de readSnapshot caiu de 3 para 2; escrita da instancia irma ainda
invalida o marcador. Revalidar no HEAD da PR antes de qualquer GO.

Revisao posterior da #255: a retencao de apenas um indice **positivo**
fazia A(200)→B(200)→A(200)→B(200) ler novamente todo o JSON a cada
pagina, apesar de ambos terem metadados validos. O cache positivo agora
usa LRU de **ate duas contas e 64 MiB serializados no total**, com
**32 MiB no maximo por conta**; o LRU negativo de 32 contas permanece
separado. Teste HTTP RED 4 leituras completas em A/B/A/B; GREEN 2
leituras, uma por conta. Troca duravel por escritor externo continua
invalidando ambos os indices; expiracao por terceira conta e limitada
e documentada. Sem alterar a admissao criptografica nem o fluxo
`syncOnce`.

Historical canonical baseline HEAD at the 2026-10-01 reconciliation start: `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1` (`refs/heads/Root/main`). It is not the current default-branch SHA.

Historical reconstruction baseline retained for provenance: `4062f4c67bfda9d144aceb6dbbed539b8a917e4a` (2026-07-25).

## Historical live GitHub reconciliation — 2026-10-01

This dated section superseded older statements at the time it was written. Its issue, branch, and PR states are historical; use the current snapshot linked above for live state. Historical phase reports below retain their original dates and evidence boundaries.

- The live default branch was `Root/main` at `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`. At that snapshot GitHub had seven open issues (#63–68 and #94) and one open PR (#95).
- Issue #83 is closed. Its sensitive-name policy remains active: `.env`, credential/service-account names, and private-key/certificate extensions remain excluded from backup content and quarantine payload references. PRs #86 and #90 contain its completion evidence.
- PR #96 is merged at `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; its exact-head CodeQL analysis, dependency review, Ubuntu validation, Windows validation, and GHAS scan passed. This does not authorize a release.
- Issue #94 is represented by PR #95, which remains open. Exact head `95d99e4a934384fcfa2101dfc210741cd791a3d1` passes CodeQL, Analyze JavaScript / TypeScript, dependency review, Ubuntu Node 22 full validation, and Windows Node 22 syntax/tests. The focused upload-security suite passes 26/26, and targeted independent reviews approve parser ordering and server-generated staging-path identity/cleanup. Production replica topology is still unknown; the in-memory limiter and local-disk staging need shared/edge enforcement or confirmed single-process deployment before #94 can close.
- Issue #63 is an approved future feature tracker, not implementation authorization. The protected-index primitive exists, but the UI does not populate it; FTS5 and advanced search remain deferred until the searchable corpus, encrypted-index lifecycle, privacy leakage, and acceptance criteria are defined.
- Issue #64 is a future Android-client tracker, not implementation authorization. There is no Android/Gradle project or Android CI. A native implementation remains gated on a separate architecture/threat-model and protocol-compatibility test plan.
- Issue #65 approves the Zero-Knowledge direction and bounded cryptographic foundation; it does not establish a Zero-Knowledge runtime. Current uploads and server-side operations can still expose plaintext. Migration inventory, client authorization, recovery authority, mixed-mode window, and exact-head runtime/backup acceptance remain open.
- Issue #66 is approved but not complete. PR #97 implements selected-path reconciliation, remote-only state, and guarded cache/materialization flows. Metadata-only remote listing and pagination, a Files On-Demand native provider/UI, and a portable guarantee that eviction cannot race an external writer with an open handle remain missing.
- Issue #67 is approved but not complete: existing backups and sync revisions are recovery prerequisites, not a ransomware shield. Burst detection, a recoverable pause/review barrier, protected per-object recovery history, and authorized restore are absent.
- Issue #68 is approved but not complete: existing public links are single-file bearer links with expiry/limits, not operation-scoped capabilities. Protected-link delivery remains gated on least-privilege capability enforcement and owner choices for link UX, expiry, and recipient recovery.

## Historical reconciliation work after the live baseline — 2026-10-01

This addendum records the published work after the live GitHub baseline above. PR #97 remains open and unmerged; PR #98 was merged into `Root/main` at `1df5e4640d4aea7dc700f2088059f489c2e51af0`. Neither PR changes issue state or marks an issue complete. PR #95 remains open after all exact-head checks passed because production replica topology is still unverified.

- Issue #64 has a native-client architecture and threat-model document only. No Android application, Gradle project, build, or CI exists.
- Issue #65 has a Zero-Knowledge migration contract and a read-only inventory prototype limited to explicitly selected fixture files under an operating-system temporary directory. The prototype reports recognized legacy encryption modes using run-scoped opaque references; it does not inspect live application storage or establish migration readiness. Its four focused tests pass. Runtime migration, authorization, recovery authority, mixed-mode window, backup/restore acceptance, and the remaining owner decisions are still open.
- Issue #66 has a selective-sync implementation in PR #97 at `a6a33a92cd6902f303254e60031da4bdc04cec04`, including selected-path tracking, remote-only state, move-out reconciliation, and guarded cache/materialization flows. The focused `test/phase16-sync-engine.test.js` run records 31 passing tests and one platform-skipped test. The current list API still transfers complete remote records including ciphertext before local path filtering, so network payload transfer is not selective. Exact-head CodeQL, Analyze JavaScript / TypeScript, dependency review, and Ubuntu/Windows CI pass; an independent targeted review of the move-out change found no actionable findings. There is no Windows Files On-Demand provider/UI, metadata-only catalog, or paginated remote listing, and portable open-handle quiescence for eviction is unresolved. PR #97 and the issue remain open.
- Issues #67 and #68 have architecture/acceptance contracts only. No runtime protection or capability-sharing feature is implemented; the owner choices recorded in those contracts remain unresolved.
- PR #98 merged the previous documentation reconciliation. This update records the later #95/#97 checks and open acceptance gates above.

## Status labels

- `[DONE]`: implemented and supported by relevant validation evidence.
- `[ACCEPTED-LOCAL]`: reviewed and accepted for the bounded local engineering scope; environment, production, or publication acceptance may remain open.
- `[IMPLEMENTED-UNVERIFIED]`: code/documentation exists, but operational or regression proof is incomplete.
- `[CURRENT]`: active phase. New execution should stay within this phase.
- `[NEXT]`: next approved phase after the current gate.
- `[PARALLEL-DISCOVERY]`: product questions may proceed without runtime implementation.
- `[LATER]`: valid future work after prerequisites.
- `[BLOCKED]`: must not start until named prerequisites are complete.
- `[DECISION REQUIRED]`: requires an explicit product or architecture decision.
- `[DO NOT IMPLEMENT YET]`: recorded idea, not approved execution work.

A feature is not `[DONE]` merely because files, routes, UI, or documentation exist. Completion requires relevant tests, disposable-data validation, or an explicit manual validation record.

## Source-of-truth order

1. Current code and tests on the actual branch.
2. `docs/issue-ledger.md` for the latest verified live GitHub issue, PR, and default-branch snapshot.
3. This plan tree for phase order and historical acceptance evidence.
4. Dedicated security, architecture, operations, and validation documents.
5. GitHub issues for executable scope.
6. Historical chat context only as input, never as proof.

The issue ledger begins with the post-#174 GitHub snapshot and labels later changes as point-in-time evidence. Re-query GitHub for live state after that snapshot; older dated reconciliations below remain historical evidence.

Master Phase 0-16 ledger and independent local blocker taxonomy: `docs/issue-ledger.md`. The governing continuation supplies the original meanings for all phases; local statuses and evidence are reconciled there without converting design or historical evidence into acceptance.

## 0. Historical product snapshot

This product inventory was reconstructed before the 2026-10-07 live-state snapshot above. Treat its implementation labels as dated evidence rather than current release acceptance.

### Application identity

- `[IMPLEMENTED-UNVERIFIED]` Independent Node.js/Express file-management application currently exists in this repository.
- `[DECIDED]` D-001 keeps this repository actively developed as Root.ark while allowing only a future, explicitly designed and approved migration or selective reuse into BielOS. Track remaining relationship consequences in issue #10.
- `[HISTORICAL DECISION REQUIRED AS OF 2026-08-13; RESOLVED 2026-08-17]` Issue #4 later resolved the final product name as `Root.ark`; any future visual rebrand remains a separate owner/product decision.
- `[RECONCILED — historical 2026-08-13]` At that local reconciliation, GitHub reported `Root/main` and `origin/HEAD` resolved to `28747c6ebdac873650e2d5a3c6193824e7cc9985`. That SHA is historical; the current default-branch SHA is recorded in `docs/issue-ledger.md`. The `codex/folders-acl` references remain historical provenance. Issue #14 was locally closure-ready at that time; remote issue closure was not claimed.

### Verified code-level capabilities

The following are present in code or project documentation, but several require operational validation:

- `[IMPLEMENTED-UNVERIFIED]` User login with bcrypt and JWT.
- `[IMPLEMENTED-UNVERIFIED]` Login rate limiting, progressive delay, IP/username blocking, generic errors, analytics, and audit events.
- `[IMPLEMENTED-UNVERIFIED]` Role and granular permission handling.
- `[IMPLEMENTED-UNVERIFIED]` Logical folders and file-level permissions.
- `[IMPLEMENTED-UNVERIFIED]` Simple and chunked upload flows with pending approval.
- `[IMPLEMENTED-UNVERIFIED]` File versions, expiration, previews, downloads, public links, and access limits.
- `[IMPLEMENTED-UNVERIFIED]` Encryption modes and encrypted-file metadata.
- `[IMPLEMENTED-UNVERIFIED]` Analytics, dashboard, audit logs, CSV export, and WebSocket refresh.
- `[IMPLEMENTED-UNVERIFIED]` Local, S3, and Google Drive storage compatibility.
- `[IMPLEMENTED-UNVERIFIED]` SQLite repositories and JSON-to-SQLite migration with legacy fallback.
- `[IMPLEMENTED-UNVERIFIED]` Backup, automatic backup, restore validation, and pre-restore backup.
- `[IMPLEMENTED-UNVERIFIED]` Trash for files and folders with restore and permanent deletion.
- `[IMPLEMENTED-UNVERIFIED]` Suspicious extension blocking, optional ClamAV integration, and quarantine.
- `[IMPLEMENTED-UNVERIFIED]` WebDAV MVP.
- `[IMPLEMENTED-UNVERIFIED]` One-way local-to-server synchronization CLI MVP.
- `[IMPLEMENTED-UNVERIFIED]` Partial modularization into repositories, services, routes, middleware, and database modules.

### Known architectural condition

- `[IMPLEMENTED-UNVERIFIED]` `server.js` remains the central integration file and is several thousand lines long.
- `[BLOCKED]` Broad modularization is blocked until critical security fixes and automated regression coverage exist. Track in issue #5.
- `[IMPLEMENTED-UNVERIFIED]` JSON and SQLite modes coexist; rollback flexibility exists, but behavioral parity and drift require proof.
- `[IMPLEMENTED-UNVERIFIED]` The main README does not accurately describe the current product surface.

## 1. Governance recovery

### Phase 1.0: Repository control layer

- `[CURRENT]` Create a short root `AGENTS.md` defining scope, safety, token economy, reasoning, validation, Git, and output rules. Issue #8.
- `[CURRENT]` Create this `docs/plan-tree.md` as the phase source of truth. Issue #8.
- `[CURRENT]` Create `docs/codex-workflow.md` with planner, executor, reviewer, and orchestrator boundaries. Issues #8 and #12.
- `[CURRENT]` Create `docs/product-discovery.md` for explicit future product decisions. Issues #4 and #8.
- `[CURRENT]` Create an initial code-backed security findings record. Issue #11.
- `[NEXT]` Open and review the governance PR.
- `[NEXT]` Merge only after confirming the documents do not claim unverified runtime behavior as completed.
- `[NEXT]` Close issue #8 after the governance PR merges.

### Phase 1.1: Release discipline

- `[NEXT]` Require one coherent goal per branch and PR. Issue #12.
- `[NEXT]` Require starting/final SHA, changed files, validations, unvalidated items, and remaining limitations in completion reports.
- `[NEXT]` Require plan-tree updates only after evidence.
- `[NEXT]` Prohibit force-pushes, history rewrites, and accidental removal of newer user work.
- `[NEXT]` Record CI status for the exact final SHA once CI exists.

## 2. Security stabilization

No new product feature should begin before the minimum security gate in phases 2.0 through 2.3 is completed.

### Phase 2.0: Bounded security inventory

Issue: #11

- `[NEXT]` Confirm the exact current code paths for the known findings below.
- `[NEXT]` Inspect only adjacent auth, realtime, and rendering helpers for equivalent defects.
- `[NEXT]` Assign severity, preconditions, impact, remediation issue, and validation requirement.
- `[NEXT]` Do not change runtime code during the inventory.
- `[NEXT]` Update `docs/security/current-findings.md` with confirmed evidence.

Known starting findings:

- hard-coded fallback for `JWT_SECRET`;
- bearer token and permission metadata in browser `localStorage`;
- user-controlled dashboard event text rendered through `innerHTML`;
- JWT passed in the WebSocket URL query string;
- role and permission claims embedded for an eight-hour token lifetime;
- no confirmed functional 2FA despite the QR dependency;
- dependency and regression-test baseline incomplete.

### Phase 2.1: Critical configuration and XSS fixes

Issue: #1

Prerequisite: phase 2.0 inventory confirms exact surfaces.

- `[DONE]` Remove the hard-coded JWT secret fallback and replace dashboard user-controlled activity/error rendering with text DOM nodes; startup, login/dashboard, adjacent-surface, and malicious-payload browser evidence are recorded.
- `[DONE]` Fail startup safely when a required production secret is absent or unacceptably weak; the disposable startup acceptance harness verifies non-zero exit and sanitized configuration output for missing and weak secrets.
- `[DONE]` Preserve a safe local-development setup with an ignored `.env` pattern, trackable invalid-placeholder template, and explicit process-environment startup instructions using a fresh Node `crypto` secret.
- `[DONE]` Replace unsafe dashboard activity rendering with DOM/text rendering; the real analytics-to-dashboard malicious-payload browser proof confirms literal rendering and no execution.
- `[DONE]` Review only directly adjacent changed dashboard surfaces for equivalent injection sinks.
- `[DONE]` Add focused startup and rendering regression tests; rendering, session-bootstrap, direct startup acceptance, and malicious-payload browser validation are recorded.
- `[DONE]` Verify login and dashboard behavior after the fixes with the recorded disposable browser validation.

Completion evidence:

- missing/unsafe production secret prevents startup;
- explicit safe configuration starts correctly;
- malicious event fields display as text;
- no real secret is committed or logged;
- relevant tests or manual validation are recorded.

### Phase 2.2: Session, token transport, and authorization freshness

Issue: #2

Prerequisites: phase 2.1 complete and initial auth tests available.

- `[DONE]` Stop placing JWTs in WebSocket query strings; cookie-authenticated upgrades validate Origin and the current session user before events are sent. Focused checks and recorded disposable browser/WebSocket validation passed.
- `[DONE]` Design and implement one bounded cookie-authenticated WebSocket handshake.
- `[DONE]` Revalidate the current user and permissions on the server rather than trusting stale permission claims for the full token lifetime. Every authenticated HTTP request reloads the active identity and derives current permissions; active WebSockets recheck expiry, current identity, disabled state, and `sessionVersion` before the next authenticated message or send. The Phase 2.2 closure audit reconciled the representative permission-removal and expiry regressions.
- `[DONE]` Implement token/session revocation or versioning for password, role, permission, disable, and deletion changes. The shared `PUT /users/:username` decision increments persisted `sessionVersion`; JSON preserves a Git-ignored per-username generation ledger across restart, and SQLite retains/increments a soft-deleted row generation atomically on recreation. Old HTTP and active-WebSocket credentials remain revoked.
- `[DONE]` Browser sessions use secure HttpOnly cookies (`SameSite=Lax`) with CSRF checks for cookie-authenticated writes; the transport decision and browser-session threat model are documented in `docs/security/browser-session-threat-model.md`. Issue #2 is ready to close after the Phase 2.2 closure-audit PR merges.
- `[DONE]` Add representative tests for disabled users, removed permissions, expiry, revocation, and realtime authentication. `test/auth-security.test.js` proves permission removal, JWT expiry, JSON delete/recreate rejection of old HTTP and active-WebSocket sessions, and new-session success; `test/users-repository.test.js` proves repeated SQLite recreation advances generation. Shared update-path analysis establishes the same protection for password, role, permissions, and disabled-state changes without redundant per-field integration tests.

Completion evidence:

- no bearer token in realtime URLs;
- removed access stops within the approved bound;
- disabled/deleted users cannot retain indefinite access;
- existing authorized HTTP and realtime behavior still works.

Closure audit: `docs/security/phase-2-2-closure-audit.md` reconciles source, regressions, merged PRs #17/#19/#20/#21/#22/#23, and successful `Security Regression` runs through #23 (`30650435892`). Issue #2 is ready to close after this documentation-only audit PR merges.

### Phase 2.3: Engineering and dependency baseline

Issue: #3

- `[DONE]` Add repeatable `test` and static-validation scripts. A clean checkout runs `npm ci` then `npm run validate`; reusable package scripts perform complete first-party JavaScript syntax validation, `npm test`, and the locked high-severity dependency audit. CI invokes the same scripts in separate steps.
- `[DONE]` Establish one meaningful vertical slice of automated security regression tests; eight focused tests now cover session, browser-token, WebSocket, WebDAV, rendering, and Archiver compatibility boundaries.
- `[IMPLEMENTED-UNVERIFIED]` Add tests for authentication, authorization, path handling, upload safety, trash, and backup/restore boundaries in small steps; authentication, backup compatibility, disposable real-server simple-upload authorization, suspicious-extension quarantine, filename containment, file-trash lifecycle, and JSON-mode backup/restore coverage are covered. The backup regression proves representative `manageBackups` denial before archive/history/lock side effects, runtime-only JSON/upload inclusion, backup-recursion exclusion (`data/backups`), no absolute/traversal archive entry names, child runtime-root archive/history/restore confinement, module-checkout non-modification, binary download checksum equality, invalid-confirmation non-mutation, pre-restore backup, and a disposable JSON round trip; existing sensitive-path filters remain source-reviewed, while dedicated hostile/sensitive archive fixtures remain the next task. A focused SQLite test preserves a configured external database path. Cloud backup, scheduler behavior, retention pressure, hostile ZIP corpus expansion, and full production SQLite recovery remain unverified.
- `[IMPLEMENTED-UNVERIFIED]` Upgrade Multer and Express through compatibility-preserving changes; Express is upgraded and validated, while Multer remains a separate bounded follow-up.
- `[IMPLEMENTED-UNVERIFIED]` Review remaining dependencies in bounded groups rather than one mass upgrade; the current lockfile audit is clean, while continuing dependency review remains open.
- `[DONE]` Add GitHub Actions CI for clean install, syntax checks, automated tests, and dependency audit; `Security Regression` run `30600354792` succeeded against `666fcbe5aee30710b20a01e13b1a24c8c6313206`.
- `[DONE]` Ensure this validation baseline and CI never include or upload real databases, uploads, backups, quarantine contents, tokens, credentials, or generated runtime ledgers; tests use disposable fixtures only.

Completion evidence:

- clean checkout has a documented validation command;
- tests fail when protected behavior is intentionally broken;
- CI reports against the exact commit;
- dependency changes preserve existing behavior.

Next bounded issue #3 task: add focused hostile-archive restore fixtures that exercise the existing traversal, symlink, sensitive-entry, and checksum rejection paths without changing restore behavior.

### Phase 2.4: 2FA design and implementation

Issue: #9

Prerequisites: phases 2.1 through 2.3 and a product decision about 2FA scope.

- `[DONE]` Implement the bounded all-user-compatible TOTP mechanism in `src/services/totp.js` and `src/routes/auth.js`: authenticated enrollment/confirmation, RFC 6238 login challenge, recovery-code consumption, secure disable, and privileged reset.
- `[DONE]` Encrypt seeds with the existing application master-key boundary, hash recovery codes with scrypt, fail closed on missing/invalid key material, and avoid secret-bearing audit/response paths.
- `[DONE]` Preserve session-version revocation, cookie/CSRF checks, enrollment-only route fencing, realtime freshness, and JSON/SQLite user persistence through migration 5.
- `[DONE]` Add optional, role-required, and global-required policy modes without implicit all-user activation; default behavior for existing users remains optional/inactive.
- `[ACCEPTED-LOCAL]` `PHASE_10_TOTP_IMPLEMENTED_AND_SECURITY_REVIEW_APPROVED`: independent evidence records 52/52 focused auth/TOTP/security tests, 616/616 broad `npm.cmd test` in 38.2 seconds, syntax 88/88, runtime artifacts, `npm ci --dry-run`, `git diff --check`, targeted secret scan, and bounded disposable HTTP evidence passing. The subsequent fail-closed policy-configuration correction passed the broader auth/TOTP/security regression matrix at 51/51, including startup and dynamic HTTP/realtime invalid-configuration rejection. `npm audit` remains non-clean only for the pre-existing high `brace-expansion` advisory. The +301s→+600s future-iat change was test-only and production behavior was unchanged. Shared live policy re-evaluation, HKDF seed-key derivation, and no-store sensitive responses are covered. Browser automation, providers, production, remote CI, release, and publication acceptance remain open; see `docs/security/phase-10-totp.md`.

Phase 9 bounded foundation closeout: `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED` for the reviewed `rootark-zk-1` foundation at the starting SHA, with local crypto vectors now passing after dependency installation. This does not accept zero-knowledge migration/runtime/release behavior. Residual Phase 9 handoffs remain dependency provenance/reproducibility, integration/runtime migration, provider/browser/CI/production evidence, and independent review.

### Phase 9 runtime protocol compatibility — Issue #65

- `[IN PROGRESS]` Add a separately versioned authorization-manifest profile for HPKE sender setup: v2 `info` binds every static core field before setup, `hpke_enc` is bound by the HPKE KEM context, and v2 AAD binds the digest of the complete core after setup. Preserve exact v1 group-wrap bytes and reject unsupported manifest versions.
- Acceptance requires deterministic v2 manifest/info/AAD vectors; public RFC 9180 context setup followed by AAD-dependent sealing/opening; signature, scope, expiry, and replay checks; v2 replay may be claimed only by the compound opener after HPKE authentication; a tampered HPKE ciphertext must not consume a replay ID; plaintext may be returned only after an atomic replay claim; unchanged v1 group-sharing behavior; independent crypto/security review; and exact-head CI. This local step does not claim full ZK runtime migration or release acceptance.

## 3. Operational validation of existing features

Issue: #7

Prerequisites: critical security fixes complete and disposable local workspace available.

### Phase 3.0: SQLite migration and persistence

- `[BLOCKED]` Run migrations in a disposable workspace.
- `[BLOCKED]` Run JSON-to-SQLite import twice and prove idempotence.
- `[BLOCKED]` Verify users, permissions, folders, links, versions, audit, analytics, pending uploads, and encrypted metadata.
- `[BLOCKED]` Restart and confirm persistence.
- `[BLOCKED]` Record JSON fallback and dual-write limitations.

### Phase 3.1: Backup and restore

- `[BLOCKED]` Create a disposable backup containing controlled metadata and files.
- `[BLOCKED]` Verify manifest, checksum, exclusion of secrets, and retention behavior.
- `[BLOCKED]` Execute a restore only against disposable data.
- `[BLOCKED]` Verify pre-restore backup and restart requirements.
- `[BLOCKED]` Test traversal, absolute-path, and symlink rejection with safe fixtures.

### Phase 3.2: Trash and file lifecycle

- `[BLOCKED]` Verify file and folder move to trash.
- `[BLOCKED]` Verify restore conflicts and metadata preservation.
- `[BLOCKED]` Verify permanent-delete authorization.
- `[BLOCKED]` Verify public links, preview, download, versions, and cloud references do not bypass trash state.
- `[BLOCKED]` Verify cleanup behavior and restart persistence.

### Phase 3.3: Upload scanning and quarantine

- `[BLOCKED]` Verify safe file upload.
- `[BLOCKED]` Verify suspicious extension handling.
- `[BLOCKED]` Verify quarantine invisibility and access denial.
- `[DONE]` Verify unavailable ClamAV fails closed by default: simple, final-chunk, and WebDAV PUT uploads are quarantined with 503 before pending registration or approval; unknown providers fail startup; production rejects disabled or fail-open scanner configuration. Focused disposable regressions passed 4/4 in the follow-up worktree based on `dec7ef02f86adc07c7f17f7d834c7bed92026ca4`.
- `[BLOCKED]` Run live ClamAV validation only when the daemon is actually available.
- `[BLOCKED]` Verify simple, chunked, pending, preview, download, share, cloud-sync, and audit boundaries.

### Phase 3.4: WebDAV MVP

- `[BLOCKED]` Verify OPTIONS, PROPFIND, GET, HEAD, PUT, and MKCOL.
- `[BLOCKED]` Verify authorization and permission filtering.
- `[BLOCKED]` Verify expired, trashed, encrypted, version-internal, and unauthorized files remain hidden.
- `[BLOCKED]` Verify traversal rejection.
- `[BLOCKED]` Verify DELETE, MOVE, LOCK, and UNLOCK remain blocked as documented.
- `[BLOCKED]` Test an actual Windows mount where feasible.

### Phase 3.5: Synchronization MVP

- `[BLOCKED]` Verify initialization without saving passwords.
- `[BLOCKED]` Verify state, hash, mtime, and ignored-file handling.
- `[BLOCKED]` Verify new and changed uploads, pending approval, optional auto-approval, and token renewal.
- `[BLOCKED]` Verify the documented 8 MB limit.
- `[BLOCKED]` Confirm that download, deletion sync, conflict resolution, background service, and bidirectional sync remain unsupported.

### Phase 3.6: Validation report

- `[BLOCKED]` Create a dated report under `docs/validation/`.
- `[BLOCKED]` Mark each claim passed, failed, blocked, or not tested.
- `[BLOCKED]` Convert confirmed defects into separate scoped issues.
- `[BLOCKED]` Do not repair unrelated defects opportunistically inside the validation run.

### Phase 3 status reconciliation (2026-08-13)

The committed Issue #7 report at `docs/validation/2026-08-02-operational-validation.md` is the current historical evidence for Phase 3: it records 21 `PASS`, 0 `FAIL`, and 2 environmental `BLOCKED` claims for live ClamAV and an actual OS WebDAV mount, with no product failure. The existing `[BLOCKED]` lines in Phases 3.0–3.6 are preserved as a derived reproduction checklist, not a claim that the validated historical run never occurred. A fresh rerun remains environment-dependent and is not claimed by this continuation.

## 4. Architecture stabilization

Issue: #5

Prerequisites: phases 2.1 through 2.3 complete and relevant tests covering each extraction target.

### Phase 4.0: Responsibility map

- `[DONE]` Map routes, repositories, services, persistence paths, and shared helpers in `docs/architecture/current-server-responsibility-map.md` at the current default SHA.
- `[DONE]` Identify concrete duplicated authorization, path, JSON/SQLite, audit, and storage logic with classifications and locations.
- `[DONE]` Define an evidence-backed extraction order and select realtime authentication/notifications as the first bounded candidate.
- `[DONE]` Complete the mapping task without moving runtime code.

### Phase 4.0.1: Realtime transport contract coverage

- `[DONE]` Add focused public-contract coverage for rejected upgrades, connected-first ordering, exact event envelopes, notification source/timestamps, message-rate reset, heartbeat/idle termination, and child-process shutdown cleanup in `test/realtime-transport-boundaries.test.js`.
- `[DONE]` Validate the focused realtime suite twice at 7/7, the auth-security suite at 13/13, and the combined auth/realtime run at 20/20; syntax and `git diff --check` also passed at local HEAD `28747c6ebdac873650e2d5a3c6193824e7cc9985`.
- `[IMPLEMENTED-UNVERIFIED]` Buffered-client close remains not directly covered because a deterministic public fixture would require brittle backpressure forcing or runtime changes; browser, CI, provider, and production behavior remain outside this phase.

### Phase 4.1: Bounded extractions

- `[DONE]` Extract the realtime transport and notification fan-out boundary into `src/realtime/server.js`; retain thin compatibility adapters in `server.js`, preserve the shared `parseBoundedNumber` helper used by WebDAV, and leave producer call sites and public contracts unchanged.
- `[DONE]` Validate the extracted working tree with realtime transport 7/7 twice, auth-security 13/13, realtime/WebDAV meta-remediation 62/62, combined realtime/auth 20/20, syntax checks, and `git diff --check` at local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`.
- `[IMPLEMENTED-UNVERIFIED]` Buffered-client close is not directly covered; browser, CI, provider, production, and remote-closure behavior remain outside this local phase.
- `[HISTORICAL]` Earlier disposable upload-scanning coverage included ClamAV-unavailable fail-open, fail-closed quarantine, clean INSTREAM parsing, infected INSTREAM quarantine, suspicious extensions, and path containment; the recorded focused suite passed 16/16 twice in that earlier working tree. The fail-open expectation is not the current safe default.
- `[IMPLEMENTED-UNVERIFIED]` Live ClamAV daemon/provider behavior and zero-knowledge client-side scanning remain unverified; current route regressions cover unavailable-scanner fail-closed behavior across simple, final-chunk, and WebDAV PUT entry points.
- `[HISTORICAL]` An earlier working-tree note recorded extraction to `src/upload-scanning.js` at local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`. That module is absent at current base `dec7ef02f86adc07c7f17f7d834c7bed92026ca4`; upload scanning and quarantine are inline in `server.js` here.
- `[HISTORICAL]` The earlier extraction validation record remains attached to its local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`; it is not evidence for the current implementation.
- `[DONE]` Validate the existing `services/cloudStorage.js` boundary with mock-only inventory contracts for S3/Drive prefix, parent, metadata, and duplicate-identity containment; `test/cloud-storage.test.js` passed 27/27 twice without provider credentials.
- `[IMPLEMENTED-UNVERIFIED]` No redundant cloud runtime extraction was made; external provider behavior and D-003/D-009 compatibility remain unverified.
- `[DONE]` Validate the existing direct-protocol WebDAV boundary with executable/oversize/abort, completed-journal recovery, crash-consistency, and meta-remediation suites (90/90 combined); no OS mount or runtime extraction was claimed.
- `[IMPLEMENTED-UNVERIFIED]` WebDAV remains inline because metadata journaling, cloud intent, and D-009 local-bridge requirements make a safe bounded extraction larger than this phase; mount/provider/production behavior remains gated.
- `[NEXT]` Execute the missing disposable JSON/SQLite parity, migration, and restart probes described in `docs/validation/2026-08-13-json-sqlite-parity-matrix.md`; native binding availability, full parity, and the final SQLite production policy remain environment- and owner-gated.
- `[BLOCKED]` Prefer existing partial boundaries rather than inventing a new framework.
- `[BLOCKED]` Preserve CommonJS, route names, response shapes, storage behavior, and UI contracts.
- `[BLOCKED]` Use one coherent commit per extraction.
- `[BLOCKED]` Compare behavior before and after with focused tests.

Potential extraction order after coverage exists:

1. realtime authentication and notifications;
2. upload scanning and quarantine;
3. cloud storage;
4. WebDAV;
5. file versions and lifecycle;
6. encryption;
7. remaining route families;
8. persistence-mode simplification.

### Phase 4.2: Persistence convergence

- `[DONE]` Validate focused SQLite recovery, migration-generation, trash-persistence, and archive/staging safety contracts: the disposable combined run passed 70/70 after rebuilding the native `better-sqlite3` binding.
- `[DONE]` Add the source-backed JSON/SQLite parity matrix at `docs/validation/2026-08-13-json-sqlite-parity-matrix.md`; it records the bounded 70/70 evidence and the remaining probes without claiming full parity.
- `[IMPLEMENTED-UNVERIFIED]` Targeted recovery/generation/transaction evidence does not establish complete JSON/SQLite parity, migration/restart coverage across every entity, or long-running production migration safety.
- `[DECISION REQUIRED]` Decide whether SQLite becomes mandatory for production; the parity matrix recommends it only after parity and migration acceptance and owner approval.
- `[DONE]` Record bounded migration, rollback, restart, and production-policy limitations in the JSON/SQLite parity matrix; implementation and full parity remain open.
- `[BLOCKED]` Remove legacy paths only after data migration and rollback strategy are proven.

## 5. Product discovery track

Issues: #4 and #10

This track may proceed conversationally in parallel with stabilization. Runtime implementation remains blocked until decisions are recorded and approved.

### Phase 5.0: Product identity and repository relationship

- `[DECIDED]` The final product name is `Root.ark`; any future visual rebrand or broader branding direction requires a separate owner/product decision.
- `[DECIDED]` D-001 keeps Root.ark active in this repository; future migration or selective reuse into BielOS requires a dedicated architecture, security, and contract phase.
- `[DECIDED]` Root.ark runtime, data, sessions, and authentication remain independent until an explicit integration is designed and approved.
- `[DONE]` Document the current independent Root.ark/BielOS boundary in `docs/architecture/rootark-bielos-relationship-contract.md`; Issue #10 was closed on 2026-08-17. Future integration, migration, identity, and key relationships remain owner-dependent and require separate approval.
- `[PARALLEL-DISCOVERY]` Existing features to preserve, redesign, or retire.

### Phase 5.1: Users and trust model

- `[DECIDED]` Private administrator-controlled storage and transfer service; accounts, compartments, and access are created or approved by an administrator, with no normal public registration.
- `[DECIDED]` Unrelated users may coexist only in rigorously isolated compartments; external links or keys do not create normal users.
- `[DECIDED]` D-004 defines bounded administrator powers, explicit time-limited audited support impersonation, and minimum metadata visibility without plaintext access.
- `[DECIDED]` D-003 selects client-side zero-knowledge protection for user content; the server and administrator do not normally receive plaintext.
- `[DECIDED]` D-005 defines direct administrator account creation, revocable expiring invitations, user-controlled recovery, default retention, and audited permanent deletion.
- `[DECIDED]` D-006 defines trusted-device and recovery-package authorization, compartment-isolated keys, future-content rotation, and authorized offline access.
- `[DECIDED]` Public account registration is not part of the approved model; isolated request or sharing surfaces require separate design and approval.

### Phase 5.2: File and storage behavior

- `[DECIDED]` Backups may preserve encrypted blobs and required metadata, but must not create an administrator plaintext-recovery path.
- `[DECIDED]` D-006 requires client-side key generation, compartment-isolated key sets, rotation for new content after access loss, and protected offline material on authorized devices.
- `[DECIDED]` D-007 requires per-file keys, isolated compartment hierarchies, mandatory recovery-package verification, explicit historical re-encryption, and future-authorization rotation after package compromise; the frozen Phase 8 technical profile records the accepted implementation parameters, while executable proof and product policy remain separate.
- `[DECIDED]` D-008 sets 30-day normal deletion and backup retention, immediate access revocation, and backup-aware cryptographic erasure that cannot be declared complete while service-controlled decryption material remains usable.
- `[DECIDED]` D-009 requires encrypted client-generated previews and indexes, server-blind sharing, local-bridge-only zero-knowledge WebDAV, and eventual mandatory bidirectional synchronization; the accepted architecture/migration contract is documented, while Phase 9 implementation and acceptance remain separate.
- `[DONE]` Record the accepted zero-knowledge architecture and migration contract at `docs/architecture/zero-knowledge-migration-contract.md`; the bounded Phase 9 foundation closeout is recorded below and full zero-knowledge migration remains separate.
- `[DONE]` Complete the independent Phase 8 security closure in `docs/validation/2026-08-14-rootark-phase8-independent-security-closure.md`; the verdict is `PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`, with the exact HPKE tuple, sender manifest, deterministic encoding, one-shot wrap construction, candidate policy, and residual risks frozen.
- `[DONE]` Close the bounded Phase 9 foundation as `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED`: the reviewed `rootark-zk-1` implementation and vectors pass locally after reproducible dependency installation; full zero-knowledge migration/runtime/provider/browser/CI/production/release acceptance remains open.
- `[DECISION REQUIRED]` Resolve only the genuine owner decisions: sharing/public-link UX, recovery authority, migration window/UX, and sync conflict UX. Primitive, envelope, nonce, library, vector, parser, and bounded 2FA policy choices are recorded technical/security decisions.
- `[IMPLEMENTED-UNVERIFIED]` Current server-readable encryption, metadata, previews/search, ClamAV, server-native WebDAV, sync MVP, and backup behavior remain legacy/current behavior and are not a claim that Root.ark is zero-knowledge today.
- `[PARALLEL-DISCOVERY]` Local, S3, Google Drive, or hybrid canonical storage.
- `[PARALLEL-DISCOVERY]` Approval workflow and intended purpose.
- `[PARALLEL-DISCOVERY]` Define the remaining sharing recipient, public-link, expiration, and limit details under D-009.
- `[PARALLEL-DISCOVERY]` Define the remaining version, restore, backup-key invalidation, and permanent-deletion mechanics under D-008.
- `[PARALLEL-DISCOVERY]` Define the remaining synchronization, conflict, offline, local-bridge, desktop, mobile, and PWA architecture under D-009.

### Phase 5.3: Privacy and operations

- `[DECIDED]` D-004 permits auditable security and operational logs with actor, IP, device, time, and action, without content, keys, decrypted names, or unnecessary sensitive data.
- `[DECIDED]` D-005 separates immediate access revocation from retained permanent deletion and requires reinforced confirmation for immediate destruction.
- `[DECIDED]` D-008 sets 30-day operational logs, 180-day security/audit logs, immediate access revocation, and truthful pending/completed states for backup-aware cryptographic erasure; detailed access, export, deletion, and privacy rules remain `[OPEN]`.
- `[DECIDED]` D-009 requires quarantine for unverified external uploads and preserves the zero-knowledge boundary for scanning, derived data, sharing, WebDAV, synchronization, and restore.
- `[DONE]` Public-link audit events correlate a link with a one-way SHA-256 token digest and do not persist the bearer token; route-level regression coverage is in `test/public-share-audit-security.test.js`. This closes the audit-secret exposure only; Issue #68 capability and zero-knowledge acceptance remains open.
- `[PARALLEL-DISCOVERY]` Define the remaining audit access, export, deletion, privacy, investigation-extension, quarantine, and operational ownership details.
- `[PARALLEL-DISCOVERY]` Data export and portability.
- `[PARALLEL-DISCOVERY]` Operational ownership, deployment, updates, and recovery.
- `[PARALLEL-DISCOVERY]` Features explicitly rejected or deferred.

### Phase 5.4: Approved product brief

The Round 1–3 status notes below preserve the local decision state at those checkpoints. Issues #4 and #10 were later closed in GitHub on 2026-08-17; the current issue status and remaining implementation gates are recorded in section 8.

- `[DONE]` Record approved Round 1 decisions D-001 through D-003 with consequences and follow-up dependencies; this checkpoint kept Issue #4 open pending final closeout.
- `[DONE]` Record approved Round 2 decisions D-004 through D-006 with consequences and explicitly open deferred details; this checkpoint kept Issue #4 open, while Issue #10's independent relationship was closure-ready locally and future integration remained owner-dependent.
- `[DONE]` Record approved Round 3 decisions D-007 through D-009 with consequences and explicitly open expert architecture and implementation details; this checkpoint kept Issue #4 open, while Issue #10's independent relationship was closure-ready locally and future integration remained owner-dependent.
- `[DONE]` Add `docs/architecture/rootark-bielos-relationship-contract.md` and `docs/architecture/zero-knowledge-migration-contract.md` for the high-risk relationship and zero-knowledge boundaries; these are architecture/threat-model deliverables, not runtime implementation or product acceptance.
- `[DONE]` Synchronize this plan tree with the accepted relationship, zero-knowledge, and parity documents while preserving owner-dependent choices, current implementation limitations, and dated local decision states as historical evidence.
- `[BLOCKED]` Do not silently reinterpret old implementation as the final product contract.

## 6. Feature backlog

Issue: #6

All items below are candidates, not commitments.

### Phase 11 backlog reconciliation — 2026-08-16

- `[ACCEPTED-LOCAL]` `PHASE_11_BACKLOG_RECONCILED` is recorded in `docs/roadmap/phase-11-backlog-reconciliation.md` for the exact accepted Phase 10 starting SHA `76f2a02cf6e3872ab2d7b61ff617021daf893c61`.
- `[DO NOT IMPLEMENT YET]` The canonical nine-item matrix maps current evidence, status, prerequisites, security boundaries, owner decisions, implementation boundaries, acceptance, validation, dependencies, and the required separate future issue for every candidate.
- `[DO NOT IMPLEMENT YET]` TOTP is reconciled to accepted Phase 10; bidirectional sync and WebDAV mutations target Phase 12; search, previews, PWA/clients, groups, and admin UX target Phase 13; deployment prerequisites target Phase 14. At the 2026-08-16 reconciliation, naming and branding remained an owner decision; Issue #4 resolved the product name as `Root.ark` on 2026-08-17, and any future visual rebrand remains a separate owner/product decision.
- `[HISTORICAL SCOPE]` No Phase 12+ source, test, migration, UI, dependency, synchronization, WebDAV, deployment, or product implementation was authorized by that reconciliation turn; later phase-specific authorizations and evidence are recorded below.

### Phase 12: ZK sync and local WebDAV bridge — 2026-08-16

- `[ACCEPTED-LOCAL]` Add the versioned client protocol with stable IDs, deterministic allow-listed metadata, AES-256-GCM/AAD envelopes, key epoch/compartment/device context, Lamport revisions, create/update/move/delete tombstones, and base-revision conflict semantics.
- `[ACCEPTED-LOCAL]` Add an atomic durable pending/seen journal with restart recovery.
- `[ACCEPTED-LOCAL]` Add the loopback-only bearer-protected local WebDAV bridge with containment/symlink/traversal checks, safe PROPFIND/GET/PUT/MKCOL/MOVE/DELETE, journal callbacks, and DELETE-to-trash behavior.
- `[ACCEPTED-LOCAL]` Add the authenticated, bounded, opaque `/sync/v1/objects` routes, including DELETE tombstone persistence, with per-user authorization, atomic persistence, conflict/replay/stale rejection, and no decryption/key handling; existing public WebDAV routes remain unchanged.
- `[ACCEPTED-LOCAL]` Record the independent 65/65 Phase 12 focused gate; the local executable slice passes 4/4. Broader dependency/provider/browser/production validation remains separate.
- `[BLOCKED]` Provider/browser/production validation, deployment hardening, release acceptance, and remote/owner review remain external to this local implementation.

### Phase 14: Deployment/adapters/resilience — 2026-08-16

- `[IMPLEMENTED-UNVERIFIED]` Add standard-library `/health` and fail-closed `/ready` adapters for JWT, explicit TOTP policy, master-key, and provider-critical configuration; responses are unauthenticated and sanitized.
- `[IMPLEMENTED-UNVERIFIED]` Normalize provider errors, cap retry/backoff and cancellation, provide idempotency helpers, and redact secret-bearing log/metric values.
- `[IMPLEMENTED-UNVERIFIED]` Attest protected sync records during sync-store restart, backup creation, and restore archive validation without decrypting ciphertext or accepting plaintext/key fields; preserve backup, trash, version, and route contracts.
- `[IMPLEMENTED-UNVERIFIED]` Focused failure-mode coverage is recorded in `test/phase14-deployment-resilience.test.js`; provider, dependency, native-binding, TLS, production, remote CI, and release gates remain open.

### Phase 15: Local release gate — 2026-08-16

- `[ACCEPTED-LOCAL]` Add `scripts/validate-release-gate.js` and preserve the exact Phase 14 starting SHA `bcf0861e3c6987331228816cb479ade525b3b555`.
- `[ACCEPTED-LOCAL]` Repair only the transitive `brace-expansion` lock resolution from 5.0.8 to the reviewed 5.0.9 registry tarball and integrity; package manifest parity and audit threshold remain unchanged.
- `[ACCEPTED-LOCAL]` The controlled pre-commit matrix records 13 passed, 0 failed, and 1 expected clean-worktree block. It covers lock/provenance, syntax, artifacts, diff, secret-material patterns, Phase 9 crypto, Phase 10 auth/TOTP, Phase 12 sync/WebDAV, Phase 13 client/groups, Phase 14 readiness/attestation, backup/restore, high-severity audit, and ciphertext-only evidence.
- `[BLOCKED]` Provider credentials/interoperability, browser/device behavior, live production/TLS/rollback, remote CI for the final commit, product approval, publication, and independent Phase 16 review remain external gates.

### Phase 16: Final security/quality review — 2026-08-16

- `[ACCEPTED-LOCAL]` Protocol v2 metadata AAD/schema enforcement, recoverable WebDAV overwrite journaling, bidirectional encrypted sync, strict client/offline boundaries, protected index/preview identity binding, and approved `rootark-zk-1` opaque group wraps are implemented and locally reviewed.
- `[ACCEPTED-LOCAL]` The controlled final-head cross-phase matrix recorded 66/66 tests passed, with separate realtime transport 4/4 and upload-security 12/12 boundary runs; syntax validation recorded 116/116 passed. WebDAV PUT has a distinct durable mutation event and explicit protocol-v2 translation, and the browser protected store now has an in-memory session hook.
- `[BLOCKED]` Canonical full `npm test` was attempted but remains blocked by the unavailable `better-sqlite3` native binding in the disposable install; remote CI, browser/provider/live-production/TLS, owner approval, and release evidence remain external.
- `[RECONCILED — 2026-10-06]` The previously unnamed Draft-PR statement cannot be mapped to a current live PR. PR #96 is merged; PR #95 remains open with its current CodeQL and Security Regression checks passing, while Issue #94's multi-process/replica enforcement gate remains unresolved. Merge state is not release authorization; no Phase 17 item is created or inferred.

### Authentication and administration

- `[ACCEPTED-LOCAL]` 2FA/TOTP Issue #9 is implemented and security-reviewed within the bounded local scope; final independent evidence is 52/52 focused and 616/616 broad tests, with remote/publication/release acceptance remaining separate.
- `[DO NOT IMPLEMENT YET]` Recovery and session-management UI.
- `[ACCEPTED-LOCAL]` Phase 13 adds authenticated group CRUD/membership with an atomic JSON store; `manageUsers` is required and folder `groupIds` add membership access without changing individual sharing.

### Search and previews

- `[DO NOT IMPLEMENT YET]` SQLite FTS5 content indexing.
- `[DO NOT IMPLEMENT YET]` Advanced filters.
- `[ACCEPTED-LOCAL]` Protected client index and preview services use browser AES-256-GCM and local decrypt-before-search/render; server search/preview behavior remains unchanged.
- `[DO NOT IMPLEMENT YET]` Thumbnail generation and lifecycle.

### Clients and protocols

- `[ACCEPTED-LOCAL]` Installable public-shell PWA, service-worker cache exclusions, encrypted client-local offline queue boundary, and opaque Phase 12 browser protocol adapter are present.
- `[ACCEPTED-LOCAL]` Bidirectional encrypted synchronization is implemented by the protocol-v2 `SyncEngine`; provider/browser/production acceptance remains external.
- `[ACCEPTED-LOCAL]` Deterministic remote-wins conflict handling, tombstones, retry, and deletion sync are covered by focused engine tests.
- `[ACCEPTED-LOCAL]` The protocol-v2 `sync:start` entrypoint runs the bidirectional engine; the legacy uploader requires an explicit development-only opt-in.
- `[ACCEPTED-LOCAL]` WebDAV PUT/MOVE/DELETE mutation events translate into strict protocol-v2 journal operations with trash/rollback protection.
- `[DO NOT IMPLEMENT YET]` Mobile client or mobile-specific strategy.

### Product and interface

- `[DO NOT IMPLEMENT YET]` Future visual rebrand or route/branding migration; none is authorized by the product-name decision alone.
- `[ACCEPTED-LOCAL]` Minimal groups admin section and protected-search/offline status panel are wired into the existing UI; no redesign was performed.
- `[DO NOT IMPLEMENT YET]` New product features proposed casually in chat without discovery and issue creation.

## 7. Documentation and release readiness

### Phase 7.0: Documentation synchronization

- `[LATER]` Rewrite README to match the actual stack and capabilities.
- `[LATER]` Add safe setup and environment-variable documentation.
- `[LATER]` Link backup, migration, trash, WebDAV, sync, scanning, and security documents.
- `[LATER]` Clearly label MVP limitations and unvalidated claims.
- `[LATER]` Remove references to dependencies or architecture that no longer exist.

### Phase 7.1: Release gate

- `[ACCEPTED]` Phase 8 independent security verdict is `PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`; the bounded Phase 9 foundation is now `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED`, while Phase 15 remains `RELEASE_GATE_BLOCKED_ENVIRONMENT`.
- `[BLOCKED]` Critical security findings closed or explicitly accepted.
- `[BLOCKED]` Repeatable tests and CI pass for the exact release SHA.
- `[BLOCKED]` Disposable operational validation completed.
- `[BLOCKED]` Backup and restore procedure proven.
- `[BLOCKED]` Secrets and generated data excluded.
- `[BLOCKED]` Deployment exposure and TLS/reverse-proxy configuration documented and verified.
- `[BLOCKED]` Product trust model and intended audience explicitly approved.
- `[BLOCKED]` Known limitations published honestly.

## 8. Immediate execution order

Issues #1, #2, #3, #4, #6, #7, #9, #10, and #11 were closed in the live repository state by 2026-08-17; their dated checkpoint notes remain historical evidence and do not imply that separately tracked future features are implemented.

1. `[NEXT]` Measure JSON/SQLite parity and migration/restart behavior with disposable fixtures; native binding availability and final SQLite production policy remain open.
2. `[DONE]` Structured product discovery Rounds 1 through 3 and decision D-010 are recorded; Issues #4 and #10 were closed on 2026-08-17. Future implementation still requires a separate approved issue and its prerequisites; Issues #63 and #64 do not authorize implementation.
3. `[BLOCKED]` Approve individual future features only after stabilization and discovery. Issues #6 and #9 were closed on 2026-08-17; any remaining or new feature work still requires its prerequisites, owner decisions, and a separate approved issue.

## 9. Plan-tree update rule

When completing a task:

1. verify the actual final commit and branch;
2. record the exact validations performed;
3. distinguish passed, failed, blocked, and not run;
4. update only the affected plan-tree items;
5. do not erase historical limitations;
6. link the PR, issue, validation report, or architecture decision;
7. select the next item based on remaining risk, not novelty;
8. stop instead of inventing filler phases.
