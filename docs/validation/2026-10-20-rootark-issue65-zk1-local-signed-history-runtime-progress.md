# Root.ark #65 — signed zk-1 v2 manifest archive, local runtime phase

**Date:** 2026-10-20
**Worktree:** `E:\servidor\.worktrees\zk-dual-recovery-20261019`
**Baseline HEAD:** `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`

## Delivered

A separate opt-in **development-only** authenticated archive now uses the
preexisting normative `rootark-zk-recovery-manifest-v2` signature, canonical
CBOR, transition and identifier verifiers. No novel cryptographic manifest
format was invented:

- `src/services/zk1LocalSignedHistoryStore.js`: durable SQLite WAL +
  `synchronous=FULL` ledger keyed by authenticated owner and exact
  `(account_id, compartment_id, keyring_id)`. It stores only canonical
  publicly signed manifests/digests, operation IDs and previously used
  identifiers, not keys, password or protected content. Every append
  verifies the signed `zk-1` transition, account/compartment scope,
  previous digest, exact revision, actor authorization, identifiers and
  bounded admission lifetime **before** attempting an atomic immediate
  transaction. Within that transaction, it re-checks expected head
  revision and digest and appends exactly one revision, or rejects all
  changes. The local history is not pruned to make room for identifier
  reuse. A corrupted retained row/digest/size chain fails closed.
- The store exposes `verifyPublicHistory` only after the caller provides a
  separately trusted pinned witness **base** and matching receipt, rather
  than deriving a trust anchor from the local database. Where recovery
  package activation occurs, it requires exact matching opaque package
  envelope bytes before calling the existing public history verifier.
  Its result must retain `authorizationVerified=false` and
  `freshnessProven=false`. It cannot authorize a protected operation.
  Unsupported later-package-activation verification fails closed.
- `src/routes/zk1LocalSignedHistoryRoutes.js` exposes a restricted
  development API at `/zk-dev/v1/zk1-history`: POST a signed canonical
  manifest with exact expected revision/digest; GET `/head` and individual
  `/entries/:revision`. All routes require the existing session
  authentication and file permissions; writer requests bind the body
  account to the active authenticated account. Responses explicitly state
  `authority: LOCAL_ONLY_UNWITNESSED`, set `Cache-Control: no-store`,
  and cannot return any secret. Invalid scope, signature, replay,
  wrong account and stale expected head fail closed.
- `server.js` mounts these API routes only when
  `ROOTARK_ZK_DEV_VAULT_ENABLED=true` **and** `NODE_ENV` is
  `development` or `test`, next to but in a separate database from the
  opt-in encrypted browser vault. Existing ordinary file routes,
  backup paths, cloud providers and migration remain unchanged.

## Evidence

- Initial RED: missing signed-history store and routes. Subsequently
  **8/8 targeted tests passed** covering valid signed initialization,
  canonical digest equality, rejected tampering, account isolation,
  rejected duplicate signatures/revisions, concurrent append from
  independently opened SQLite connections, exact restart persistence,
  malformed retained row detection, independently supplied witness-base
  verification and package-envelope requirements, with authenticated
  HTTP routes.
- Full real Node/Express server boot in a disposable directory confirms
  that signed-history routes exist behind existing authentication and
  reject invalid scope. The separate encrypted-file test still passes.
- #65 focused suite plus Packet B mock: **192 passed, 0 failed on Windows**;
  **190 passed, 2 browser-only platform skips, 0 failed in WSL**.

### Security follow-up under independent review

The first independent review identified the following concrete risks and
these corrections have been implemented:

- **HTTP/parser bound mismatch:** the actual Express app initially imposed
  the 100 KiB default JSON body limit on the new signed-manifest POST
  despite supporting up to 8 MiB canonical CBOR. A true full-app test
  observed RED HTTP 413 for 150 KiB synthetic signed-manifest JSON; GREEN
  now skips the global default parser **only** for the opt-in signed-manifest
  POST and uses `express.json({limit:"11mb"})` inside that route **after**
  session authentication and upload permission checks. The real app accepts
  this bounded authorized JSON and then rejects invalid CBOR with HTTP 400.
  Other API body limits are unchanged and anonymous clients do not trigger
  the exceptional 11 MiB parsing path.
- **Unbounded quadratic retained-ID comparison:** converted repeated
  `Array.includes` inventory checks on every append to `Set.has`.
- **Incomplete ID ledger corruption detection:** before appending another
  transition, the store now re-decodes every retained signed manifest
  and rebuilds the exact union of operation, device, key, wrap and
  challenge identifiers. A mismatch against the separate SQLite
  retained-identifier table fails closed with `ZK1_HISTORY_CORRUPT`,
  rather than relying only on the latest manifest's current keys.
  Adversarial test deletes an old operation identifier and observes
  RED→GREEN refusal. This is corruption detection, **not protection
  against a malicious full-database snapshot rollback**.
- HTTP regression also rejects a forged actor signature (422) even with
  a syntactically valid canonical manifest, and real server E2E signs a
  fresh initialization with an ephemeral Ed25519 key, commits it through
  the actual authenticated route, retrieves its head, and rejects
  replayed initialization.
- **Consistent read snapshots:** initial metadata reads used distinct
  SQLite SELECTs, so another connection's valid append between reading
  the head and reading its entries could spuriously raise
  `ZK1_HISTORY_CORRUPT`. A deterministic concurrent two-handle test
  reproduced the failure. GREEN now reads head, entries and aggregate
  counters within a single deferred read transaction; append preflight
  also reads its head, historical rows and used identifiers in a single
  coherent transaction, while the write CAS remains a separate immediate
  transaction. This prevents false corruption during legitimate local
  concurrent writes without claiming multi-host consensus.
- **Account/global resource caps:** default maximum 8 signed scopes per
  owner, 64 scopes across the local store, 128 MiB of retained signed
  history per owner and 512 MiB global. These caps are checked both before
  public-signature verification and under the final immediate write
  transaction so competing writers cannot bypass them. The per-scope
  normative history capacity limit remains in addition. A synthetic
  RED→GREEN regression verifies rejected extra scope/bytes never mutate
  an existing signed head.

The signed history, HTTP and real server targeted suites passed
**12/12** after these corrections. The broader test suite excluding
`upload-security.test.js` passed in a preceding revision of this
uncommitted worktree with **1,556 passed, 56 skipped, 0 failed**;
the separate upload-security suite previously passed **133 passed,
1 skipped, 0 failed**. Neither is an exact-final-commit unsplit release
gate. Whole-project regression results must be tied to their actual
candidate, not borrowed as proof from an earlier worktree state.

**Final scoped rerun after the quota, coherent-snapshot and
post-authorization parser changes:** all #65 tests and Packet B mock:
**195 passed, zero failed/skipped on Windows**; **193 passed, 2 Edge
platform skips, zero failed on WSL**. `npm run validate:syntax` checked
**267 files, 0 failures**; `npm run validate:artifacts` and
`git diff --check` both exited 0. The narrowed signed-history and
real-server integration set independently passed 12/12 before this
full #65 rerun. Earlier green broad and upload-security runs are
historical evidence, not an exact final release claim.

## Not complete, not a production-security claim

This **local metadata ledger is not the #65 required shared, linearizable,
independently witnessed recovery CAS**. Its SQLite writer lock is local to
the database file and proves no cross-host replication, independent
status authority, witness freshness, backup rollback resistance, or
physical admission/egress fence. A malicious operator can replay an
entire self-consistent old SQLite snapshot; valid old signatures alone
cannot detect this. `verifyPublicHistory` only demonstrates anchored
historical public signatures and is explicitly insufficient for trusted
device authorization or a fresh recovery gate.

Remaining complete-issue gates: a separate trust-root-pinned status/CAS
authority and witness with real failure topology; finalized `zk-1`
client key/epoch/wrap lifecycle and protected-content I/O integration;
independent anti-rollback high-water storage or always-online verified
witness; complete user-approved reversible migration across legacy modes
and storage/backups; cross-device/physical acceptance; an exact-candidate
unsplit CI/release gate and crypto review. Do not close #65 or claim a
secure Zero-Knowledge runtime on the basis of these tests.

## 2026-10-20 follow-up: package activations and pure witness/history consistency

The independent reviewer reproduced a **P2 feature-completeness failure**:
signed `initialize rev1 → enroll-device rev2 → register-package rev3`
verified as a trusted-device history but failed the public archive's
package-envelope verification. The crypto verifier incorrectly assumed
that the first recovery-package envelope must refer to the initial
history base revision.

**RED→GREEN change:** the public verifier now resolves each supplied
package envelope at its **actual activation transition** and invokes the
existing `verifyRecoveryPackageActivation` check, which compares the
exact signed predecessor revision and digest, activation revision,
operation ID, package ID, activation context and envelope digest.
Missing, altered, reordered, duplicate, unrelated and unused supplied
envelopes fail closed. The public archive also demands an envelope for
`compromise-package` forward-rotation (not only registration and
replacement). The existing trusted-device proof can still verify the
device epoch MAC without a recovery-package file, with
`packageEnvelopeBound=false`; callers requiring recovery-package
retention proof must check that result separately.

Independent read-only review reproduced valid delayed registration and
registration→replacement/compromise sequences and wrong-envelope cases,
with **no residual P1/P2 in the bounded package-binding correction**.
The `test/issue-65-recovery-history-v2.test.js`,
`test/issue-65-recovery-package-compromise.test.js` and signed store
suite passed **35/35**.

Another new **pure cryptographic composition** module,
`src/crypto/rootark-zk-witness-history-consistency-v1.js`, accepts a
branded, independently signed/public-verified history and a separately
pinned Ed25519 witness head, challenge nonce, expected scope and
independent minimum head. It checks the existing strict witness-wire
signature verifier and **requires the receipt's exact revision and
manifest digest to match the verified history**. A valid witness
signature for a different historical head is insufficient. The result
deliberately declares `authorizesRecovery=false` and
`authorizesProtectedIo=false`.

An adversarial test found a mutable-input timing bug on the first
implementation: the caller could supply incorrect raw witness bytes and
replace them with valid bytes in a microtask while the first asynchronous
branded-history check ran. **RED→GREEN:** exact raw, nonce, pinned
witness key ID, scope, floor and branded history fields are copied
**before the first await**; the branded history is verified both before
and after the signed witness verification. The targeted witness and
history suites pass **10/10** after this fix. The module itself cannot
fetch a genuinely independent witness, guarantee nonce generation or
uniqueness, pin trust roots on physical devices, or enforce protected
content I/O admission/egress. Those are still separate blockers.

## Exact local regression outcome after these changes

The reviewer completed a second bounded, independent READ-ONLY inspection
of the corrected witness/history composition: no confirmed residual P1/P2
in its local pure cryptographic scope. Separate adversarial checks rejected
wrong floor/high-water, changed digest, replayed nonce under a new
challenge, substituted witness identity and mutation of the branded
history during asynchronous verification.

- #65 focused suite + Packet B mock, **Windows: 201/201 passed**, 0 failed,
  0 skipped; **WSL: 199 passed, 2 Edge/Windows-only skipped**, 0 failed.
- One complete, unsplit Windows run of every discovered
  `test/*.test.js`, **including the full upload-security test**, with
  `node --test --test-concurrency=2 --test-reporter=spec`: **1,754 tests;
  1,697 passed, 57 skipped, 0 failed**, exit 0. This replaces an earlier
  inconclusive combined-test attempt **for the current uncommitted local
  code candidate**. It does not establish GitHub CI or independent
  infrastructure readiness.
- `npm run validate:syntax`: **269 files checked, 0 failed**, exit 0.
  `npm run validate:artifacts`: exit 0.
  `git diff --check`: exit 0 (preexisting harmless CRLF warnings);
  `node --check src/crypto/rootark-zk-witness-history-consistency-v1.js`:
  exit 0.

**Not an issue closure.** The exact local worktree is still uncommitted
with preexisting tracked edits and untracked lab files. An isolated
SQLite archive, an optional browser-development vault and a pure
witness-proof checker do not implement the missing independent
CAS/status/witness service, physically enforced epoch admission, real
device high-water guarantees, fully authorized reversible legacy
migration across backends and backups, or client-side zk-1 recovery
integration. No commit/push/merge/release or deletion/migration of user
data occurred in this pass.
