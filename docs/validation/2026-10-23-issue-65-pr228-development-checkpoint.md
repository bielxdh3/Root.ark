# Issue #65 / PR #228 — Zero-Knowledge v1 development checkpoint

**Observed on 2026-10-23. This is a SHA-scoped development record, not an acceptance certificate.**

## Continuation published at `f117eb4` (same day)

### Further DEV patchset tested locally after `d527cf0`

An isolated integration branch validated three additional commits before
fast-forward publication. Their hosted status must be checked by exact SHA:

- `22f7a2b`: reconcile a lost recoverable ciphertext PUT acknowledgement by
  one exact signed GET; never repeat PUT, never release an owner-held recovery
  bundle for forged or unavailable readback
- `7f44668`: opt-in, private and bounded archive member-to-historical SQLite
  version joins, retaining explicit UNKNOWN on mismatches, history gaps and
  derived references; no owner-signed corpus completeness or deletion
- `237392b`: normal-browser opt-in local AES-GCM metadata decrypt/listing only
  after independently owner/witness/CAS-verified exact catalog head, scoped
  AAD and nonextractable key; clear on logout/close/reanchor

The three commits together passed **80/80 targeted Node24 tests**, including
real Edge, HTTP/SQLite second-device readback, logout and adversarial tamper;
syntax **600/0** and runtime artifacts PASS. Node22 targeted validations for
the component workers passed separately, but that is not equivalent to a
Node22 complete integrated verdict. A durable, encrypted local pre-PUT journal
is still needed to recover when PUT ACK and signed GET both remain unavailable
after losing the browser session. Witness revocation fencing across actual
CAS/FLOOR physical writes remains another active development blocker. A new
full-suite and fresh hosted checks are required after publication.

### Follow-up CI defect and repair: `d527cf0`

The hosted Ubuntu Node22 canonical test run at `f117eb4` completed with
**2,558 tests / 2,406 PASS / 8 FAIL / 144 SKIP**. All eight failures shared
one test-fixture error, `TypeError: archiver is not a function`, in the new
recoverable legacy ZIP graph tests. The repository lockfile requires Archiver
8's `ZipArchive` constructor, not the removed factory API. The test-only
correction was committed and fast-forward published as
`d527cf06229e9b64e1db8198547c86a7db5ea7ad`. With the corrected fixture,
the related legacy test selection passed **18/18 on Windows Node24 and 18/18
on Windows Node22**. Syntax **597/0**, runtime artifacts **PASS**. The new
SHA's hosted canonical runs must still complete; do not transfer the earlier
result to them. CodeQL policy remains red with 87 static annotations on the
previous SHA, and confirmed/false-positive findings require itemized review.

The branch advanced by fast-forward from `5827833` to
`f117eb4897ee8841a3928eae80d679fad7f8ffde`, adding the following
independently committed and reviewable development changes:

- `af28dac`: deterministic backup-lock contenders test handshake instead of a
  clock-based race; 33 focused Windows Node24 tests and 12 repeated races pass.
- `772c90b`: coalesced provider mutation queue sweeps and bounded retry
  cooldown; separate real child lifecycle-lock contention and 2 focused
  integrated tests pass; durable pending intent remains intact.
- `e3f0e2e` and `88eff1e`: opt-in, bounded read-only legacy ZIP central
  references and recoverable graph, linked to SQL checksum/manifest and local
  derived candidates, always declaring unknown coverage and no cutover.
- `a0499f1`: S3 provider refuses foreign single-link source substituted between
  original preflight stat and pinned descriptor, including bounded ZK input.
- `891645d`: offline historical endorsement issuer selects independently
  witnessed owner approval signer rather than the static initial owner key.
- `c67b63d`: pre-grant legacy checkpoint migration test reconstructs the exact
  historical SQLite schema and rejects extra signer grants instead of weakening
  the strict on-disk preflight.
- `c356ac7`, `2a42261` and `f117eb4`: witnessed historical A129/B130/B131
  owner approval across CAS/FLOOR, actual revocation before finalization,
  immutable historical signer cross-check and rotated local publish contract.

On the integrated source before publishing `f117eb4`, Windows Node24 targeted
V2 mTLS, real browser, recovery, stage and hostile SQLite tests passed **8/8**;
Node24 legacy ZIP, source-inventory and S3 preflight race tests passed **25/25**;
`validate-syntax.js` passed **597/0** and runtime artifacts passed. Node22
historical migration regression was reproduced and fixed by an isolated worker
in WSL; it still requires the exact-head hosted Ubuntu suite for a complete
validation verdict. The GitHub CI workflows for the new SHA started and were
**pending** when this addendum was written. The local `npm test` full suite
was also rerunning, and its final result must be recorded separately.

Current unresolved development risks include witnessed revocation TOCTOU
between authority check and SQLite commit, absent proven independent durable
custody across remote providers/multi-host, incomplete global legacy corpus
inventory/cutover semantics and outstanding static CodeQL findings. This
remains **OPEN/DRAFT**, never a production-readiness or 100% implementation
declaration.

## Published source and state

- PR branch `cdx/rootark-dual-recovery-20261019` was observed at
  `58278338c1666346e513ed30c15d41a4c9e61fac`, with PR #228 `OPEN/DRAFT`
  and issue #65 `OPEN`. No merge, deploy, production activation or legacy cutover.
- Verified additive commits include `eb1138f` (WebDAV source-ctime fence),
  `9a06ffb` (SQLite immutable historical signer grants), `d1cfef9` (remote
  CAS/FLOOR SQLite fd pin), `2fbbd21` (conditional strong WebDAV ETags),
  `650199d` (per-sequence historical owner-approver evidence), `2a6dda4`
  (terminal CAS bootstrap cannot adopt a preexisting journal), and `5827833`
  (remote V2 authority owner signer selected from witnessed recovery history).
- All published commits in this continuation have author and committer
  `bielxdh3 <bielxdh3@gmail.com>` and one `Co-authored-by: Codex
  <codex@openai.com>` trailer. Remote publication was fast-forward only.

## Executable evidence (do not transfer across SHAs)

| Code selection | Evidence | Limits |
| --- | --- | --- |
| WebDAV ctime and strong ETag at `2fbbd21` | 8 PASS / 0 FAIL on each of Windows Node 22 and 24 | mTLS fixture; ETag does not prove third-party custody or durable remote fsync |
| Signed historical owner grants through `650199d` | Windows Node 22: 6 PASS / 0 FAIL; Node 24 mTLS/Edge and client tests passed | Does not by itself authorize rotated physical CAS/FLOOR publication |
| Rotated remote owner authority changes integrated before `5827833` | Node 24 combined mTLS/browser/staging: 8 PASS / 0 FAIL, syntax 591 checked / 0 failed, artifacts PASS | Requires issuance of historical v2 endorsements from the newly authenticated historical approver and further fail-stop race review |
| Hosted `2fbbd21` disposable PostgreSQL 18 | SUCCESS | Local isolated PG18 lab, not evidence of external multi-host persistence |
| Hosted `2fbbd21` JS/TS analysis and dependency review | SUCCESS / SUCCESS | Distinct CodeQL security-annotation policy check FAILED with 86 static findings; each requires classification |
| Windows Node 24 full local `npm test` at `2fbbd21` | 2,544 total: 2,374 PASS, **3 FAIL**, 167 SKIP | NOT GREEN; reported backup lock test competition and file lifecycle lock assertions, with further isolated diagnosis underway |
| Hosted Ubuntu Node 22 full at `2fbbd21` | 2,544 total: 2,399 PASS, **1 FAIL**, 144 SKIP | Failure at V2 legacy129 migration; do not misattribute to general suite or waive it |
| Hosted Windows Node 22 at `2fbbd21` | Mandatory release gates SUCCESS, canonical CANCELLED | CANCELLED is not a completed successful canonical run |

The red tests are being investigated and patched by isolated workers; a
subsequent head needs fresh complete local and hosted test evidence. Node 22
and Node 24 native `better-sqlite3` ABI builds must not be interchanged.

## Development acceptance boundaries still OPEN

1. **Historical device and owner key rotation:** a valid A129 -> B130 -> B131
   sequence needs independent per-epoch owner/signature/witness validation at
   issuer, client, browser and *both* physical CAS/FLOOR writers, with restart,
   revocation and unknown-ACK tests. Previously current-key-only checks were
   reproduced and corrected incrementally, but do not presume final cross-layer
   continuity without the complete integrated test.
2. **Authority/fencing:** verify the behavior of revocation during the four
   distributed PREPARED / CAS_COMMITTED / FLOOR_FINALIZED / CAS_FINALIZED stages
   without claiming atomic PostgreSQL x SQLite x cloud transactions.
3. **Legacy coverage:** owner-signed selection of chosen entries and strict
   physical reference inventories do not prove full-account or historical
   derived/archive/trash/backup reference coverage. Unknown remains fail-closed;
   no deletion of a legacy source or cutover is authorized.
4. **External custody and multi-host:** local mTLS, physical PostgreSQL 18,
   WAL/FULL, a signed HTTP receipt, conditional ETag and simulated providers are
   different proofs. Actual external S3, Google Drive, WebDAV and independently
   operated monotonic floor durability were not certified by these tests.
5. **Complete DEV gate:** rerun all relevant Node22/24, real Edge, Windows,
   Ubuntu, PostgreSQL18, negative/rollback suites and analyze remaining genuine
   P1/P2 CodeQL findings on the *exact final* SHA. Do not call #65 100%
   implemented or mark PR ready while any development requirement is missing.

Threat model remains compromised server/storage/DB, malicious administrator,
stolen backup, lost/revoked device, replay/rollback, corrupted ciphertext,
cross-compartment mixing, and missing recovery authority. No plaintext/key
fallback may be introduced. Android #64 and protected search #63 are out of
scope other than compatibility with these cryptographic boundaries.
