# Root.ark ZK-1 v1: threat boundary, review split, traceability

**Owner decision: approved 2026-10-26.** Source: issue #65 and integrator PR #228. This is a review/extraction contract, not production authorization, a scope reduction, or evidence of independent custody. No merge, deploy, cutover, automatic enablement, or issue closure is authorized.

## Provenance and immutable references

- Integration source: `cdx/rootark-dual-recovery-20261019` at `6da354230bbcfa8326329e3f8b2b77c84677a9bd` (565 commits against the merge base and 725 changed paths at inventory time).
- Extraction base: `Root/main` at `30168d072bbb82b9b513dccf3eae535443619046` (15 newer commits from merge base; never overwrite its package files or documentation blindly).
- Original PR #228 and all worktrees/branches remain untouched; every extracted module must retain byte-identical content unless a separately reviewed fix is necessary. Shared `server.js`, packages, routing, config and workflows require hunk-level reconciliation.

## Approved threat model

Protect content, sensitive object names/types, CEKs, recovery secrets, private identity keys, signed object/ciphertext roots, epochs, revocations and checkpoints against compromised server/storage/admin, malicious cloud provider, hostile network and previously enrolled but now revoked devices. Adversarial server/cloud can deny availability or erase ciphertext; crypto cannot guarantee external durability. Ciphertext sizes, access timing, IPs and opaque routing identifiers may leak. Compromised local browser/OS, same-user malware, privileged local ACL tampering and native trusted-host SQLite/VFS TOCTOU are not guaranteed defenses **unless they cross an enabled remote or independent trust boundary**.

**Four mandatory review amendments:**

1. Revocation requires an identified serialization/linearization point. After a confirmed revocation, no new remote protected write may commit under the stale authority. If the chosen authority cannot fence an operation, deny it; a second temporal check alone is insufficient.
2. Rollback defense requires current monotonic head/floor from a trust source independent of the potentially compromised server. Ed25519 signatures without freshness do not prove current authorization.
3. Experimental features are default-off at **UI, API and service boundaries**. Feature flags do not bypass cryptographic checks. Sync, WebDAV, preview, ordinary backups and legacy plaintext remain outside ZK mode unless explicitly proven and guarded.
4. "v1 usable" and "issue #65 complete" are different outcomes. Unproven original-scope functionality remains tracked and disabled, not silently removed from acceptance criteria.

## Ordered review PRs and dependency boundaries

| PR | Scope | Required predecessors | Mandatory proof (not only helper tests) |
| --- | --- | --- | --- |
| 1 | AES-GCM/Ed25519, canonical wire, trusted owner/device identities, recovery crypto | Root/main | Trust bootstrap never from server, wrong-key/replay/tamper/epoch tests, two documented owner-authorized recovery paths |
| 2 | Protected ciphertext object API, roots, catalog, versions, server-side downgrade fence | PR1 | Signed HTTP PUT/GET, restart, roots, opaque names and authorization failure paths |
| 3 | S3/Google Drive/WebDAV ciphertext adapters | PR2 and required crypto contracts | Exact physical IDs/version pins, GET/readback, delay/rollback/ACK-loss, opt-in only |
| 4 | PostgreSQL 18, CAS/witness, mTLS, STOP, revocation fencing | PR1+PR2 | Operation-bound physical proof, monotonic fences, concurrency/crash/restart, clear external custody prerequisites |
| 5 | Browser workspace, enrollment, protected sync/deltas/lifecycle | PR2+PR4 (+PR3 if cloud used) | Real browser and two sessions/devices, cross-route downgrade prevention, only proven features enabled |
| 6 | Offline operators, migration, backup/restore | PR2+PR4; PR3/PR5 by path | Reversible imported state, signed inventories, both recovery flows, non-destructive interrupted migrations |

Some browser primitives imported into PR1 are dependencies of cryptographic enrollment; their presence **does not** independently enable or certify the PR5 UI. Tests and code can be shared only when the dependent PR already contains them. An actual crosscut change needs one clear owning PR and a regression test.

## Issue #65 traceability (live evidence required)

| ID | Original requirement | Owner PR | Acceptance evidence | Current claim |
| --- | --- | --- | --- | --- |
| ZK01 | Client-only encryption/decryption and no plaintext or CEK on server | 1, 2, 5 | Browser HTTP E2E and negative server-leak checks | Not yet proven by this extraction |
| ZK02 | AEAD version/AAD and deterministic signed protocol | 1 | Cross-platform test vectors, tamper and scope rejection | Focused PR1 crypto tests |
| ZK03 | Owner trust import independent from server | 1, 5 | Onboarding two browsers with out-of-band pin | Pending integrated E2E |
| ZK04 | Device keys, enrollment/PoP, epochs | 1, 5 | Enrollment and replay/expired proof E2E | Focused crypto only |
| ZK05 | Revocation and rotation of current authority | 1, 4, 5 | Linearized concurrent PUT/revoke, restart, ABA tests | Requires review in PR4/PR5 |
| ZK06 | Two authorized recovery paths and key loss model | 1, 5, 6 | Client full recovery after restart from verified ciphertext, separate owner and authorized flows | Pending integrated E2E |
| ZK07 | Server-blind protected filenames and metadata | 1, 2, 5 | HTTP/database/backup inspection without plaintext | Pending |
| ZK08 | Roots, chunks, signed catalog and versions | 1, 2 | Manifest/root and persisted HTTP lookup, restart | Pending integrated E2E |
| ZK09 | Multi-device synchronization without decryption server side | 2, 5 | Two-device delta/lifecycle and strict legacy fence | Experimental until proved |
| ZK10 | Legacy sync/WebDAV/preview downgrade protection | 2, 3, 5 | Negative remote routes under strict ZK mode | Pending |
| ZK11 | S3/Drive/WebDAV ciphertext transport and adversarial readback | 3 | Exact remote IDs, tamper/replay/missing proof | Experimental; vendor durability not guaranteed |
| ZK12 | Independent monotonic CAS/witness/fencing | 4 | Actual independent custody and cross-host abort/failover | Experimental; custody external prerequisite |
| ZK13 | Physical SQL/mTLS attestation and STOP | 4 | PG18, real role permissions, challenge, adversarial restart | Pending SHA gates |
| ZK14 | Signed history, operation_id, anti-replay and rollback | 1, 2, 4 | Per-op signature/nonce, monotonic stale-head rejection | Focused PR1 crypto tests only |
| ZK15 | Backup ciphertext and key material recoverable | 6 | Full signed inventory and authorized client decrypt | Experimental, external retention not guaranteed |
| ZK16 | Pre-ZK data migration with safe ambiguity handling | 6 | Reversible journal, no destructive cutover, restart | Experimental/opt-in |
| ZK17 | Residual metadata leakage and threat documentation | 1-6 | Clearly listed and matching enabled code | Contract drafted; per-PR verification pending |
| ZK18 | Compatibility with protected search #63 and Android #64 | 2, 5 | Protocol compatibility and no duplicate mobile crypto | Pending compatibility tests |

## Mandatory gates on each exact PR head

- Relevant focused and adversarial tests **plus** complete canonical Ubuntu and Windows suites, mandatory release gates, syntax/artifact checks and CodeQL with alert-by-alert impact triage.
- A test that reproduces an exploit passing is not a security PASS. A failing Windows or CodeQL job is a blocker until fixed or explicitly dispositioned; a prior SHA's green gates are not transferred to a new SHA.
- At the inventory SHA `6da3542` on 2026-10-26: Ubuntu complete, Windows mandatory, PostgreSQL disposable, Dependency Review and CodeQL succeeded; **Windows full canonical failed 7 tests** (5 assertions, 1 runtime, 1 unknown, logged under run `40342521511`). This is the **integrator's** state, not PR1 gates.
- Release from Draft requires an external human security review. No claim of off-host custody, vendor fsync, multi-provider atomicity or formal crypto audit based on synthetic fixtures.

## PR1 partial extraction evidence (local only)

Focused Windows Node24 crypto/wire/enrollment suite: **117 PASS / 0 FAIL / 0 SKIP**, JS syntax **58 files / 0 errors**. Uses dependencies installed in the original development worktree via `NODE_PATH`; does **not** establish a clean-install/full-suite gate for this branch. Owner V2 enrollment test exercises independently pinned committed head and PoP; production authenticated UI and two complete recovery flows remain to be proved before calling PR1 ready for review. No commit publication is proof of complete acceptance.