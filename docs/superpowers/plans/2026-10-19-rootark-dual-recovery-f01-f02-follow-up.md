# Root.ark Dual Recovery — F-01/F-02 Correction Report

**Status:** `CORRECTED_LOCALLY — INDEPENDENT_REVIEW_REQUIRED — NOT_READY_FOR_MERGE_OR_INTEGRATION`

This report supersedes the earlier no-blocker conclusion for the reviewed history-verification API. It records the bounded correction requested by the independent review; it is not itself an independent security review or cryptographic certification.

## Exact source and range

- Repository: `E:\servidor`; worktree: `E:\servidor\.worktrees\zk-dual-recovery-20261019`.
- Branch: `cdx/rootark-dual-recovery-20261019`.
- Correction base: `22dfc78ae740ef22854f61ca89976ac62685a3e5`.
- Reviewed source before correction: `6f75d331a2577fe4a6c722448a84c9a5d4994f0c`.
- First correction commit: `7ec22ceada65c6006db5bfc9347c4dd0b34e9193`.
- Final source commit: `7dd1c861d2b570d7bc51ce66e8054bcc431f4c07` (parent `7ec22ceada65c6006db5bfc9347c4dd0b34e9193`).
- Review the exact code range `22dfc78ae740ef22854f61ca89976ac62685a3e5..7dd1c861d2b570d7bc51ce66e8054bcc431f4c07`.

The code range changes four files: `src/crypto/rootark-zk-recovery-history-v2.js`, `src/crypto/rootark-zk-recovery-manifest-v2.js`, `test/issue-65-recovery-history-v2.test.js`, and `test/support/issue-65-recovery-v2-fixtures.js`. No production runtime adapter, storage provider, dependency, migration, or UI was added.

## Finding F-01 — future epoch recovery from package wraps

Package history verification now accepts epoch keys only through the package snapshot's base epoch. It rejects caller-supplied future epoch keys. For a later `revoke-device` or `compromise-package` transition, it validates the signed transition and exact HPKE context, opens the recovery wrap with the matching package private key, derives the missing next-epoch key, and verifies the transition MAC with that key before adding it to the verified history. A valid HPKE wrap carrying the wrong epoch key fails the MAC check. Malformed, misbound, duplicate, wrong-recipient, or unopenable wraps fail closed.

The recovery package result proves this bounded library's package-wrap/history checks. It does not prove user export/retention, decrypt the package envelope by itself, or recover protected file contents end to end.

## Finding F-02 — independent verification contracts

The history library now exposes three distinct contracts:

| API | What it verifies | Secret inputs | Result and signer use |
|---|---|---|---|
| `verifyRecoveryHistoryPublicV2` | Witness-anchored base plus public signed transition chain and structural invariants | None | Public-state result only; no authorization or package-recoverability claim; cannot sign a transition |
| `verifyTrustedDeviceRecoveryHistoryV2` | Signed chain and transition MACs using device-held epoch keys | Epoch keys; no recovery-package private keys | `trusted-device` provenance; device authorization/signing accepts this mode |
| `verifyRecoveryPackageHistoryV2` | Signed chain, MACs, and actual recovery-wrap opening, deriving missing future epochs as needed | Base-snapshot epoch keys and matching package private key(s) | `recovery-package` provenance and package-wrap verification; package actor use requires this mode |

The original `verifyRecoveryHistoryV2` entry point remains a strict package-recovery alias, preserving its prior stronger wrap-verification contract. Trusted-device callers must choose the explicit device API. Public-only results and trusted-device results cannot claim package recoverability.

## RED/GREEN evidence

The first Windows Node `v22.22.1` run reproduced both supplied findings without fixture bypasses: 13 history tests passed and the two new regressions failed. F-01 failed with `KEY_COVERAGE_INCOMPLETE` at the pre-open `keysThrough(nextEpoch)` check. F-02 failed with `KEY_COVERAGE_INCOMPLETE` while constructing the recovery-package key map after the package key was omitted.

A compatibility regression then failed with `HISTORY_INVALID` when the old generic entry point was temporarily routed to device-only verification. It passed after the original entry point was restored as the package-verification alias.

Final focused validation on the exact source tree: **107 tests passed, 0 failed, 0 skipped** on each platform:

- Windows portable Node `v22.22.1`.
- WSL Ubuntu Node `v22.22.1`.

The 11 suites were `test/rootark-zk-1.test.js`, `test/issue-65-zk-keyring.test.js`, and the nine `test/issue-65-recovery-*.test.js` suites: state model, rootKey compatibility, package, package compromise, manifest v2, KDF, history v2, history capacity, and authorization. The history regressions use runtime-generated keys and real HPKE operations. `git diff --check` passed for the code changes before commit; the final source range remains available for independent inspection.

## Review limitations and blocked integrations

- This implementer did not perform or claim an independent final review. Native reviewer model/effort provenance was not verified. Review the exact source range above independently before any merge or integration.
- The full repository `npm test`, Windows release gate, hosted CI, CodeQL, independent Argon2id vectors, and minimum-hardware latency/RSS validation were not run for this correction range. Earlier incomplete full-gate attempts are recorded in `2026-10-19-rootark-dual-recovery-revision3.md`; they are not treated as passing.
- Repository source has no verified shared CAS provider, independently pinned truthful CAS-status authority, deployed witness/reservation ledger, OS-backed device key custody, or rollback-resistant client high-water store. Do not fall back to single-node SQLite or JSON.
- Browser/mobile integration, pairing and package-retention UX, package envelope export/read-back on a supported client, end-to-end protected-content recovery, external v1 `rootKey` consumer audit, migration, and production remain blocked.
- Issue #65 remains open. No push, PR, merge, deployment, real-data migration, or issue update was performed or authorized by this correction.

## Independent review questions

1. Confirm that the package verifier's base-key-only contract and post-unwrap MAC validation resolve F-01 without permitting caller-supplied future epoch keys to bypass wrap authentication.
2. Confirm that public-only, trusted-device, and package-recovery result brands remain distinct at every signer call path and cannot overstate package recoverability.
3. Confirm the preserved generic API alias is an appropriate compatibility boundary; no external consumer inventory has been completed.
4. Identify any additional regression cases required before accepting this bounded library correction. Runtime, persistence, device-storage, and production blockers remain outside this review range.
