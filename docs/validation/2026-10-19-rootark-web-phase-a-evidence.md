# Root.ark Web-First Recovery Phase A Evidence

**Evidence date:** 2026-10-19
**Status:** `IN_PROGRESS` — evidence-only foundation; independent review pending.
**Scope:** Owner-approved Phase A plan tasks 1–4. This document records test-only and read-only evidence. It does not establish production recovery, fresh authorization, or release readiness.

## Task 1 — Owner policy record

- Added `[DECIDED]` D-011 to `docs/product-discovery.md` without rewriting D-006, D-008, or D-009.
- D-011 records web-first temporary encrypted transfers, Android remaining on the roadmap, no new Windows/Linux desktop app, access to already downloaded/exported files offline, and online fresh authorization for new transfers, downloads, recovery, and device changes.
- Browser key custody requires independent verification. Both approved recovery paths remain: the user's password-protected emergency package and previously trusted devices. D-008 retention is separate from transfer TTL; no transfer TTL is selected.
- Windows Node.js `v22.22.1`, 2026-10-19: `node --test test/issue-65-web-policy-record.test.js` first returned **2 failed** because D-011 was absent (RED), then **2 passed, 0 failed, 0 skipped** (GREEN).
- Task commit: `2af24c98953de35fa81949db0635c55e6ff3082d`.

## Task 2 — Browser capability evidence only

- Added the test-only `assessWebRecoveryEvidence(record)` classifier. Its only statuses are `UNVERIFIED` and `CANDIDATE_FOR_INDEPENDENT_REVIEW`; output contains only a status and bounded reason strings. It cannot return a production authorization, freshness result, trusted-device token, or approval.
- The evaluator accepts only the documented evidence fields, requires a plain object with own data properties, rejects unexpected/missing fields and sensitive blobs, and retains unknown observations as `UNKNOWN`.
- Added a local-only manual probe. A button click is required before it collects sanitized browser-family/platform and secure-origin observations. It does not invoke an authenticator operation, create or delete credentials, persist results, or transmit data. API presence is labeled as feature presence only and is not treated as a PRF result or proof of key custody.
- Windows Node.js `v22.22.1`, 2026-10-19: the evaluator test first returned **1 failed** because the module was absent (RED). The probe-safety test first returned **1 failed** because the probe was absent (RED). After the implementation, `node --test test/issue-65-web-capability-evidence.test.js` returned **6 passed, 0 failed, 0 skipped** (GREEN).
- **Real browser/authenticator evidence: `NOT_RUN`.** No browser version, browser OS/key-store behavior, WebAuthn PRF result, credential synchronization behavior, profile restore result, authenticator operation, or independent platform review was observed in this phase. The probe was created for a future explicit manual observation; its code and unit tests do not establish browser support.

## Task 3 — Online/offline policy evidence

Pending.

## Task 4 — Readiness and validation matrix

Pending. The final report will bind the validation results to the exact tested source SHA and list remaining integration blocks.

## Current blocks

- No real shared linearizable CAS, independently pinned terminal-status authority, durable witness/reservation ledger, or protected-content admission gate is selected or verified.
- No browser secure key custody, rollback-resistant high-water storage, browser KDF profile, browser HPKE/Ed25519 interoperability, or trusted-device enrollment is proven.
- End-to-end protected-content recovery, Android runtime/interoperability, migration, and transfer TTL policy remain out of scope or unselected.
- Independent security review, complete repository CI/release checks, merge, production deployment, and issue #65 acceptance remain pending/not authorized.
