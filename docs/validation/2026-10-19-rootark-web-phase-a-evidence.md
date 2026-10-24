# Root.ark Web-First Recovery Phase A Evidence

**Evidence date:** 2026-10-19
**Status:** `EVIDENCE_BASELINE_COMPLETE — BROWSER_ELIGIBILITY_UNVERIFIED` — evidence-only foundation; independent review pending.
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
- Adversarial cases cover unknown PRF, synchronized credentials, profile restoration/loss, deleted credentials, copied credentials, incomplete key-copy/restore testing, and an apparently positive PRF observation without independent review.
- Added a local-only manual probe. A button click is required before it collects sanitized browser-family/platform and secure-origin observations. It does not invoke an authenticator operation, create or delete credentials, persist results, or transmit data. API presence is labeled as feature presence only and is not treated as a PRF result or proof of key custody.
- Windows Node.js `v22.22.1`, 2026-10-19: the evaluator test first returned **1 failed** because the module was absent (RED). The probe-safety test first returned **1 failed** because the probe was absent (RED). After the implementation, `node --test test/issue-65-web-capability-evidence.test.js` returned **6 passed, 0 failed, 0 skipped** (GREEN).
- **Real browser/authenticator evidence: `NOT_RUN`.** No browser version, browser OS/key-store behavior, WebAuthn PRF result, credential synchronization behavior, profile restore result, authenticator operation, or independent platform review was observed in this phase. The probe was created for a future explicit manual observation; its code and unit tests do not establish browser support.
- Follow-up coverage RED: adding the explicit `PROFILE_LOST` case failed because that evidence label was not accepted. After adding it as a conservative non-candidate label, the targeted test passed. Copied credentials and profile loss remain `UNVERIFIED`.

## Task 3 — Online/offline policy evidence

The test-only fixture `test/fixtures/issue-65-web-offline-contract.json` uses schema `rootark-web-offline-contract/v1`. It separates user-controlled downloaded/exported files and already-held plaintext from new remote actions, and marks itself as policy evidence rather than runtime enforcement.

### Read-only source observations

Inspected at source HEAD `fe55dfa0907569e240a708e99b44d7a52b21c3cd`; no runtime source was changed.

- `public/service-worker.js` caches the versioned public shell, including protected client scripts. It excludes `/auth` and `/api` (as well as file, preview, sync, and other sensitive paths) from cache handling; login paths use `cache: "no-store"`. Cached shell delivery is not fresh authorization or witness proof.
- `public/client/rootark-offline-queue.js` stores normalized opaque envelopes in a local-storage queue and exposes a `drain()` operation that returns and clears them. This legacy queue does not itself establish Zero-Knowledge authorization.
- `public/client/rootark-protected-store.js` encrypts IndexedDB records with Web Crypto using a caller-supplied key and exposes `drainQueue(key)`. `public/client/rootark-client-crypto.js` imports a raw key as AES-GCM with `extractable=false`; this describes local encryption behavior, not how the caller obtained or protected the key, rollback resistance, or device-bound custody.
- `public/client/rootark-protected-session.js` receives its key through a caller-provided `getKey` callback. `public/client/rootark-bootstrap.js` invokes an optional `syncOnce` callback when connectivity returns; a scoped search of `public/client` found no `syncOnce` callback configuration, so actual queue publication/replay wiring was not established.
- `public/client/rootark-bootstrap.js` describes offline index access as requiring a locally available index and an already-unlocked key. This is distinct from downloading new protected content from the service.
- An actual test-generated signed-history fixture passed public history verification with `signedStateVerified=true`, while returning `authorizationVerified=false` and `freshnessProven=false`. Its synthetic pinned witness fixture is library-test input, not a deployed freshness service.

| Case | Test-only policy | Current runtime evidence | Status |
|---|---|---|---|
| Read file already downloaded/exported | `allow-user-copy` | User-controlled copy is outside remote admission; not tested as a product journey | `PASS_TEST_ONLY` |
| View already-held plaintext | `already-held-only` | Existing UI code describes local index/key requirements; plaintext revocation is not possible | `OBSERVED` |
| New transfer or service download | `block`, fresh authority required | No independently verified admission gate | `BLOCKED` |
| New authorization or device enrollment | `block`, fresh authority required | No CAS/status/witness admission path | `BLOCKED` |
| Package/account/content recovery | `block`, fresh authority required | Public signed-history validation does not prove freshness or authorization | `BLOCKED` |
| Offline legacy queued operation | `not-authorized-for-zk`, fresh authority required | Legacy queues can retain and drain ciphertext/envelopes; publication authorization is not established | `BLOCKED` |
| Cached public shell | Not an authorization decision | Shell assets may be served from cache; `/auth` and `/api` are excluded | `OBSERVED` |

Windows Node.js `v22.22.1`, 2026-10-19: `node --test test/issue-65-web-offline-evidence.test.js` first returned **2 failed** because the test-only policy fixture was absent (RED), then **5 passed, 0 failed, 0 skipped** (GREEN). These tests verify the fixture and read-only source/library facts only; they do not prove that production operations are blocked offline.

## Task 4 — Readiness and validation matrix

### Readiness classifier

- Added test-only `assessWebRecoveryIntegrationReadiness(...)` at `914aceec0406987712a52e5a885c0b90e82124d2`. The later coverage correction commit `4954d8d28d4d4656666f227d451e45d70ef632e8` adds explicit copied-credential and profile-loss cases without changing the readiness rules.
- Any missing prerequisite or any value other than literal `PASS` returns `BLOCKED_FOR_INTEGRATION`. A record where every input says `PASS` returns only `REQUIRES_SEPARATE_INTEGRATION_APPROVAL`. Neither result includes an authorization field, enrollment token, or trusted-device grant.
- RED: the capability suite had **3 failing readiness tests** because the export did not exist. GREEN: the capability suite then had **9 passed, 0 failed, 0 skipped**.
- The profile-loss/copy coverage extension produced a targeted RED for the unsupported `PROFILE_LOST` label, then **1 passed, 0 failed, 0 skipped** after the helper classified it as unverified.

### Claim matrix

The final focused suite and validations below were run against code/test SHA `4954d8d28d4d4656666f227d451e45d70ef632e8`, except the Task 3 source scan, which was read at `fe55dfa0907569e240a708e99b44d7a52b21c3cd`. Runtime source files were unchanged in Phase A.

| Claim | Status | Evidence and limit |
|---|---|---|
| Owner-approved policy is recorded | `PASS_TEST_ONLY` | `test/issue-65-web-policy-record.test.js`; D-011 added while D-006/D-008/D-009 remain historical records. |
| Offline/online policy matrix matches D-011 | `PASS_TEST_ONLY` | `test/issue-65-web-offline-evidence.test.js` and `test/fixtures/issue-65-web-offline-contract.json`; fixture explicitly says it is not runtime enforcement. |
| Existing service-worker, queue, and protected-store behavior | `OBSERVED` | Read-only source assertions in `test/issue-65-web-offline-evidence.test.js`; stale public shell caching, auth/API cache exclusions, encrypted-envelope queue storage/drain, caller-provided keys, and optional sync callback are source observations only. |
| Actual browser version, secure-origin behavior, and WebAuthn PRF result | `NOT_RUN` | The local probe was not run in a real browser or with an authenticator. No platform support is claimed. |
| Browser key custody, sync/copy resistance, and profile-restore recovery | `BLOCKED` | Unit tests reject unsupported claims; no real browser/OS key-store or rollback-resistant high-water test was performed. |
| Browser HPKE/Ed25519 interoperability and protected-content admission | `BLOCKED` | No browser crypto execution, online witness, or deployed admission gate was exercised. |
| Node recovery package/history/KDF library focused suites | `PASS_TEST_ONLY` | The approved Node 22 focused suite passed on Windows and Ubuntu WSL; this is not browser or production evidence. |
| Argon2id in a supported browser worker and minimum hardware profile | `BLOCKED` | Node worker tests pass, but no browser-worker compatibility, browser memory/latency, or minimum-device evidence was collected; the profile remains provisional. |
| Independent witness and trusted fresh-head service | `BLOCKED` | No independently pinned, durable witness service exists or was tested. A generated unit-test witness is not deployment evidence. |
| Shared linearizable CAS and terminal-status authority | `BLOCKED` | No provider was selected, verified, or deployed. |
| New transfers, service downloads, enrollment, or recovery are runtime-blocked offline | `BLOCKED` | Desired policy is test-only. No production admission enforcement was added or validated. |
| Transfer TTL | `BLOCKED` | D-008 retention remains separate; no transfer TTL was selected. |
| Android interoperability/runtime | `BLOCKED` | No Android client or cross-client interoperability test was run. |
| End-to-end protected-content recovery | `BLOCKED` | No real trusted-device/browser key custody, package retention, online freshness, file decryption, or user journey was exercised. |
| Independent security review | `NOT_RUN` | Review is pending. No independent reviewer provenance is claimed. |

### Validation evidence

- **Windows:** Portable Node.js `v22.22.1`, executable SHA-256 `923A41F268AB49EDE2E3363FBDD9E790609E385C6F3CA880B4EE9A56A8133E5A`; focused five-suite command from the plan: **45 passed, 0 failed, 0 skipped**.
- **Ubuntu WSL:** `/usr/bin/node`, Node.js `v22.22.1`; same five-suite command with `TMPDIR=/mnt/e/Chats/rootark-tests`: **45 passed, 0 failed, 0 skipped**.
- `npm run validate:syntax`: **233 checked, 0 failed**.
- `npm run validate:artifacts`: exit code **0**; the script emitted no summary line.
- `git diff --check` and the exact changed-file allowlist check are recorded after the final evidence-only commit. Runtime code, dependencies, lockfiles, infrastructure, issue state, and remote refs are out of scope and unchanged.
- Full repository `npm test`, release gate, hosted CI/CodeQL, and browser/authenticator runs were not performed. They are not represented as passing.

### Review and next gate

Independent security review remains `PENDING`; it must assess the exact final evidence commit and code/test SHA above. Phase A does not authorize merge, release, provider selection, or issue #65 closure.

Recommended next separately approved design gate: Packet B feasibility and architecture for a real shared CAS, independently trusted terminal-status authority, durable witness/reservation service, and online protected-content admission. Verify candidate infrastructure and independent key bootstrap before implementation. Packet C transfer-lifetime policy and browser/device integration remain separate owner decisions.

## Current blocks

- No real shared linearizable CAS, independently pinned terminal-status authority, durable witness/reservation ledger, or protected-content admission gate is selected or verified.
- No browser secure key custody, rollback-resistant high-water storage, browser KDF profile, browser HPKE/Ed25519 interoperability, or trusted-device enrollment is proven.
- End-to-end protected-content recovery, Android runtime/interoperability, migration, and transfer TTL policy remain out of scope or unselected.
- Independent security review, complete repository CI/release checks, merge, production deployment, and issue #65 acceptance remain pending/not authorized.
