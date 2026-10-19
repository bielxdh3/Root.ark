# Issue #203 — Mammoth transitive advisory: reachability and containment

**Status:** bounded technical mitigation and repeatable validation, **not** an acceptance of residual risk or closure of #203.  
**Reviewed:** 2026-10-19. **Baseline:** `Root/main` `75d511decc5546a34a4999b47e14bf773a0e6369`.

## Affected dependency chain

The current production lockfile pins `mammoth@1.13.0` → `argparse@1.0.10` → `sprintf-js@1.0.3`. GitHub advisory [GHSA-hp3w-g68c-fv3c](https://github.com/advisories/GHSA-hp3w-g68c-fv3c) describes a moderate denial-of-service vulnerability in `sprintf-js` through 1.1.3, with **no patched version** as of this review. Upstream [Mammoth issue #491](https://github.com/mwilliamson/mammoth.js/issues/491) requests migration away from `argparse` 1.x; merely upgrading within Mammoth 1.13.0 or installing npm's suggested old downgrade is not a safe fix.

These packages **remain installed and the advisory remains unresolved in `npm audit`**. Do not suppress, falsify, or silently waive that signal, and do not assert that a library-only import removes all transitive supply-chain risk.

## Current app-specific exposure boundary

- `server.js` does **not** directly require Mammoth. `services/documentPreviewService.js` launches `services/documentPreviewWorker.js` with the Node executable and **no shell**; only the bounded worker imports the `mammoth` library API (`extractRawText`) for `.docx` inputs. That worker does not invoke the package CLI `bin/mammoth`.
- The runtime test `test/issue-203-mammoth-library-boundary.test.js` instruments fresh child-process imports. A deliberately loaded `sprintf-js` must be detected (positive control), while `require("mammoth")` must not import either CLI-only module. A worker-source assertion guards against accidental CLI wiring. Existing document-preview service and parser-process tests cover size/time/output bounds and process isolation.
- The assessment is **specific to the current code and installed dependency graph**. A future package upgrade, new import path, CLI invocation, or loader behavior may change reachability. No remote server, proxy, production environment, or real client was examined.

## Follow-up and non-waiver conditions

1. Keep `npm audit --omit=dev` visible in the security gate and track the open moderate advisory. Do not weaken fail thresholds or add an audit suppression simply to make reports appear green.
2. Recheck the upstream issue and published patched dependency graph at least monthly and immediately on any Mammoth or Node dependency update. Prefer an upstream-compatible fix, with document conversion and Windows/Linux regressions, rather than an ad-hoc unreviewed fork or `overrides` pointing to an incompatible `argparse` API.
3. Preserve child-process timeout, byte/output caps, no-shell invocation, failure isolation, and deny executable document content. If any bound fails, or if an import trace reaches `argparse`/`sprintf-js`, treat it as a new security blocker.
4. Any formal decision to accept the residual supply-chain/advisory risk requires **explicit authorized security-owner review**. This document does not approve release, weaken CI, or mark #203 complete.
5. Continue the unrelated #203 requirements: current HTTP/browser headers and upload lifecycle proof, benchmarked hot-path latency after async KDF conversion, and actual deployment/proxy/TLS evidence if and when an authorized deployment exists.

**Verification command** (run inside a legitimate isolated checkout, not on user data): `node --test test/issue-203-mammoth-library-boundary.test.js test/document-preview-service.test.js test/document-preview-meta-remediation.test.js`. Run the complete `npm test`/CI gates before integration.
