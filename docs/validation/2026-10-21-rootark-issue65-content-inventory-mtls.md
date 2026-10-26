# Root.ark #65 content inventory mTLS transport — local evidence

## Scope and authority

This is an experimental, standalone HTTPS/mTLS transport around the signed content inventory. It is not connected to protected production routes or storage I/O. This work does not prove independent operators, multi-host durability, provider write fencing, migration readiness, or release authority. Root.ark #65 remains **NO-GO**.

Branch: `cdx/rootark-dual-recovery-20261019`

Starting and final local HEAD: `c5c6e59a640066a516a32bf33deede1c848e77e1` (no commit created)

## Correction

The client used `crypto.KeyObject` during client construction and `crypto.timingSafeEqual` for response identity checks without importing `node:crypto`. The missing binding caused the reported `instanceof` TypeError before client requests could exercise TLS or signature verification. Added the standard-library import; no test, authorization, timeout, response, or signature semantics were changed.

## Validation evidence

- **Prior RED evidence supplied with the B2 task:** standard Windows Node reported one passing top-level test and 11 failing nested cases. The failures stopped at the missing `crypto.KeyObject` binding.
- **Local post-fix `node --test test/issue-65-content-inventory-mtls.test.js`: not run.** Node's test runner failed before loading the test file with `spawn EPERM`; it reported one failed test-file launch, zero suites, zero passed cases, and zero executed nested cases. The same worker-spawn restriction was observed before the correction.
- **Syntax checks:** `node --check` passed for the client, server, and test file.
- **Constructor smoke check:** passed using a generated in-memory Ed25519 public key; the client factory returned the three expected methods without the `KeyObject` TypeError. This does not exercise HTTPS, mTLS, or response verification.
- **Static review:** all 11 nested test cases were inspected, including scope/role checks, TLS and Ed25519 pinning, stale floors, nonce replay, terminal proofs, malformed and oversized messages, pending/committed status, timeout recovery, and response bounds. No test was changed. The full transport cases remain unexecuted in this sandbox.
- **Not run:** project-wide `npm test`, live or multi-host validation, production-route integration, and remote CI.

## Prime verification on Windows after B2 handoff

- On the actual authorized worktree at `c5c6e59a640066a516a32bf33deede1c848e77e1`, standard `node --test test/issue-65-content-inventory-mtls.test.js` ran **12/12 PASS, 0 FAIL**. These cases exercise real disposable TLS 1.3 connections, Ed25519, pinned identities, replay, scope, tampering, pending states, restart, and timeouts.
- Standard `node --test test/issue-65-content-inventory-authority.test.js test/issue-65-content-inventory-mtls.test.js` ran **45/45 PASS, 0 FAIL**. Both modules are independently exercised together.
- `node --check` passed for both HTTPS source modules.
- These validations substantiate only the experimental, standalone, nonauthorizing transport. They do not prove independently operated authorities or atomicity with protected content writes.

## Independent P2 review and adversarial RED to GREEN

- An independent READ-ONLY reviewer confirmed two transport-level P2 findings: (1) a forged HTTP append ACK could be combined with a correctly signed **ABSENT** inventory to produce a misleading committed result, and even a correctly signed **PRESENT** tuple could not attest which operation ID committed it; (2) non-200/non-JSON responses were drained using `response.resume()` after clearing the wall timer, permitting indefinite pinned-peer slow streaming.
- Added adversarial cases for forged committed+signed ABSENT, forged alternate operation ID for an already-present signed tuple, and streaming HTTP 503 requiring physical socket closure. **RED: 11 PASS / 4 FAIL** (three failing subtests plus their parent), demonstrating both findings with actual TLS sockets.
- Fixed the client to require signed `PRESENT` before accepting a claimed append response, but conservatively return `status: "present_unattributed"` with `operationCommitProven: false`, `transportReportedCommittedOnly: true`, and `transportReplayReported` rather than asserting signed commitment/replay of the operation ID. Exact signed per-operation receipt remains absent.
- Invalid HTTP status or content type now actively destroys the request/socket via `abort()`, not an uncapped drain, before clearing its absolute deadline. **GREEN: 15 PASS / 0 FAIL**, including verified socket closure.
- This correction changes the experimental client response classification intentionally; it must not be upgraded to operation-commit proof without an independently verified, operation-bound signed receipt.

## Remaining validation

Run `node --test test/issue-65-content-inventory-mtls.test.js` with standard Windows Node outside the restricted child-process sandbox. In particular, verify the real TLS fixtures, SQLite restart case, and all 11 nested assertions after the import correction. Do not treat this local constructor smoke check or the prior RED result as GREEN evidence.
