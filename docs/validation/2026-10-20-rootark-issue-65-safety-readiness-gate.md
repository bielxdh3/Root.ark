# Root.ark #65 — Security hardening evidence and non-production gate

**Date:** 2026-10-20
**Starting worktree HEAD:** `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`
**Branch:** `cdx/rootark-dual-recovery-20261019`
**Scope:** test-only cryptographic contract hardening and evidence classification. No production runtime, server-side recovery authority, real client keys, migrations, credentials, deployment or operator services were added.

## New evidence in this pass

- The existing `test/issue-65-wire-type-registry.test.js` was strengthened as a **test-only oracle**, not a production verifier.
- RED observed: a correctly signed terminal status with an invalid 15-byte account identifier passed the former test-only verification helper. GREEN: strict scope lengths, digest lengths, signed status enums, expected/proposed revision relationship, observed-head binding, nonce width and numeric bounds now reject malformed synthetic signatures.
- RED observed: a correctly signed terminal proof with a different account ID passed when the verifier was asked to authorize the original query. GREEN: the test-only helper now checks the complete caller-supplied status query tuple (scope, IDs, request/package digests and expected/proposed heads) independently of signature validity.
- Malformed raw CBOR is rejected by the existing `src/crypto/rootark-zk-1.js` `decodeDeterministic` parser: duplicate map keys, non-canonical key order, nonminimal integer, indefinite map, trailing item and forbidden prototype key. Canonical signed terminal-proof bytes decode, verify and reject a different **validly re-signed** type under the original domain.
- Independent primitive interoperability probe: a synthetic Ed25519 status-proof signing preimage produced by Node (fixed domain + `0x00` + project deterministic CBOR) was signed with a volatile Node key and **successfully verified by WSL OpenSSL 3.5.5**. A one-byte extension caused OpenSSL verification failure. Only the synthetic public SPKI, signature and messages were placed in a uniquely named disposable directory, then removed; no private key was written to disk. This demonstrates Ed25519 signer/verifier compatibility for one vector, **not** independent CBOR encoding or full protocol interoperability.
- Further RED observed: a correctly signed status proof for another account was accepted by the test-only signature helper without matching the original query tuple; GREEN now compares the complete caller-supplied status query independently of the signature.
- Further RED observed: cryptographically valid status and cancellation proofs could pass the test-only helper with **no external query/nonce or proof-digest context**; GREEN requires both exact query and fresh nonce for a status proof and an externally supplied verified proof digest for cancellation. This is a primitive predicate, not end-to-end cancellation authorization.

## Whole-project regression attempt

A Windows `node --test --test-concurrency=4` run across all 127 discovered files under `test/` was attempted for breadth, but **did not pass**. Multiple disposable-server tests timed out during startup (10–15 seconds), and `test/upload-security.test.js` remained active for more than five minutes until the owned test-process tree was deliberately terminated by verified PID/command identity. This run is **INCOMPLETE/FAIL, NOT a green full CI gate**. A subsequent isolated run of `test/approval-method-security.test.js`, one of the failed files, passed 2/2 in about 2.6 seconds, consistent with possible concurrent harness/resource contention; causation is **not proven**. Tests outside the direct wire change should not be silently marked successful. No unrelated runtime/test changes were made to mask this failure.

**Final scoped validation (after the mandatory-context RED/GREEN update):** `node --test` over the 14 `test/issue-65-*.test.js` files and existing mock lab test passed **125/125 on Windows** and **125/125 on WSL Node 22** (both exit 0). `npm run validate:syntax` checked **238** files with 0 failures; `npm run validate:artifacts` and `git diff --check` returned exit 0. The full release/CI gate remains **blocked** by the failed/incomplete broad test attempt and by the operational/protocol gaps below.

These tests help prevent incorrect local evidence from being interpreted as proof of real security. The test oracle is not imported by product runtime; therefore none of the two RED findings demonstrates an exploitable runtime bug or a fixed production vulnerability.

## Remaining production security gate — NO-GO

| Required independent evidence | Current state | What would satisfy the gate |
|---|---|---|
| Actual browser/package and trusted-device recovery | NOT PROVEN | Real browser/OS/key-custody experiments across sync, profile copying, backup/restore and device revocation; independent trust-root bootstrap |
| v1 signed proof encoders/decoders and complete interoperability | TEST-ONLY PARTIAL | Actual producer and consumer implementations, authenticated raw CBOR negative corpus, exact schema and semantic validation, independent vectors across runtimes |
| Linearizable CAS/status and irreversible terminal no-commit | LOCAL POSTGRES ONLY | Selected real provider, crash/restart and lost-ACK failover under controlled configuration, independent status authority and root rotation |
| Independent witness with monotonic high-water and split-view detection | NOT PROVEN | Separated administrative domains, durable ledger, direct verified nonce reads, independent consistency monitors and restore drills |
| Physical gate and storage/egress generation fencing | NOT PROVEN | Real multi-gateway storage and chunk-output tests proving no post-quiesce effects, physical ACKs and fail-closed partitions |
| Emergency revocation at history capacity | UNSOLVED | Reviewed checkpoint/rekey/lifecycle that avoids hard-cap starvation of compromise response at 4096 entries / 64 MiB |
| Transfer TTL, migration, recovery UX and incident response | UNSELECTED | Explicit owner/product decisions, testable lifecycle and migration acceptance, documented RTO/RPO and rollback recovery |
| Operational security and third-party evaluation | NOT PROVEN | Owner/operator approval, threat-model verification, adversarial review on actual deployed builds, measured restore/key rotation and penetration testing |

**Verdict:** `WIRE_TEST_ORACLE_HARDENED; ROOTARK_ISSUE65_PRODUCTION_NO_GO`. A passing Node test suite and a single-machine PostgreSQL lab are not guarantees of Zero-Knowledge recovery, rollback resistance or independent operator custody. Absolute security ("100% safe") is not a technically provable endpoint; the acceptance target is a clearly scoped, auditable residual-risk decision supported by production-representative evidence. No commit, push, merge, release or issue close may be inferred from this document.

**Later same-day continuation:** An additional pure, isolated status wire verifier and 4 focused TDD cases are now recorded in `docs/validation/2026-10-20-rootark-issue-65-cas-status-wire-verifier-progress.md`. This partially advances the v1 status *decoder* evidence, not the independent status authority, durable fence, other four signed wire object parsers, browser or recovery runtime. The production NO-GO verdict remains unchanged.
