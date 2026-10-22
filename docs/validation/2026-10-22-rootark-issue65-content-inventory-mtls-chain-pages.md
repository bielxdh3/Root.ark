# Root.ark #65 — bounded mTLS delivery of signed inventory history

## Goal and authorization boundary

The earlier receipt-chain verifier required callers to supply a complete ordered `committedProofChain` out of band. This milestone delivers historical signed entries through a **standalone**, scope-authorized TLS 1.3 test service. The endpoint is read-only and does not access physical ciphertext bytes or protected application routes.

The mTLS-delivered pagination metadata is **not** independently authoritative. Neither the endpoint nor its `status` is used as proof of current inventory contents, release permission, remote physical storage, independent signer custody or monotonic rollback protection.

## Implementation

- `Zk1DurableContentInventoryLedger.getCommittedProofPage({afterSequence,limit})` revalidates the single SQLite snapshot and all previously signed entries, refuses pending intents and invalid cursors, and returns the original signed Ed25519 entries for a contiguous sequence interval. Each call is capped at **16 receipts**, with each signed receipt at most 4,096 bytes.
- `POST /v1/inventory/chain` requires the preexisting `read` mTLS client-certificate role and exact ledger account/compartment/keyring scope. Request JSON is capped at 4,096 bytes and responses at 128 KiB. It strictly validates cursor/count/head bounds, typed payloads and contiguous page sizes.
- `getProofPage` returns only `status: "transport_unverified"`, bounded decoded receipt bytes and reported (untrusted) cursor/head. Results explicitly carry `authorizesIo: false`.
- `getVerifiedSnapshotWithChain` snapshots all user input before networking, fetches consecutive pages (at most **64** signed receipts per invocation), and validates the complete collected history against a caller-pinned head and signed minimum snapshot plus a fresh nonce-bound Ed25519 snapshot. An omitted, reordered, altered, malformed or stale chain fails closed. If concurrent appends overtake the fetched chain, the fresh snapshot check fails closed rather than implying success.
- No paginated result is promoted into `signedLedgerOperationCommitted` or protected I/O solely by HTTP status. Independent cryptographic verification remains mandatory.

## RED → GREEN evidence on disposable local real TLS and SQLite

- **RED:** the new mTLS page test failed because `getProofPage` did not exist; the combined suite reported **52 PASS / 2 FAIL** including the outer test. An additional test failed until `getVerifiedSnapshotWithChain` was implemented (**18 PASS / 2 FAIL**, outer test included).
- **GREEN:** `node --test test/issue-65-content-inventory-authority.test.js test/issue-65-content-inventory-mtls.test.js` — **56 PASS / 0 FAIL** after final adversarial additions.
- Adversarial cases include mTLS role denial, wrong scope, out-of-bounds limit/cursor, an empty terminal page, a complete 17-entry chain spanning the 16-receipt page boundary, forged signed-receipt bytes delivered by a pinned server (not accepted by snapshot verifier), a forged premature terminal page, a concurrent append racing the final signed snapshot, multi-step root linkage, and previous forged/slow-stream/malformed JSON cases.
- **Broad suite caveat:** a best-effort `npm test` full-repository run was started; it progressed through many existing synchronization and upload/chunk tests but produced no final aggregate result and was manually stopped to avoid leaving the long-running test runner consuming the machine. This attempt is **inconclusive** and is **not counted as PASS**; it did not produce a captured summary of failing tests.
- **Independent READ-ONLY P1/P2 review:** no confirmed exploitable regressions in this isolated new endpoint/ledger/client milestone. Possible CPU pressure from re-verifying the entire signed ledger per page and O(N²) multi-step catalog-root verification remains a separate benchmark/gating requirement prior to any production exposure.

## Still missing / NO-GO

This change does not establish external third-party content-inventory operator independence, a nonrollbackable external client floor, physically verified remote object PUT/GET or worker fencing, provider integration, production client recovery flows, backup/restore or multi-host adversarial proofs. `getVerifiedSnapshotWithChain` caps automatic verification at 64 history steps to bound quadratic full-catalog hash recomputation; larger histories require an explicitly separate validated plan. The issue and PR must remain NO-GO until normative requirements are independently demonstrated.
