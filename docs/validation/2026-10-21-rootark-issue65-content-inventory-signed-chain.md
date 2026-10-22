# Root.ark #65 — bounded signed content-inventory continuity chain

## Problem and scope

An exact operation receipt confirms one signer-attested inventory operation, but independently signed older operation receipts and a fresh newer snapshot do not, by themselves, establish the continuity of every intervening inventory root. This remains an **experimental local verification boundary**. It does not grant protected I/O, authorization to recover/cut over, independent authority operation or multi-host rollback protection.

## Implementation

- The caller may supply `committedProofChain` to `verifySnapshot`: a contiguous sequence of canonical, domain-separated Ed25519 operation entry receipts beginning immediately after a separately trusted `minimumHead`.
- A complete prior signed snapshot (`minimumSnapshot`) must match that floor. For each receipt, the verifier checks pinned signer/public key/key ID, exact scope, operation ID, request digest, predecessor sequence/root and version tuple; inserts the tuple in the sorted full catalog; recomputes the complete catalog root and compares it with the signed new root. The reconstructed terminal sequence/root and full tuple catalog must equal the fresh signed snapshot.
- An insufficient chain, reordered/altered/duplicate receipt, incorrect external floor, signature mismatch or forged omission fails closed. Without a chain the existing one-step-only policy remains unchanged: a gap of more than one still fails.
- Limits are applied before copying attacker-controlled receipt bytes: at most 4,096 receipts, 4,096 bytes each, and 2 MiB aggregate; arrays with extra properties, holes or accessors are rejected.
- The standalone mTLS `getSnapshot` client accepts an optional **caller-provided** signed chain and copies it before the first network await, preventing caller-side mutation from altering a pending verification. A fresh nonce-bound signed snapshot is still fetched and verified via pinned TLS.

## RED → GREEN

- **Local RED:** new multi-step continuity regression — 34 PASS / 1 FAIL, because `committedProofChain` was not accepted and multi-step floors were refused.
- **Local GREEN:** after implementation, the authority suite passed 35/35. It covers valid three-step root reconstruction and missing, reordered, tampered, oversized, sparse and property-polluted receipt arrays.
- **mTLS RED:** the new browser-independent HTTPS/TLS integration failed as expected because `committedProofChain` was not a recognized client input (16 PASS / 2 FAIL including its parent).
- **mTLS GREEN:** the real TLS integration verifies three historical steps, rejects a gap and preserves the byte snapshot when input arrays are mutated after the request starts.
- **Combined GREEN:** the 35 authority and 18 HTTPS tests passed, **53 PASS / 0 FAIL** prior to the additional malformed-array assertions.
- **Final standard Windows gate:** the combined 53/53 PASS suite was rerun after the malformed-array checks. `npm run validate:syntax` checked **383/383 files**, `npm run validate:artifacts` passed, and `git diff --check` passed.
- **Independent READ-ONLY final review:** no additional exploitable P1/P2 confirmed for the standalone change. A known computational tradeoff remains: recomputing full bounded inventory roots for each successive receipt is O(N²); worst-case chains should be benchmarked/optimized before any production-facing exposure. This performance note does not change the current fail-closed NO-GO status.

## Explicitly missing

This method assumes the operator already possesses the complete ordered receipt chain and a truly independently trusted floor. The standalone HTTPS server does not yet provide a paginated chain-fetch endpoint. Even a fully verified chain of locally signed history cannot establish custody of physical ciphertext bytes, safe egress fencing, or independent signer administration. The application routes are unchanged; production remains NO-GO.
