# Root.ark #65 — exact signed inventory operation receipt (experimental)

## Scope

This is an additional verification boundary for the **standalone** signed ciphertext-version inventory; it is not wired into real application PUT/GET, backup/restore, WebDAV, S3, Google Drive, or a distributed physical gate. It **does not** independently prove bytes were committed to any storage provider or survive a hostile whole-host restore. The issue remains NO-GO.

## Problem

Before this change, a valid Ed25519 full-inventory snapshot authenticated only an object/version tuple. It could not authenticate the HTTP response's claimed append `operationId`, because the signed snapshot did not contain that field. A malicious pinned HTTPS endpoint could report `committed` for another operation ID while returning a genuinely signed, matching, already-present tuple.

## Implemented

- `verifyCommittedEntryProof` independently validates the ledger's existing Ed25519/domain-separated `rootark-content-inventory-entry/v1` signature against a caller-pinned key ID and public key, exact scope and canonical CBOR. It binds operation ID, full request digest, expected previous root/sequence, resulting sequence/root, ciphertext digest, object ID, revision and epoch; it checks byte budgets **before** copying.
- The ledger exposes the original verified signed entry as a bounded canonical proof only for an operation proven `committed` by its independently revalidated SQLite snapshot and entry-signature verification. A pending, final-noncommit or unknown operation never obtains a committed proof. The receipt is available after process/database restart.
- The experimental mTLS append endpoint returns that proof together with the nonce-bound signed full-inventory snapshot. The client separately verifies both and requires `PRESENT`, matching sequence/root when both refer to the same head, and receipt sequence not newer than snapshot. A purported HTTP success without the correctly signed operation ID fails closed.
- The operation-status endpoint likewise returns and verifies the original operation-specific signed proof; a forged status for another ID or digest cannot be promoted to a signed-commit result.
- Explicit `signedLedgerOperationCommitted: true`, `externalDurabilityProven: false`, `authorizesIo: false` in successful client results. Only the `transportReplayReported` field contains the transport's untrusted replay assertion; the signed proof does **not** attest replay or whether this was the first ACK.

## RED → GREEN and local evidence

- **RED (before crypto/ledger fix):** `node --test test/issue-65-content-inventory-authority.test.js` — **33 PASS, 1 FAIL**, missing committed `proof` field.
- **GREEN (crypto/ledger):** same focused authority test — **34 PASS, 0 FAIL**; exercises altered signature, alternate operation ID, alternate ciphertext digest and post-restart equality.
- **RED (before transport fix):** `node --test test/issue-65-content-inventory-mtls.test.js` — **11 PASS, 5 FAIL** (four failed nested scenarios plus the parent), showing that claimed commit/HTTP status was not independently bound to the signed operation entry.
- **GREEN (integrated authority + mTLS):** `node --test test/issue-65-content-inventory-authority.test.js test/issue-65-content-inventory-mtls.test.js` — **50 PASS, 0 FAIL** before the subsequent additional committed-status forgery regression.
- **GREEN (current focused mTLS):** `node --test test/issue-65-content-inventory-mtls.test.js` — **17 PASS, 0 FAIL**, including fresh forged operation ID and ciphertext-digest responses, honest retry, process restart, and tampered signed entry.
- **Final combined gate:** `node --test test/issue-65-content-inventory-authority.test.js test/issue-65-content-inventory-mtls.test.js` — **51 PASS, 0 FAIL** (34 authority plus 17 mTLS). Standard `npm run validate:syntax`: **383 checked, 0 failed**; `npm run validate:artifacts`: **PASS**; `git diff --check`: **PASS**.
- **Independent final READ-ONLY security review:** previous two mTLS P2 findings remain closed and no additional exploitable P1/P2 was confirmed within this receipt patch. Reviewer explicitly notes that an old signed receipt and a newer signed snapshot are not a multi-step historical proof of every intervening root, and that cryptographic signatures do not provide independent operator or physical durability evidence.

## Precise limits

The receipt proves only that the **pinned signing authority signed an entry for the exact request** and that the local ledger can reconstruct this signed entry from a committed row under its own integrity checks. A signer key controlled by the same compromised host cannot replace independent external operator custody, a monotonic multi-host floor, a physical-storage commit receipt, or continuous socket-owning process fencing. Old signed receipts remain replayable as evidence of historical local signoff, not as current I/O authorization. No change to user content, production routes, or deployment was made.
