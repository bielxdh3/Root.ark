# Root.ark #65 — separately signed ciphertext-version inventory (experimental Phase A)

## Proven problem

The existing independently signed CAS/witness history commits to recovery **keyring** manifests; it does not authenticate a complete catalog of ciphertext objects or historic revisions. The application SQLite version archive can be forged by a privileged database writer. A signature on a GET authorization binds the expected digest of one revision but cannot prove that the catalog contains *all* versions or that an object has not disappeared.

## Implemented Phase A

- `src/crypto/rootark-zk-content-inventory-v1.js` implements bounded full-inventory snapshots encoded in canonical deterministic CBOR; a separate domain binds the SHA-256 root and Ed25519 signature to account, compartment, keyring, signer key ID, ordered (object ID, revision, epoch, ciphertext digest) entries, sequence, previous root, and fresh 32-byte nonce. The verifier takes a separately pinned Ed25519 signer key and exact scope, an independently obtained sequence/root floor and optionally the complete prior signed snapshot. Signed present/absent answers remain explicitly nonauthorizing.
- `src/services/zk1DurableContentInventoryLedger.js` implements explicit-bootstrap single-scope SQLite WAL/FULL identity plus monotonic append-only signed entries. Every append has an immutable operation ID, predecessor sequence and root, request digest, pending record, content version and signed successor inventory head. Exact replay and restart verification must hold. Unknown outcomes remain pending.
- Enforced caps: 4,096 inventory entries, 2 MiB canonical signed snapshot, at most 128 pending operations. Check byte lengths before copies. No plaintext key or raw file contents are stored in the inventory.

## Correction validation — 2026-10-21

- Focused RED before correction: **18/22 passed, 4 failed**. After aligning the malformed/unknown bootstrap assertions with `INVENTORY_BOOTSTRAP_NEW_ONLY`, the pre-fix run was **19/22 passed, 3 failed**: two terminal status lookups returned `unknown`, and exact pending retry failed terminal-proof validation.
- Focused GREEN: `node --test-isolation=none --test test/issue-65-content-inventory-authority.test.js` — **22 passed, 0 failed, 0 skipped**. The test runner's default worker mode failed to spawn with `EPERM`; in-process isolation completed the same test file.
- `npm run validate:syntax` could not enumerate files because Node child-process creation is blocked (`spawnSync git EPERM`). Its shell-runner equivalent checked **380 JavaScript files, 0 failed**.
- `npm run validate:artifacts` was blocked by the same Node `spawnSync git EPERM`. Its shell-runner equivalent found no protected runtime data artifacts.
- `git diff --check` exited **0**. Since task files are untracked, a direct trailing-whitespace check also ran on the three edited files and passed.

## Concurrent exact-retry correction — 2026-10-21

- The D3 handoff recorded the prime's standard runners passing before this regression test was added: `node --test test/issue-65-content-inventory-authority.test.js` **32 passed, 0 failed**; `npm run validate:syntax` checked **380/380** JavaScript files; `npm run validate:artifacts` exited **0**. This is the 32-test baseline; D4 adds one test, so the corrected suite has **33 tests**.
- In this executor sandbox, the default `node --test test/issue-65-content-inventory-authority.test.js` failed before loading the suite with `spawn EPERM`. The in-process RED command, `node --test-isolation=none --test test/issue-65-content-inventory-authority.test.js`, ran **32 passed, 1 failed**; the new concurrent exact-retry test failed because the second append returned `INVENTORY_OPERATION_CONFLICT`.
- GREEN with the same in-process command: **33 passed, 0 failed, 0 skipped**. It verifies two successful results with the same sequence/root, exactly one replay, one signed ledger entry, and replay after reopening the ledger. `loadState()` verified the Ed25519 entry and its canonical request digest before replay was returned.
- The standard syntax and artifact commands were also retried in this executor sandbox: `npm run validate:syntax` exited **1** because `spawnSync git EPERM` prevented file enumeration; `npm run validate:artifacts` exited **1** because `spawnSync git EPERM` prevented status inspection. Shell equivalents then checked **380 JavaScript files, 0 failed** and **0 protected runtime artifact violations**, respectively.
- After D4, the prime independently executed the standard Windows Node runner on the full current file: `node --test test/issue-65-content-inventory-authority.test.js` — **33 passed, 0 failed, 0 skipped**. Standard `npm run validate:syntax` checked **380/380** files successfully, and `npm run validate:artifacts` exited **0**. These are observed runs outside the Executor sandbox; the sandbox's separate `spawn EPERM` limit remains accurately recorded above.

## Authority and safety limits

The ledger is **experimental local code**, not a provider-operated authority. Terminal operation status is returned only from the ledger's verified signed proof; an unrecognized operation remains `unknown`. The signer, storage, TLS and external floor must be independently administered and pinned before deployment. Local SQLite/WAL and Ed25519 signatures cannot prevent a whole-host rollback of database and signer-controlled state. There is no crash-atomic transaction with the application's current SQLite ciphertext PUT archive or physical PostgreSQL writer, no independently proven custody/availability of raw cloud bytes, and no mTLS API or production route wiring. A valid signed inventory alone does **not** prove deletion/absence of all remote copies, authorize recovery, authorize egress, permit legacy cutover, or change NO-GO.

Next Phase B must establish a separate mTLS principal/server transport and independently operated monotonic floor, integrate physical receipt attestation into the actual ciphertext write path with crash reconciliation, and later gate strict GET in the correct socket-owning process. Keep existing endpoints unchanged until complete fencing.
