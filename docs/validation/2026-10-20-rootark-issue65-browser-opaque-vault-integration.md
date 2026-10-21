# Root.ark #65 — real browser-to-server encrypted development workflow

**Date:** 2026-10-20
**Base HEAD:** `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`
**Branch:** `cdx/rootark-dual-recovery-20261019`
**Status:** real opt-in development slice; the overall issue #65 is **not closed**.

## Run the working feature

1. On a **development or test** server, set `ROOTARK_ZK_DEV_VAULT_ENABLED=true` in the local environment. Optionally set `ROOTARK_ZK_DEV_VAULT_DB` to an absolute path in disposable test data; default is `./data/zk-dev-vault.sqlite`.
2. Start the existing Root.ark app and sign in with an authorized account.
3. Visit `/zk-dev-vault.html`. Click **Gerar chave nova**, copy the displayed high-entropy 43-character recovery secret into your own password manager, or import a previously saved recovery secret.
4. Choose a file (maximum **4 MiB**), click **Cifrar e enviar**, and confirm the resulting opaque ID appears in the list. Click **Descriptografar e baixar** to download the original clear file **locally**.
5. Optionally save the **non-extractable AES-GCM `CryptoKey`** in this browser's IndexedDB for device-local reopening. This is a convenience, not a hardware key guarantee. Clear it with **Esquecer chave deste navegador**. A different browser/device can import the user-owned recovery secret manually.
6. Optionally create a **user-held emergency file encrypted under a strong passphrase**: paste your original 43-character vault recovery key in the new emergency section, enter a password of at least 12 characters, and download `rootark-emergency-dev-v1.json`. Keep that file and password separately. To regain access, select the file and supply its password; your browser reconstructs and imports the recovery key locally. This process does not call a server KDF or send the password or raw recovery secret to an API. A password manager-generated high-entropy passphrase is strongly recommended.

### What actually runs

- Browser-only AES-256-GCM in `public/client/rootark-dev-vault-crypto.js`: random 256-bit user-held key and a fresh 96-bit IV per file; authenticated context binds server-provided account ID/name and random opaque 16-byte object ID. Plaintext file name, MIME and bytes are together encrypted. A nonsecret **SHA-256 key commitment** is derived over a versioned domain, the account name and the uniformly random recovery key. This is only a stable, account-scoped key identity; it does not give the server the decryption key and it does not substitute for signed device enrollment.
- **User-held development emergency package:** `public/client/rootark-dev-vault-emergency.js` wraps the vault's original 32-byte recovery key with **Argon2id13**, operations=3, memory=256 MiB and a fresh 16-byte salt, followed by **AES-256-GCM** with a fresh 12-byte IV and account/domain-bound authenticated data. A wrong password, changed account, tampered package or reduced KDF profile cannot be accepted. The package is downloaded locally and is not saved to the Root.ark service. Only the two existing pinned npm `libsodium-sumo` browser scripts are served under local `/zk-dev/vendor/` paths when the development feature is enabled, not from a CDN.
- A simple developer UI with `public/zk-dev-vault.html`, `public/client/rootark-dev-vault-ui.js` and `public/styles/zk-dev-vault.css`.
- Authenticated, permission-guarded `/zk-dev/v1/session` and `/zk-dev/v1/objects` APIs registered in `server.js` only when explicitly opted in outside `NODE_ENV=production`. The existing CSRF cookie/header policy applies. They accept **opaque ciphertext envelopes**, not filenames, plaintext, encryption keys or passphrases.
- SQLite persistence in `src/services/zkOpaqueDevVault.js` with per-user owner/object uniqueness, create/update CAS revision checks, persistent tombstones and bounded active-storage quotas: 1,000 active files/account, 128 MiB active ciphertext/account, 512 MiB total active ciphertext, 100,000 lifetime IDs/account, and 500,000 lifetime IDs in one database. Removed files release active quotas without allowing ID replay. Lifetime-ID limits deliberately fail closed to avoid unbounded tombstone growth; **hitting those lifetime limits requires a separately designed safe history compaction or migration**. A consistent key-commitment field is retained in the active object rows. The same-account key-identity check and insert run in an SQLite `BEGIN IMMEDIATE` transaction; a second sender presenting a different key identity cannot silently join a nonempty vault. When all files are deleted, a new key may be generated. Old experimental rows created before the `key_id` schema existed are preserved with NULL key identity and **block new writes while active** until a specifically reviewed migration or cleanup. Server-visible leakage: login identity, key commitment, 16-byte opaque IDs, object count, ciphertext size, revisions, and access timing. The server cannot itself decrypt a correctly encrypted envelope without the user's recovery key.
- The entire feature is isolated from existing legacy upload/download, sync, backup, migration, WebDAV, sharing and content indexing. It **does not migrate or automatically protect** any existing content.

## Test evidence

- Storage unit tests: persistence after reopen, same-ID cross-account isolation, stale revision and replay conflicts, delete tombstone, active/global byte quotas, active-object capacity release, permanent ID replay block, lifetime-ID upper bounds, key-identity mismatch rejection and server refusal of plaintext/key/filename fields — **7/7 pass**.
- Express HTTP tests with synthetic authenticated sessions: create/list/get/update/delete and isolation — **1/1 pass**.
- WebCrypto browser-module Node tests: round-trip hiding filename/MIME, wrong-key/cross-account/cross-object/AES-GCM tamper rejection, 4 MiB limit, account-scoped key-identity derivation and refusal to silently overwrite a different local device key — **5/5 pass**.
- Emergency package tests: independently restore the same encrypted file, reject wrong password, wrong account, tampered IV/ciphertext/schema and downgraded Argon2id profile — **2/2 pass**. A synthetic Microsoft Edge headless browser fixture also loaded the installed libsodium browser distributions and module, performed the Argon2id wrap/unwrap, and returned **`BROWSER_ARGON2ID_PASS`** with exit 0. All disposable browser profile/fixture files were removed.
- **Real app integration test**: boot disposable `server.js` with temporary users and storage, authenticate using real login cookies and CSRF, encrypt client-side, POST envelope, GET persisted envelope, decrypt locally, verify other user is denied and plaintext file name absent from SQLite — **1/1 pass**.

The independent scoped review found and the implementation corrected two genuine P2 issues: an upload-only account could invoke DELETE, and a browser account switch after encryption could store ciphertext bound to the wrong account. DELETE now separately requires the `delete` permission, and POST/PUT/DELETE each require `account` to equal the **current authenticated user in the same request**. The browser revalidates identity, locks the local key and clears the stale listing after a switch; the backend comparison remains authoritative across races between a separate session check and upload. Both are covered by integration regression tests. The reviewer also found tombstone growth unbounded by the active-object quota. Distinct active and retained-ID limits were added with a RED→GREEN regression.

### Earlier consolidated checks (before the emergency-package extension)

- Issue #65 `test/issue-65-*.test.js` and existing local Packet B mock lab: **164/164 Windows**, **164/164 WSL**; both exited 0.
- `npm run validate:syntax`: **254 checked, 0 failed**. `npm run validate:artifacts` and `git diff --check`: exit 0.
- Broad application regression **on the final source**, excluding only the pre-existing stuck `test/upload-security.test.js`: **1,527 passed, 56 skipped, 0 failed**, spanning **134 other test files**, exit 0. The `test/upload-security.test.js` isolated run passed 47 subtests but its worker remained unresponsive and was explicitly terminated after 145 seconds; this file is **not** approved.
- A naïve `node --test` across the entire repository is NOT a valid release-gate invocation without its lab runner: it also discovers `lab/issue-65-packet-b/postgres-lab.test.js`, which intentionally requires the disposable PostgreSQL container name `PGB_CONTAINER` and fails without it. A separate bounded attempt of `test/upload-security.test.js` recorded **47 passing tests**, followed by an unresponsive test worker terminated after approximately 145 seconds. **The full unsplit regression remains unapproved.** Neither timeout is attributed to the new vault without direct causal evidence.
- Dev vault itself has no unhandled test failures on Windows or WSL in the above checks. SQLite/HTTP and real-server E2E tests are synthetic, run on disposable data, and do not change legacy live data.

All test objects, keys, accounts and databases above are disposable/synthetic; no user content or live secret was read, migrated, changed or removed.

## What this does **not** claim

This is a working engineering vertical, **not** the accepted Root.ark `zk-1` cryptographic protocol: this developer file envelope uses browser WebCrypto/AES-GCM and direct random user-held secrets rather than the frozen CBOR/HPKE keyring/Argon2id recovery-package and witness-authority protocol. It does not create device-specific, hardware-backed non-exportable authorizations, independent recovery guardians, autonomous trusted-device approval, key rotation and revocation with fresh epochs, or the complete cross-device recovery flow. Browser IndexedDB storage can be cleared, rolled back, or accessed by same-origin code. The optional **development emergency file is now passphrase-protected using Argon2id**, but it does **not** bind a signed zk-1 keyring manifest, trusted recovery-authority keys, CAS revision, independent witness or durable I/O fence as required for the normative emergency recovery path. This feature is not a replacement for `zk-1` and must not be relabeled as compliant. Protected files should not be considered backed up or recoverable merely because they exist in this development store.

Generating a new key while the cofre contains encrypted files is disabled: mixing keys without a keyring/rotation protocol would make access confusing and risk permanent loss. An empty cofre can generate a new key; a nonempty cofre must use its original user-held key. An account rename in the legacy login domain changes the AAD identity and requires an approved migration/rebinding operation before protected files could be opened under the renamed identity.

After another independent finding on unrestricted import and device-key replacement, the browser also checks its computed key commitment against the currently committed active vault key before accepting a new import, restoring/saving a device key, decrypting a stored record or uploading. The SQLite backend enforces the same key identity **per request** as the final authority, even if an alternative browser bypasses the UI preflight. These safeguards prevent *accidental* mixed-key writes from the first-party client; a malicious authenticated client can always choose to upload unusable ciphertext to its own vault, and signatures/device authorization are not yet implemented.

A final independent review exposed a TOCTOU risk in IndexedDB: an existing saved key could be overwritten when the vault appeared empty during an earlier API check, but another tab created remote files afterward. The UI now **always** rejects silent replacement of a different locally saved key, regardless of remote object count. The IndexedDB `readwrite` transaction itself performs the check and conditional write atomically, so another tab cannot change the stored record between those operations. To intentionally use a different device key, the user must first back up their recovery material and explicitly choose **Esquecer chave deste navegador**; this does not automatically rotate encrypted files. A new policy test covers both matching and mismatching commitments, including legacy saved-key records with no identity.

The owner-approved dual independent recovery, encrypted metadata policy, monotonic CAS/witness and gate, full-device lifecycle, non-ambiguous legacy migration, server-blind protected search, rollback/restore, and complete app regression remain substantive #65 work. No issue closure or merge of #65 as completely implemented follows from this slice.

## Same-day update — browser emergency-package extension and independent review

An additional browser-owned development emergency package is now implemented in
`public/client/rootark-dev-vault-emergency.js`, exposed in the development
cofre page. The user can download a local JSON package protected by a chosen
passphrase and later restore the original 32-byte vault key from the file and
passphrase, without submitting either to Root.ark. The fixed KDF profile is
Argon2id13, opslimit=3, memlimit=268435456 bytes, 16-byte random salt, then
AES-256-GCM with a fresh 12-byte nonce and account-bound authenticated data.
This is a **developer format, not the signed/authorized normative zk-1
emergency package**. Its password is susceptible to offline guessing if
weak; a strong unique high-entropy passphrase is essential.

The JavaScript bundles of the already installed `libsodium-sumo` and
`libsodium-wrappers-sumo` dependencies are delivered as fixed first-party
assets by the opt-in route, not from a CDN. The CSP `wasm-unsafe-eval`
allowance is applied to `/zk-dev-vault.html` only when the development
feature is explicitly enabled and the server is not in production mode.
`unsafe-eval` stays forbidden, including on the development page.

### Findings and corrections

- An independent read-only reviewer confirmed a **P1 Argon2id
  interoperability risk** in the third-party pure-JavaScript fallback at the
  prescribed 256 MiB memory limit. It could produce incompatible outputs
  across processes when WASM compilation was denied by CSP, resulting in
  unreadable backup packages. This is mitigated by the strictly scoped
  browser CSP and a mandatory KDF known-answer test at the **exact**
  Argon2id13 opslimit/memlimit: the 32-byte output for 20 zero password bytes
  and 16 zero salt bytes is
  `6752db303bb8916a149e207626f46cf6aaf2305747801ea0b75a6c7014128a45`.
  Creation and restoration now **fail closed** if this exact result is not
  reproduced, preventing use of a non-interoperable runtime.
- The reviewer also confirmed a **P2 local lock defect**: the newly added
  emergency password/key fields remained in the DOM and an in-flight restore
  could place a key back in memory after an explicit lock. Both are fixed:
  locking clears the emergency secret/file inputs, increments an operation
  generation, and aborts post-lock key assignment, password-package download
  or plaintext file download. The optional IndexedDB key-save path similarly
  checks the generation at the transaction boundary.
- Independent follow-up read-only review reported **no confirmed residual
  P1/P2 in these two bounded fixes**. This is not independent certification of
  the complete issue, migration, trusted-device path or operating services.

### Validation after fixes

- Focused #65 and mock Packet B suite: **170/170 Windows**, **169/170 WSL,
  with one platform-skipped Edge test**, and **zero failures** on either OS.
- `npm run validate:syntax`: **258 files checked, zero failures**;
  `npm run validate:artifacts` and `git diff --check`: exit 0.
- Real Edge headless executed the *actual* developer-page script ordering
  with first-party libsodium files and scoped CSP:
  `BROWSER_CSP_ARGON2ID_PASS`, exit 0. The browser's temp profile and
  fixture server were disposed after the test.
- New emergency package tests exercise local round-trip recovery, wrong
  password, cross-account binding, tamper, unknown fields, downgrades and a
  deliberately fake incompatible KDF. The new UI regression verifies
  clearing secret inputs and blocking recovery or download after a lock.
- Separately, a single 2,000-chunk legacy upload boundary test and five
  lightweight upload/release-gate tests passed in isolated runs. The monolithic
  `upload-security.test.js` has **no conclusive green result**, so the
  repository-wide single-run release gate is not marked complete.

**Delivery boundary:** this fully working, opt-in browser-to-server encrypted
development cofre now supports manual user-held emergency package restoration.
It does **not** implement the second independent already-trusted-device
recovery, cryptographically authorized zk-1 keyring, actual CAS/status/witness
operators or full legacy migration. Leave GitHub issue #65 open and do not
represent this partial vertical as the complete specification.
