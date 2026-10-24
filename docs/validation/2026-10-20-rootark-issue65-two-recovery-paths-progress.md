# Root.ark #65 — two recovery paths, actual browser integration and remaining acceptance gates

**Date:** 2026-10-20
**Worktree:** `E:\servidor\.worktrees\zk-dual-recovery-20261019`
**Baseline:** `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`
**Issue verdict:** **NOT COMPLETE**. Developer-only working vertical, no complete `zk-1` integration, no independent witness release authorization.

## Working end-to-end in the opt-in development vault

The existing /zk-dev-vault.html browser client encrypts file bytes, file name and media type with client-owned AES-256-GCM and sends only an opaque envelope and nonsecret key commitment to a permission-checked authenticated API and SQLite database. This mode is explicitly disabled by default and in production and is isolated from legacy file storage, backup, sync and migration.

Two **different recovery paths** for the same random 32-byte vault key now exist:

1. **User-held emergency package:** user's original recovery secret is wrapped entirely in the browser with Argon2id13 (3 operations, 256 MiB, fresh 16-byte salt) and AES-256-GCM (fresh IV, account-bound AAD). A JSON file plus its independently remembered passphrase restores the vault key without the server ever receiving either. A mandatory fixed KDF known-answer result blocks non-interoperable libsodium JS fallback at the required memory profile. The development page's CSP permits WASM compilation but not `unsafe-eval`, and the rest of the application's CSP remains unchanged.
2. **Previously trusted browser, without that package or passphrase:** while the original recovery secret is present, the user explicitly enrolls that browser. A fresh non-exportable local AES-GCM `CryptoKey` encrypts an offline escrow of the secret in IndexedDB, scoped to account, device ID and key commitment. Another browser generates a temporary non-exportable ECDH P-256 private key and an expiration-bound JSON request and stores that key locally. The trusted browser only approves after the user independently enters the 22-character 128-bit SHA-256 fingerprint displayed on the requesting browser. The fingerprint binds the exact request public key, account, ID and expiry. It wraps the original key under an ECDH/HKDF-SHA256-derived AES-GCM transport key with authenticated context. The requesting browser verifies request identity, recipient's ephemeral key, AEAD tag, account and key commitment before importing the key. The request is removed after successful import. No recovery material is submitted to the server.

### Tested invariants and threat limitations

- The trusted-device cryptographic module performs a real encrypted source→destination key handoff and decrypts a previously encrypted file. Tests reject wrong account, other private key, replaced request, changed response ID/commitment, corrupted ciphertext, unknown fields and expiry. A separate adversarial regression proves substituting `request.publicKey` while preserving `requestId` changes the fingerprint: the UI **must receive the independently copied fingerprint**, never auto-read it from received JSON.
- Microsoft Edge headless loaded both cryptographic modules with the development CSP and completed emergency Argon2id wrap/unwrap and ECDH device handoff. A separate Edge DevTools test saved **both** nonextractable AES-GCM escrow and ECDH private key objects in actual IndexedDB, closed and reopened the database, and completed decryption with the restored objects. The unique disposable browser profile was cleaned up.
- The local browser lock invalidates in-flight key recovery and prevents pre-lock plaintext downloads; all newly introduced secret fields clear immediately. The 'Forget' action also deletes trusted-device escrow and pending requests, rather than silently preserving independent recovery material.
- Threat model **not solved by the developer handoff:** the user must check the fingerprint through a separate trusted human/device channel. A malicious or tricked user can deliberately approve a stranger. A compromised origin/browser or already-unlocked device can still read keys. IndexedDB non-extractability is not hardware enforcement. Device trust is local/manual, **not an independently signed enrollment or revocation authorized by a zk-1 keyring and durable witness**. There is no cross-device revocation, audit-proof one-use server ticket, hardware keychain or independent anti-rollback root in this slice.

## Still necessary before issue #65 can close

| Gate | Status | Concrete acceptance criterion |
|---|---|---|
| Two recovery paths for the opt-in developer cofre | **Implemented, locally tested** | Manual cross-physical-device UX acceptance remains; code cannot claim zk-1 authorization |
| Final `zk-1` signed keyring manifest + authorized device recovery | **Missing runtime integration** | Client signs and independently verifies exact CBOR manifest/history, device proof of possession, epoch wraps, MAC, actor signature and complete revocation transitions; reject legacy downgrade |
| Shared compare-and-append, status authority and independent signed witness | **Local PostgreSQL prototype only** | A real durable configured provider with distinct trust keys/operators, measured HA/failover, crash/lost-ACK, witness pending/final no-commit gate, signed nonce-bound proofs and independent root bootstrap |
| Physical I/O and egress fence | **Missing actual gate** | No protected read/write can complete against a fenced epoch, including previously admitted work across process/replica/provider failures |
| Full legacy user-data migration/compatibility | **Missing** | Inventory by backend/mode, owner authorization and pre-migration recovery, encrypt client-side into verifiable target, compare source/target, reversible rollback, preserve names and metadata policy, negative corrupt/partial fixtures and no silent deletion |
| Keyring/history capacity, revocation and restoration | **Missing safe lifecycle** | 4096-transition/64 MiB limits cannot strand compromise response; reviewed checkpoint/rotation before capacity exhaustion and restore monotonic verification |
| Complete application and CI regression | **Not fully proven** | A green unsplit release gate on exact candidate commit, no unsupported skip claims, independent cryptographic review, measured recovery in actual browser/build |

**No commit/push/merge or issue closure is implied**. Existing local source and earlier validation evidence are preserved for continued work; no user or production data was read, overwritten or migrated as part of this developer recovery extension.

## Exact same-day validation after adversarial pairing fix

The initial independent audit reproduced a **P1 recipient public-key substitution**: replacing the ECDH public key inside an intercepted JSON request while retaining its `requestId` resulted in the trusted browser encrypting the vault key to the attacker's public key. The first implementation showed only `requestId` to the user, so that display was not an authenticated recipient binding. This P1 was corrected with a separately entered 22-character SHA-256-derived fingerprint of the complete canonical request, including the ECDH public key and expiry. A new RED→GREEN regression explicitly demonstrates that substituting only the public key changes the fingerprint and that unequal independently supplied codes are rejected. A second independent bounded read-only review found **no remaining confirmed P1/P2 in this corrected developer-device flow**.

- Windows `test/issue-65-*.test.js` plus local Packet B mock lab: **175/175 passed**, 0 failed/skipped, exit 0.
- WSL same focused suite: **173 passed, 2 Edge/Windows-only skipped**, 0 failed, exit 0.
- `npm run validate:syntax`: **261 checked, 0 failed**, exit 0.
- `npm run validate:artifacts`: exit 0; `git diff --check`: exit 0 (only existing CRLF normalization warnings).
- Broad `test/*.test.js` suite **excluding `upload-security.test.js`**: **1,538 passed, 56 skipped, 0 failed**, 1,594 total tests, exit 0. This includes general backup, account, upload, WebDAV and restore regression in 171 seconds.
- `test/issue-65-trusted-device-indexeddb-browser.test.js`: **1/1 Edge CDP real-browser test** persisted and reloaded nonextractable escrow/wrapping and pending ECDH private `CryptoKey` objects in IndexedDB, then successfully recovered the original key. Unique test browser/profile cleanup was verified through successful completion.
- An earlier isolated 2,000-chunk maximum-upload boundary test also passed in approximately 59 seconds; nevertheless the **unsplit complete `upload-security.test.js` / release gate is not green** because a prior full-file attempt became unresponsive. Do not claim a green full gate.

## Follow-up — verified ciphertext copy before declaring an import successful

The opt-in browser cofre previously displayed upload success after only a POST
and list refresh. A new RED→GREEN guard in
`public/client/rootark-dev-vault-crypto.js` (`verifyStoredCopy`) and
`public/client/rootark-dev-vault-ui.js` reads the **separately persisted**
encrypted object back through the authenticated GET API. The browser checks
the exact object ID, key commitment, initial revision, byte-for-byte envelope,
AES-GCM decryptability under the original account/object binding, original
file name, MIME type and exact original content bytes. A failed check MUST
NOT display a successful migration message or discard the selected source
file. It explicitly warns that the encrypted copy is **unverified** and the
original must not be deleted. Only a successful read-back clears the file
selector and reports a verified copy. Original plaintext remains client-local
and no additional plaintext is sent to the server.

Negative tests include corrupt/changed ciphertext, wrong account/object
identity, wrong key commitment, original-content mismatch, name or media-type
mismatch, wrong revision and a UI mock showing no success after a failed
independent GET. The full e2e still uses disposable synthetic users/files.

**Boundary:** this is a safer manually selected legacy-file **copy** into
the separate developer vault. It is **not** an automatic migration of the
Root.ark legacy database, does not change or remove legacy records, does not
enforce zk-1 signed keyring/witness gates and does not complete the reversible
per-backend migration acceptance in issue #65.

The same page now offers an explicitly confirmed **legacy plaintext read/copy**
path under `public/client/rootark-dev-vault-migration.js`. The browser GETs
the existing authenticated `/files/:name` endpoint with same-origin
credentials, denied redirects and a hard 4 MiB bound on declared **and streamed**
bytes, then applies exactly the same encryption, persisted GET read-back and
content/metadata checks. The original source is never deleted or modified;
temporary in-memory bytes are zeroed best effort after processing. Already
encrypted legacy files are refused by the existing legacy route, with **no
automatic server-side decryption or credential forwarding**. Users must
explicitly name a file and its folder and authorize the copy. Source
readability is governed by existing folder/file ACLs.

New RED→GREEN tests also cover the optional folder parameter, explicit
same-origin fetch, unsafe names/folder traversal, HTTP 403 and redirect
refusals, oversize header/stream, UI avoidance of plaintext in the new API
payload, local byte scrubbing and non-deletion of original data.

### Final follow-up evidence and independent review

The original explicit legacy-copy integration was independently reviewed
READ-ONLY. The reviewer reproduced one **P2**: a synthetic HTTP 200 HTML
login fallback or a source with a misleading Content-Length could be copied
and reported as correct even though its bytes were not the intended legacy
file. The fix now requires **exact HTTP 200**, `Content-Disposition:
attachment`, a finite integer `Content-Length` within 4 MiB, and an
**exact match between declared and streamed bytes**. Intermediate stream
chunks are zeroed best effort. A new adversarial RED→GREEN test validates
the false-200 and truncated-source refusals. The real authenticated legacy
GET → browser encryption → SQLite create → authenticated GET → AES-GCM
decrypt/byte verification test also succeeds and asserts the original
legacy file stayed byte-identical. The reviewer then returned **PASS, no
confirmed residual P1/P2 for this bounded developer-only copy**.

**Exact tests after this correction:**

- `node --test` all `test/issue-65-*.test.js` plus Packet B mock lab:
  **184 passed, 0 failed, 0 skipped on Windows**; **182 passed,
  2 Windows/Edge-only skipped, 0 failed in WSL**, both exit 0.
- `npm run validate:syntax`: **263 checked, 0 failed**;
  `npm run validate:artifacts` and `git diff --check`: exit 0.
- Previously inconclusive `node --test test/upload-security.test.js`
  subsequently finished as a standalone run: **133 passed, 1 skipped,
  0 failed**, exit 0, including the 2,000-part upload boundary. The
  one skip was a platform-specific symlink precondition. This proves the
  **individual upload-security file** is green, not a single unsplit
  repository-wide release gate.

**Strict remaining scope:** This copy is intentionally opt-in and
non-destructive. It does not silently elevate the old plaintext route into
Zero-Knowledge confidentiality, cannot authenticate the *legacy source*
against an independent pre-existing owner signature if a compromised legacy
server returns different same-length bytes, cannot automatically open
legacy password-encrypted files, and does not delete/retire the old
plaintext from the legacy store or its backups. Full zk-1 keyring integration,
independent witness/CAS/fencing and authorized reversible legacy migration
are still required by issue #65. Do not close the issue or merge these
developer-only changes as if all acceptance criteria were met.
