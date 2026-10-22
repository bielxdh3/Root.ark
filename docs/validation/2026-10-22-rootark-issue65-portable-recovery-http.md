# Issue #65 — one-file offline-key recovery and actual protected HTTP GET

**Development-only**, PR #228. Not a password recovery-package replacement and
not a production or release authorization. No merge, deploy, or data migration.

## Implemented

- The browser creates a random non-extractable AES-GCM CEK for a file. A 256-bit
  **user-held random recovery secret** derives a separate AES-256-GCM wrapping
  key by HKDF-SHA256 with a 256-bit random salt. The CEK is wrapped with fresh
  96-bit nonce and AEAD AAD binding schema, exact metadata, revision, ciphertext
  SHA-256 and ciphertext root. Raw CEK and temporary raw copies are zeroed.
- The portable JSON has ciphertext and encrypted CEK, **never** the user-held
  secret, plaintext or private signing key. The user saves the root **outside**
  the JSON and validates provenance independently.
- Real development-only browser UI provides explicit offline secret generation,
  package creation, protected signed PUT, historical signed GET + local
  decryption, and explicitly requested plaintext download. Input selections
  containing the secret, plaintext and signing PKCS8 are cleared on exit.
- Historical GET requests sign the **current** device grant/head/epoch while
  expecting exact object revision, old ciphertext epoch, SHA-256 and pinned
  ciphertext root. The protected store's latest signed witness/head and current
  device authorization are checked on the server. A revoked device or stale
  head cannot use these protected HTTP paths.
- Recovery after a legitimate epoch rotation succeeds for archived revisions
  1 and 2. Changed owner/scope/epoch, invalid ciphertext/CEK/tag, replay to a
  new revision, forged grant, lost authority, and server refusal fail closed.

## Direct tests

Tests: `test/issue-65-portable-file-recovery.test.js` and
`test/issue-65-normal-browser-protected-content.test.js`.
The latter includes real localhost Express protected PUT/GET, archived rev1
after epoch rotation, rev2, subsequent revocation, and a **real Microsoft Edge
WebCrypto + IndexedDB + CSP** UI publish/restore sequence. Related tests cover
actual owner-authorized ciphertext import and owner-grant local floor.

## Unresolved trust boundaries

- This key is **not a human password** and receives no memory-hard password
  protection. Only a CSPRNG-generated 32-byte random user-held secret is safe.
  The existing Argon2id recovery package is a separate format and flow.
- A manually entered owner key/head/root is not independent provenance simply
  because a field is named trusted. Owner-issued externally retained signed
  checkpoint/current head and key custody must be independently established.
- The HTTP response does not carry an independently signed proof that its
  server actually performed current revocation/gate admission; the application
  server is assumed to enforce its gate. Cryptographic ciphertext verification
  cannot replace an independently verifiable operation receipt or physical STOP.
- Erasure of a browser profile can remove its local monotonic IndexedDB floor.
  An offline user already holding an old ciphertext and its key cannot be made
  to forget that ciphertext after revocation.
- No production restore/cutover, application metadata restore, durable
  multiprovider storage proof, distributed remote witness custody, or full
  dynamic normal-workspace replacement is claimed.
