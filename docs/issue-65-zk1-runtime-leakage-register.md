# Issue #65 — zk-1 runtime metadata and trust-boundary register (development)

Evidence baseline: PR #228, commit `0c9034c` plus the 2026-10-23 local
integration of independently tested catalog, owner CLI, legacy-transition and
versioned-browser milestones. This register
describes only the **opt-in zk-1 protected content path**. It must not be read
as a claim that Root.ark's legacy files, ordinary sync, WebDAV, public links,
existing backups, or existing server-readable previews became zero-knowledge.

## Protected zk-1 wire: confidentiality versus observable data

| Data or event | Current observer / treatment |
| --- | --- |
| File content, filename, and original media type | Encrypted **inside** the per-version AES-256-GCM payload by `public/client/rootark-zk1-file-content.js`. A server receiving that encrypted envelope does not obtain these plaintext fields from the zk-1 put/read API. |
| Key material | Fresh content encryption keys are created/imported in the authorized client; the normal zk-1 PUT/GET body contains ciphertext and signed authorization, not a usable CEK. Recoverable and historical archive operations rely on holder material and owner/device verification **outside** the server. An ordinary one-use upload without a separately saved recovery package is *not* automatically recoverable. |
| Protected routing | The zk-1 authorization wire exposes the account, compartment and keyring identifiers; device ID; opaque object ID; expected object revision; manifest revision/digest; epoch; operation; nonce; issue/expiry; ciphertext digest and signature. The ciphertext envelope also authenticates opaque object/version/parent identity, epoch, and object kind. These fields are **not** confidential. |
| Storage and network activity | Server, host, network operators and configured storage providers can observe ciphertext sizes, number of objects, access times/frequency, IP/network endpoint and session/authentication events, operation outcomes, provider placement, and coarse traffic/access patterns. Encryption and Ed25519 authentication do not hide these. |
| Authenticated access | HTTP cookie/session, CSRF, account permissions, trusted scope resolution and device/owner signed authority remain required. The server's acceptance of a signed object operation is not an independent proof of a durable cloud write or of externally custodied witness keys. |
| Recovery and exports | A client explicitly authorized to decrypt can release local plaintext/downloaded files to the device; device theft, OS compromise, exported copies, screenshots and already-seen legacy plaintext are outside server-blind cryptographic erasure. Session/logout fences prevent late releases in supported browser flows, not copies already delivered. |

The zk-1 route `src/routes/zk1ProtectedObjectRoutes.js` accepts signed
ciphertext PUT/GET by opaque object identity, with a separate optional
supervised multiprovider restore. An opt-in opaque **catalog commit/read**
now permits witnessed, versioned discovery between authorized devices under
independently pinned owner history and an **external, independently pinned
Ed25519 CAS head authority**. It cannot safely activate without that configured
authority; normal application bootstrap keeps this integration disabled by
default. Catalog entries expose opaque object ID, revision, epoch, ciphertext
digest, padded 284-byte encrypted filename metadata, paging and sequencing;
they must never contain plaintext `name` or `path`. The published implementation
does not yet supply a complete automatic normal-browser bidirectional sync,
delete/move/trash protocol or proven comprehensive inventory for objects absent
from the owner-signed root. The separately signed offline backup inventory and
keyring roster likewise attest only their explicitly signed and independently
pinned scope, not unknown/unrecorded objects.

## Separate services are **not** an implicit zk-1 downgrade

The generic `sync-client/rootark-sync-protocol.js` v2 protocol carries
plaintext `metadata.name`, `metadata.path`, and related routing fields,
which `src/routes/sync.js` stores/returns. This is **not** the protected
zk-1 protocol and must not be connected to a protected compartment without a
separately versioned encrypted-metadata adapter and adversarial proof.
Legacy upload/download, server-native WebDAV, previews, search, antivirus
scanning and public-link workflows may still process server-readable material.
Legacy migration starts from data that **was already known** to the service;
copying it into protected ciphertext does not retroactively erase caches,
backups, snapshots or third-party disclosures.

Server-blind public sharing, fully encrypted derived indexes, real Android
compatibility, and a trusted client-local WebDAV bridge are distinct future
integration scopes. Existing technical protocol compatibility notes do not
prove these external workflows completed.

## Cryptographic and physical evidence must not be conflated

1. An Ed25519 signature or owner-signed head authenticates the exact signed
   statement only, not a physical disk, a host, a provider or current device
   possession unless independently checked.
2. A local PostgreSQL physical admission/readback test establishes only the
   tested local transaction and fencing boundary, not PostgreSQL × SQLite ×
   TCP atomicity or remote `fsync`/durability.
3. mTLS sockets and independently pinned signing keys in disposable
   multi-process tests do not prove physical ownership or failure-domain
   separation of real cloud tenants/hosts.
4. A cloud HTTP ACK or a 2/3 signed catalog quorum without independent
   external custody and authenticated physical readback cannot establish
   indefinite retention of the bytes. Deadlines and STOP/fencing are
   deliberately fail-closed when providers do not cooperate.
5. The signed local owner/current-device grant is distinct from both a global
   witness head and a browser session cookie. Offline revocation cannot
   retrieve plaintext or keys already copied to an authorized endpoint.

## Verifiable sources and regression entry points

- `public/client/rootark-zk1-file-content.js`: per-version AEAD, encrypted
  filename/media type, bounded opaque AAD and exact wire serialization.
- `src/routes/zk1ProtectedObjectRoutes.js`: authenticated signed PUT/GET
  fields, permissions, no-name wire, status handling and capability
  version/downgrade fence.
- `public/client/rootark-zk1-normal-browser-content.js` and
  `public/client/rootark-zk1-authenticated-workspace.js`: client-only
  decryption, session/logout gates, ordinary versus recoverable upload.
- `test/issue-65-normal-browser-protected-content.test.js`,
  `test/issue-65-normal-browser-logout-fence.test.js`, and
  `test/issue-65-edge-v2-witnessed-positive.test.js`: signed HTTP, browser
  ciphertext, V2 witness/PoP, session and negative cases.
- `test/issue-65-authoritative-backup-inventory.test.js` and
  `test/issue-65-versioned-keyring-ciphertext-archive.test.js`: owner-pinned
  inventory/revision snapshots, archive roots and recovery.
- `src/services/zk1OpaqueCatalog.js`,
  `src/crypto/rootark-zk1-opaque-catalog-client-v1.js` and
  `test/issue-65-zk1-opaque-catalog-http.test.js`: witnessed opt-in catalog,
  encrypted filename metadata, two-device HTTP and rejection tests.
- `scripts/zk1-owner-offline-enroll-local.js` and
  `test/issue-65-owner-offline-local-orchestrator.test.js`: independently
  witnessed owner candidate/commit/delivery, without a forged local witness.
- `test/issue-65-legacy-transition-receipt.test.js`: signed per-version
  migration receipt without authorization to delete plaintext legacy sources.
- `docs/architecture/zero-knowledge-migration-contract.md` and
  `docs/architecture/android-client-architecture.md`: target threat model,
  independent cross-client boundaries and metadata policy decisions.

Update this register when a *further implemented and tested* zk-1 browser
catalog, owner revocation/rotation or additional client is integrated.
Do not weaken it with a production-readiness percentage or an unverified
security guarantee.
