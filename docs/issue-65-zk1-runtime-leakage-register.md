# Issue #65: zk-1 metadata and trust-boundary register (split review)

Scope: the published, **opt-in development** zk-1 implementation in stacked PRs
#231–#236, assessed against `1466c126a64f7e651dac6c1421f802725c453dcf`.
This describes observable data and limits of individual implemented paths; it
does **not** authorize deployment, production recovery, cutover, deletion of
legacy data, or a zero-knowledge label for the whole application.

## What remains visible

| Boundary | Protected content / trust claim | Still observable or unproven |
| --- | --- | --- |
| Client file envelope (`public/client/rootark-zk1-file-content.js`) | Authorized clients encrypt file content, original filename, and media type in an AEAD envelope before protected PUT. CEKs are client-held and are not sent as normal protected object fields. | Ciphertext size, version count, timing, and the opaque routing identifiers remain visible. Endpoint compromise and any exported plaintext remain outside the server-blind guarantee. |
| Protected HTTP object (`src/routes/zk1ProtectedObjectRoutes.js`) | Signed operations bind object, revision, epoch, scope and ciphertext digest; protected GET is subject to authentication and current authority checks. | Account/compartment/keyring scope, device and opaque object IDs, operation type, signed checkpoint metadata, network addresses, and access timing are available to the service. A successful HTTP response is not independent cloud durability. |
| Opaque catalog (`src/services/zk1OpaqueCatalogCasLedger.js`, `public/client/rootark-zk1-browser-opaque-catalog-commit.js`) | Opt-in signed catalog pages contain encrypted filename metadata and opaque object references. Independently provisioned CAS/floor proofs may reject old heads. | Opaque page count/order, ciphertext digests, epochs and revisions are visible. A local test's mTLS signer and SQLite database do not prove external administrator separation, multi-host persistence, or a complete object inventory. |
| Independent witness / PostgreSQL gate (`src/services/zk1DurableWitnessLedger.js`, `src/services/zk1PgPhysicalInventoryBridge.js`) | Signed, scoped, nonce-bound receipts and physically checked local PG operations support replay/revocation fencing. | Witness/CAS heads, operation IDs, sequence, status, counts, host/network activity. Actual off-host custody, independent key administration and cross-provider atomicity require separate deployment evidence. |
| Remote ciphertext restore (`src/services/zk1MultiproviderCiphertextRestore.js`) | Owner-signed provider version pins, fresh owner/device authorization, ciphertext root and digest checks precede releasing returned ciphertext. | Cloud object key/version IDs, namespace, provider, byte length, timestamps and request patterns may be seen by each provider. A GET or provider ACK cannot guarantee long-term retention. |
| Recovery (`public/client/rootark-zk1-recoverable-pending-journal.js`, `public/client/rootark-zk1-browser-recovery-http.js`) | Recovery secrets and unwrapped CEKs remain client-held in supported paths; pending state is locally sealed before uncertain uploads and must reject forged readback. | IndexedDB and browser/OS security are separate trust assumptions. A browser that is offline, missing an independently pinned current head, or holding an invalid package must fail closed; recovery is not automatically available for an arbitrary historical object. |
| Legacy migration (`src/services/zk1LiveLegacyReferencePreflight.js`, `public/client/rootark-zk1-legacy-migration-workflow.js`) | Optional source observation and owner-authorized copied ciphertext can preserve an ambiguous journal after lost ACK. No automatic legacy deletion/cutover is authorized. | The legacy application already possesses plaintext and names. Old backup snapshots, derived indexes, links, trash, undeclared remote aliases and third-party copies may survive. Partial local inventory is explicitly not a complete signed corpus proof. |

## Normal application and legacy paths are outside this claim

The regular `sync-client/rootark-sync-protocol.js` v2 path uses readable
`metadata.name`/`metadata.path` and is **not** the server-blind protected zk-1
protocol. The ordinary file APIs, preview/thumbnail/search, native server-side
WebDAV, public links, pre-zk backups, and historical data can process
server-readable information. An encrypted zk-1 object does not retroactively
remove material previously held by those paths. The client-local trusted WebDAV
bridge and full Android #64 interoperability must be assessed separately.

No application flag, successful login, signed but stale history, or locally
verified test receipt can replace an independently retained current owner,
CAS, or witness head. After confirmed revocation, new protected writes under
the prior authority must be refused at the real commit boundary. Protocol
tests and disposable multi-process PostgreSQL/mTLS fixtures do not establish
production key custody or physical failover.

## Validation pointers and exclusions

- `test/issue-65-w99-sync-queued-revocation.test.js`: queued PUT, retry and
  sign/dispatch race rejection after revocation.
- `test/issue-65-w99-recoverable-lost-ack-client.test.js`: Node WebCrypto
  with **mocked HTTP and strict IndexedDB transaction fixtures** exercises
  uncertain PUT, forged readback, sealed pending state, and simulated restart
  without duplicate PUT. This is not a real browser/Edge or provider E2E.
- `test/issue-65-w99-browser-legacy-resumable-migration-http.test.js` and
  `test/issue-65-w99-legacy-source-type-inventory.test.js`: signed HTTP
  migration remains non-destructive; unknown/orphan sources reject inventory.
- `test/issue-65-w99-offline-proof-mutable-claims.test.js` and
  `test/issue-65-w99-opaque-cas-signer-rotation-mtls.test.js`: mutable claims,
  signer rotation, independent floor, restart and rollback rejection.

These are focused review regressions, not evidence that all 18 issue #65
traceability items, complete cross-device recovery, real Android interoperability,
physical off-host isolation, or independent vendor durability have passed.
See `docs/issue-65-v1-pr-split-traceability-20261026.md` for mandatory gates.
