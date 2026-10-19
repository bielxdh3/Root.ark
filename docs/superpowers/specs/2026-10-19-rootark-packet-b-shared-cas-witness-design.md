# Root.ark #65 Packet B — Shared CAS, Terminal Status, Witness, and Online Admission

**Status:** PACKET_B_SPEC_PROPOSED_AWAITING_OWNER_DECISION
**Date:** 2026-10-19
**Repository:** bielxdh3/Root.ark
**Branch:** cdx/rootark-dual-recovery-20261019
**Design baseline inspected:** 8209a145693bb7810509b8da5b8b9cc272488cbe
**Scope:** Provider-neutral architecture only. No backend, witness, status service, client gate, migration, or runtime is selected or implemented here.

## 1. Decision boundary

This document translates the already approved recovery policy and the accepted bounded crypto-library contract into a provider-neutral server-coordination design.

The existing owner decisions remain controlling:

- Recovery keeps both methods: a user-controlled password-protected emergency package and previously trusted devices. There is no administrator master key, hidden fallback, or default recovery delegate.
- If both recovery paths are lost, protected content can be permanently unrecoverable.
- New web transfers, service downloads, authorizations, device changes, and recovery require an online connection and fresh independent authorization. Already downloaded/exported local copies remain user-controlled and usable offline.
- Root.ark is primarily a temporary file-transfer service; web is first, Android remains in the roadmap, and no new Windows/Linux desktop client is approved.
- Existing D-008 trash, backup, and log-retention decisions do not choose a transfer TTL. Transfer TTL remains unselected.

The following is a proposed technical contract, not an owner decision:

- Each keyring is coordinated through a shared, linearizable compare-and-swap (CAS) store.
- A separately administered terminal-status authority proves exact committed or fenced no-commit outcomes.
- A separately administered freshness witness owns the durable pending-reservation gate and emits nonce-bound, signed state.
- An unresolved reservation blocks fresh state-dependent reads and writes. No component may accept the earlier committed head while that gate is pending.

The following remain blocked: provider selection; hosting and administration; trust-root bootstrap; operational RTO/RPO and budget; real browser key custody; protected-content admission integration; migration; release; and any claim that Root.ark currently provides complete Zero-Knowledge recovery. This document does not authorize an implementation plan or code changes.

## 2. Existing contracts this design must preserve

The accepted dual-recovery specification at docs/superpowers/specs/2026-10-19-rootark-dual-recovery-design.md, Section 12, remains the cryptographic authority for the bounded library profile, operation matrix, recovery-package binding, target proof, and signed history. In particular:

- The library's signed public state is separate from secret-dependent MAC and wrap checks; public signatures alone are not freshness.
- The emergency package recovers later epoch keys through authenticated wraps. A trusted-device verifier does not require the emergency package private key.
- A suspected package compromise requires a trusted active device, complete key coverage, package replacement, one forward epoch rotation, and new wraps in the same state transition. The compromised package receives no new epoch key. If required authority or material is missing, recovery is unavailable; no administrator fallback is allowed.
- Public target-proof bytes do not let the server prove X25519 private-key possession by themselves. The active authorizer verifies the live authenticated pairing response.
- The operation lifetime is nominally at most 300 seconds. With monitored clock skew bounded to 30 seconds, the effective worst case is 330 seconds. There is no post-expiry grace; unknown or excessive skew blocks admission.
- The history bounds are 4,096 transitions, 64 MiB total, and 8 MiB per entry/page, with a 75% warning. At hard exhaustion, mutations including safety revocation can be blocked. There is no approved pruning/checkpoint shortcut; safe lifecycle capacity is a production blocker.
- The existing v1 keyring shape and rootKey semantics are not changed by this design.

Packet B supplies the persistence, freshness, and admission trust boundaries around that contract. It does not revise its wire encodings.

## 3. Current repository and issue evidence

Read-only inspection at the design baseline found:

| Area | Observed repository fact | What it does not establish |
|---|---|---|
| Server database adapter | db/index.js opens better-sqlite3; DB_ENABLED defaults to false; the default path is data/rootark.sqlite; DATABASE_URL is passed through path.resolve as a filesystem path; WAL, foreign keys, and a busy timeout are configured. | No PostgreSQL/shared database or production database configuration is present or verified. DATABASE_URL is not a network-database adapter here, and a path setting is not a distributed CAS contract. |
| Legacy synchronization persistence | src/routes/sync.js has a JSON SyncObjectStore, durable temp-file/fsync/rename writes, and a per-instance Promise queue. | The queue is process-local, and a local JSON file is not cross-process atomicity, shared CAS, durable witness state, or authorization freshness. |
| Recovery crypto library | src/crypto/rootark-zk-recovery-history-v2.js and src/crypto/rootark-zk-recovery-manifest-v2.js implement bounded verification and signed receipt parsing. | Static source and test fixtures do not provide an online status service, shared store, external freshness, or content admission. The recovery modules are not imported by the inspected runtime route, server, public-client, or sync-client paths. |
| Browser protected store/session | public/client/rootark-protected-store.js uses IndexedDB for encrypted derived records; rootark-protected-session.js accepts a caller-provided key function. | This does not prove OS-backed key custody, rollback-resistant high-water storage, browser profile anti-cloning, trusted-browser eligibility, or a production gate. |
| Product policy | D-011 is present in docs/product-discovery.md; D-006, D-008, and D-009 remain preserved historical decisions. | Documentation does not alter legacy runtime behavior. |
| Issue #65 | The [live issue](https://github.com/bielxdh3/Root.ark/issues/65) was fetched read-only on 2026-10-19 and is open. Its [owner comment](https://github.com/bielxdh3/Root.ark/issues/65#issuecomment-6260021696) approves both recovery methods, no hidden master key, and permanent unrecoverability if both paths are lost. | The issue and comments do not select a provider or prove implementation. |

The primary local records are docs/product-discovery.md, docs/architecture/zero-knowledge-migration-contract.md, the two specifications named above, and docs/validation/2026-10-19-rootark-web-phase-a-evidence.md. No runtime behavior or deployment configuration was inspected.

## 4. Trust domains and protected claims

The architecture separates four trust domains. They must not share deploy credentials, signing keys, privileged operators, backup administrators, or recovery procedures in a way that collapses the separation.

1. **Root.ark application tier:** authenticates the account session and transports opaque requests/responses. It is not authoritative for the current keyring head, reservation terminality, or freshness. It can deny service and may be malicious.
2. **Shared CAS domain:** serializes and durably stores signed state transitions and idempotency outcomes for all app instances. It never receives private recovery/device keys, epoch keys, content keys, passwords, or plaintext.
3. **CAS terminal-status authority:** independently observes the CAS's durable transaction ledger and issues signed, exact-scope terminal proofs. It must not infer a result from an app-server assertion. Its CAS credential may read terminal records and invoke only a conditional no-commit-fence operation; it may not append manifests or move a keyring head. It may not certify no-commit until a CAS-side fence makes a late commit impossible.
4. **Freshness witness:** has its own pinned signing root and durable reservation ledger. It closes the admission gate before issuing a reservation ticket and publishes a new accepted head only after validating terminal status. It does not issue keys or decrypt content.

Clients hold the cryptographic authorities described in the accepted recovery spec. A browser is not a trusted recovery device in this proposal. The witness and status public roots must arrive through an independently authenticated bootstrap. A key delivered only by the Root.ark application origin is not a trust anchor. Origin-delivered JavaScript is itself in the trusted computing base: a compromised origin may replace the verifier and attempt to steal keys. TLS, WebAuthn login/PRF availability, IndexedDB, or a non-extractable CryptoKey does not resolve that risk. Until a supported client can authenticate both its code and pinned roots independently, browser recovery remains blocked.

An independently signed witness head is only as trustworthy as its key bootstrap, durable ledger, and operating domain. One witness can sign conflicting views to isolated clients. Before production, use a separately operated consistency monitor or a reviewed transparency/consistency-proof protocol and require clients to advance from pinned high-water state. The current witness receipt v1 encodings are not silently extended here; any proof wrapper or receipt-v2 format requires a separate cryptographic review.

### Threats and limits

| Attacker or failure | Required control | Residual limit |
|---|---|---|
| Stale, replaying, or malicious app tier | Clients and admission gateways verify signed receipts, exact scope, nonce, request digest, head digest, status, and one-use permit; no cached app response is fresh by itself. | App tier can deny service. A compromised delivered client can violate client-side checks. |
| Restored/rolled-back CAS snapshot | Independently pinned witness high-water and unresolved-reservation ledger prevent the old head from being accepted; restore remains gated until exact reconciliation. | Collusion or compromise of CAS, status authority, and witness can defeat the trust separation. |
| Concurrent or altered CAS requests | Conditional expected-head compare, unique operation IDs, immutable request digests, single pending reservation per keyring, and serialized append. | Availability decreases under contention; callers must safely retry the exact same request. |
| Forged or premature no-commit | Status authority requires a durable CAS terminal tombstone/fence for the exact reservation, proving that no late commit can follow. | The authority's independent operation and CAS integration are trusted assumptions, not currently deployed properties. |
| Witness outage, restart, fork, or lost ledger | Gate is closed; unresolved state remains pending. Restore requires continuity checks against pinned roots and status history; fork evidence blocks both views. | Security-sensitive operations are unavailable until recovery is proved. A single witness operator remains a residual trust risk without independent monitoring. |
| Stolen device or compromised recovery package | Existing signed actor matrix, revocation and forward epoch rotation, distinct keys, complete-wrap checks, and no new wrap to a compromised package. | Previously received keys, plaintext, and downloaded/exported copies cannot be remotely revoked. |
| Malicious or compromised browser origin | Keep browser trust blocked until code/root authentication and OS key custody are independently verified. | Web platform support is not established by feature detection or this design. |
| Network partition or unbounded clock error | No fresh witness/status result or unhealthy clock means no authorization. | Fail-closed unavailability is intentional and must be included in service planning. |

## 5. Per-keyring CAS data contract

All coordination is scoped by the immutable tuple (account_id, compartment_id, keyring_id). IDs are opaque and random where the accepted crypto format requires them. The database must not key rows by username, filename, content name, password, or user-controlled path.

The CAS stores only signed public manifests, digests, ciphertext envelope bytes, opaque identifiers, status proofs, and bounded protocol metadata. It must never store private keys, epoch keys, content-encryption keys, package passwords, decrypted names, plaintext, or plaintext-derived indexes.

Logical records:

| Record | Required fields and invariant |
|---|---|
| **KeyringHead** | Scope; committed revision; complete-manifest digest; current epoch; witness committed sequence; current gate generation; history transition count and byte total. One row/value per immutable keyring. |
| **Transition** | Scope; exact next revision; previous and next manifest digests; canonical signed manifest bytes; operation ID/type; actor key ID/type; request digest; package-envelope digest or null; CAS transaction ID. Immutable once committed. |
| **Operation** | Scope + operation ID as unique key; immutable request digest; terminal result reference. Same ID and same digest returns the exact prior result; same ID with a different digest is a conflict. |
| **Reservation** | Scope; reservation ID; expected and proposed revision/digest; operation ID/request digest; package digest; gate generation; state; timestamps; exact witness ticket and status-proof digests. Never silently expires into an open gate. |
| **PackageBlob** | Immutable bytes addressed by the envelope digest. Stage and read back exact bytes before CAS; orphaned staged blobs are harmless. Pointer activation is part of the atomic manifest/head transition. |
| **NoCommitFence** | Unique scope + reservation/operation ID; expected head; request digest; terminal tombstone digest. Its existence prevents the delayed request from committing later. It is immutable and durable. |

Each successful keyring mutation is one conditional append. In one linearizable durable CAS transaction, the backend must: compare the current head with the exact expected revision and digest; validate that the reservation is still authorized and unused; validate the public actor signature and operation invariants; enforce uniqueness/idempotency; append exactly one contiguous transition; advance the head; store the terminal operation result; and consume the reservation. The transition history, head, active package pointer, and operation result must become visible atomically.

A failed conditional compare writes no transition. The same request may be retried only with its exact operation ID, digest, manifest bytes, and package bytes. A delayed request whose operation ID has a no-commit fence must be rejected even if its original witness ticket has not expired.

The CAS must provide a strongly consistent read of the head and terminal operation ledger. Authorization may not read from an asynchronous replica or local cache. A backend's claim of serializable transactions alone is insufficient unless the complete admission/read/write path is linearizable and failover cannot lose an acknowledged commit.

## 6. Reservation, terminal status, and gate protocol

The durable witness gate is the critical safety boundary. A reservation does not authorize use of the earlier committed head. A timeout, ticket expiry, application restart, database restore, or lost response does not cancel a reservation.

State machine:

| From | Event | To | Required behavior |
|---|---|---|---|
| OPEN(r,d,g) | Witness accepts a valid reservation intent | QUIESCING(id,r,d,g+1) | Atomically stop issuing new permits. Fresh head requests return signed pending/unavailable with no acceptable old head. Drain or terminate prior-generation permits before reservation ticket issuance. |
| QUIESCING | All prior-generation admissions are terminal | PENDING(id,r,d,g+1) | Persist the exact reservation and gate state; only then return its signed ticket. A crash or uncertainty remains blocked and does not start CAS. |
| PENDING | CAS commits exact request | COMMITTED_UNWITNESSED(r+1,d') | CAS atomically appends the transition, head, operation result, and reservation consumption. Witness still withholds any acceptable committed head. |
| PENDING | CAS never commits; status authority obtains durable fence | NO_COMMIT_PROVEN(r,d) | The fenced request can never commit later. Witness records exact resolution before reopening the same head. |
| COMMITTED_UNWITNESSED | Status authority independently confirms exact durable CAS commit | RESOLVED_COMMIT(r+1,d') | Witness appends a commit receipt and advances committed head/sequence. |
| NO_COMMIT_PROVEN | Witness validates exact signed terminal proof | RESOLVED_NO_COMMIT(r,d) | Witness records the cancellation and opens only the unchanged head. The next write must use a new operation ID. |
| Any unresolved/ambiguous state | Timeout, outage, missing proof, digest mismatch, restore uncertainty, or conflicting receipt | BLOCKED | Keep the gate closed. Do not expose revision r as a fresh committed head. Reconciliation may continue when authorities return. |

Gate generation strictly increases at reservation intent and terminal resolution. QUIESCING and PENDING are both non-admitting states; the witness never issues an acceptable committed head in either. The existing recovery specification ties the committed witness sequence to committed keyring revisions; this separate gate generation does not change the committed revision or existing receipt-v1 field set.

### Read/write admission linearization

A fresh signed head is not itself an admission permit: a new reservation could begin after the head response. The witness therefore needs an atomic acquireAdmission(scope, request, nonce) operation. It succeeds only while the gate is OPEN and the requested current head still matches; it records a unique, single-use permit with the current gate generation and a short bounded lease. The shared content/admission gateway consumes that permit exactly once before serving or publishing the operation. No permit can be minted or consumed while the gate is QUIESCING or PENDING.

Beginning a reservation atomically switches the gate to QUIESCING and stops new permit acquisition. The witness returns no acceptable head while prior-generation permits are drained. It may change QUIESCING to PENDING and issue the reservation ticket only after all admitted operations have either completed or been terminated by an enforced lease deadline. The CAS transition cannot start before that point. Streaming responses must be interruptible at that boundary; a server that cannot prove termination remains blocked. Bytes/plaintext already delivered before an operation ends remain outside remote-revocation control. Permit lease limits, maximum response duration, and enforcement integration are provider/runtime acceptance criteria, not capabilities shown by current code.

### Receipt and terminal-proof contract

The existing witness-head receipt remains the exact deterministic-CBOR type rootark-recovery-witness-head/v1 and its already specified signature domain. Its committed form binds witness_key_id, exact keyring scope, current revision/digest, committed witness sequence, fresh 32-byte nonce, observed_at, committed status, null pending_reservation_id, and signature. Its pending form is signed, has no acceptable committed revision/digest, and names the unresolved reservation. Unknown or missing status is unavailable. The reservation ticket retains the accepted recovery specification's exact scope, expected and proposed heads, reservation ID, operation ID, request digest, package-envelope digest, expiry, witness key ID, and signature.

The proposed terminal proof is a new interface, not an existing runtime artifact. It uses deterministic CBOR and Ed25519 with type rootark-cas-terminal-status/v1 and domain Root.ark/zk-1/cas-terminal-status/v1 followed by one NUL byte. Its exact fields are: type; status_key_id; account_id; compartment_id; keyring_id; reservation_id; operation_id; request_digest; expected_revision; expected_manifest_digest; outcome; committed_revision; committed_manifest_digest; terminal_record_digest; no_commit_fence_digest; observed_at; signature. account_id, keyring_id, reservation_id, operation_id, and status_key_id are 16 bytes; compartment_id is 1–128 bytes; digests are 32 bytes. For a non-initialize committed operation, committed_revision must equal expected_revision + 1, committed_manifest_digest and terminal_record_digest are required, and no_commit_fence_digest is null. Initialize commits require null expected revision/digest and committed revision 1. For outcome no_commit, committed fields are null and no_commit_fence_digest and terminal_record_digest are required; initialize no-commit also has a null expected head. terminal_record_digest hashes the exact durable CAS terminal record. No timestamp alone establishes ordering or finality.

The status authority verifies the terminal record at the CAS's authoritative linearization point and verifies durability to the configured acknowledgement quorum before signing committed. For no_commit it must use the narrow CAS fence operation, which conditionally records the tombstone only when the exact operation has not committed and the expected head still matches. The CAS permanently rejects later attempts using the fenced operation ID. Both terminal outcomes are immutable and retryable by the exact reservation ID.

### Write sequence

1. The client obtains a fresh nonce-bound committed head from the pinned witness and compares it with the strongly consistent CAS head. It validates the complete signed chain and operation authorization under the accepted crypto specification.
2. The client submits the exact scoped request digest and proposed head. The witness validates scope, expected head, operation ID, size and time bounds, then atomically changes OPEN to QUIESCING. New permits stop and the witness withholds every acceptable committed head immediately.
3. The witness fences or drains all previously issued read/write permits, including aborting unfinished protected streams. Only after the drain is proven does it durably change QUIESCING to PENDING and issue the reservation ticket. The CAS write cannot begin before then.
4. The client/CAS submits one conditional append with the ticket. The CAS validates the ticket, expected head, transition signature/matrix, exact envelope digest, idempotency, history capacity, and operation TTL.
5. The terminal-status authority queries the authoritative CAS transaction ledger, not an app server cache. For COMMITTED, it signs the exact reservation, request digest, revision, manifest digest, and durable commit identity. For NO_COMMIT, it first creates or verifies the CAS-side immutable no-commit fence and proves the current head is still the expected head.
6. The witness verifies the independently pinned status signature and exact reservation binding. It records the terminal resolution and only then publishes the signed accepted head (or the unchanged head after fenced no-commit) and reopens the gate.
7. The client verifies the new contiguous signed history, witness freshness, and CAS/witness digest equality before continuing. Local promotion before terminal witnessed resolution is forbidden.

NO_COMMIT is not a statement that a status query happened to see no row. It is a final CAS outcome. The CAS must atomically fence that operation ID and prove the expected head still matches. If a concurrent append wins first, the authority reports its commit; if the fence wins, every later append under that ID is rejected. A stale application assertion, timeout, missing response, or replica read is never sufficient.

### Fresh reads and protected-content admission

Every new service-mediated protected-content read, transfer, download, authorization, device operation, recovery action, and state-dependent write requires an online fresh witness result for its exact scope and request. The client uses a new unpredictable nonce; the response must echo it, match the pinned witness key, use a committed status, contain no pending reservation, and match the current CAS head and local high-water. Unknown, pending, stale, unavailable, or mismatched responses fail closed.

The admission permit binds the scope, request/operation ID, action, object or transfer identity, accepted revision/digest, witness sequence, gate generation, issue/expiry time, and one-use nonce. A shared admission component atomically consumes it and rejects replay. Every actual content read/write/download/transfer path must use this gate; a process-local cache, SQLite queue, local JSON file, signed token reused for multiple operations, service worker, or mock witness is not an admission control.

## 7. Metadata, audit, and retention

Coordination necessarily reveals that a pseudonymous keyring changed or was accessed, when it happened, the transition class, the result, and the sizes of manifests/package envelopes. Account/compartment identifiers, key IDs, operation cadence, online presence, and outage timing remain metadata leakage. The design does not claim traffic-analysis resistance or hide all access patterns.

Application/security audit records should be minimized to a correlation ID, pseudonymous scope, actor type/key ID, operation ID/type, request digest, outcome, revision/witness sequence/gate generation, and timestamp. IP address or device label is retained only where D-008's approved security purpose requires it and access is audited. Never log passwords, private keys, epoch/content keys, package bytes, plaintext, decrypted names, search terms, previews, or full request bodies. Do not copy full signed histories into general application logs.

D-008's operational-log period (30 days), security/audit-log period (180 days), backup retention (rolling 30 days), and access-audit requirement apply to their approved categories. They do not authorize deleting immutable keyring transitions, active reservation/no-commit records, or witness continuity checkpoints. Those protocol records require their own reviewed retention/lifecycle rule; hard history limits remain separate from log retention.

The owner-approved offline exception is limited to files already downloaded/exported to the user's device. Offline drafts and legacy queued operations remain unpublished until fresh online authorization. Previously delivered plaintext or decryptable ciphertext cannot be revoked remotely.

## 8. Freshness roots, rollback, and recovery

- The witness signing root and terminal-status signing root are distinct. Clients pin each through an independently authenticated release/configuration or an already trusted device. The application origin may transport roots but may not define or rotate them unilaterally.
- A fresh-head receipt binds scope, a fresh client nonce, committed revision/digest, witness sequence, observation time, status, and pending-reservation identity under the already specified domain and exact receipt-v1 format.
- Clients persist the highest accepted revision, digest, witness sequence, and root generation in storage with rollback resistance. A client that restores a lower local high-water must query the witness before accepting state. Browser local storage/IndexedDB and current protected-session APIs are not proven rollback-resistant.
- A new device or recovery package must validate the immutable base receipt under an independently trusted witness root, then fetch a fresh head and every contiguous transition. A valid signed base snapshot is not current authorization.
- Witness head history must be monitored for equivocation. A signed sequence number detects rollback only when compared with a previously pinned high-water; it does not stop a malicious witness from signing two branches to clients that never compare. A transparency log/independent monitor or a separately reviewed multi-witness consistency protocol is a release gate. Any conflict between monitors or pinned client checkpoints blocks both views pending reconciliation.
- Root rotation requires the old trusted root to authenticate the next root plus an independent owner-reviewed trust transition. Loss or compromise of a root is not solved by asking the app server to publish a replacement. If no valid continuity proof exists, affected authorization remains unavailable.
- A CAS backup restore to a point behind the witness is a recovery event, never an implicit rewind. Restore the CAS, replay the exact witnessed transition chain, compare terminal receipts, and keep the gate closed until its head matches. If the exact chain or terminal evidence is lost, do not lower the witness, reinitialize the keyring, or promote the snapshot.

## 9. Failure, availability, and disaster recovery

Safety is fail-closed for the affected keyring:

- CAS unavailable or no quorum: no transition, no fresh server-mediated protected admission.
- Status authority unavailable after CAS success: remain pending; reconcile by operation ID when it returns.
- Witness unavailable, ledger continuity uncertain, or key pin unknown: no current authorization and no new protected admission.
- Clock-health monitor unknown or skew above 30 seconds: reject new signed operations.
- Network partition: only the side that can prove the current head and complete the prescribed independent protocol may proceed; otherwise both sides stop. There is no split-brain mode.
- CAS failover: a successful commit must survive the configured durable/quorum boundary before the CAS acknowledges it. Asynchronous failover that can lose an acknowledged transition is not acceptable.
- Witness failover/restore: preserve reservation and head history with authenticated continuity; if uncertain, stay blocked. A stale witness backup must not reopen an earlier head.
- Status-authority failover/restore: preserve its signing key identity, terminal proof history, and no-commit tombstones. Lost terminal history means unresolved reservations stay blocked.
- A crash after each durable step is recovered by re-reading the immutable operation/reservation ID and its exact status; never infer outcome from process memory.
- Safety holds do not revoke offline copies already in user control. No RTO, availability SLO, or service credit is approved here; owner and operators must accept that sensitive operations can remain unavailable throughout an authority outage.

The CAS, status authority, witness, and content-admission monitor need independently documented backups, recovery keys, retention, and restore drills. D-008's 30-day trash/backup and 30/180-day log periods do not authorize pruning the keyring history, terminal ledger, witness checkpoints, or active no-commit fences. Those records need an explicit, separately reviewed retention/lifecycle design.

## 10. Bounds, capacity, clocks, and compromise handling

Use only the accepted bounded library limits: 4,096 transitions, 64 MiB aggregate history, 8 MiB per entry/page, up to 256 devices and 64 epochs, and a warning at 75% of either count or aggregate bytes. Record exact canonical serialized sizes for maximum device/epoch manifests and near-limit chains. The CAS rejects an append that exceeds a hard bound without pruning or changing the head.

These limits can prevent emergency device or package revocation. A warning is not capacity recovery. No production launch is permitted until a separately reviewed checkpoint/rekey or other safe lifecycle prevents capacity exhaustion from locking out necessary safety actions. Never label an implementation unrestricted, truncate proofs, or lower a bound to avoid a limit.

The signed operation validity remains nominally at most 300 seconds with monitored 30-second pairwise clock skew, making the worst real acceptance window 330 seconds. Both CAS and witness use monitored time, reject unknown/excessive skew, and enforce one-use operation IDs/tickets. The reservation itself does not expire open; once created, only an exact terminal commit or fenced no-commit resolution can release its gate.

A suspected recovery-package compromise follows the accepted compromise-package transition. It requires a trustworthy active device and every required historical epoch key; it revokes old signing/wrapping authority, activates a new package, increments the epoch once, and wraps the new epoch only to remaining active devices and the new package in the same CAS append. If no usable alternative authority, missing key material, missing complete wraps, absent export read-back/retention confirmation, or hard history exhaustion exists, report the precise blocking/unrecoverable condition. Do not continue new protected writes on the known-compromised epoch. Historical keys and copies are not retroactively revoked.

## 11. Provider patterns — comparison, not selection

All three patterns still require separate status and witness trust domains. A platform's built-in consistency feature does not make the platform an independent witness for its own database.

| Pattern | Atomicity and scale | Operations, failure and restore | Independence and migration |
|---|---|---|---|
| PostgreSQL primary with synchronous standby/quorum | A single transaction can compare and advance one keyring head while appending transition, operation result, reservation consumption, and fence. Row/advisory locking or serializable isolation needs careful retry handling. Reads must use the authoritative writer/linearizable path. | Synchronous replication can wait for selected standbys to flush WAL; the default is not synchronous, and per-transaction settings can weaken it. A managed service still needs verified promotion fencing, backup/restore procedures, and no stale replica reads. Self-hosting adds patching, failover drills, backup/PITR, connection and on-call work. | Most natural fit for structured history and current Node service, but no PostgreSQL provider or shared service is configured or verified. Separate CAS operations/credentials and backups from the app tier; use separately operated status and witness services. One-time import from local JSON/SQLite requires a quiesced write boundary and signed snapshot; no dual-write authority. |
| Cloudflare Durable Objects with SQLite, one object per keyring | Each object has private transactional strongly consistent storage. It can serialize one keyring's state. Cross-keyring or account-wide atomic mutations are not implied; routing and keyring-to-object identity must be immutable. | Restart-safe state must use persistent storage, not memory. SQLite-backed objects support point-in-time restore to the prior 30 days, so restore may roll back and must be fenced by the external witness. Cloudflare account administrators remain one platform trust domain. | Requires a new Workers runtime and data model; no DO binding exists here. The witness and terminal-status authority must be outside the same Cloudflare admin/backup domain to count as independent. Current pricing has usage-based request, duration, row, and storage dimensions; see cost model below. |
| etcd quorum cluster as a coordination ledger | etcd KV operations are atomic and strictly serializable by default; transactions can compare the head and append small coordination values. Use quorum-linearizable reads, never serializable stale reads for authorization. Large history entries may need content-addressed immutable blob storage staged and verified before an atomic digest/pointer append. | A three-member cluster tolerates one permanent member loss; loss of quorum stops updates. Snapshot restore starts a new logical cluster and can lower revisions; revision bumping helps consumers but does not replace the independent keyring witness. Operational burden includes peer networking, TLS, quorum, compaction, upgrades, snapshot checks, and restore drills. | A strong fit for a small coordinator but an extra specialized service beside the current Node/SQLite stack. Blob storage adds a separate durability dependency. The status authority and witness remain separate and must not be hosted under the same operational root as etcd if independence is claimed. |

PostgreSQL Serializable transactions provide serial execution semantics but can abort and require application retries; synchronous_commit and synchronous_standby_names must be configured deliberately for the durability guarantee. See [PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html), [WAL durability settings](https://www.postgresql.org/docs/current/runtime-config-wal.html), and [replication configuration](https://www.postgresql.org/docs/current/runtime-config-replication.html).

Cloudflare states that each Durable Object has private, transactional, strongly consistent storage; its SQLite-backed storage offers point-in-time restore within the past 30 days. Those are platform properties, not a separate Root.ark witness or proof of application admission. See [Durable Objects storage](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/) and [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/).

etcd documents durable, strictly serializable KV operations and linearizable reads by default, while serializable reads may be stale. Its disaster-recovery documentation warns that restoring snapshots can move revisions backward and describes revision-bump recovery. See [etcd API guarantees](https://etcd.io/docs/v3.6/learning/api_guarantees/) and [etcd disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/).

### Cost model (illustrative, not a quote or provider approval)

A deployment estimate must include both money and operator time:

- For a self-hosted candidate, estimate monthly total as node and durable-storage charges across failure domains + network/backup/PITR/monitoring + status and witness service costs + independent key custody + operator hours × the owner's loaded hourly cost. For a managed candidate, replace node cost with its measured request/CPU/storage/replication charges; do not omit the independent authorities or operations.
- **PostgreSQL:** provider/VM or managed-cluster base; primary plus synchronous standby across failure domains; durable storage/WAL; backup/PITR and restore exercises; network; monitoring; and staff/on-call. The separate status authority and witness add their own compute, durable ledger, key custody, monitoring, and restore costs. No current Root.ark provider, region, scale, or price is known, so no numerical PostgreSQL total is represented as fact.
- **etcd:** three or five coordinator members across failure domains; persistent disks/snapshots; network/TLS; optional immutable blob storage for large history; plus independently operated status and witness services and staff/on-call. No selected host means no defensible monthly total yet.
- **Cloudflare example only:** the official pricing page, checked 2026-10-19, lists a $5/month Workers Paid account base, 1 million Durable Object requests/month included then $0.15 per additional million, 400,000 GB-s duration included then $12.50 per additional million GB-s, 25 billion SQLite row reads/month and 50 million row writes/month included, and 5 GB-month SQL storage included then $0.20/GB-month. Under a transparent example of 10 million head/admission calls plus 100,000 transitions/month, assuming one Durable Object request and one SQLite row read per head call, four requests per transition, 1 ms average metered active time at 128 MiB, six row writes per transition, and 2 KiB per retained event, the estimated DO request overage is 9.4 million × $0.15 = $1.41. Compute, rows, and raw event storage remain below the published included amounts under those assumptions. The illustrative Durable Objects portion is therefore about $6.41/month including the account base, excluding Workers front-door request/CPU costs, status authority, witness, backups beyond included storage, taxes, support, and operations. This is not a system TCO or workload forecast; real operation counts, indexes, retained history, per-object activity, and independent services may dominate.
- For all candidates, cost at actual workload requires measured read admissions, transition rates, average/max manifest sizes, retained bytes, cross-region replication, witness/status proof volume, audit retention, availability target, and restore objectives. Do not reduce freshness checks or share administration merely to meet a budget.

## 12. Invariants and acceptance evidence

The following are design invariants, not current test results. Deterministic mocks can establish API/state-machine behavior only. Every item marked provider/runtime acceptance requires the actual selected system, credentials, topology, failure controls, independent roots, and cross-process tests.

| ID | Invariant / adversarial case | Mock-only evidence | Required real acceptance |
|---|---|---|---|
| CAS-1 | Two concurrent requests at the same expected head produce at most one committed next revision. | State-machine race test. | Concurrent clients/processes against the selected CAS with forced overlap and restart. |
| CAS-2 | Same operation ID + same digest is idempotent; same ID + changed bytes or digest conflicts. | Exact retry and altered-request tests. | Provider uniqueness/transaction tests and failover/retry. |
| CAS-3 | History append, head advance, package pointer, reservation consume, and operation result are atomic. | Fault injection around simulated transaction. | Kill processes/nodes at each transaction boundary and verify durable exact head. |
| GATE-1 | Witness pending is durable before ticket release; no fresh read or write accepts old r while pending, including after a committed-but-unwitnessed revocation. | Pending-state model tests. | Cross-process and service restart tests while CAS is restored to r and an actor revoked at r+1 attempts access. |
| GATE-2 | Existing admissions are fenced/drained before CAS mutation begins; no stale permit publishes after gate closure. | Permit ordering/replay tests. | Actual content and transfer adapters under concurrent streams, node restart, and revocation race. |
| STATUS-1 | Status proof binds exact scope, reservation, operation, request digest, and terminal head; app assertions are ignored. | Forged/mismatched proof tests. | Independent authority reads authoritative CAS state and signs only exact durable outcomes. |
| STATUS-2 | No-commit is a permanent CAS-side fence; delayed writes under that operation ID cannot commit after gate release. | No-commit race model. | Provider transaction/fencing test under lost replies and delayed in-flight writers. |
| FRESH-1 | Stale CAS snapshot, stale witness response, wrong nonce, lower local high-water, or mismatched digest fails closed. | Stale receipt and rollback fixtures. | Real pinned-root clients, durable high-water, backup restore, and live witness/status. |
| FRESH-2 | Witness split view, key rotation loss, and inconsistent monitors block both branches. | Forked signed-log fixtures. | Independent monitor, two isolated clients, root recovery exercise, and exact proof verification. |
| CRASH-1 | Crash after gate, CAS commit, terminal proof, or witness finalize is reconciled by exact IDs; no uncertain path opens. | Restartable fake-service state machine. | Cross-process crash/restore at every durable edge with real status and witness services. |
| OUTAGE-1 | Any required authority outage or unknown status blocks new sensitive operations. Offline user-held exported files remain local and accessible. | Mock unavailable/pending results. | Partition, timeout, clock failure, and restored-copy tests on selected topology plus real user-client behavior. |
| TIME-1 | Boundary acceptance never exceeds nominal 300 seconds + monitored 30-second skew; no grace or ticket reuse. | Full time-boundary vectors. | Independent clock monitoring and skew fault injection at CAS and witness. |
| REC-1 | Compromise rotation is one CAS transition; no future epoch wrap to compromised package; final-path loss reports unrecoverable. | Crypto-library vectors plus transition tests. | Full export, fresh package, trusted device, content rotation, and user-approved retention flow. |
| CAP-1 | Maximum 256-device/64-epoch manifests are measured; 75% warning appears; first over-limit append fails without truncation. | Exact deterministic-CBOR sizing/capacity fixtures. | Provider stored-size/index/backups measurements and safe emergency response beyond the cap; checkpoint lifecycle remains a separate gate. |
| MIG-1 | No dual-write split-brain or legacy-store fallback creates current authority. | Import/export format tests. | Quiesced one-time migration, reconciled snapshot, witness base receipt, restore and rollback drill. |
| ORIGIN-1 | Client code and pinned trust roots are authenticated outside the app origin. | Static bundle/root-signature verification tests. | Supported browser/OS custody and hostile-origin assessment; currently not demonstrated. |

A green mock suite never satisfies a provider-acceptance row. A single-node SQLite test, in-memory service, local JSON file, or one-process test is not evidence of distributed ordering, terminal truth, witness independence, restore safety, or protected-content gating.

## 13. Integration gates and proposed roadmap

1. **Owner decision:** select a provider pattern only after an infrastructure inventory, cost envelope, outage target, and independent operator/key-root plan exist. This specification does not select it.
2. **Trust-root design:** define who operates CAS, terminal status, and witness; prove separate administration/backup roots; define client bootstrap, witness fork monitoring, root rotation/loss, and supported client high-water storage.
3. **Provider contract and threat review:** turn Sections 5–12 into a backend-specific contract and exact acceptance plan. Do not write the implementation plan until Packet B has independent review and owner approval.
4. **Provider prototype in isolated non-production infrastructure:** first RED then GREEN provider races/crash/restart/restore tests. A mock can precede it but cannot pass this gate.
5. **Client and content admission:** independently approve actual browser/Android client security and integrate fresh authorization with every protected read/write/download/transfer entry point. Browser eligibility remains blocked until exact browser, OS, code-root, and key-storage configuration is verified.
6. **Migration and operations:** inventory legacy JSON/SQLite data without treating it as current CAS; design a quiesced one-time import if protected runtime data exists; prove backups, restore, witness reconciliation, retention, incident response, and capacity lifecycle.
7. **Separate release decision:** exact-SHA independent review, full platform tests, deployed topology evidence, migration/user acceptance, approved transfer TTL, and all remaining issue #65 criteria. Keep #65 open until accepted evidence exists.

### Explicitly blocked by this proposal

- Selecting or provisioning PostgreSQL, Cloudflare Durable Objects, etcd, or any other provider.
- Claiming shared linearizable CAS, independently truthful terminal status, an independently pinned witness, durable reservations, anti-rollback local storage, or fresh protected-content admission is deployed.
- Browser or Android trusted-device enrollment, OS-backed key custody, WebAuthn PRF binding, package-retention UX, or full content recovery.
- Protected file upload/download/transfer enforcement, migration, cross-client interoperability, or production data access.
- Transfer TTL, service RTO/SLO, recovery-root rotation ceremony, history checkpoint format, and data lifecycle beyond current limits.
- Merge, release, deployment, production inspection, remote PR changes, or closing issue #65.
