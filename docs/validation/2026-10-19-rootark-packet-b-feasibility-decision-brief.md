# Root.ark Packet B — Technical Feasibility Decision Brief

**Status:** FEASIBILITY_PLAN_READY_FOR_OWNER_DECISIONS
**Review scope:** Documentation and read-only technical/pricing research. No runtime code, tests, packages, cloud resources, credentials, production data, migrations, or external state were changed.
**Repository baseline:** ad2373b2a71feec6bb201f627038d93d12196047, branch cdx/rootark-dual-recovery-20261019.
**Packet B source examined:** Corrected provider-neutral spec at that baseline; the previously reviewed Packet B SHA is aa19c72f831cd9e847b6d37b15f840a008c0901a.
**Prior protocol source:** [dual-recovery specification](../superpowers/specs/2026-10-19-rootark-dual-recovery-design.md), Section 12.4.
**Current Packet B spec:** [shared-CAS and witness design](../superpowers/specs/2026-10-19-rootark-packet-b-shared-cas-witness-design.md).
**Feasibility plan:** [PostgreSQL-first provider-neutral plan](../superpowers/plans/2026-10-19-rootark-packet-b-postgresql-feasibility-plan.md).

## Decision summary

The shared-CAS / independent-status / witness-GateAuthority direction is a plausible target for a bounded non-production feasibility study. **PostgreSQL is the non-binding first lab candidate**, because its transactional records and structured immutable history fit the current Node server more naturally than the alternatives. It is not selected or provisioned. Cloudflare Durable Objects and etcd remain candidates.

The current repository does not supply the required guarantees: persistence is local SQLite/filesystem-backed JSON, the sync JSON store is serialized only within one process, and there is no shared CAS, status authority, witness/GateAuthority, independent client trust-root bootstrap, or physical data-plane gate. Existing Node recovery-library evidence is not deployed recovery evidence.

Two feasibility blockers precede protocol implementation:

1. **Wire-schema blocker:** Prior v1 status-proof, reservation-ticket, and cancellation-receipt type literals are not frozen in the inspected source/test registry. Do not guess a literal or change the v1 schemas. Resolve the values in an owner-approved schema artifact after cryptographic review.
2. **Data-plane blocker:** No selected existing Root.ark storage/egress boundary has demonstrated per-effect generation fencing or a trustworthy stop acknowledgement. If an authorized future lab cannot make each storage read, write commit, and output chunk linearize with the gate, the feature remains blocked.

The 4096-transition / 64-MiB history limit can block emergency revocation and compromise response. A warning at 75% does not solve that availability risk. Production readiness requires a separately reviewed safe capacity lifecycle.

## Evidence provenance and current implementation gap

- Read-only checkout inspection confirmed db/index.js loads better-sqlite3 and resolves DATABASE_URL through path.resolve as a filesystem path. It is not a PostgreSQL URL.
- src/routes/sync.js persists a JSON object and serializes updates through a promise queue in the current process. This does not provide multi-process or multi-host linearizability.
- package.json exposes node --test, npm run validate:syntax, and npm run validate:artifacts; no PostgreSQL driver/provider fixture is in the current manifest.
- The F-01/F-02 recovery-library corrections remain bounded library evidence. The Phase A evidence report marks browser/authenticator evaluation NOT_RUN and does not establish browser key custody, CAS, witness, runtime admission, or content recovery.
- The independent architecture review accepted the corrected Packet B design for bounded feasibility planning only; it did not approve runtime or infrastructure. Prior P1/P2 design findings were addressed in documentation only and have not been validated against a real provider or data plane.
- The accepted F-01/F-02 crypto-library source is commit 7dd1c861d2b570d7bc51ce66e8054bcc431f4c07. It resolves two bounded library findings; it does not prove online freshness, trusted browser custody, provider CAS, service recovery, or issue #65 completion.
- Read-only issue #65 owner decisions preserve both recovery paths, prohibit an admin master/fallback, require online fresh authorization for new operations, and leave runtime recovery incomplete. Issue #65 remains open.
- The requested AI Memory lookup did not find an authoritative Root.ark Packet B page; one focused global search also had no direct Packet B record. The requested Obsidian vault search found no direct Packet B decision. Repository source documents and issue #65 owner decisions are the evidence used here; historical imported notes, if any, are not binding.
- No independent security reviewer was used in this feasibility pass. This is a documentation-level assessment, not an independent audit.

## Provider feasibility comparison

| Dimension | PostgreSQL with WAL/replication | Cloudflare Durable Objects with SQLite | etcd with immutable external blob staging |
|---|---|---|---|
| Atomic per-keyring compare-and-append | A transaction can compare the exact scoped head, validate operation/reservation state, append immutable canonical manifest bytes, advance the head, record idempotency, publish package pointer, and consume reservation. Enforce with constrained transaction API, uniqueness, append-only privilege model, and exact digest checks. SQL does not supply Root.ark authorization semantics. | One object per keyring is a plausible serialization boundary. SQLite-backed storage is transactional and strongly consistent per object, with storage private to that object. Keep every correlated atomic record in the same object; do not assume cross-object atomicity. | etcd transactions provide atomic compare/then/else across keys within request/operation limits. The application still validates signatures/policy and maps history to immutable blob digests. |
| History, package envelope, and idempotency | Store exact canonical bytes and digest; append-only transitions, unique scope/operation, exact request digest, and active package pointer. Stage envelope immutably, verify read-back, then publish pointer in CAS. | Same logical records in a single per-keyring object; independent envelope staging and object placement need design. | Store large history/envelope bytes in immutable blob storage; etcd holds revision/digest pointers. Stage/read back blob before pointer transaction. Default 1.5-MiB request is below the protocol 8-MiB history-entry ceiling. |
| Terminal record and irreversible fence | Must serialize in the same CAS domain as append. Status authority reads authoritative durable result and receives only a narrowly scoped conditional fence privilege. Querying no row is not finality. | Durable fence must be in same per-keyring object/transaction order as append. Separate status operator still needs restricted fence API and key custody. | Compare/update fence and append keys in one transaction. Blob bytes do not prove finality; test exact transaction operation count and request size. |
| Reads, acknowledged durability, failover, restore | Must configure and prove synchronous acknowledgement, retained acknowledged WAL through promotion, no stale replica admission, and fencing of the old primary. Streaming replication is asynchronous by default. remote_apply makes a transaction visible on synchronous standby, but does not itself fence a primary, select a safe promotion, or prove restore continuity. Serializable isolation and synchronous_commit alone are insufficient. Synchronous replication also does not create independent operators or by itself prove no-loss failover. | Strong consistency and transactional storage are within one object. PITR can roll an object back, so restore must reconcile independently pinned witness high-water and stay closed if continuity is uncertain. | Default range reads are linearizable; serializable member-local reads may be stale. Quorum, leader change, snapshot restore, revision repair, and witness high-water need tests. etcd restore/revision tools do not replace the independent Root.ark witness. |
| Capacity and limits | Measure append-only records, indexes, WAL, replicas and backup sizes. Existing project SQLite is not a shared store. | SQLite row/value max is 2 MiB and paid Durable Object storage max is 10 GB per object. Each object is single-threaded with a documented soft limit of 1,000 requests/s; measure per-keyring gate queues and overload behavior. Split large immutable bytes out of rows. | Default request limit 1,572,864 bytes; default transaction limit 128 operations; default quota 2 GiB with 8 GiB recommended for normal deployments. The 8-MiB entry and 64-MiB per-keyring history need staged blobs, digest pointers and measured aggregate quota. |
| Additional components | Root.ark authorization/signature validation, scoped CAS API, no-commit fence, status signer, separate witness ledger, gate generations, storage/egress stop, client trust bootstrap, monitoring, failover and restore operation. | Same, plus Worker/object routing, per-keyring object placement, separately operated status and witness, externally pinned roots, and real egress/storage generation enforcement. Cloudflare alone does not create organizational trust independence. | External blob store, transaction mapping, status authority, witness/GateAuthority, protected-I/O fencing, root bootstrap, monitoring and restore operations. |
| Maintainability / burden | **Best first feasibility candidate (non-binding).** Relational transactions and structured history are a relatively natural fit for current Node server. HA correctness, SQL privilege discipline, failover tooling, independent authorities and backup recovery remain substantial work. | Per-object serialization and managed operations are attractive; platform-specific routing, cross-service topology, per-gate-call cost/latency and data-plane fences need proof. One Cloudflare admin account is one trust domain. | Strong compare/read primitives but greatest app/ops complexity here; external blobs and explicit consensus restore/high-water coordination are required. |

Official provider statements describe primitives and limits, not Root.ark guarantees. Only a real-provider lab can validate the chosen configuration, durability, promotion fencing, and restore behavior.

## Non-binding first lab candidate and trust topologies

> **Evaluate PostgreSQL first as a lab/prototype candidate** because its transactional append and structured history map naturally to Root.ark's existing Node server; a production choice needs measured durability, failover, operator independence and full cost evidence.

The possible future lab is disposable and synthetic-data-only, and requires a separate owner authorization. A concrete target contains a CAS candidate with primary/standby roles and an explicit old-primary fence; two independently addressable gateways; a restricted status/fence authority; a separate witness/GateAuthority with durable append-only ledger and key custody; at least two independent consistency monitors; immutable blob staging; and storage/egress adapters capable of generation fencing and stop acknowledgement. No current product, operator, vendor, cloud account, key, region, or client trust root is assumed to exist.

Candidate trust topologies:

1. **Distinct service operators:** CAS under operator A; status/fence signer under separately governed operator B; witness/GateAuthority and monotonic ledger under operator C; independent consistency monitors D and E. Deploy credentials, backup roots, key rotation, and incident access are separate. Client pins are carried by an independently authenticated client release/configuration.
2. **Institutional control split:** Root.ark infrastructure organization operates CAS; a separate security/control-plane organization holds the status signer and narrowly scoped read/fence access; an independent witness organization runs GateAuthority; a different auditor/transparency-monitor service checks equivocation. Client trust-root delivery still needs a separately reviewed channel.

These are candidate diagrams, not assigned or provisioned parties. Shared cloud account administrators, shared backup credentials, or a single individual controlling all three services do not establish adversarial independence. Web-first JavaScript from the application origin cannot bootstrap trust in a key delivered by that same potentially compromised origin. No verified browser trust anchor or key custody currently exists.

## Exact v1 wire compatibility and unresolved schema literals

The prior dual-recovery specification Section 12.4 remains normative. Packet B's prior incompatible status-proof proposal is withdrawn. No new v1 wire shape is authorized.

| Object | Existing v1 domain and field set | Compatibility ruling |
|---|---|---|
| Fresh witness-head receipt | Root.ark/zk-1/recovery-witness-head/v1 + NUL; type, witness_key_id, account_id, compartment_id, keyring_id, current_revision, current_manifest_digest, witness_sequence, 32-byte nonce, observed_at, status, pending_reservation_id, signature. Prior spec explicitly names type rootark-recovery-witness-head/v1. | Separate signed object. Committed head has revision/digest and no pending reservation; pending response is not an acceptable head. |
| Reservation ticket | Root.ark/zk-1/recovery-witness-reservation/v1 + NUL; type, reservation_id, witness_key_id, scope, expected revision/digest, proposed revision/digest, operation_id, request_digest, package_envelope_digest, expires_at, signature. Expected head is null only for initialize; envelope digest is the post-transition active package digest or null when none is active. | Separate object; exact type literal is not frozen in prior text or inspected src/test registry. Resolve by reviewed schema clarification, never infer from the domain. |
| Terminal CAS status proof | Root.ark/zk-1/recovery-cas-status/v1 + NUL; type, status_authority_key_id, scope, reservation_id, operation_id, request_digest, package_envelope_digest/null, expected revision/digest, proposed revision/digest, observed revision/digest, terminal_status, observed_at, fresh 32-byte nonce, signature. Expected revision/digest are null only for initialize; observed head fields are null only when absent. | terminal_status is committed or not-committed-final. Binds exact request, witness/client challenge, envelope, and expected/proposed/observed heads. Prior type literal is not frozen in prior text or inspected src/test registry; do not guess. |
| Commit receipt | Root.ark/zk-1/recovery-witness-commit/v1 + NUL; type, reservation_id, scope, committed_revision/digest, operation_id, witness_sequence, status, signature. | Separate witness-signed receipt; status must be committed. Preserve any existing literal named in prior contract. |
| Cancellation receipt | Root.ark/zk-1/recovery-witness-cancel/v1 + NUL; type, witness_key_id, scope, reservation_id, operation_id, status_authority_proof_digest, resolved_at, status=cancelled, signature. | Separate witness-signed receipt. Its prior type literal is not frozen in prior text or inspected src/test registry. Receipt alone does not reopen the old head. |

Every proof is deterministic CBOR and uses its prior Ed25519 domain plus a NUL separator; signatures cover the exact existing fields except signature. The status proof is fetched directly by the witness from the independently pinned status authority, not accepted from an app-server assertion.

Preserve the prior encoded widths: account_id, keyring_id, reservation_id, operation_id, witness_key_id, and status_authority_key_id are 16 bytes; compartment_id is 1–128 bytes; digests are 32 bytes; signatures are 64 bytes; nonce is 32 bytes; revision/sequence and timestamp values retain the prior unsigned integer constraints. Null is accepted only where the existing v1 contract permits it.

For committed, exact durable CAS result must exist and observed head must equal proposed head. For not-committed-final:

1. Wait through reservation expiry plus the 30-second skew bound.
2. Confirm via authoritative CAS that the head remains exactly expected and no result exists.
3. Atomically persist an irreversible tombstone preventing a delayed append forever; a no-row query is never terminality.
4. Sign the exact v1 status proof with the fresh challenge nonce.
5. Witness verifies it and persists the separate cancellation receipt bound to proof digest.
6. Client verifies the status proof, matching cancellation receipt, then obtains a new nonce-bound committed witness-head receipt with no pending reservation matching fresh CAS state. Otherwise remain blocked.

Operation lifetime is nominally at most 300 seconds with 30 seconds maximum monitored skew: worst-case effective acceptance is 330 seconds and there is no post-expiry admission grace. CAS, status and witness block on unknown/excessive clock health. A fence and exact proof are both required: the proof authenticates an outcome to clients; only the CAS-side durable fence makes a future commit impossible.

A read-only source/test search found no implementation registry defining the status-proof, reservation-ticket, or cancellation-receipt type literals. This is a specific wire-schema clarification dependency and blocks v1 encoders. Do not invent a literal or change a v1 domain/field set.

There are two safe ways to resolve that gap: find an authoritative pre-existing schema registry/fixture that freezes the literal and verify its provenance, or have the owner and an independent protocol reviewer approve a schema clarification that freezes the intended type values while preserving the existing v1 domains and fields. If neither proof exists, do not emit/accept those v1 objects. No v2 extension is proposed here.

## Single linearizable gate and data-plane feasibility

One logical per-keyring gate ledger must serialize acquireAdmission, consumeAdmission, authorizeIoStep, and beginQuiescing across all gateways. Separate local atomicity in the gateway and witness is insufficient.

| State | Required behavior |
|---|---|
| OPEN(g, head) | acquireAdmission may create a one-time permit bound to current gate generation g and exact keyring head. The permit grants no I/O. |
| consume | On the same linearizable ledger, consume succeeds only while OPEN with matching generation/head, consumes once and creates one durable active session. Exact authenticated idempotent retry can return that same result after lost reply but cannot create another stream/worker. |
| authorizeIoStep | Storage/egress asks the live authority at each actual protected read, write commit, and output chunk. The data plane enforces the result at the effect boundary. Token possession or a check followed by uncontrolled I/O is a TOCTOU flaw. |
| QUIESCING | beginQuiescing linearizes on that ledger, closes acquire/consume, increments generation and cancels unconsumed permits. Previously consumed sessions are tracked. Storage/egress generation-fences old effects, stops active work and gives a trusted acknowledgement. CAS mutation starts only after all prior effects finish or the adapter proves they can no longer read, commit, or emit another chunk. |
| PENDING | Exact reservation is durable. New sensitive reads, recovery, enrollment, authorization, write and content admission all fail closed. |
| COMMITTED_UNWITNESSED | CAS committed but witness finalization is pending. Old head never becomes acceptable; only exact status proof and witness resolution can continue. |
| RESOLVED_COMMIT / RESOLVED_NO_COMMIT | Reopen only after exact terminal proof, corresponding witness receipt, fresh nonce-bound head, and generation advance. |
| BLOCKED | Any ambiguity, root/ledger restore uncertainty, partition, missing stop acknowledgement, clock fault, split view, or CAS/witness mismatch remains closed. |

If a returned authorization can be delayed while a storage operation proceeds under an old token, the gate must proxy the I/O or the storage/egress adapter must enforce generation atomically with the effect. Otherwise the design has no safe linearization point. Lease expiry, timeout, worker self-report, process restart, empty memory, or network partition does not prove termination. Already emitted plaintext, in-flight network buffers, and files already downloaded/exported are not remotely revocable.

Per-step checking adds authoritative round trips, per-keyring serialization, queue contention, audit volume, stream interruption, and dependency on controlled egress. Measure p50/p95/p99 and throughput under backpressure, but do not batch across a security boundary or weaken checks to meet a performance target.

## Workload and cost model

**Pricing snapshot:** checked 2026-10-19. USD public list prices. DigitalOcean illustration assumes NYC3 only as an example; it is not a selected region/provider. Cloudflare pricing is global. Taxes, FX, discounts, support, backup add-ons, status/witness operators, signing-key custody, monitor, blob store, gateway/egress, and staff are excluded unless listed. No cloud account or quote was created.

### Hypothetical workload bands

| Band | Active keyrings | Transitions/mo | Gate/effect checks/mo | Encrypted transfer/mo | Mean transition size | Logical one-year history plus 64-KiB head/keyring |
|---|---:|---:|---:|---:|---:|---:|
| Light personal | 100 | 100 | 0.25 million | 100 GiB | 4 KiB | about 10.9 MiB |
| Moderate | 20,000 | 5,000 | 5 million | 10 TiB | 16 KiB | about 2.14 GiB |
| Higher-volume stress | 300,000 | 100,000 | 50 million | 100 TiB | 64 KiB | about 91.6 GiB |

Assume 4-MiB transfer chunks. Each band’s gate/effect-check input exceeds its transfer-chunk count and also includes admissions, storage steps, write commits and control operations. Inputs are planning scenarios, not measured Root.ark behavior. Storage estimate includes one year of transitions plus the stated current head only; this is a cost-model horizon, not a product-retention decision. It excludes indexes, WAL, replication, backups, proof/log copies, metadata, staged envelopes and unbounded older history. No history pruning is defined. Hot-key limits must be measured separately. No uptime/SLA or availability credit is assumed.

### Illustrative monthly component prices

| Candidate | Light | Moderate | Stress | Limits of illustration |
|---|---:|---:|---:|---|
| PostgreSQL, DigitalOcean Advanced | 2 × $130 = **$260** | 2 × $130 = **$260** | 3 × $130 = **$390** | $130/node starting Advanced 8-GiB/2-vCPU plan; HA standby bills same rate; additional billable storage is $0.115/GiB-month. Node counts are illustrative lab shapes only. Backup, status, witness, blob, monitor, egress, and labor are additional. |
| Cloudflare Worker + SQLite Durable Object modeled subset | **about $5.00** | **about $5.60** | **about $48.23** | Formula below covers only modeled Worker+DO CAS/gate usage. Separate status, witness, independent keys/monitoring, backups, trust-root client, app data plane, and staff are excluded. Earlier approximately $6.41/month DO example is also limited and may omit application Workers or workload-specific operations; it is not system TCO. |
| Three DigitalOcean Basic Droplet etcd compute nodes | 3 × $6 = **$18** | 3 × $12 = **$36** | 3 × $24 = **$72** | VM compute only; add blob storage, backups, status, witness, keys, monitoring, network/egress and labor. Three nodes in one provider/account/region do not prove independence or safe quorum recovery. |

Cloudflare formula on Workers Paid:

    C = $5 account base
      + $0.15 × max(0, DO_requests_millions - 1)
      + $12.50 × max(0, DO_GB_seconds_millions - 0.4)
      + $0.001 × max(0, SQLite_reads_millions - 25,000)
      + $1.00 × max(0, SQLite_writes_millions - 50)
      + $0.20 × max(0, SQLite_decimal_GB_month - 5)
      + $0.30 × max(0, Worker_requests_millions - 10)
      + $0.02 × max(0, Worker_CPU_milliseconds_millions - 30)

Assumptions: DO requests = gate checks + four control RPCs per transition; one Worker request per modeled DO request; Worker CPU 5 ms/request; DO billed duration 10 ms/request at 128-MiB allocation; SQL reads = 2 × gate checks + 4 × transitions; SQL writes = gate checks + 6 × transitions; logical GiB converted to decimal GB for billing. Resulting modeled Worker+DO totals are approximately $5.00 / $5.60 / $48.23. They are illustrative only: actual billing depends on class/object topology, row/index counts, CPU and request durations, storage and actual usage.

Full monthly system cost must use:

    C_total = CAS + durable storage/replicas/WAL + staged blobs
            + status service/key custody + witness/GateAuthority/key custody
            + independent monitors/transparency + backup/restore + network/egress/logs
            + client/admission runtime + operator hours × loaded labor rate

Where vendor, workload, retention, geography, egress and labor are unknown, retain the formula and collect owner inputs. Price cannot establish trust independence or justify unsafe fail-open behavior.

### Availability / recovery options

| Option | Cost and operations | RTO/RPO implications |
|---|---|---|
| Lower-cost fail-closed personal service | Minimize redundant components only if the owner accepts low availability; separate status and witness still carry fixed trust/ops cost. | Feature RTO may be unbounded during any required authority outage. No RPO claim unless every acknowledged commit survives promotion/restore and external witness high-water matches. |
| Isolated synthetic lab | Disposable resources and synthetic state only; no user admission or data. | RTO/RPO apply only to fixtures and measured experiments, not service. |
| Higher-availability multi-operator candidate | Redundant CAS, status, witness/GateAuthority, monitoring, and separate backups; highest compute, audit and coordination burden. | May improve recovery time, but objectives remain unselected. RPO zero for acknowledged changes only after promoted-head continuity is proven; mismatch stays blocked. |

## Future adversarial acceptance and verdicts

The executable test matrix is in the feasibility plan. It covers two same-head CAS appends; exact retry versus changed digest; acknowledged commit then leader loss; stale follower/snapshot and old-key replay; status crash before/after fence; delayed append after no-commit; expiry/skew boundaries; forged/missing status, stale nonce, changed envelope/head and wrong v1 type/domain; pending-gate permit race and replay; two gateways; slow streaming download/upload; gateway and egress crashes; partition and stop acknowledgement; partial stream abort during CAS commit; witness split view, key loss, high-water mismatch, old signed head, monitor conflict and clock failure; 75% warning and hard-cap safety revocation; compromised-package future rotation; and crash/restore after every durable transition.

- **GO** only for a later separately approved stage after real-provider failover/restore, durable no-commit fence, independent operators and pinned roots, per-effect storage/egress generation fence, stop acknowledgements, capacity lifecycle, and independent exact-SHA review pass.
- **CONDITIONAL** means lab evidence only; keep production recovery and protected admission disabled and list each unresolved proof.
- **NO-GO** is mandatory for missing trust independence, status from stale/no-row/app assertion, late append after fence, lost acknowledged CAS transition, no external witness pin, old-generation I/O, absent physical stop proof, unresolved split view, guessed v1 type, or history exhaustion that can prevent emergency revocation.

Mocks and single-machine simulations can validate code contracts only. They do not earn real-provider PASS, independent-operator proof, customer runtime readiness, or issue closure.

## Official source links and bounded claims

Prices and limits were checked on 2026-10-19:

- [DigitalOcean PostgreSQL pricing](https://docs.digitalocean.com/products/databases/postgresql/details/pricing/) — Advanced Edition $130/month starting node, standby billed at same rate, $0.115/GiB-month additional storage; Standard standby/account limits are date-sensitive.
- [DigitalOcean Droplet pricing](https://www.digitalocean.com/pricing/droplets) — Basic $6 / $12 / $24 monthly plans and listed resources/transfer.
- [DigitalOcean regional availability](https://docs.digitalocean.com/platform/regional-availability/) — must be rechecked when any region is proposed.
- [Cloudflare Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) — Workers Paid base and request/CPU prices; Durable Object request, duration, SQLite row read/write and storage pricing.
- [Cloudflare SQLite-backed Durable Object storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/) and [limits](https://developers.cloudflare.com/durable-objects/platform/limits/) — transactional strongly consistent storage private to one object, PITR, 10-GB paid storage per object, and 2-MB row/value limit.
- [PostgreSQL standby and synchronous replication](https://www.postgresql.org/docs/current/warm-standby.html) — streaming replication defaults asynchronous; remote_apply waits for replay visibility but does not provide Root.ark promotion authority or old-primary fencing.
- [PostgreSQL failover](https://www.postgresql.org/docs/16/warm-standby-failover.html) — old primary must be prevented from returning as primary to avoid split brain.
- [etcd request/storage limits](https://etcd.io/docs/v3.6/dev-guide/limit/) and [configuration defaults](https://etcd.io/docs/v3.6/op-guide/configuration/) — 1.5-MiB request default, 128-operation transaction default, and quota guidance.
- [etcd transactions and reads](https://etcd.io/docs/v3.6/learning/api/) — atomic compare/then/else; linearizable range reads by default; serializable local reads may be stale.
- [etcd disaster recovery](https://etcd.io/docs/v3.7/op-guide/recovery/) — revision-bump/compaction tools mitigate consumer rollback but are not an independent Root.ark freshness witness.

Vendor documentation is not Root.ark service validation, operational independence proof, failover guarantee, trust assurance, or vendor approval.

Other repository evidence: [D-011 product decision](../product-discovery.md), [Phase A evidence](2026-10-19-rootark-web-phase-a-evidence.md), [zero-knowledge migration contract](../architecture/zero-knowledge-migration-contract.md), and [issue #65 plan tree](../plan-tree.md). These documents preserve product policy and current readiness boundaries; none is deployment proof.

## Owner decisions — all UNSELECTED

| Decision | Current state |
|---|---|
| First disposable lab candidate | UNSELECTED. PostgreSQL is recommended to evaluate first only; Durable Objects and etcd remain alternatives. |
| Provider, geography and data residency | UNSELECTED. NYC3 appears only in a DigitalOcean cost illustration. |
| CAS, status, witness/GateAuthority, key custody, backup and monitor operators | UNSELECTED. Distinct accountable trust domains and separate admin/backup roots are required. |
| Client trust-root bootstrap and browser key custody | UNSELECTED / BLOCKED. Same-origin JavaScript/key is not independent; no verified browser custody exists. |
| Monthly budget, support and operator labor | UNSELECTED. Prices here are partial illustrations. |
| RTO, RPO, outage tolerance and fail-closed availability | UNSELECTED. User-held exported files remain usable offline; new protected operations require online fresh authorization. |
| Status/witness rotation, key loss, ledger restore and incident authority | UNSELECTED. Restore uncertainty stays fail closed. |
| History capacity lifecycle and emergency revocation near hard cap | UNSELECTED / BLOCKED. No pruning/checkpoint protocol is approved. |
| Package export/retention, last-path-loss communication, migration and content recovery | UNSELECTED / BLOCKED. No administrator fallback. |
| Transfer TTL | UNSELECTED; separate from D-008 trash, backup, and log retention. |
| Future execution roles | UNSELECTED. Before implementation choose native subagents or verifiably configured Dual Agents/Dual Codex, with explicit Architect, Executor and reviewer roles. |

## Safe next step

The next gate is one owner review of the feasibility plan and this brief, followed by explicit choices on lab candidate, independent trust-domain operators, client-root bootstrap, budget/regions, outage objectives, and authorization for a disposable synthetic-data lab. Until then, do not provision a database, select a production service, create keys/accounts, change runtime behavior, close issue #65, or claim deployed Zero-Knowledge recovery. Runtime integration, browser trust, migration, issue closure, and release remain **BLOCKED / NOT READY**.
