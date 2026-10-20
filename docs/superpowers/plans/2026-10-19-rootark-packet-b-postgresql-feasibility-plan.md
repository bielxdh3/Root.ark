# Root.ark Packet B — PostgreSQL-First Provider-Neutral Feasibility Plan

> **Status: FEASIBILITY PLAN ONLY.** This plan does not authorize execution, provider selection, implementation, infrastructure provisioning, runtime admission, migration, merge, release, or issue closure. All tasks below are unchecked and unstarted.

**Goal:** Decide whether a provider-neutral shared compare-and-swap (CAS), terminal-status authority, freshness witness/GateAuthority, and protected-I/O fence can be safe and operable for Root.ark. If the owner separately authorizes a disposable lab, evaluate PostgreSQL first as one candidate against Cloudflare Durable Objects and etcd. Produce evidence and a GO / CONDITIONAL / NO-GO recommendation; do not infer a production choice.

**Architecture baseline:** The [provider-neutral Packet B design](../specs/2026-10-19-rootark-packet-b-shared-cas-witness-design.md) at starting baseline ad2373b2a71feec6bb201f627038d93d12196047 and prior dual-recovery normative [Section 12.4](../specs/2026-10-19-rootark-dual-recovery-design.md) are design inputs. Packet B's earlier incompatible terminal-status proposal was withdrawn. Existing v1 domains and fields remain normative. No repository wire encoder or registry currently freezes the type literals for the v1 status proof, reservation ticket, or cancellation receipt.

**Current stack evidence:** Root.ark uses Node.js/CommonJS, local better-sqlite3, and filesystem-backed JSON for existing persistence. DATABASE_URL in db/index.js is resolved as a filesystem path, not a PostgreSQL connection URL. The package manifest has no PostgreSQL driver. No shared CAS, terminal-status authority, witness, GateAuthority, or protected-I/O generation fence is implemented. Existing F-01/F-02 crypto-library evidence is bounded to the prior library and does not establish provider, browser, runtime, or deployed recovery.

**Plan owner:** Root.ark owner decides all open options and grants any later lab or implementation authority.
**Planning author:** Primary Codex Architect; this document is not an independent review.
**Future execution:** Before execution, the owner chooses native subagents or verified Dual Agents/Dual Codex roles. If Dual Codex is selected, Architect specifies and reviews, the same verified Executor/backend implements, and ChatGPT retains final review authority. Textual self-report is not backend/identity provenance.

## Global constraints

- Preserve both approved recovery paths: user-held password-protected emergency package and previously trusted devices. No administrator master key, hidden recovery path, or silent loss of the last valid path.
- Online, fresh, independently pinned authorization is required for new transfers, service downloads, recovery, enrollment, device changes, and protected operations. User-held files already exported/downloaded remain usable offline. D-008 trash/backup and log retention remain separate from unselected transfer TTL.
- No browser becomes trusted from feature detection, WebAuthn login/PRF presence, synchronized passkeys, IndexedDB, or nonextractable CryptoKey claims alone. The web client needs trust-root bootstrap independent of the application origin.
- Do not treat the legacy SQLite database, JSON queue, one-process tests, serializable SQL isolation, signed token, lease timeout, app-server statement, empty in-memory map, or mock as proof of distributed safety.
- Keep signed manifest bytes, package-envelope digests, operation/request idempotency, reservation consumption, exact immutable history, and no-commit fencing in one atomic authoritative CAS contract. A late commit after a final no-commit fence must be impossible.
- Status proof, witness head, reservation ticket, commit receipt, and cancellation receipt remain distinct prior v1 objects. Do not invent missing type literals or merge wire shapes. A v2 change requires separate versioned cryptographic review and owner approval.
- Per-step protected I/O must fail closed and be ordered against gate closure. If storage or egress cannot enforce the gate generation at its effect boundary, remain blocked.
- Use synthetic non-production data and test-only keys only after the owner separately authorizes the lab. Never inspect production, create production credentials, change live accounts, install dependencies, or clean up outside explicitly isolated disposable lab resources.

## Review focus

- Exact compare-and-append and terminality invariants under concurrent requests, lost replies, leader changes, stale reads, partitions, crash, and restore.
- Independently administered CAS, status, witness/GateAuthority, client trust-root bootstrap, signing-key custody, and consistency-monitor domains.
- One per-keyring linearization order for acquire, consume, I/O-step authorization, and quiesce, plus physical stop/fencing at storage and controlled egress.
- Full cost equation and operational burden, including independent authorities and human on-call time omitted by provider-only examples.
- History-capacity behavior and whether emergency revocation can complete safely before 4096 transitions / 64 MiB.

---

## Stage 0 — Reconfirm prerequisites and close wire-schema blockers

- [ ] **Task 0.1 — Freeze v1 wire literals before encoder work.**
  **Owner:** Root.ark owner with an independent protocol reviewer.
  **Inputs:** Prior dual-recovery Section 12.4; Packet B reconciliation; read-only source/test registry search in the decision brief.
  **Work:** Resolve the missing type values for the v1 terminal-status proof, reservation ticket, and cancellation receipt against an authoritative approved registry or issue a separately reviewed schema clarification. Do not guess, silently derive them from domains, or change existing v1 fields/domains. If v2 is proposed, review migration and downgrade rules separately.
  **Exit evidence:** Owner-approved registry/schema artifact or explicit unresolved blocker. Until resolved, no v1 encoder/decoder integration can pass acceptance.

- [ ] **Task 0.2 — Approve trust bootstrap and non-production boundaries.**
  **Owner:** Root.ark owner and security owner.
  **Work:** Select no vendor yet. Decide what independently authenticated client release/configuration pins status and witness roots without relying on JavaScript and keys delivered only by the same potentially compromised application origin. Identify accountable operators, separate administrator and backup roots, recovery authority, regions/residency, allowed test-data handling, and outage envelope.
  **Exit evidence:** Written trust-domain map, owner assignments, recovery/loss process, and explicit permission for an isolated lab. If any root can only be learned from the untrusted application origin, client freshness is blocked.

- [ ] **Task 0.3 — Baseline current integration boundaries.**
  **Owner:** Future verified Executor, reviewed by Architect.
  **Grounded read-only anchors:** db/index.js, src/routes/sync.js, package.json, and existing src/crypto/rootark-zk-recovery-*.js.
  **Work:** Map current local SQLite/JSON persistence and callers without modifying them. Confirm provider clients, APIs, migration behavior, and storage/egress boundaries selected for the lab. Existing files are not pre-approved insertion points.
  **Exit evidence:** Reviewed interface map showing where an adapter could later be isolated, what data remains opaque, and which exact boundaries can physically fence storage reads, write commits, and streamed output.

## Stage 1 — Provider-neutral contract and candidate comparison

- [ ] **Task 1.1 — Turn the logical contract into adapter acceptance criteria.**
  **Owner:** Architect, then Future Executor for implementation design.
  **Logical records to model in later authorized work (not SQL DDL):**
  - keyring_head: scope primary key (account_id, compartment_id, keyring_id), revision, manifest digest, active package-envelope digest/pointer, witness sequence/high-water, gate generation, transition count, and canonical history bytes used.
  - transition: immutable scope/revision, previous and proposed digests, exact canonical signed-manifest bytes, operation ID, request digest, package-envelope digest, actor/approval metadata, and commit identity. Normal application credentials cannot update/delete committed rows.
  - operation_result: unique scope + operation ID; exact request digest and immutable terminal result. Identical retry returns stored outcome; reuse with different bytes/digest is rejected.
  - reservation: exact reservation/operation/request, expected/proposed head, envelope digest, expiry, and state. Consumed exactly once as part of the CAS append.
  - package_blob: immutable package-envelope bytes or immutable staged-object pointer, keyed by verified digest. Stage and read back exact bytes before CAS publishes the pointer; orphan staged blobs are harmless.
  - no_commit_fence: unique scope/reservation/operation/request and expected head; durable irreversible tombstone. It serializes against append so exactly one of append or fence wins and the loser observes terminal result.
  - gate_keyring, admission_permit, active_admission, and ordered gate/effect records: one logical linearizable ledger shared by all gateways for a keyring. Persist generation, head binding, consumed sessions, per-effect sequence, stop acknowledgements, reservations, and terminal resolutions.
  - witness_event / reservation ledger: append-only pending/commit/cancel/high-water history; restore uncertainty or split view remains unavailable.
  These are logical names, not existing code, schema, or provider-specific design. The later adapter may map them differently only with a reviewed invariant mapping.

- [ ] **Task 1.2 — Define provider adapter contracts.**
  **Owner:** Architect and Future Executor.
  **Proposed logical method names only:** readHead(scope, linearizable), compareAndAppend(exactRequest), readTerminalStatus(exactScopeAndNonce), fenceNoCommit(exactOperationAndExpectedHead), acquireAdmission(...), consumeAdmission(...), authorizeIoStep(...), beginQuiescing(...), and acknowledgeStop(...).
  **Required behavior:** Explicit compare result, durable idempotency, signed v1 proof inputs, linearizable-read evidence, single-use reservation, generation comparison, and fail-closed errors. These names are not current exports. Implementation must bind each to the actual reviewed storage/egress boundary rather than an unused abstraction.

- [ ] **Task 1.3 — Evaluate all candidates using the same workload and failure matrix.**
  **Owner:** Architect; Future Executor supplies measurements only after lab approval.
  **Candidates:** PostgreSQL with transactional WAL/replication and demonstrated promotion/fencing; Cloudflare Durable Objects with SQLite storage; etcd with immutable external blob staging.
  **Work:** Compare atomic transition mapping, history durability, operation limits, strong reads, acknowledgement durability, leader failover, catastrophic restore, trust-domain separability, maintenance, recovery time, and measured tail latency for per-effect checks. Do not award provider PASS from product documentation alone.

- [ ] **Task 1.4 — Keep capacity a safety requirement.**
  **Owner:** Architect and owner.
  **Work:** Generate canonical size distributions through 256-device / 64-epoch bounds; measure maximum manifests, transition bytes, history pages, storage/index/WAL overhead. Verify the 4096 / 64-MiB hard stop and warning at 75%. Demonstrate whether revocation and compromise response remain possible near/exceeding the ceiling. No pruning/checkpoint/compaction without separately reviewed protocol and owner approval.

## Stage 2 — Trust domains, authority, and gate feasibility

- [ ] **Task 2.1 — Select a candidate trust topology for evaluation, not deployment.**
  **Owner:** Owner selects accountable independent operators; Architect documents separation.
  **Topology A (managed CAS candidate):** CAS database and storage administration under independently governed operator A; status authority service/key under operator B with read-only authoritative operation-result access and only narrowly scoped conditional immutable fence capability; witness/GateAuthority, signing key, and durable reservation ledger under operator C; at least two independently administered consistency monitors. Separate deployment credentials, database/storage administrator roots, backups/restore control, key rotation/recovery, and incident/break-glass access.
  **Topology B (self-managed consensus candidate):** CAS quorum and immutable blob service under operator A; status signer and its read/fence interface under separately administered security/control-plane organization B; witness/GateAuthority and append-only ledger under independent operator C; monitors under separate roots. Separate deployment, storage, backup/restore, key, and incident-control authority. A different cloud account under the same uncontrolled administrator is not independent.
  **Gate:** No single person or common backup administrator controlling all domains qualifies as adversarial independence. Names, organizations, accounts, keys, and locations remain UNSELECTED.

- [ ] **Task 2.2 — Prove status-authority permissions and exact terminal proof.**
  **Owner:** Future Executor with security review.
  **Work:** Status authority reads authoritative durable CAS operation ledger, signs only prior v1 status object, and can create only exact conditional no-commit fence. It cannot append/edit manifests, create reservations, alter package pointers, or accept an app-server assertion. Witness obtains proof directly and verifies pinned signature and nonce. Test before/after-fence crashes and denied unrelated writes.

- [ ] **Task 2.3 — Prove a single ordered admission gate.**
  **Owner:** Future Executor; storage and egress operators must provide verifiable enforcement.
  **Required order:** One per-keyring linearizable ledger serializes acquireAdmission, consumeAdmission, authorizeIoStep, and beginQuiescing. acquireAdmission issues a one-time, generation/head-bound permit but grants no I/O. consumeAdmission succeeds only while OPEN on that generation/head and creates one durable active session; an exact retry may return the same result after a lost reply but cannot start a second worker. Different requests/replays reject.
  - authorizeIoStep must be authoritative at the protected effect boundary: every storage read, upload/write commit, and each controlled-egress output chunk. A prior permit, signed token, or check followed by uncontrolled I/O is insufficient.
  - Before beginQuiescing returns, it atomically closes acquire and consume, increments generation, and invalidates unconsumed old-generation permits. Any operation that linearized earlier is tracked as active. The data plane then fences old-generation effects and stops active sessions. CAS mutation may start only after prior active effects complete or trusted storage/egress acknowledgement proves old-generation work can no longer read, commit, or emit another chunk.
  - The gate must define the effect linearization point. If authorization and actual I/O cannot be ordered together (for example, a response can be delayed while storage proceeds under an old token), require the gate to proxy the I/O or require a generation fence enforced atomically by the storage/egress adapter. If neither is possible, fail closed.
  - Lease expiry, worker self-report, process restart, timeout, empty memory, and network partition are not proof of termination. Missing acknowledgement keeps the keyring BLOCKED. Already emitted plaintext and bytes already buffered/delivered cannot be recalled.
  **Measurement:** Record per-effect p50/p95/p99 latency, saturation, lock/queue contention, stream throughput under backpressure, and witness/CAS delay. Do not reduce checks or batch effects across a safety boundary to meet a target.

- [ ] **Task 2.4 — Specify witness freshness and equivocation detection.**
  **Owner:** Witness operator and independent monitors, with security review.
  **Work:** Pin witness and status roots outside compromised application origin; maintain nonce-bound fresh heads and reservation states in a durable monotonic ledger; reconcile terminal proof, cancellation receipt, and newly challenged committed head. Detect split views using independently operated consistency monitors or a separately reviewed transparency method and authenticated gossip. One witness can sign inconsistent heads to different clients and, alone, cannot prove it did not equivocate. Any lost root, lost ledger, unverified restore, conflicting high-water, unknown clock health, or monitor conflict is BLOCKED.

## Stage 3 — Isolated lab design (requires separate owner authorization)

- [ ] **Task 3.1 — Prepare a disposable synthetic-data topology.**
  **Owner:** Owner authorizes; future Executor and separately assigned operators execute.
  **Design target:** One candidate CAS quorum with explicit primary/standby roles and external promotion fencing; at least two independently addressable gateways; a status-authority process with restricted CAS role; distinct witness/GateAuthority with durable ledger and signing-key custody; at least two independent consistency monitors; immutable blob-store adapter; protected storage read/write test adapters; and controlled egress/stream proxy capable of generation fencing and stop acknowledgement. Isolate networks and admin credentials by trust domain. Actual cloud/vendor and region are unselected.
  **Synthetic data only:** Deterministic test accounts, manifests, envelopes, and non-production keys generated only after lab approval. Keep tokens/private material out of logs. Do not reuse user, production, or backup data.
  **Failure domains:** For real-provider acceptance, hosts, storage, credentials, backups, status operator, and witness operator must be separately administered as the intended threat model requires. Containers or multiple processes on one workstation may develop tests but are not proof of independent failure domains, quorum, operator independence, or safe production failover.
  **Privileges:** CAS application role may execute only reviewed atomic append/read paths; status role may read terminal records and invoke only a conditional immutable fence; witness role owns its append-only ledger and signer; gateways cannot change committed keyring state; operators cannot silently restore only one trust domain and reopen. Secret-manager/HSM and break-glass approach must be selected and reviewed before provisioning.

- [ ] **Task 3.2 — Pre-register lab fault injection and cleanup.**
  **Owner:** Future Executor; security reviewer reviews before start.
  **Work:** Define snapshots, crash points, network partitions, stale-replica routes, leader promotion, status/witness outages, clock-skew simulation, egress slow-stream controls, and full restore scenarios. Ensure every disposable resource has explicit names and teardown scoped only to the lab. Preserve immutable non-secret test logs/proof digests for review; redact secrets. Cleanup must never target shared or production resources.

- [ ] **Task 3.3 — Measure candidate behavior, not advertised behavior.**
  **Owner:** Future Executor and actual platform operators.
  **Work:** Measure durable commit latency and survivability after acknowledged-write leader loss, promotion fencing, read linearization, restore high-water reconciliation, service outage, payload-volume independence, per-I/O gate overhead, and retained-data growth. Document exact provider configuration, observed topology, operator roles, timestamps, source SHA, clocks, fault results, and retained non-secret logs/proofs. A single-machine simulation is labeled MOCK/LOCAL ONLY.

## Stage 4 — Authorized implementation and RED/GREEN acceptance

> These tasks require separate owner approval after Stages 0–3. This feasibility plan does not authorize packages, schemas, source, tests, cloud resources, or credentials.

- [ ] **Task 4.1 — Implement pure v1 protocol and state contracts test-first.**
  **Owner:** Future verified Executor; Architect reviews contract; independent security review follows.
  **RED:** Add parser/signature tests for exact deterministic-CBOR fields and existing v1 domains; missing/unexpected fields, wrong type literal, wrong nonce, wrong scope, wrong request digest, wrong package-envelope digest, stale observed head, expiry/skew boundary, signature failure, and downgrade. Resolve literals before encoder work.
  **GREEN:** Minimum implementation preserves exact existing v1 field sets and Ed25519 domains, rejects malformed messages before allocation, retains 300-second maximum operation lifetime plus 30-second monitored skew (330-second worst-case admission; no post-expiry grace), and exposes no not-committed-final before expires_at + 30 seconds plus durable irreversible fence.
  **Proposed future Node test command:** node --test test/issue-65-packet-b-protocol-v1.test.js. This file does not exist in this planning phase.

- [ ] **Task 4.2 — Implement provider CAS adapter and authority roles test-first.**
  **Owner:** Future verified Executor with selected provider operator.
  **RED:** Concurrent same-head appends, exact retry vs changed digest, malformed authorization, blob digest mismatch, operation/reservation replay, stale/replica read, lost acknowledgement, leader loss, no-commit-vs-delayed-append race, restart/restore.
  **GREEN:** One durable linearizable transaction compares the exact scoped expected revision/digest, validates reservation/request/envelope, appends one contiguous immutable transition, advances head, stores idempotent result and package pointer, and consumes reservation. The immutable fence races the same operation and permanently rejects later commit.
  **Proposed future commands:** node --test test/issue-65-packet-b-cas-contract.test.js for pure contracts; node --test test/issue-65-packet-b-postgres-provider.test.js only after PostgreSQL candidate and disposable provider fixture are separately approved/provisioned. These test names are proposed; current repository has only the Node test runner and no PostgreSQL driver/provider fixture.

- [ ] **Task 4.3 — Implement independent status/witness reconciliation test-first.**
  **Owner:** Future verified Executor plus distinct status/witness operators.
  **RED/GREEN:** Status service direct reads, exact nonce/operation binding, committed proof, not-committed timing, fence durability, cancellation receipt, fresh witness head, restart/restore and root rotation. Verify witness returns signed pending/unavailable during any unresolved reservation and does not reopen on app-server assertion, missing row, timeout, fence alone, or stale snapshot.
  **Proposed future command:** node --test test/issue-65-packet-b-status-witness.test.js; provider and multi-operator fault-injection evidence remains separate.

- [ ] **Task 4.4 — Implement gate and data-plane fencing test-first.**
  **Owner:** Future verified Executor plus storage/egress operators.
  **RED/GREEN:** Same-ledger acquisition/consume/quiesce ordering, active-session drain, generation fencing at each actual read/write/output effect, multi-gateway races, retries, crash/restart, slow streams, partitions, orphaned worker stop acknowledgements, and no post-fence content effects. Test physical adapters, not just policy object.
  **Proposed future command:** node --test test/issue-65-packet-b-gate-data-plane.test.js; real-provider and controlled-egress proof required before passing.

- [ ] **Task 4.5 — Keep cryptographic and product boundaries intact.**
  **Owner:** Future Executor and security reviewer.
  **Work:** Do not modify previously accepted F-01/F-02 crypto library opportunistically. Prove package-only future-epoch unwrap, trusted-device mode separation, and exact package binding using already reviewed vectors. Browser trust, browser KDF/interoperability, Android, D-008 retention, user consent/retention, transfer TTL, migration, and protected-content recovery require separate evidence and approval.

## Stage 5 — Future executable adversarial acceptance matrix

All case IDs use deterministic synthetic identifiers: account lab-acct-<case>, compartment lab-comp-<case>, keyring lab-kr-<case>, operation IDs op-<case>-a / op-<case>-b, reservation res-<case>, and a unique fresh 32-byte challenge per request. Each run records exact bytes/digests and IDs, never secret values. Mock checks validate code behavior only. Real acceptance requires selected provider and independently operated components under the stated failure topology.

| Case | Preconditions and actions / fault | Expected result | Required logs or proof | Real-provider acceptance beyond mock |
|---|---|---|---|---|
| CAS-01 | Two clients append from the same expected head with distinct op IDs and proposed manifests. | Exactly one contiguous append wins; loser gets conflict, then re-reads and re-authorizes. | Both request digests, expected/proposed digests, committed revision, transaction result. | Concurrent multi-process/provider test; one durable head and immutable transition only. |
| CAS-02 | Retry op-A with identical bytes/digest; then reuse op-A with changed request digest. | Exact retry returns identical stored terminal outcome; changed request is rejected. | Operation ID, digest, immutable result identity. | Durable uniqueness survives process and leader restart. |
| CAS-03 | Commit is acknowledged, then CAS leader/primary is lost before witness finalization. | Promoted authority contains acknowledged result or system rejects all admissions and reports unresolved; never accept missing/stale result. | Commit receipt, WAL/quorum position, promoted generation, status nonce. | Real lost-ack/leader-promotion run; demonstrate old-primary fencing and no acknowledged commit loss. |
| CAS-04 | Restore app/CAS data behind independently witnessed head; read through stale follower. | Witness/CAS mismatch blocks; stale follower cannot authorize; no reinitialization or old-head acceptance. | Fresh witness head, CAS head, restore epoch/high-water, rejection. | Real restore and stale-route run with external witness high-water continuity. |
| CAS-05 | Replay old signed manifest/key authorization after rollback. | Old state is rejected for fresh online authorization. | Current nonce-bound head, revision, signer/device state. | Multi-client rollback test with externally pinned witness roots. |
| STAT-01 | Crash status authority before fence; crash after durable fence but before response; retry exact request. | Before fence: no final non-commit proof and gate stays pending. After fence: same final result is recoverable; no later append wins. | Fence identity/digest internally, exact status nonce, result digest, durable log position. | Crash/restart plus delayed writer and immutable-fence test on selected CAS. |
| STAT-02 | Attempt not-committed-final before, at, and after expiry + 30 seconds; vary clocks within allowed ±30 seconds and inject unknown clock health. | Before bound: reject. At/after only with unchanged expected head, no result, durable fence. Unknown/excessive skew blocks. Operation accepts no later than 330 seconds; no grace. | expires_at, observed_at, nonce, expected/proposed/observed heads, clock health. | Independent clocks and provider-backed fence; actual status and witness boundary matrix. |
| STAT-03 | Deliver app-server “no row”; delay commit after no-commit lookup; try after durable fence. | App assertion/absence is ignored; without fence stays pending; after fence late commit is impossible. | Direct authority source, operation result, fence state, status signature. | Status role cannot sign on replica/no-row alone; CAS rejects late writer across restart. |
| WIRE-01 | Forge signature, replay nonce, change package-envelope digest/head/request digest, use wrong/unresolved v1 type/domain, omit/add fields. | Reject every mismatch. No guessed literal or alternate v1 schema. | Object digest, domain/schema version, challenge ID, parser error. | Cross-implementation deterministic-CBOR vectors and independent wire review after literals are frozen. |
| WIRE-02 | Resolve final no-commit; send cancellation receipt before proof, wrong proof digest, or stale committed head; then perform exact order. | Only status proof → matching signed cancellation receipt → new nonce-bound committed witness head with no pending reservation reopens unchanged head. | Status nonce/proof digest, cancel digest/sequence, fresh head nonce/revision. | Separate status/witness processes and pinned keys; crash between steps remains closed. |
| GATE-01 | Acquire permit at generation g, begin quiesce to g+1, then delay consume from old permit until after closure. | Consume rejects; old permit cannot start content I/O. | Permit/session ID, g/g+1, gate sequence and rejection. | Two gateways and shared real linearizable gate; no independent local gate maps. |
| GATE-02 | Race acquire, consume, authorizeIoStep, and beginQuiescing on two gateways with reordered replies/retries. | One total order; no post-close admission/effect. Exact consume retry cannot create another worker. | Gate sequence, generation, session/effect IDs, idempotency key. | Provider linearization evidence plus repeated concurrent cross-process run. |
| GATE-03 | Slow streamed download with backpressure; quiesce between output chunks. | No new chunk authorized/emitted after gate close sequence. Drain/stop acknowledgement precedes CAS mutation. Already emitted/network-buffered bytes are not claimed revocable. | Chunk/effect sequence, gate sequence, stop acknowledgement, bytes count. | Real controlled-egress test proves effect-generation fence, including network-buffer behavior and stop deadline. |
| GATE-04 | Upload/write commit races gate closure; pause a previously authorized write before storage commit. | Storage atomically rejects stale generation or reports completed-before-close; no old-generation write commits after fence. | Write ID, generation, gate sequence, durable commit result. | Storage-side generation fencing under transaction race; policy-layer check alone fails. |
| GATE-05 | Crash/restart gateway or egress worker with active session; reconnect through another gateway; partition gate authority. | Orphan cannot continue or emit; second gateway cannot revive old session. Partition fails closed. Missing physical stop proof stays BLOCKED. | Worker identity, generation, session state, storage/egress stop receipt. | Kill/restart and partition test on real controlled data plane; lease expiry alone is not evidence. |
| GATE-06 | Abort partial stream while keyring transition CAS append commits; retry finalization. | Stream abort does not forge CAS rollback; exact committed head reconciles once; no old-generation stream resumes. | CAS op/result, stream abort, witness sequence, new generation. | Provider + egress test of partial bytes, durable commit, and restart. |
| WIT-01 | Witness partitions/splits view; replay old signed head to one client; consistency monitors disagree. | Client refuses fresh admission; witness BLOCKED until histories reconcile. One witness signature alone does not clear conflict. | Head nonce/sequence, monitor roots/checkpoints, conflict proof. | At least two independent monitor domains observe/report same append-only history; partition/split-view test. |
| WIT-02 | Rotate/lose witness key, restore stale witness snapshot, or report mismatched high-water. | No silent root replacement; stale snapshot cannot reopen; root recovery requires independently approved trust update and ledger reconciliation. | Old/new key IDs, restore high-water, independently signed root-update record. | Real key/backup recovery drill with separately controlled roots and no app-origin trust. |
| WIT-03 | CAS, status, witness clocks drift, stop reporting, or exceed 30-second skew. | Fresh authorization and terminal resolution block. | Clock-health sample, source/time, nonce, blocked status. | Independently monitored clocks and fault injection on all authority processes. |
| HIST-01 | History approaches 75% then exceeds 4096 entries / 64 MiB during normal write and safety revocation. | Warning includes usage. Hard cap commits nothing and does not prune. If emergency revoke can be starved, production GO denied pending separately reviewed capacity lifecycle. | Canonical bytes/count, warning, rejected operation, unchanged head. | Worst-case 256-device/64-epoch size and near-limit failure across provider backup/restore. |
| PKG-01 | Compromise package; attempt routine replacement versus compromise response; omit required old epoch material or final usable authority. | Compromise response revokes old authority and atomically rotates independent new epoch without wrapping new key to compromised package; missing material/path fails closed as unrecoverable. | Signed operation, prior/new epoch digests, recipient set, exact wraps, CAS result. | Real-provider atomic append; crypto tests prove old package cannot unwrap future key. |
| REST-01 | Crash/restore after every durable boundary: gate close, reservation, ticket, blob stage, CAS append, status proof, witness commit/cancel, local promotion; attempt replay/stale resurrection. | Resume only from exact durable state and matching external high-water. No split brain, revoked-device resurrection, or hidden last-device fallback. | Durable transition log, proof digests, gate generations, restore IDs/high-water. | Repeated full restore from actual backups and independent domains; no lost acknowledged append or stale-head acceptance. |

## Stage 6 — Evidence package and decision gate

- [ ] **Task 6.1 — Report provider-specific evidence with provenance.**
  Bind every report to source revision, provider product/version/configuration, topology, operator roles, clocks, test corpus, fault IDs, measured results, and retained non-secret logs/proofs. Separate MOCK_ONLY, SINGLE_HOST_SIMULATION, REAL_PROVIDER, and INDEPENDENT_OPERATOR evidence.

- [ ] **Task 6.2 — Obtain one independent security review of the exact evidence SHA.**
  **Owner:** Owner chooses reviewer/process. Implementer does not self-certify. A mock green suite, prior architecture review, static self-review, or unverifiable agent prose is not independent review.

- [ ] **Task 6.3 — Apply the decision criteria.**
  - **GO for a later, separately authorized stage only if:** protocol literals are frozen; v1 vectors pass; real CAS acknowledged-write and no-commit fencing survive concurrency/lost-response/failover/restore; fresh heads and pending gates work across independently pinned roots; independent operator and backup/key boundaries are evidenced; data-plane I/O is generation-fenced at every side effect; active sessions stop before mutation; catastrophe restore and equivocation monitoring pass; history capacity has a safe lifecycle; owner approves budgets, regions, availability, retention/consent, and execution method; independent reviewer has no blocking finding.
  - **CONDITIONAL:** useful lab evidence exists, but some gates remain unverified. Keep protected recovery/admission disabled. List each missing provider/operator/client proof and next test.
  - **NO-GO (mandatory):** missing trust-domain independence; CAS can acknowledge then lose transition on promotion; status authority can assert without durable result/fence; no externally pinned witness root; old-generation I/O cannot be physically fenced; restore accepts stale state or resurrects revoked authority; unknown v1 schema is guessed; last-path loss is hidden; or any mock is represented as real-provider proof.

## Future test and execution notes

- Repository currently exposes node --test, npm run validate:syntax, and npm run validate:artifacts. Current package manifest has no PostgreSQL dependency/provider fixture.
- After separate execution approval, begin each code task with a failing Node test, record exact RED output, implement the minimum contract, and record GREEN. Proposed issue-65 Packet B test paths above do not yet exist.
- Do not install a provider driver or test dependency until owner selects and authorizes implementation/test stack. A future PostgreSQL lab should use an isolated non-production connection string only; do not change DATABASE_URL semantics or retrofit the existing filesystem variable.
- Do not run full app tests as a substitute for isolated adapter and real-provider acceptance. Run full repository checks only if the separately approved implementation scope requires them.
- UI-UX-PRO-MAX applies only if a separately approved UI task is added. This plan creates no product/lab UI.
- Preserve D-008 retention, D-011 online-only new operations, Android roadmap, and transfer TTL as a separate unselected owner decision.

## Required owner choices in one place

Before authorizing a lab or implementation, record:

1. Candidate provider for the first isolated lab; recommendation is PostgreSQL first, not a selection.
2. Status, witness/GateAuthority, client-root, CAS, blob, and monitoring operators; evidence each is independently administered.
3. Monthly budget, allowable operator hours, support/backup/log/egress funding.
4. Supported regions, data residency, and cross-region failover policy.
5. Outage envelope, acceptable RTO/RPO, and whether online protected operations may remain unavailable indefinitely.
6. Client trust-root bootstrap for web-delivered JavaScript and key rotation/recovery path.
7. Status/witness signing-key custody, root replacement, lost-ledger recovery, and incident authority.
8. Safe capacity path before 4096/64-MiB exhaustion, including emergency revocation behavior.
9. Retention/export confirmation, user-facing unrecoverability policy, and separate temporary transfer TTL.
10. Migration and end-to-end content recovery scope.
11. Future execution arrangement: native subagents or verifiably configured Dual Agents/Dual Codex, with Architect, Executor, and independent reviewer roles.

**Current readiness:** Feasibility may be investigated after separate lab approval; implementation, runtime admission, browser trust, end-to-end recovery, provider selection, migration, release, and issue #65 closure remain blocked.
