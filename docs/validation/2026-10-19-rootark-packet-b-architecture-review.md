# Root.ark #65 Packet B — Architecture Evidence and Owner Decision Sheet

**Status:** PACKET_B_REVIEW_FINDINGS_ADDRESSED_IN_DESIGN_ONLY_SELF_REVIEWED_NOT_APPROVED_FOR_IMPLEMENTATION
**Date:** 2026-10-19
**Repository:** bielxdh3/Root.ark
**Branch:** cdx/rootark-dual-recovery-20261019
**Correction starting SHA:** 21fda3b2d91dd0b3f9190a31451176f622286e72
**Packet B baseline:** 8209a145693bb7810509b8da5b8b9cc272488cbe
**Specification before correction:** aa19c72f831cd9e847b6d37b15f840a008c0901a
**Specification:** [Shared CAS, terminal status, witness, and online admission](../superpowers/specs/2026-10-19-rootark-packet-b-shared-cas-witness-design.md)
**Review type:** Documentation correction and primary-author self-review using repository documents, issue #65 owner decisions, and official technical sources. This is not an independent security audit, live-provider test, or deployment validation.

## 1. Review boundary

Packet B is a provider-neutral design proposal for a shared linearizable CAS, independent terminal-status authority, independent freshness witness, durable pending-reservation gate, rollback-aware authorization, and protected-content admission.

The Packet B specification was added in 1de403a1ecfd2d7ddfc63e7287b189295c3480c6 and received a two-line evidence/cost-assumption clarification in aa19c72f831cd9e847b6d37b15f840a008c0901a. Both commits change only the linked design document. This companion record is its evidence index and owner decision sheet. No push, pull-request change, deployment, migration, issue update, or production inspection was performed during this work.

This correction addresses the terminal-status v1 mismatch, the permit-consumption/quiesce race, and no-commit finality in the two authorized documents only. The P1/P2 findings are addressed in design only; no provider or runtime evidence validates them. This work does not select a database/provider, create an implementation plan, enable runtime recovery, or authorize issue #65 closure. The document remains a proposal requiring owner review; any backend-specific implementation plan requires a later approval.

## 2. Repository and issue facts inspected

The correction starts from clean worktree head 21fda3b2d91dd0b3f9190a31451176f622286e72 on cdx/rootark-dual-recovery-20261019. The Packet B baseline remains 8209a145693bb7810509b8da5b8b9cc272488cbe; the uncorrected specification input is aa19c72f831cd9e847b6d37b15f840a008c0901a. The earlier Packet B commits and the accepted dual-recovery specification remain in history. The configured Git author and committer are bielxdh3 <bielxdh3@gmail.com>; the local documentation correction is committed with the configured global commit-msg hook and exactly one Codex co-author trailer. The final correction SHA is recorded in the local Git handoff and final response.

Read-only source checks at the baseline:

- db/index.js creates a better-sqlite3 database, defaults DB_ENABLED to false, resolves the default database path to data/rootark.sqlite, enables WAL/foreign keys/busy timeout, and passes DATABASE_URL through path.resolve as a filesystem path. This is local SQLite capability, not a verified network/shared database.
- src/routes/sync.js contains a JSON SyncObjectStore with durable temp-file/fsync/rename writes and a Promise queue stored on the object instance. This is not cross-process CAS or a witness ledger.
- The recovery history and manifest modules define pure cryptographic verification and receipt parsing. A scoped search found no runtime imports in the inspected route/server/public/sync-client paths.
- public/client/rootark-protected-store.js uses IndexedDB for encrypted derived records; public/client/rootark-protected-session.js accepts a supplied key function. Neither proves operating-system-backed custody or rollback-resistant browser high-water storage.
- docs/product-discovery.md includes D-011 while preserving D-006, D-008, and D-009. The approved policy permits offline use of already downloaded/exported files and requires fresh online authorization for new service-mediated operations.

The GitHub connector fetched issue [#65](https://github.com/bielxdh3/Root.ark/issues/65) and its comments read-only on 2026-10-19. The issue remains open. The owner's comment approves both recovery methods, rejects an administrator/server-wide master decryption key or hidden fallback, and accepts possible permanent unrecoverability if the package and all trusted devices are lost. It does not select a backend, approve runtime recovery, or close #65.

## 3. Architecture coverage and evidence classification

| Area | Classification | Evidence and remaining boundary |
|---|---|---|
| Owner recovery and online/offline policy | OBSERVED | D-011 and the owner comment on issue #65 were read. Both recovery authorities remain in the proposal. No offline queue obtains publish rights. |
| Crypto-library compatibility | PRIOR_ACCEPTED_BOUNDED_SCOPE | F-01/F-02 corrections at source commit `7dd1c861d2b570d7bc51ce66e8054bcc431f4c07` were independently accepted for the bounded Node crypto-library scope. Packet B preserves that crypto authority and does not modify its formats, rootKey semantics, or suite. That acceptance is not provider, browser, runtime, or end-to-end recovery evidence. |
| Current server persistence | OBSERVED | Static inspection found local SQLite/JSON modes; no shared CAS service or selected production database was found or configured in the inspected repository. |
| CAS state and atomic append | PROPOSED | The design defines per-keyring immutable revisions, signed history, request digest/idempotency, expected-head compare, package pointer, operation result, and a single conditional append. No provider implementation exists. |
| Terminal status authority | ADDRESSED_IN_DESIGN_ONLY | Packet B now preserves the prior Section 12.4 deterministic-CBOR v1 field set, signature domain, terminal outcomes, fresh 32-byte nonce, expiry-plus-skew rule, and cancellation receipt/head order. No authority or trust root is deployed or validated. The prior spec has no explicit `type` literal for the status proof, reservation ticket, or cancellation receipt in the bounded repository search; implementation remains blocked until each frozen value is located or separately clarified. |
| Witness reservation and pending gate | ADDRESSED_IN_DESIGN_ONLY | One durable per-keyring GateAuthority ledger orders permit acquisition/consumption and reservation closure, withholds any acceptable old head, records prior admissions, and issues a ticket only after stop/fence acknowledgement. Crash, stale restore, outage, and ambiguous status remain blocked. No real witness or gate exists. |
| Read/write race boundary | ADDRESSED_IN_DESIGN_ONLY | The design now requires an authoritative decision immediately before each protected I/O step and data-plane generation fencing for storage and streamed egress. Current runtime routes do not implement this contract; lease expiry or an application acknowledgement alone cannot prove termination. |
| Freshness, roots, and rollback | PROPOSED / BLOCKED | Nonces, exact heads, local high-water, pinned roots, and fork monitoring are specified. Root bootstrap, durable witness log, independent monitor, and supported client high-water storage are unverified. |
| Provider capabilities and limits | OBSERVED_FROM_OFFICIAL_DOCS | PostgreSQL, Cloudflare Durable Objects, and etcd features and recovery behaviors were compared from official documentation. Vendor documentation does not establish Root.ark's configuration or deployed evidence. |
| Cost model | ILLUSTRATIVE | Cloudflare's approximately $6.41/month example is a DO-only arithmetic illustration, not system TCO; app Workers, independent status/witness services, backup/restore, monitoring, staffing, and workload/model omissions may materially change it. PostgreSQL and etcd totals remain input-based models because no host, region, or service was selected. |
| Adversarial validation matrix | PROPOSED | The spec separates mock-only protocol evidence from actual-provider, cross-process, restart/restore, browser, and admission acceptance. No tests in this matrix were run for Packet B. |
| Independent security review | PENDING_INDEPENDENT_REVIEW | The primary author read the result for scope and internal consistency. No independent reviewer with verifiable separate provenance reviewed this Packet B spec. |

### Consolidated review disposition

- **P1 — terminal-status proof compatibility: addressed in design only.** The incompatible Packet B proof is withdrawn. The existing dual-recovery Section 12.4 schema/domain and `committed` / `not-committed-final` outcomes remain normative. The prior `type` literals for the status proof, reservation ticket, and cancellation receipt are not stated in the specification or found in the bounded repository search; no value was invented. These schema gaps block wire implementation until the frozen source is located or an explicit reviewed clarification is made.
- **P2 — permit consumption versus gate closure: addressed in design only.** Acquisition, consumption, per-step authorization, and quiesce now share one durable per-keyring linearizable gate ledger. Closure rejects delayed consumption, increments a data-plane fence generation, and waits for authoritative termination of prior admissions before CAS begins. No provider, storage plane, or streaming gateway has demonstrated these guarantees.
- **P2 — no-commit finality/cancellation: addressed in design only.** The exact v1 final non-commit proof is allowed only after reservation expiry plus the 30-second skew bound, with an unchanged expected head and irreversible CAS tombstone. The signed cancellation receipt and a fresh committed witness-head receipt are both required before accepting the old head. No absence-of-row query is terminal.
- These corrections preserve the owner-approved two recovery methods, online-only new operations, the accepted crypto profile, and the previously accepted bounded Node crypto-library evidence. They do not establish provider/runtime safety or integration readiness.

## 4. Official technical sources consulted

The following official documentation was opened on 2026-10-19 and supports only the stated platform-level comparison:

- [PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html) — serializable transactions provide serial execution semantics and applications must handle serialization failures/retries.
- [PostgreSQL WAL durability settings](https://www.postgresql.org/docs/current/runtime-config-wal.html) — synchronous_commit controls local and standby durability acknowledgement; relaxed settings can weaken commit durability.
- [PostgreSQL replication configuration](https://www.postgresql.org/docs/current/runtime-config-replication.html) — synchronous standby selection and quorum settings affect when commits are acknowledged.
- [Cloudflare Durable Objects storage](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/) — each object has private transactional strongly consistent storage; SQLite-backed objects provide point-in-time restore into the previous 30 days.
- [Cloudflare Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) — current Workers Paid and Durable Objects request, duration, row, and storage dimensions used for the bounded illustrative calculation.
- [etcd API guarantees](https://etcd.io/docs/v3.6/learning/api_guarantees/) — KV operations are durable and strictly serializable; linearizable operations use consensus, while serializable reads may be stale.
- [etcd system limits](https://etcd.io/docs/v3.6/dev-guide/limit/) and [configuration options](https://etcd.io/docs/v3.6/op-guide/configuration/) — the default maximum request size is 1,572,864 bytes (1.5 MiB), below Packet B's 8 MiB history-entry limit.
- [etcd disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/) — quorum loss blocks updates and restoring a snapshot can lower revisions; restore/revision-bump procedures do not replace Root.ark witness state.
- [PostgreSQL standby and synchronous replication](https://www.postgresql.org/docs/current/warm-standby.html) and [failover](https://www.postgresql.org/docs/current/warm-standby-failover.html) — synchronous replication has configured acknowledgement semantics; external failover fencing is still required.

These sources do not prove provider availability, account configuration, commercial commitments, Root.ark operational topology, independent administration, current performance, or a production service price.

## 5. Validation performed and not performed

Performed for this correction:

- Confirmed the exact linked worktree, branch, starting SHA, clean status, origin, and configured Git author/committer identity before editing.
- Read the project/global instructions, prior dual-recovery Section 12.4, Packet B specification, this decision sheet, D-006 through D-011, Phase A evidence, plan-tree context, and live issue #65 owner comments read-only.
- Queried AI Memory; the project-name lookup was not recognized, and one focused global search returned no Packet B-specific decision. The repository instructions designate AI Memory as the only live memory source, so the archival Obsidian vault was not used.
- Verified official etcd request limits/configuration, PostgreSQL synchronous replication/failover, and Cloudflare Durable Objects pricing/storage docs; retained the provider comparison without selecting or provisioning a service.
- Changed only the two authorized documentation files. Pre-commit `git diff --check` passed and `git diff --name-only` matched the exact two-file allowlist. After the local commit, the parent SHA, commit trailer, exact final SHA, and clean status are verified and included in the completion handoff.

Not run by design:

- Unit, integration, full repository, Node, browser, or Android tests.
- Provider race, linearizability, failover, partition, clock, backup/restore, status-authority, or witness tests.
- Performance, pricing workload measurements, security scan, CodeQL, hosted CI, or deployment validation.
- Live account, database, production, credential, user-content, or issue mutations.

There is no implementation to test. A passing document diff check is not evidence of runtime security.

## 6. Owner decision sheet

These decisions remain open and are not answered by this proposal:

1. **Provider candidate:** keep PostgreSQL, Cloudflare Durable Objects, and etcd under comparison; select or provision none in this phase. **Non-binding recommendation:** Evaluate PostgreSQL first as a lab/prototype candidate because its transactional append and structured history map naturally to Root.ark's existing Node server; a production choice needs measured durability, failover, operator independence and full cost evidence.
2. **Independent trust operations:** identify who would separately administer and restore the CAS, terminal-status authority, witness, and client trust roots. Confirm independent key bootstrap and witness-fork monitoring. A same-origin key download or shared admin/backup account does not satisfy this boundary.
3. **Availability and operating envelope:** owner must still set any cost ceiling, supported geography, outage envelope, maintenance ownership, recovery objectives, and acceptable fail-closed behavior. No operator, budget, geography, or availability target is invented here.

Provider notes: the approximately $6.41/month Durable Objects example is an illustrative DO-only calculation, not full system cost; it may omit or under-model application Worker costs, independently administered status/witness services, backups/restore, monitoring, and operations. etcd's documented 1,572,864-byte default request limit is below an 8 MiB history entry, so retain immutable staged blob storage with an atomic digest/pointer append. PostgreSQL synchronous acknowledgement does not itself prove no-loss failover or separate operator independence. See the technical-source section above.

**Recommended next gate:** owner review of this corrected exact-SHA design and decision sheet, with approval limited to architecture review. Provider/operator/budget/geography/outage choices remain open; a provider-specific implementation plan requires its own explicit approval. Browser key custody, temporary transfer TTL, Android runtime, migration, deployment, and production remain separate gates.

## 7. Explicit remaining blocks

- No selected or verified shared CAS provider.
- No independent, truthful, durable terminal-status authority or irreversible no-commit ledger.
- No independently pinned deployed witness, reservation ledger, fork monitor, or restore continuity proof.
- No selected storage/egress plane that enforces admission-generation fencing or proves that active streaming workers have stopped; inability to prove termination keeps the keyring blocked.
- The prior Section 12.4 `type` fields for the status proof, reservation ticket, and cancellation receipt have no explicit literals in the inspected specification or bounded repository search; implementation must wait for each exact frozen v1 value or a separately reviewed clarification.
- No browser/OS key-custody and high-water guarantee; no browser code-root bootstrap proof.
- No real browser KDF profile or cross-client crypto interoperability acceptance.
- No protected-content admission enforcement across existing upload, download, transfer, and authorization paths.
- No safe history-capacity lifecycle beyond 4,096 transitions/64 MiB/8 MiB limits.
- No selected transfer TTL, end-to-end content recovery, Android runtime, migration, production, merge, or issue #65 acceptance.

**Review provenance:** self-review only; no independent reviewer with verifiable separate provenance was used. The exact corrected specification and evidence-report commit SHAs are in the final local Git handoff. This correction does not change issue #65 state, select a provider, or authorize runtime integration.
