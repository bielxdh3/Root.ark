# Root.ark #65 Packet B — Architecture Evidence and Owner Decision Sheet

**Status:** PACKET_B_SPEC_PROPOSED_AWAITING_OWNER_DECISION
**Date:** 2026-10-19
**Repository:** bielxdh3/Root.ark
**Branch:** cdx/rootark-dual-recovery-20261019
**Starting source SHA:** 8209a145693bb7810509b8da5b8b9cc272488cbe
**Packet B specification review target:** aa19c72f831cd9e847b6d37b15f840a008c0901a
**Specification:** [Shared CAS, terminal status, witness, and online admission](../superpowers/specs/2026-10-19-rootark-packet-b-shared-cas-witness-design.md)
**Review type:** Read-only repository/source inspection, owner-policy reconciliation, and official-document research. This is not an independent security audit, live-provider test, or deployment validation.

## 1. Review boundary

Packet B is a provider-neutral design proposal for a shared linearizable CAS, independent terminal-status authority, independent freshness witness, durable pending-reservation gate, rollback-aware authorization, and protected-content admission.

The Packet B specification was added in 1de403a1ecfd2d7ddfc63e7287b189295c3480c6 and received a two-line evidence/cost-assumption clarification in aa19c72f831cd9e847b6d37b15f840a008c0901a. Both commits change only the linked design document. This companion record is its evidence index and owner decision sheet. No push, pull-request change, deployment, migration, issue update, or production inspection was performed during this work.

This work does not select a database/provider, create an implementation plan, enable runtime recovery, or authorize issue #65 closure. Its next boundary is independent review of the exact specification commit, followed by explicit owner decisions. A backend-specific implementation plan requires a later approval.

## 2. Repository and issue facts inspected

The source baseline was the clean worktree head 8209a145693bb7810509b8da5b8b9cc272488cbe on cdx/rootark-dual-recovery-20261019. The exact specification review target is aa19c72f831cd9e847b6d37b15f840a008c0901a; the baseline-to-target diff changes one path only. Its first draft commit is 1de403a1ecfd2d7ddfc63e7287b189295c3480c6. The configured Git author and committer were bielxdh3 <bielxdh3@gmail.com>. Both local commits used the configured global commit-msg hook and contain exactly one Codex co-author trailer each.

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
| Crypto-library compatibility | PRIOR_ACCEPTED_BOUNDED_SCOPE | The accepted dual-recovery Section 12 and F-01/F-02 correction verdict are preserved as the crypto authority. This Packet B design does not modify their formats, rootKey semantics, or cryptographic suite. |
| Current server persistence | OBSERVED | Static inspection found local SQLite/JSON modes; no shared CAS service or selected production database was found or configured in the inspected repository. |
| CAS state and atomic append | PROPOSED | The design defines per-keyring immutable revisions, signed history, request digest/idempotency, expected-head compare, package pointer, operation result, and a single conditional append. No provider implementation exists. |
| Terminal status authority | PROPOSED | A new domain-separated terminal proof is specified for exact committed/no-commit outcomes. A no-commit requires an immutable CAS fence. The authority and its trust root are not deployed or verified. |
| Witness reservation and pending gate | PROPOSED | The design closes admission, withholds any acceptable old head, drains prior permits, persists PENDING, then issues the ticket. Crash, stale restore, outage, and ambiguous status remain blocked. No real witness or gate exists. |
| Read/write race boundary | PROPOSED | An atomic admission permit and enforced drain/termination are required across protected routes and streams. Current runtime routes do not implement this contract. |
| Freshness, roots, and rollback | PROPOSED / BLOCKED | Nonces, exact heads, local high-water, pinned roots, and fork monitoring are specified. Root bootstrap, durable witness log, independent monitor, and supported client high-water storage are unverified. |
| Provider capabilities and limits | OBSERVED_FROM_OFFICIAL_DOCS | PostgreSQL, Cloudflare Durable Objects, and etcd features and recovery behaviors were compared from official documentation. Vendor documentation does not establish Root.ark's configuration or deployed evidence. |
| Cost model | ILLUSTRATIVE | Cloudflare example uses the official published rate dimensions and explicit workload assumptions. It excludes the independent authorities and full Workers front-door/operations cost. PostgreSQL and etcd totals remain input-based models because no host, region, or service was selected. |
| Adversarial validation matrix | PROPOSED | The spec separates mock-only protocol evidence from actual-provider, cross-process, restart/restore, browser, and admission acceptance. No tests in this matrix were run for Packet B. |
| Independent security review | PENDING_INDEPENDENT_REVIEW | The primary author read the result for scope and internal consistency. No independent reviewer with verifiable separate provenance reviewed this Packet B spec. |

## 4. Official technical sources consulted

The following official documentation was opened on 2026-10-19 and supports only the stated platform-level comparison:

- [PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html) — serializable transactions provide serial execution semantics and applications must handle serialization failures/retries.
- [PostgreSQL WAL durability settings](https://www.postgresql.org/docs/current/runtime-config-wal.html) — synchronous_commit controls local and standby durability acknowledgement; relaxed settings can weaken commit durability.
- [PostgreSQL replication configuration](https://www.postgresql.org/docs/current/runtime-config-replication.html) — synchronous standby selection and quorum settings affect when commits are acknowledged.
- [Cloudflare Durable Objects storage](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/) — each object has private transactional strongly consistent storage; SQLite-backed objects provide point-in-time restore into the previous 30 days.
- [Cloudflare Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) — current Workers Paid and Durable Objects request, duration, row, and storage dimensions used for the bounded illustrative calculation.
- [etcd API guarantees](https://etcd.io/docs/v3.6/learning/api_guarantees/) — KV operations are durable and strictly serializable; linearizable operations use consensus, while serializable reads may be stale.
- [etcd disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/) — quorum loss blocks updates and restoring a snapshot can lower revisions; restore/revision-bump procedures do not replace Root.ark witness state.

These sources do not prove provider availability, account configuration, commercial commitments, Root.ark operational topology, independent administration, current performance, or a production service price.

## 5. Validation performed and not performed

Performed:

- Confirmed the exact worktree root, branch, starting SHA, clean baseline, origin, and contributor identity before writing.
- Read the project policy and relevant product decisions, Packet A/dual-recovery specifications, Packet A evidence, the current persistence adapters, browser store/session, and issue #65.
- Compared official PostgreSQL, Cloudflare Durable Objects, and etcd documentation; included links and dated price assumptions in the spec.
- Kept tracked changes to the two authorized documentation paths.
- Ran git diff --check on the staged Packet B specification before its local commit; it passed.
- Verified the specification commit parent and exact co-author trailer. The evidence document is the only remaining authorized file to write for this documentation task.

Not run by design:

- Unit, integration, full repository, Node, browser, or Android tests.
- Provider race, linearizability, failover, partition, clock, backup/restore, status-authority, or witness tests.
- Performance, pricing workload measurements, security scan, CodeQL, hosted CI, or deployment validation.
- Live account, database, production, credential, user-content, or issue mutations.

There is no implementation to test. A passing document diff check is not evidence of runtime security.

## 6. Owner decision sheet

These decisions are needed before backend-specific implementation planning. They are not answered by this proposal.

1. **Provider candidate:** choose whether to evaluate PostgreSQL with synchronous replication, Cloudflare Durable Objects with SQLite, etcd plus durable immutable event storage, or defer selection until an infrastructure inventory is available. This proposal selects none.
2. **Independent trust operations:** identify who would separately administer and restore the CAS, terminal-status authority, witness, and client trust roots. Confirm how clients receive pinned roots and how witness forks are monitored. A same-origin key download or shared admin/backup account does not satisfy this boundary.
3. **Availability and operating envelope:** define the monthly cost ceiling, supported regions, maintenance ownership, recovery objectives, and acceptable outage behavior. Fresh protected reads/writes remain blocked whenever an authority is unavailable; this is not an owner decision to weaken.

After independent review and these decisions, the next proposed gate is a backend-specific design and test plan. Only a separate owner approval of that plan would authorize implementation. Browser key custody, temporary transfer TTL, Android runtime, migration, and production remain separate gates.

## 7. Explicit remaining blocks

- No selected or verified shared CAS provider.
- No independent, truthful, durable terminal-status authority or irreversible no-commit ledger.
- No independently pinned deployed witness, reservation ledger, fork monitor, or restore continuity proof.
- No browser/OS key-custody and high-water guarantee; no browser code-root bootstrap proof.
- No real browser KDF profile or cross-client crypto interoperability acceptance.
- No protected-content admission enforcement across existing upload, download, transfer, and authorization paths.
- No safe history-capacity lifecycle beyond 4,096 transitions/64 MiB/8 MiB limits.
- No selected transfer TTL, end-to-end content recovery, Android runtime, migration, production, merge, or issue #65 acceptance.

**Independent-review handoff:** review the exact specification state at aa19c72f831cd9e847b6d37b15f840a008c0901a against baseline 8209a145693bb7810509b8da5b8b9cc272488cbe. The final local SHA including this evidence record is available from the repository handoff metadata.
