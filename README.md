<div align="center">

# Root.ark

**Private storage, file transfer, and synchronization under administrator control.**

[![Status](https://img.shields.io/badge/status-active%20development-orange)](#project-status)
[![Security Regression](https://github.com/bielxdh3/Root.ark/actions/workflows/security-regression.yml/badge.svg)](https://github.com/bielxdh3/Root.ark/actions/workflows/security-regression.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Runtime](https://img.shields.io/badge/Node.js-22%2B-339933)](#requirements)
[![Database](https://img.shields.io/badge/database-SQLite-003B57)](#architecture)
[![Network](https://img.shields.io/badge/deployment-private%20network-blueviolet)](#security-boundary)

Root.ark is a self-hosted Node.js service for managing files, permissions, versions, public links, backups, synchronization, and storage integrations from one controlled environment.

</div>

> [!CAUTION]
> Root.ark is **not ready for unreviewed public deployment or production use**. Keep it on a trusted private network unless the exact deployment has been reviewed, hardened, and monitored.

## How it fits together

```text
          ┌──────────────────────┐   ┌──────────────────────┐
          │ Browser interface    │   │ Local sync client    │
          │ files · users · links│   │ watched local files  │
          └──────────┬───────────┘   └──────────┬───────────┘
                     │                          │
                     └────────────┬─────────────┘
                                  │
                       ┌──────────▼───────────┐
                       │   Root.ark server    │
                       │ auth · permissions   │
                       │ uploads · WebDAV     │
                       └──────┬────────┬──────┘
                              │        │
                metadata      │        │ files and versions
                              │        │
                    ┌─────────▼───┐ ┌──▼──────────────────┐
                    │   SQLite    │ │ Managed storage     │
                    │ users · ACL │ │ uploads · trash     │
                    │ links · jobs│ │ quarantine · backup │
                    └─────────────┘ └──┬──────────────────┘
                                      │ optional adapters
                         ┌────────────▼────────────┐
                         │ S3 · Google APIs ·      │
                         │ external storage bounds │
                         └─────────────────────────┘
```

Root.ark combines a browser-facing service, a local synchronization client, and optional integration boundaries. Authentication and authorization decisions stay in the server rather than being delegated to the browser.

## Project status

The repository currently contains working foundations for:

- [x] user, role, and permission management;
- [x] file and folder upload and download;
- [x] file versioning and sharing;
- [x] public-link handling;
- [x] trash and quarantine workflows;
- [x] suspicious-file handling boundaries;
- [x] SQLite persistence;
- [x] backup and restore tooling;
- [x] WebDAV integration;
- [x] cloud-storage adapter boundaries;
- [x] local synchronization client;
- [x] unauthenticated health/readiness endpoints with fail-closed deployment checks;
- [x] bounded provider retry/cancellation, idempotency, ciphertext-only attestation, and secret-safe observability helpers;
- [x] automated syntax, test, dependency, and artifact validation.

### Current source and GitHub snapshot — 2026-10-09 (after PR #142; source SHA `8771d87084e458202d77ab956e3d341c0fe4868f`)

PR #141 (`Revoke active sessions on logout`) and PR #142 (`Keep keyboard focus inside shared dialogs`) are merged. On exact `Root/main` SHA `8771d87084e458202d77ab956e3d341c0fe4868f`, push-triggered Security Regression [run #37931149881](https://github.com/bielxdh3/Root.ark/actions/runs/37931149881) passed on Ubuntu and Windows Node 22: Ubuntu ran 1,039 tests (1,028 passed, 11 skipped, 0 failed); Windows ran 1,039 (1,032 passed, 7 skipped, 0 failed). CodeQL [run #37931149727](https://github.com/bielxdh3/Root.ark/actions/runs/37931149727), default-branch Dependency Review [run #37931149738](https://github.com/bielxdh3/Root.ark/actions/runs/37931149738), and Pages [run #37931148943](https://github.com/bielxdh3/Root.ark/actions/runs/37931148943) passed on the same SHA. This is a point-in-time application-code snapshot before the current documentation follow-up; it does not validate a later documentation merge SHA.

Closure remains **PARTIAL**. A local official release-gate attempt on PR #142's exact candidate head reported one failed final-head `npm test` subgate, although a separate direct full test run and focused tests passed; the instrumented diagnostic mirror is not an official gate result. Real-browser coverage exercised the listed workflows, but quarantine ingestion remains unproven. Whole restore has local rollback/restart recovery with durable provider reconciliation, not cross-domain atomicity. See [the current validation snapshot](docs/validation/2026-10-09-rootark-current-state.md) and [the issue ledger](docs/issue-ledger.md).

### Historical exact-SHA CI snapshot — 2026-10-08 (after PR #127; source SHA `25e50cbaa26062202d470330e93d7beb4575693a`)

PR #127, `fix(restore): preserve provider inventory baseline`, merged from head `2334bf0cd02125d316b3ff083cf784b3e9f82abb`. The push-triggered Security Regression passed on exact `Root/main` SHA `25e50cbaa26062202d470330e93d7beb4575693a`: Ubuntu Node 22 ran 987 tests (976 passed, 11 skipped, 0 failed), and Windows Node 22 ran 987 tests (983 passed, 4 skipped, 0 failed). Syntax validation passed on both; the Ubuntu job also passed the runtime-artifact guard and configured high-severity dependency audit. CodeQL, default-branch Dependency Review, and Pages passed ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37787160598), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37787160551), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37787160662), [Pages](https://github.com/bielxdh3/Root.ark/actions/runs/37787159434)). The PR-candidate release gate passed on `2334bf0…` with 21 passed, 0 blocked, and 0 failed; the gate has not yet been run on this merged SHA. Whole restore remains locally rollback-recoverable with durable provider reconciliation, not atomic across storage domains. Provider identity changes, legacy queue rebinding, and ambiguous queues now fail closed or require a validated baseline; live provider interoperability remains unverified. The full browser acceptance matrix remains incomplete.

The issue and PR snapshot for this source SHA was queried after PR #127 and before the documentation-only follow-up; see [the issue ledger](docs/issue-ledger.md). It is time-scoped and does not describe any later merge.

### Historical exact-SHA CI snapshot — 2026-10-08 (after PR #120, source SHA `acbdd721ac49fdd5d01d17817f723168ee53a57b`)

After PR #120 merged, the push-triggered Security Regression workflow passed on exact `Root/main` SHA `acbdd721ac49fdd5d01d17817f723168ee53a57b`: Ubuntu Node 22 ran 939 tests (928 passed, 11 skipped, 0 failed) and Windows Node 22 ran 939 tests (935 passed, 4 skipped, 0 failed). CodeQL, default-branch Dependency Review, Pages, and `node scripts/validate-release-gate.js` on a clean Windows checkout also passed on this SHA ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37737256757), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37737256839), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37737256816), [Pages](https://github.com/bielxdh3/Root.ark/actions/runs/37737256170)). The release gate reported 21 passed, 0 blocked, and 0 failed. The browser acceptance matrix remains incomplete.

### Historical exact-SHA CI snapshot — 2026-10-08 (after PR #118, source SHA `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e`)

After PR #118 merged, the push-triggered Security Regression workflow passed on exact `Root/main` SHA `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e`: Ubuntu Node 22 ran 938 tests (927 passed, 11 skipped, 0 failed) and Windows Node 22 ran 938 tests (934 passed, 4 skipped, 0 failed). CodeQL, default-branch Dependency Review, and Pages also passed on that SHA ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37729789854), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37729789865), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37729789780), [Pages](https://github.com/bielxdh3/Root.ark/actions/runs/37729789584)). This historical snapshot does not validate the later PR #116 merge SHA or complete the browser acceptance matrix.

### Historical exact-SHA CI snapshot — 2026-10-08 (after PR #117, source SHA `14428690bef7c02648fd0be9570aabb17ae6de1a`)

After PR #117 merged, the push-triggered Security Regression workflow passed on this exact `Root/main` SHA: Ubuntu Node 22 ran 938 tests (927 passed, 11 skipped, 0 failed) and Windows Node 22 ran 938 tests (934 passed, 4 skipped, 0 failed). CodeQL, default-branch dependency review, and Pages also passed on this exact SHA ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37720151580), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37720151634), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37720151454), [Pages](https://github.com/bielxdh3/Root.ark/actions/runs/37720150655)). This snapshot predates the current-base update of PR #116 and any later merge; it is not evidence for any later merge SHA.

### Historical exact-SHA CI snapshot — 2026-10-07

On `Root/main` SHA `964f820417baf44f059a04e5363a2a172dccdc7a`, the push-triggered Security Regression workflow passed Ubuntu Node 22 full validation and Windows Node 22 syntax/tests. CodeQL and the default-branch dependency-review check also passed on this exact SHA ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37549800190), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37549800373), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37549800109)). The PR-only dependency-review job was skipped on the push. This is exact-commit CI evidence; it does not establish browser acceptance, provider interoperability, production deployment safety, or release authorization.

### Historical exact-SHA CI snapshot — 2026-10-08 (source SHA `566a3d24591423c624ef3bcb82290a77ff359210`)

At the recorded snapshot, `Root/main` was `566a3d24591423c624ef3bcb82290a77ff359210`. The push-triggered Security Regression workflow passed Ubuntu Node 22 full validation and Windows Node 22 syntax/tests; CodeQL analysis, default-branch dependency review, and GitHub Pages build and deployment also passed on that exact SHA ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37712454578), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37712454551), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37712454481), [Pages](https://github.com/bielxdh3/Root.ark/actions/runs/37712453703)). The PR-only dependency-review job was skipped on the push. This snapshot predates publication of the documentation PR and is not evidence for the later merge SHA.

### Historical exact-SHA CI snapshot — 2026-10-08 (source SHA `b12d6286a867f1562ea6a9c557f8bd93fadfd5c1`)

After PR #115 merged, the push-triggered Security Regression workflow passed Ubuntu Node 22 full validation and Windows Node 22 syntax/tests; CodeQL, default-branch dependency review, and GitHub Pages build/deployment also passed on exact `Root/main` SHA `b12d6286a867f1562ea6a9c557f8bd93fadfd5c1` ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37715043302), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37715043209), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37715043243), [Pages](https://github.com/bielxdh3/Root.ark/actions/runs/37715042929)). The PR-only dependency-review job was skipped on the push. This historical evidence does not replace validation of a later final SHA.

### Historical local release-gate evidence

Phase 15 introduced a local release-gate runner and repaired the release-candidate lockfile to the reviewed `brace-expansion` 5.0.9 integrity. Its recorded candidate-local verdict was `RELEASE_GATE_BLOCKED_ENVIRONMENT`: 13 passed, 0 failed, and 1 expected clean-worktree block. That earlier local result is not the current exact-`Root/main` validation result.

Phase 16 evidence is recorded in [the Phase 16 security review](docs/security/phase-16-final-review.md): 66/66 cross-phase tests and 116/116 syntax checks passed, with separate realtime 4/4 and upload 12/12 boundary runs. The review's then-current disposable-install failure to load the `better-sqlite3` native binding, and its pending remote CI evidence, are historical; the exact-SHA CI evidence above supersedes only the remote-CI status. Browser, provider, live-production/TLS, owner, and release authorization remain separate gates, with release authorization `NOT_AUTHORIZED`.

The historical 2026-10-06 GitHub snapshot at `1955eab3d05f72632396eff62ef96d39eedd634b` is retained in [the issue ledger](docs/issue-ledger.md); it is not the current default-branch SHA.

> [!IMPORTANT]
> The approved long-term direction includes client-side zero-knowledge encryption. The current implementation predates that architecture and must not be described as zero-knowledge or treated as the final security model.

## Requirements

- Node.js 22 or newer;
- npm;
- a private, randomly generated `JWT_SECRET`;
- SQLite-compatible local storage;
- optional external credentials only for integrations you intentionally enable.

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/bielxdh3/root.ark.git
cd root.ark
npm ci
```

### 2. Create a private environment file

Copy `.env.example` to `.env`, then replace every placeholder with private values.

> [!WARNING]
> Never commit `.env`, JWT secrets, API credentials, database files, uploads, backups, or generated runtime data.

### 3. Prepare the database

```bash
npm run db:migrate
```

### 4. Start the development server

```bash
npm start
```

The server uses port `3000` unless `PORT` is configured.

See [Local development setup](docs/development-setup.md) for clean-install user bootstrap and local-only sample account rules.

For a reviewed deployment profile, set a strong `JWT_SECRET`, an explicit
`TOTP_POLICY` (`optional`, `role-required`, or `global-required`), and a
32-byte `SERVER_MASTER_KEY` or protected `data/server-master.key`. `GET
/health` is liveness-only; `GET /ready` returns `503` until these checks and
the selected cloud-provider prerequisites and Secure session-cookie policy
pass. `NODE_ENV=production` enables Secure cookies by default; production
startup rejects an explicit insecure setting, while non-production HTTPS
deployments can set `SESSION_COOKIE_SECURE=true`. These endpoints do not
require authentication and intentionally return no paths, credentials, or key data.
WebDAV Basic authentication cannot complete a TOTP challenge and is rejected
for accounts with TOTP enrolled or covered by a required TOTP policy; with
`optional` policy, Basic authentication remains available only to accounts
without enrolled TOTP. WebDAV authentication also shares the normal per-IP and
per-username login throttles. WebSocket upgrades authenticate and validate
Origin before `101`, with configurable per-peer rate and concurrent-connection
bounds (`REALTIME_UPGRADE_MAX_PER_WINDOW`, `REALTIME_UPGRADE_RATE_WINDOW_MS`,
and `REALTIME_MAX_CONNECTIONS_PER_PEER`).

## Architecture

| Area | Responsibility | Current implementation |
|---|---|---|
| HTTP application | Routes, authentication, authorization, uploads | Express 5 |
| Identity | Password validation, tokens, permissions | `bcryptjs` + JSON Web Tokens |
| Persistence | Users, metadata, versions, operational state | SQLite + `better-sqlite3` |
| File handling | Uploads, archives, extraction, document processing | Multer, Archiver, Unzipper, Mammoth |
| Scheduling | Recurring maintenance and background tasks | `node-cron` |
| Real-time boundary | Live communication where enabled | WebSocket |
| Integrations | S3-compatible storage and Google APIs | AWS SDK + Google APIs |
| Synchronization | Local initialization and continuous sync | Root.ark sync client |

## Main workflows

### File lifecycle

```text
upload
  └─► permission check
       └─► validation and storage
            ├─► active file
            ├─► version history
            ├─► quarantine
            └─► trash
```

### Backup lifecycle

```text
SQLite metadata + managed files
              │
              ▼
       backup operation
              │
              ▼
     isolated backup output
              │
              ▼
       restore validation
```

Backups are not useful until restore behavior is tested. Read [BACKUP.md](BACKUP.md) before relying on the tooling.

## Commands

| Command | Purpose |
|---|---|
| `npm start` | Start the development server with file watching |
| `npm test` | Run Node.js tests |
| `npm run validate` | Run syntax, tests, and dependency validation |
| `npm run validate:artifacts` | Detect runtime artifacts contaminating the repository |
| `npm run validate:release-gate` | Run the bounded Phase 15/16 local release gate |
| `npm run db:migrate` | Apply database migrations |
| `npm run db:migrate-json` | Migrate supported JSON data to SQLite |
| `npm run db:backup` | Run the database backup tool |
| `npm run sync:init` | Initialize the local sync client |
| `npm run sync:start` | Start the local sync client |

## Validation

Run the full repository validation before trusting a change:

```bash
npm run validate
npm run validate:artifacts
```

The checks cover:

- JavaScript syntax;
- automated tests;
- lockfile-backed dependency auditing at high severity;
- accidental repository contamination by generated runtime data.

The bounded Phase 15 matrix and its external residuals are recorded in
[the Phase 15 local release gate](docs/security/phase-15-local-release-gate.md).
Phase 16 closeout evidence and limitations are recorded in
[the Phase 16 final security review](docs/security/phase-16-final-review.md).

## Security boundary

Root.ark should currently be treated as a private administrative service, not a public SaaS product.

- bind and expose it only where explicitly intended;
- keep secrets and runtime data outside Git;
- use a strong, unique `JWT_SECRET`;
- do not assume a public link is equivalent to a complete security review;
- quarantine and suspicious-file handling reduce risk but do not replace malware scanning or sandboxing;
- external storage adapters expand the trust boundary and require separate credential review;
- historical security notes are engineering records, not proof that every deployment is safe;
- current server-side storage is not the future zero-knowledge design.

See [SECURITY.md](SECURITY.md) for responsible vulnerability reporting.

## Repository documentation

- [Development setup](docs/development-setup.md)
- [Product discovery](docs/product-discovery.md)
- [Plan tree](docs/plan-tree.md)
- [Backup and restore](BACKUP.md)
- [Synchronization](SYNC.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)
- [Security policy](SECURITY.md)

## Roadmap

- [ ] Define and implement the approved client-side zero-knowledge architecture
- [ ] Separate cryptographic, storage, and sharing trust boundaries
- [ ] Harden deployment defaults and document a reviewed production profile
- [ ] Expand restore testing and disaster-recovery evidence
- [ ] Strengthen suspicious-file isolation and scanning integrations
- [ ] Review every external adapter independently
- [ ] Define any BielOS integration as a separate approved architecture

## Project direction

Root.ark remains an independent project. Future integration or selective reuse with BielOS requires an explicit architecture, security review, migration plan, and authorization. Similar goals do not make the two systems interchangeable.

## License

Root.ark is released under the [Apache License 2.0](LICENSE).

You may use, modify, redistribute, embed, and sell the software, including in commercial or closed-source products, subject to the Apache-2.0 terms. Redistributions must preserve applicable license, copyright, and attribution notices, including the project [NOTICE](NOTICE) where required.

**Copyright 2026 bielxdh3.**

## Disclaimer

Root.ark is experimental self-hosted software. It is provided without a guarantee that a particular deployment, network, configuration, integration, backup, or stored file is secure.
