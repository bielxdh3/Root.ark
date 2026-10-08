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

### Exact-SHA CI snapshot — 2026-10-08 (after PR #117, source SHA `14428690bef7c02648fd0be9570aabb17ae6de1a`)

After PR #117 merged, the push-triggered Security Regression workflow passed on this exact `Root/main` SHA: Ubuntu Node 22 ran 938 tests (927 passed, 11 skipped, 0 failed) and Windows Node 22 ran 938 tests (934 passed, 4 skipped, 0 failed). CodeQL, default-branch dependency review, and Pages also passed on this exact SHA ([Security Regression](https://github.com/bielxdh3/Root.ark/actions/runs/37720151580), [CodeQL](https://github.com/bielxdh3/Root.ark/actions/runs/37720151634), [Dependency Review](https://github.com/bielxdh3/Root.ark/actions/runs/37720151454), [Pages](https://github.com/bielxdh3/Root.ark/actions/runs/37720150655)). This snapshot predates the final closure documentation PR and is not evidence for a later merge SHA.

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
the selected cloud-provider prerequisites pass. These endpoints do not require
authentication and intentionally return no paths, credentials, or key data.

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
