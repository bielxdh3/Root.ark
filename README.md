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
          ┌───────────────────────┐   ┌─────────────────────────┐
          │ Browser / WebDAV      │   │ Local sync client       │
          │ ordinary file paths   │   │ signed v2 / legacy-dev  │
          └───────────┬───────────┘   └────────────┬────────────┘
                      └─────────────┬──────────────┘
                                    │
                     ┌──────────────▼─────────────────┐
                     │ Root.ark server (Express)      │
                     │ auth · ACL · uploads · WebDAV  │
                     │ sync · opt-in protected routes │
                     └──────────┬───────────┬─────────┘
                                │           │
                    ┌───────────▼────┐ ┌────▼──────────────────┐
                    │ SQLite + JSON  │ │ Managed file storage  │
                    │ accounts · ACL │ │ versions · trash      │
                    │ metadata/audit │ │ quarantine · backups  │
                    └────────────────┘ └────┬──────────────────┘
                                            │ optional adapters
                                  ┌─────────▼─────────────┐
                                  │ S3 / Google Drive     │
                                  │ provider boundaries   │
                                  └───────────────────────┘

        ZK-1 protected path (opt-in, default-off; separate trust):
             ┌──────────────────────────┐
             │ Authorized ZK-1 client   │
             │ encrypts + signs locally │
             └─────────────┬────────────┘
                           │ signed ciphertext
             ┌─────────────▼────────────┐   ┌──────────────────────┐
             │ ZK-1 routes in server    │──►│ Independent witness  │
             │ isolated protected API   │   │ and CAS trust gates  │
             └──────────────────────────┘   └──────────────────────┘
```

The protected routes are part of the same server but are separately gated and disabled by default. Ordinary file, WebDAV, and legacy sync paths can process server-readable data; the ZK-1 client encrypts and signs before transport. Witness/CAS services require independent provisioning and do **not** imply production authorization. SQLite and JSON store state according to the configured feature/mode; PostgreSQL 18 trust/admission validation is not the default application database.

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
- [x] an **opt-in, default-off** Zero-Knowledge v1 (ZK-1) protected-content implementation, with client-held keys and independent trust/fencing requirements.

### Zero-Knowledge v1 (opt-in, default-off)

Root.ark includes protected-content paths for client-side authenticated encryption, signed device/owner authorization, encrypted object/catalog metadata, ciphertext version transport, guarded synchronization, and bounded backup/recovery and legacy-migration workflows. Storage integrations and trust witnesses have additional configuration and verification boundaries.

> [!IMPORTANT]
> **ZK-1 is not a system-wide Zero-Knowledge guarantee and is not approved for unreviewed production use.** Ordinary or legacy file, WebDAV, preview, search, sharing, backup and sync paths may process server-readable data. Protected-content metadata such as size, timing, operation/device identity and opaque routing identifiers may remain observable. Independent off-host key custody, external provider durability, production failover, and an authorized legacy cutover require separate evidence and approval.

See the [migration and trust contract](docs/architecture/zero-knowledge-migration-contract.md), [metadata leakage register](docs/issue-65-zk1-runtime-leakage-register.md), and [historical integration and exact-SHA CI evidence](docs/validation/readme-historical-evidence-through-2026-11-04.md). CI results are not deployment authorization.

## Requirements

- Node.js 22 or newer;
- npm;
- a private, randomly generated `JWT_SECRET`;
- SQLite-compatible local storage;
- optional external credentials only for integrations you intentionally enable.

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/bielxdh3/Root.ark.git
cd Root.ark
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
| Protected ZK-1 (opt-in/default-off) | Client-side encryption, signed protected requests, opaque catalog, CAS/witness and guarded recovery | ZK-1 browser client, protected HTTP routes, independently pinned verification boundaries |

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
| `npm run sync:init` | Initialize the development-only legacy uploader; bearer configuration is stored under the private user config directory by default |
| `npm run sync:start:legacy-dev` | Run that legacy uploader with explicit development opt-in; an existing CWD config is reused only when its permissions are private |
| `npm run sync:start` | Run Sync v2 with separately provisioned device credentials and trusted policy; legacy `sync:init` does **not** provision v2 |

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
- ordinary and legacy server-readable storage is **not** equivalent to the opt-in ZK-1 protected protocol; enablement requires separate authorization, independent trust anchors and deployment review.

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
- [Zero-Knowledge migration and trust contract](docs/architecture/zero-knowledge-migration-contract.md)
- [ZK-1 metadata leakage and security boundary register](docs/issue-65-zk1-runtime-leakage-register.md)
- [Historical integration and exact-SHA CI archive](docs/validation/readme-historical-evidence-through-2026-11-04.md)

## Roadmap

- [x] Integrate the approved opt-in client-side Zero-Knowledge v1 architecture (Issue #65; PRs #231–#236)
- [x] Separate protected cryptographic, storage, and sharing trust boundaries in ZK-1 v1
- [ ] Independently certify production key custody, deployment configuration, external durability and authorized ZK-1 cutover
- [ ] Harden deployment defaults and document a reviewed production profile ([single-instance profile](docs/security/single-instance-execution-profile.md) documented; real deployment acceptance pending)
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
