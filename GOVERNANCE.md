# Governance

Root.ark currently uses a maintainer-led governance model.

## Maintainer

The repository owner, `@bielxdh3`, is the final decision maker for project scope, roadmap, merges, releases, security response, compatibility, and repository policy.

## Sources of truth

Project decisions follow the authority order documented in [AGENTS.md](AGENTS.md):

1. current code and tests;
2. [docs/plan-tree.md](docs/plan-tree.md);
3. dedicated architecture, security, and validation documents;
4. scoped GitHub issues.

## Decision model

- Issues define executable scope and acceptance criteria.
- Pull requests implement one coherent goal and provide validation evidence.
- `Root/main` is the canonical integration branch.
- Security and data-safety invariants take precedence over convenience.
- Documentation must not present unverified behavior as completed.

## Security-sensitive decisions

Authentication, authorization, encryption, storage, backups, restore, trash, uploads, WebDAV, synchronization, migration, and external-adapter changes require explicit review and focused validation.

## Releases

A merge does not automatically authorize a production release. Release claims must respect the release-gate and security evidence recorded by the project.

## Governance changes

This file may evolve as sustained contribution volume or additional maintainers make a broader model useful.
