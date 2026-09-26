# Contributing to Root.ark

Thanks for contributing to Root.ark.

Root.ark is a security-sensitive storage application. Contributions that touch authentication, authorization, file paths, uploads, backups, trash, encryption, WebDAV, synchronization, storage adapters, or deployment boundaries require focused review and evidence.

## Before you start

1. Read [AGENTS.md](AGENTS.md).
2. Read [docs/plan-tree.md](docs/plan-tree.md) and confirm the change fits the current approved phase.
3. Review [SECURITY.md](SECURITY.md) for vulnerability-reporting rules.
4. Search existing issues and pull requests.
5. Keep one pull request focused on one coherent goal.

Do not combine unrelated refactors, dependency upgrades, redesigns, and features.

## Development setup

See [docs/development-setup.md](docs/development-setup.md).

Typical setup:

```bash
npm ci
npm run validate
npm run validate:artifacts
```

Use only disposable data for destructive or lifecycle tests.

## Validation

Run checks appropriate to the affected boundary:

```bash
npm run validate:syntax
npm test
npm run validate:dependencies
npm run validate:artifacts
```

For release-related changes, also use the bounded release gate where appropriate:

```bash
npm run validate:release-gate
```

Never claim a check passed unless it actually completed.

## Security-sensitive changes

Extra scrutiny is required for:

- authentication, sessions, JWTs, cookies, and CSRF;
- authorization, roles, permissions, and public links;
- path construction, extraction, archives, and traversal defenses;
- upload validation, quarantine, and malware-scanning boundaries;
- encryption, key handling, or cryptographic metadata;
- backup, restore, trash, and permanent deletion;
- WebDAV and synchronization;
- cloud-storage adapters and credentials;
- database migrations and data lifecycle;
- logging, audit, diagnostics, and secret handling.

Preserve fail-closed behavior, least privilege, auditability, and compatibility with currently supported storage modes.

## Pull requests

A good pull request should include:

- the problem and intended behavior;
- the linked issue or plan-tree phase when applicable;
- starting and final revision;
- exact files changed;
- validations performed and their results;
- validations not run and why;
- security/data-safety implications;
- remaining limitations or risks.

Use the repository pull request template.

## AI-assisted contributions

AI-assisted contributions are welcome, but the contributor remains responsible for the submitted code, evidence, and security claims. Review generated diffs and never submit secrets, private data, local databases, uploads, backups, or credentials.

## License

Unless explicitly stated otherwise, contributions intentionally submitted for inclusion in Root.ark are accepted under the repository's [Apache License 2.0](LICENSE).
