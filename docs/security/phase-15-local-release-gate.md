# Phase 15 local release gate

> Historical phase report for the Phase 14 base below. It is not the current
> closure verdict; see the [2026-10-09 current validation snapshot](../validation/2026-10-09-rootark-current-state.md)
> for the later exact-SHA CI state and remaining release gates.

Status: `RELEASE_GATE_BLOCKED_ENVIRONMENT`. This is a bounded local release
gate for the exact Phase 14 base `bcf0861e3c6987331228816cb479ade525b3b555`.
It is not a release, deployment, production approval, remote-CI result, or
publication authorization.

## Scope and dependency state

The release-candidate lockfile now resolves the known high
`GHSA-rgw5-rvv9-x895` / CVE-class `brace-expansion` advisory to the previously
reviewed `5.0.9` package and official registry integrity:

```text
https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.9.tgz
sha512-ScQ4IuvIEF1TMlP7Zt+vjJ//9zlPb2SDcxWxM3bk8s6t6GGdJ7KO1dCcTidOPJKePW30LE/2cT7wCyPho9/Wxg==
```

`package.json` dependency keys and ranges remain identical to the lockfile
root; no new direct dependency was added. The lockfile contains 383
transitive package records. `npm audit --package-lock-only --audit-level=high`
reported `found 0 vulnerabilities` in the disposable controlled install.

## Local gate

The focused runner is `npm run validate:release-gate`. With the disposable
install at `E:\rootark-phase15-install-backup\node_modules`, the controlled
pre-commit matrix was:

| Result | Count | Coverage |
|---|---:|---|
| PASS | 13 | lock/provenance and manifest parity; syntax; runtime artifacts; diff; secret-material patterns; ciphertext-only evidence; Phase 9 crypto; Phase 10 auth/TOTP; Phase 12 sync/WebDAV; Phase 13 client/groups; Phase 14 readiness/attestation; backup/restore evidence; high-severity audit |
| FAIL | 0 | No gate failure |
| BLOCKED | 1 | Expected clean-worktree check before the required local commit |

The focused phase test counts were 9/9 for Phase 9, 11/11 for Phase 10,
4/4 for Phase 12, 5/5 for Phase 13, 7/7 for Phase 14, and 1/1 for the
disposable backup/restore security test. The runner also checks 106 JavaScript
files for syntax and scans repository files for secret-material patterns.

The ciphertext-only evidence creates a disposable encrypted sync record,
accepts its structural attestation, and rejects injected plaintext or key
fields. This proves the local structural boundary only; it does not prove
provider interoperability, decryption, or production backup recovery.

## Explicit residual gates

The following remain external or unavailable and are not claimed by this
local verdict:

- S3/Google/provider credentials, provider interoperability, and provider
  failure behavior in a real deployment;
- browser installation, offline replay, and browser/device behavior;
- live production topology, TLS/reverse-proxy exposure, monitoring, rollback,
  and disaster-recovery acceptance;
- remote CI for this final commit, product approval, release/tagging, and
  publication authorization;
- independent Phase 16 security/quality review.

No release, tag, deploy, merge, push, PR, issue, or repository-setting change
was performed.
