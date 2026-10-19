# Root.ark Agent Instructions

## Purpose

This repository is a security-sensitive file storage application. Preserve user data, authentication boundaries, permissions, auditability, backups, trash, encryption, upload scanning, sharing, storage compatibility, WebDAV, and synchronization behavior.

The repository has accumulated features faster than it accumulated tests and governance. Work must now be phase-scoped, evidence-backed, and economical with context.

## Sources of truth

Use this order:

1. Current repository code and tests.
2. `docs/plan-tree.md` for phase order and status.
3. Dedicated architecture, security, and validation documents.
4. The linked GitHub issue for the executable task.
5. Old chat context only as historical input.

Never invent repository state. A document claiming a feature exists is not proof that it works. A `[DONE]` item requires relevant validation evidence.

## Main execution rule

Use the smallest safe scope possible.

- Do not inspect the whole repository unless the task explicitly requires a repository-wide review.
- Do not reopen large files repeatedly.
- Use targeted searches for exact routes, functions, services, or UI elements.
- Stop searching after the relevant implementation point and adjacent security boundary are understood.
- Do not refactor unrelated code.
- Do not add extra features.
- Do not redesign the UI unless the task is explicitly visual.
- Do not convert CommonJS to ESM.
- Do not convert the project to TypeScript.
- Do not mass-upgrade dependencies.
- Do not combine planning, implementation, unrelated cleanup, and redesign in one task.

## Agent model

Use one primary agent by default.

Do not spawn subagents for routine scanning, planning, implementation, documentation, or repeated review. For authentication, permissions, migrations, backup/restore, upload scanning, storage, or WebDAV, at most one independent final reviewer may be used after implementation and focused tests are complete.

## Before editing

1. Read `docs/plan-tree.md` and the linked issue.
2. Confirm the actual branch, HEAD, remote relationship, and worktree state.
3. Preserve newer work. Never reset, force-push, or discard user changes.
4. Identify the exact outcome, files, routes, and invariants involved.
5. State the narrow scope and explicit exclusions internally before editing.
6. Inspect only the files needed for that scope.
7. For security work, identify the trust boundary, attacker input, authorization decision, and sensitive data involved.

## During editing

1. Make the smallest coherent safe change.
2. Preserve route names and response shapes unless the issue explicitly approves a migration.
3. Preserve current design, layout, colors, fonts, and user flow unless the task is visual.
4. Preserve local, S3, and Google Drive compatibility where the affected feature currently supports them.
5. Preserve audit logging for security-relevant actions without logging secrets or file contents.
6. Preserve trash, versions, expiration, links, encryption metadata, and backup behavior when file lifecycle code changes.
7. Use safe path construction and canonicalization. Reject traversal, absolute paths, unsafe separators, and unexpected symlinks where relevant.
8. Use disposable fixtures and temporary directories for destructive tests.
9. Keep implementation and documentation claims synchronized.

## Security rules

Never print, commit, log, expose, or include in test fixtures:

- `.env` contents;
- JWT secrets or tokens;
- session tokens or cookies;
- passwords or recovery codes;
- private keys or encryption keys;
- AWS or Google credentials;
- authorization headers;
- raw private audit logs;
- databases, WAL/SHM files, dumps, or migrations containing real data;
- backups;
- uploads, quarantine contents, trash contents, or synchronization state containing user data;
- absolute private filesystem paths.

Always:

- validate user-controlled input;
- authorize on the server;
- distrust role and permission data stored in the browser;
- escape or render user-controlled text without HTML interpretation;
- avoid placing bearer tokens in URLs;
- use generic authentication errors;
- keep rate limiting and audit behavior intact;
- fail safely when required security configuration is missing;
- state what could not be validated.

## Data safety

Never permanently delete or restore non-disposable user data during development or validation.

For backup, restore, trash, migration, encryption, upload scanning, synchronization, or cloud storage tasks:

1. use a disposable workspace;
2. confirm the data path before destructive actions;
3. create a recoverable pre-test state when appropriate;
4. stop if the target may contain the user's only copy;
5. do not commit generated artifacts.

## Reasoning guidance

Use MEDIUM reasoning for:

- small UI fixes;
- isolated CRUD behavior;
- simple validation;
- filters and search changes;
- focused dependency upgrades after tests exist;
- documentation-only synchronization.

Use HIGH reasoning for:

- authentication and sessions;
- permissions and authorization;
- security fixes;
- database migrations;
- backup and restore;
- encryption;
- upload scanning and quarantine;
- cloud storage;
- WebDAV;
- synchronization conflicts;
- architecture extraction;
- bugs that already failed once.

Use VERY HIGH/MAX only when explicitly requested for:

- a bounded deep security audit;
- a final independent review of completed high-risk work;
- an unusually difficult defect with evidence that HIGH reasoning was insufficient.

## Validation rules

Do not claim behavior works unless it was tested through the relevant route, UI path, or service boundary.

Prefer focused tests during implementation and one coherent validation gate before completion.

For each task, record:

- tests run;
- tests passed or failed;
- validations not run;
- environmental blockers;
- remaining risk.

Do not repeatedly run identical broad validations after every small edit. Do not skip critical regression checks merely to save tokens.

## Git and pull request rules

- Use a dedicated branch for nontrivial work.
- One PR must have one coherent goal.
- Link the GitHub issue and plan-tree phase.
- Do not force-push or rewrite published history.
- Keep commits coherent and intentionally scoped.
- Keep the Git author and committer identity tied to the authenticated repository contributor. For owner-authored work on this repository, use `bielxdh3 <bielxdh3@gmail.com>` unless the owner explicitly specifies another verified identity. Never invent placeholder bot/audit names or `@users.noreply.github.com` addresses, and never override an established identity via `git -c`, `GIT_AUTHOR_*`, or `GIT_COMMITTER_*` without explicit authorization.
- Before publishing commits, check `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT`; stop and report any unexpected identity instead of publishing misattributed commits.
- Do not create empty commits.
- After publishing, verify the remote branch and PR state.
- Update `docs/plan-tree.md` only after implementation and validation evidence exist.

## Large feature rule

Do not implement large features from a casual idea or one broad prompt.

The orchestrator must first:

1. capture the product decision;
2. identify security and architecture consequences;
3. create an approved plan-tree item;
4. create a scoped issue with dependencies, exclusions, acceptance criteria, and validation;
5. hand only that issue to the executor.

Bad task:

`Implement a complete secure synchronization platform.`

Good task:

`Implement only token-safe WebSocket authentication for issue #2. Do not change HTTP session transport, permissions, 2FA, UI design, WebDAV, or synchronization.`

## Stop conditions

Stop and report the blocker when:

- the working tree contains unexpected user changes that overlap the task;
- the requested action risks non-disposable data;
- a required secret would need to be printed or committed;
- the issue conflicts with the plan tree or a newer commit;
- a security design decision is materially unresolved;
- a destructive action exceeds explicit authorization;
- a critical validation cannot be performed and completion would otherwise be misleading.

Do not stop for minor uncertainty that can be resolved safely from the repository.

## Final response format

Use only:

- Status
- Starting and final SHA
- Files changed
- Behavior changed
- Validations run
- Validations not run
- Remaining limitations
- Next plan-tree item

Keep the final report compact. Do not include long logs, secrets, routine narration, or speculative claims.
