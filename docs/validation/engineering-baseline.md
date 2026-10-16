# Engineering validation baseline

## Clean checkout

```text
npm ci
npm run validate
```

## Individual commands

- `npm run validate:syntax` uses Git's tracked-plus-unignored inventory to run `node --check` on every first-party JavaScript file. Explicit file arguments are checked only when supplied, and missing files or directories fail.
- `npm test` runs the current Node test suite using disposable fixtures.
- `npm run validate:dependencies` performs the locked dependency audit at high severity.
- `npm run validate` runs syntax validation, tests, and the locked dependency audit in that order. CI keeps those commands in separate steps so failures remain easy to identify.

## Included

- First-party JavaScript syntax.
- Current automated Node tests, including disposable real-server coverage for upload authorization-before-Multer, suspicious-extension quarantine, disabled-scanner extension policy across multipart, chunk-completion, and WebDAV paths, staging cleanup, Windows trailing-dot/space aliases, filename/path containment, file-trash lifecycle safety, and JSON-mode backup/restore isolation. The backup regression confirms representative `manageBackups` denial before archive/history/lock side effects, archive/history/pre-restore/restore-temp ownership by the child runtime root, checkout isolation, manifest/download access, safe archive inclusion and exclusion, invalid-confirmation non-mutation, and exact JSON/upload round-trip bytes. A disposable SQLite test proves the configured database path is archived and restored without changing `db.ROOT_DIR` or default database semantics.
- Locked production and development dependency audit at high severity.
- Disposable test data only.

## Environment-dependent validation

This baseline does not automatically validate live ClamAV, S3, Google Drive, Windows WebDAV mounting, browser-driven flows, long-running migration, cloud backup storage, scheduler behavior, retention under time/count pressure, hostile ZIP corpora beyond current protections, full production SQLite recovery, folder-trash, empty-trash, automatic cleanup, cloud trash deletion, multi-chunk retry/recovery, or synchronization exercises. The upload-policy tests cover one completed chunk and WebDAV PUT with a disabled scan provider while retaining the extension block; production HTTPS, reverse-proxy, Host, and Origin configuration also requires a real deployment environment. Those checks require disposable data and the relevant real prerequisites.

## Data safety

The default command and CI do not upload or retain databases, backups, quarantine contents, credentials, JWTs, cookies, user files, or generated runtime ledgers. This baseline is not evidence that every Root.ark feature is validated.
