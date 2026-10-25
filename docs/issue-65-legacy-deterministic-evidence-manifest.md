# Issue #65 — bounded legacy evidence manifest

`scripts/zk1-legacy-evidence-manifest.js` is an opt-in, read-only inventory of the legacy host's **selected** SQLite database, uploads, temp/preview tree, trash tree, ZIP backups, and SQL references. The output is deterministic when the observed bytes and references are unchanged.

Run from the project directory (PowerShell; supply real absolute paths):

```powershell
node scripts/zk1-legacy-evidence-manifest.js --opt-in --database 'E:\rootark-data\rootark.sqlite' --uploads 'E:\rootark-uploads' --temp 'E:\rootark-temp' --trash 'E:\rootark-trash' --backups 'E:\rootark-data\backups'
```

Each physical file and extracted ZIP member receives a SHA-256 content digest, length, a stable SHA-256 path-derived identifier and the classification `PROVEN` **only for its observed bytes**. SQLite rows are joined against physical versions, current logical references, trash items and backup checksums. ZIP central headers, individual decompressed members and declared manifest membership are verified within bounded limits. Missing revisions, unknown SQL tables, in-flight transactions, symlinks, hardlinks, mixed snapshots, unsupported archives and unavailable roots produce `UNKNOWN`. Files are reopened with no-follow checks, checked for identity changes, and rescanned after ZIP processing.

`sections` gives separate coverage for each observed source and semantic join. A readable physical tree can be `PROVEN` while its ownership, restoration lineage or retention semantics remain `UNKNOWN`. A SHA-256 name identifier is deterministic **but is not a confidentiality guarantee against guessing common filenames**. No plaintext file content, source path, filename, token or credential is included in the report.

The top-level result **always** has `status: "UNKNOWN"`, `wholeCorpusVerified: false`, `canDeleteLegacy: false`, and `authorizesCutover: false`. It does not establish remote provider custody, historic deleted generations, archived JSON mirror completeness, independent owner-signed inventory, cross-host consistency or writer quiescence. It never deletes, restores, migrates or changes SQLite state. A missing live journal/WAL requirement can limit inspection, and the report must not be used to justify migration or garbage collection.
