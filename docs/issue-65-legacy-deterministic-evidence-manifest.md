# Issue #65 — bounded legacy evidence manifest

`scripts/zk1-legacy-evidence-manifest.js` is an opt-in, read-only inventory of the legacy host's **selected** SQLite database, uploads, temp/preview tree, trash tree, ZIP backups, and SQL references. The output is deterministic when the observed bytes and references are unchanged.

Run from the project directory (PowerShell; supply real absolute paths):

```powershell
node scripts/zk1-legacy-evidence-manifest.js --opt-in --database 'E:\rootark-data\rootark.sqlite' --uploads 'E:\rootark-uploads' --temp 'E:\rootark-temp' --trash 'E:\rootark-trash' --backups 'E:\rootark-data\backups'
```

Each physical file and extracted ZIP member receives a SHA-256 content digest, length, a stable SHA-256 path-derived identifier and the classification `PROVEN` **only for its observed bytes**. SQLite rows are joined against physical versions, current logical references, trash items and backup checksums. The SQLite reader opens a private, disposable copy of the **exact bytes already hashed**, never reopening the source pathname for SQL queries. Files are read through descriptor-bound requests capped at 16 KiB and their original verified length, with post-read inode/size/timestamp checks. The temporary SQLite image is deleted after its read-only query; no original database or backup is changed.

ZIP central headers, decompressed members and declared manifest membership are verified within bounded limits. The ZIP declaration must match the exact set of non-manifest physical members; the manifest cannot include itself. SQL backup and trash references require a one-to-one mapping to every observed physical artifact. Missing revisions, unknown SQL tables, in-flight transactions, duplicate aliases, symlinks, hardlinks, mixed snapshots, unsupported archives and unavailable roots produce `UNKNOWN`. Source files are checked for identity changes and rescanned after ZIP processing.

`sections` gives separate coverage for each observed source and semantic join. A readable physical tree can be `PROVEN` while its ownership, restoration lineage or retention semantics remain `UNKNOWN`. A SHA-256 name identifier is deterministic **but is not a confidentiality guarantee against guessing common filenames**. No plaintext file content, source path, filename, token or credential is included in the report.

The top-level result **always** has `status: "UNKNOWN"`, `wholeCorpusVerified: false`, `canDeleteLegacy: false`, and `authorizesCutover: false`. It does not establish remote provider custody, historic deleted generations, archived JSON mirror completeness, independent owner-signed inventory, cross-host consistency or writer quiescence. It never deletes, restores, migrates or changes SQLite state. A missing live journal/WAL requirement can limit inspection, and the report must not be used to justify migration or garbage collection.
