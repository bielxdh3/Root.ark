# Multer Security Validation

The installed Multer version was `1.4.5-lts.2` under the declared `^1.4.5-lts.1` range. Multer 1.x is deprecated and its official changelog records multipart security fixes across 2.0 through 2.2.

`2.2.0` is the smallest stable release outside the published ranges for [CVE-2026-5038](https://github.com/expressjs/multer/security/advisories/GHSA-3p4h-7m6x-2hcm) and [CVE-2026-5079](https://github.com/expressjs/multer/security/advisories/GHSA-72gw-mp4g-v24j). Earlier 2.x releases also fixed CVE-2025-47935, CVE-2025-47944, CVE-2025-48997, CVE-2025-7338, CVE-2026-2359, CVE-2026-3304, and CVE-2026-3520. The documented major-version compatibility change is a Node.js minimum of 10.16.0.

Root.ark uses Multer `^2.2.0` with one-file, 8 MiB simple-upload, flat-field, and bounded field-count limits. Focused real-server regressions cover parser failures and cleanup, nested-field and single-file enforcement, binary integrity, UTF-8 filenames, authorization-before-parser behavior, traversal-safe basenames, and quarantine policy.

## Incomplete chunk-session retention

Accepted chunks update server-managed `lastActivityAt` metadata. Startup cleanup and a periodic sweep remove chunk part files after seven days without accepted activity, under the same per-session lifecycle lock used by uploads. Cleanup first writes an expiry marker so a stale client cannot resume from the deleted parts; the metadata-only marker is retained for up to seven additional days, then removed. Existing sessions without an activity timestamp receive a new timestamp when safely migrated, giving them a conservative seven-day grace period instead of estimating age from filesystem modification times. Invalid or unsafe sessions are blocked from resume and preserved for inspection. Multer staging files in `.chunks/incoming` are outside this session sweep and are not modified by it. The sweep interval defaults to 60 seconds and may be bounded with `CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS` from 1 second to 1 hour.
