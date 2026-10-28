# Issue #65 — combined strict authenticated legacy HTTP metadata egress (W145)

**Status: DEV-OFF, deny-only, nonauthorizing.** Derived from local
`c5c09513adeb9819c57ca00bc0b558665e47437d` in a new isolated worktree.
The first W145 eight-route patch is included as a copy without editing its
original frozen worktree. The extension below has its own real HTTP TDD.

## Explicit registered routes and methods

An early `server.js` guard after construction of `authenticate`, before all
route registrations, recognizes only the exact GET/HEAD data-plane patterns
and two POST reads below. It authenticates the real JWT and replies 503,
`Cache-Control: no-store`, `ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE`, before
Express conditional 304, Range/streaming and route handler execution.
Unrecognized routes, ordinary mutations, authentication and readiness
remain under their existing handlers. The existing strict switch follows
its existing `ROOTARK_ZK10_SYNC_CUTOVER_STRICT` semantics: trim; empty,
`0`, `off` disable; other non-empty values enable.

Original eight GET/HEAD routes covered (see previous W145 doc):
`/files/search`, `/files/:name`, `/list`, `/versions/:filename`,
`/download/:filename/v/:version`, `/history`,
`/preview/file/:scope/:name` and `/preview/text/:scope/:name`.

Supplemental exact GET/HEAD read routes:

| Registration owner | Data-plane paths |
| --- | --- |
| `server.js` | `/folders`, `/folders/:id/access`, `/file-access`, `/encrypted/:filename/metadata`, `/pending`, `/quarantine` |
| `src/routes/trash.js` | `/trash`, `/trash/summary` |
| `src/routes/backups.js` | `/backups`, `/backups/latest-status`, `/backups/:id/manifest`, `/backups/:id/download` |
| `src/routes/analytics.js` | `/analytics/summary`, `/analytics/uploads-by-month`, `/analytics/uploads-by-user`, `/analytics/active-users`, `/analytics/file-types`, `/analytics/downloads-by-file`, `/analytics/recent` |
| `src/routes/audit.js` | `/audit/logs`, `/audit/summary` |
| `src/routes/groups.js` | `/groups`, `/groups/:groupId/key-manifest` |

**Two read-response POST paths** are separately listed, not a blanket POST
block: `/encrypted-download/:filename` (returns decrypted file bytes) and
`/audit/export` (returns JSON/CSV private audit data). In contrast,
`GET /audit/export` is a 405-only refusal and remains untouched.
Likewise `POST /folders`, `PUT /file-access` and other mutations are not
intercepted by this *read-egress* fence. Backup create/restore job mutations
are left to the separate worker, even though the *read/download* egress is
denied here.

## Genuine failure and regression evidence

The combined test uses a throwaway child `server.js` with actual
`/auth/login` JWT cookie sessions for Alice (admin) and Bob, distinct
passwords, Alice-owned folder/file ACL, a quarantine entry and pending upload.
Crucially it creates production-format **AES-256-GCM server-key encrypted**
bytes from a disposable 32-byte master key and tests the real
`/encrypted-download/:filename` decrypt-and-send route, not a mocked
handler or an invented failure.

On unprotected base `c5c09513`, with **strict enabled**, authenticated
GETs to private folder/ACL/file/encryption/pending/admin inventory and
module-registered read routes responded with HTTP 304 to conditional
requests, instead of 503. A real POST encrypted download returned
**HTTP 200 with Alice's exact decrypted plaintext**, despite strict cutover.
This is a genuine *strict-mode downgrade*, not a normal legacy ACL bypass.

After the fix, all scoped GET/HEAD with conditional or Range request headers
and the two POST read exports return 503/no-store before bytes are sent;
an anonymous request remains 401. With the strict switch **OFF**, Alice
still reads her actual private folder, ACL and encryption metadata, pending
and quarantine records, decrypts the exact original AES-GCM bytes, and Bob
is still forbidden by ordinary ACL. `POST /folders` remains 201.

## Not a production security authorization

- There is **no** independently verified immutable owner/account/object
  mapping, externally trusted signer, retained off-host monotonic
  `ever_enrolled` floor, physical custody, trusted owner-negative
  membership proof or signed read lease here.
- The source still uses **route enumeration**, not a verified exhaustive
  cutover architecture. A newly added route or another read-response POST
  could evade it until separately tested/reviewed.
- This work intentionally does **not** edit Sync/WebDAV handlers,
  anonymous /share/open, realtime WebSocket, unrelated health/auth,
  background jobs or other worktrees. No production deployment or
  permission to merge follows from these tests.
- Static/OPTIONS metadata-only 204s are not a protected-content release and
  are not changed.

Focused validation:

```sh
node --test test/issue-65-w145-authenticated-http-egress-fence.test.js \
  test/issue-65-w145-supplemental-authenticated-metadata-egress.test.js
```
