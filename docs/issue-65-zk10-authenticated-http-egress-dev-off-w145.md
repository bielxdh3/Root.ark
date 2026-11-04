# Issue #65 — authenticated legacy HTTP egress fence (W145, DEV-OFF only)

## Scope and route order

Experimental `ROOTARK_ZK10_SYNC_CUTOVER_STRICT` uses the **existing** interpretation:
trimmed empty string, `0`, or `off` disables it; other values enable it.
There is **no** production owner/account cutover authority bootstrapped into
`server.js`. When enabled, an early middleware after JWT `authenticate`
construction, **before** the legacy handlers, returns HTTP **503**,
`Cache-Control: no-store`, `ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE`.
Missing/invalid JWTs continue to return **401**.

The closed set is read-only **GET and implicit HEAD**:

| Route (in legacy registration order) | Legacy content at risk |
| --- | --- |
| `/files/search` before `/files/:name` | Search result metadata |
| `/files/:name` | Optimized attachment stream, Range, conditional response |
| `/list` | Folder file inventory |
| `/versions/:filename` | Versions and action history metadata |
| `/download/:filename/v/:version` | Historical version stream |
| `/history` | Action history metadata |
| `/preview/file/:scope/:name` | Inline preview stream |
| `/preview/text/:scope/:name` | Preview text JSON |

The fence executes before conditional GET/HEAD freshness processing or the
legacy stream handler. It rejects even missing-file paths in this closed set,
so an anonymous requester cannot infer content through status: a JWT is
validated first. The real-process regression seeds Alice's private bytes and
metadata, logs Alice and Bob in via `/auth/login`, and checks GET/HEAD,
conditional headers and Range. Unauthenticated access remains 401.

## Deliberate non-goals and security boundary

- **DEV-OFF / nonauthorizing** transitional denial only; the default mode
  retains existing route behavior and ACLs. This is not a ZK migration, not
  server proof of `never_enrolled`, and not a production cutover GO.
- No signed external immutable account/owner mapping, trustworthy retained
  off-host monotonic cutover floor, real owner-authorized legacy lease, or
  external physical custody is attached here. JWT session != owner evidence.
- POST `/versions/:filename/initialize`, all other legacy mutations and
  independent paths are intentionally outside this **read egress** slice.
  In particular W146 anonymous `/share`/`/open`, W148 realtime WebSocket,
  W147 backup ZIP/jobs, Sync and WebDAV are unchanged.
- Only the enumerated legacy authenticated paths are covered. Other
  authenticated metadata or payload routes may still need dedicated
  inventory, tests and independent authority before production.
- An unrelated OPTIONS/static 204 response is not confidential-data
  authorization and is not changed by this GET/HEAD fence.

## Reproduction

```sh
node --test test/issue-65-w145-authenticated-http-egress-fence.test.js
```

The test is RED on base `913fb8524400aa0cd6a10c3f62c34238982f5832`:
strict Alice GET `/list?folderId=root` returned HTTP 200 containing her
private filename/metadata; conditional `/files/search` returned 304 instead
of fail-closed 503. With the deny-only fence the same authenticated requests
return 503; default OFF still returns Alice's allowed content and denies Bob
under the original ACL.
