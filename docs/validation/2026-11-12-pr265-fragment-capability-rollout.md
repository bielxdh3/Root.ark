# PR #265 — Fragment capability rollout and security boundary (Draft)

**Status: NO-GO for production, deploy or merge.** This document records the
local implementation contract and the independent deployment dependencies;
passing disposable JSON/SQLite tests is not an authorization to enable it.

## Canonical self-hosted origin

- Operators MUST configure `ROOTARK_CAPABILITY_PUBLIC_ORIGIN` to a dedicated,
  preapproved `https://` origin serving the same self-hosted Root.ark backend.
  It must not reuse the former public-link hostname that issued capability
  bearer tokens inside request paths or cookie names. No cloud provider is
  required. Production without this variable fails closed on new capability
  issuance and exchange; direct loopback HTTP is only for disposable tests.
- Configure HTTPS and the trusted reverse-proxy boundary correctly. Validate
  its forwarded protocol and Host allowlist; do not expose direct HTTP from
  the public network. Exclude `Cookie`, `Set-Cookie`, credential-bearing JSON
  request bodies, and raw fragments from reverse-proxy/WAF/application logs.
  HTTP fragments are not sent in request targets; browser extensions and XSS
  before `history.replaceState` remain privileged local threats.
- Existing capability links of the form `/share/C...` must be reissued as
  `/share/c#C...`. Old uppercase-bearer pathname routes deny; legacy lowercase
  48-hex public shares remain separate and supported.
- Before rollout, determine whether the old capability implementation was
  ever exposed. Revoke and reissue any potentially logged capabilities, purge
  affected access/header logs, and expire historical cookies with appropriate
  same-origin controls. A first request carrying a browser's preexisting
  token-bearing Cookie header cannot be retroactively sanitized by the app;
  the migration response clears the legacy names on subsequent requests.

## Session, revocation and storage

- The browser exchanges the bearer only via same-origin JSON POST, removes
  the fragment from the address bar and uses a public random routing alias
  plus an independent, hashed 256-bit secret in an HttpOnly SameSite=Strict
  cookie. Alias alone grants nothing. Sessions expire after at most five
  minutes and cannot outlive the underlying grant.
- After session expiry/reload, users must reopen the **original** fragment
  link. The browser does not persist the bearer in Web Storage or grant alias
  sessions the power to reconstruct the original long-lived secret. QR
  generation requires explicit original fragment possession in a POST body.
- Production capabilities require the self-hosted transactional SQLite
  repository. JSON mode is deliberately allowed only under `NODE_ENV=test`
  for isolated fixture coverage; it is **not** safe for multiprocess
  revocation because whole-map writes have no cross-process CAS/tombstones.
- An exchange updates ONLY the matching active capability row under an
  immediate SQLite writer transaction, merging currently active session
  aliases from the latest row. Never use the legacy `savePublicLinks()`
  whole-map reconciliation for exchange: a stale snapshot can otherwise
  revoke another newly created link or discard concurrent cookie sessions.
- Revocation is authenticated/CSRF-protected and takes the capability bearer
  in the JSON body, never the request target. Resource generation is bound
  to inode metadata including change time (`ctimeMs`); previously issued
  version-1 bindings fail closed and must be reissued. The change-time check
  is a conservative local-filesystem fence, not an independently attested
  immutable-content commitment.

## Mandatory remaining release gates

- Independent SOURCE review and GH formal approval of the exact final SHA.
- Full hosted Windows Node22 release/CI, Ubuntu, CodeQL, and all applicable
  public-share security suites, including disposable JSON and SQLite mode.
- Production-like dedicated-host/TLS/reverse-proxy configuration test, CSP
  browser test, restart/revocation and multi-process authorization checks.
- No RootSession, ZK authority or production promotion inferred from the
  test fixture, and no merge or deploy without separate authorization.
