# Browser session threat model

## Scope and non-scope

This document covers Root.ark browser login/logout, the `rootark_session` HttpOnly cookie, CSRF handling, authenticated HTTP requests, the authenticated `/auth/session.js` identity endpoint, authenticated WebSocket upgrades, current-user/session-version revalidation, disabled or deleted users, and permission freshness. The tracked frontend does not load `/auth/session.js`; the current session UI uses `/auth/me`. It excludes WebDAV Basic Auth, sync-client bearer authentication (a separate trust boundary), public-share routes, 2FA, password-reset design, and unrelated application features.

## Protected assets

- Session confidentiality and account identity.
- Current authorization state and administrative privileges.
- Integrity of cookie-authenticated state changes and realtime events.
- User files and metadata reachable through authenticated routes.

## Actors and attacker capabilities

- A normal user or administrator holds a browser session.
- An unauthenticated remote attacker can submit login requests and send cross-site requests from a malicious website.
- An attacker with JavaScript execution in the Root.ark origin can read non-HttpOnly browser state and issue same-origin requests.
- An attacker may possess a stolen session cookie or separate bearer credential.
- A reverse proxy or deployment can misstate protocol, Host, or forwarded headers.

## Trust boundaries and data flows

1. `POST /auth/login` checks the current enabled user and password, signs an eight-hour JWT containing username and `sessionVersion`, sets `rootark_session` as HttpOnly/Lax (Secure in production), and sets a readable `rootark_csrf` token. The shipped login page redirects after success and does not persist the JSON response, although that response currently includes a token.
2. `createAuthenticate` verifies a bearer token or session cookie, then loads the current non-deleted user from the repository, rejects disabled users and mismatched session versions, and derives role and permissions from that current user. Cookie-authenticated non-safe requests additionally require a matching CSRF cookie/header and, when present, a matching Origin. The legacy authenticated `GET /files/:name` read also rejects cookie-authenticated requests with a mismatching Origin, Fetch Metadata other than `same-origin` or `none` (including `same-site`), a mismatching Referer when Fetch Metadata is absent, or no Origin/Fetch Metadata/Referer at all. This source guard runs before file lookup, cloud hydration, or download/denial audit writes; same-origin downloads and address-bar navigation remain supported. Bearer API requests are not subject to browser metadata checks.
3. `/auth/session.js` is authenticated, no-store JavaScript that exports only current username, role, and permissions after escaping `<`. No tracked page includes this endpoint or `auth-bootstrap.js`. A bare classic script request uses HTML's No CORS state, which includes credentials; a same-site, cross-origin page can therefore execute this response without CORS approval. A disposable browser probe from a different loopback port reproduced disclosure of the identity and permission metadata (not the session credential). The route sets `Cross-Origin-Resource-Policy: same-origin` so browsers block cross-origin No CORS embedding while same-origin consumers remain supported, and rejects any supplied `Origin` that differs from the expected application origin before returning JavaScript. The Origin check also denies credentialed CORS loads if a deployment proxy adds permissive CORS response headers. The deployment proxy must preserve the CORP response header for bare-script requests and must not rewrite the request Origin. See the [HTML Standard](https://html.spec.whatwg.org/multipage/urls-and-fetching.html#cors-settings-attributes) and [Fetch Standard](https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header).
4. `POST /auth/logout` is authenticated and clears both cookies for the current browser. It does not globally revoke independently copied JWTs unless a server-side identity change changes their generation. User updates increment `sessionVersion` when password, role, permissions, or disabled state changes; deleted users are absent from `loadUsers()`. JSON mode retains only a Git-ignored per-username generation ledger containing version metadata; SQLite retains `session_version` on the soft-deleted row. Recreating a deleted username receives a greater generation than its prior identity.
5. A `/ws` upgrade obtains `rootark_session` only from cookies, requires `Origin` to equal the expected request origin, then verifies the token and current user/session version before attaching `socket.user` with its internal expiry instant. No bearer credential is used in the WebSocket URL.

## Security invariants and assumptions

- Shipped browser pages must not store session credentials in browser storage or place them in URLs. The login response token must likewise not be retained or sent by browser code.
- Cookie-authenticated state-changing HTTP requests require matching CSRF evidence; bearer authentication is a separate API-client boundary.
- Cookie-authenticated file reads are also source-checked because `SameSite=Lax` permits cookies on cross-site top-level safe navigations. The `/files/:name` guard requires at least one source header and validates supplied Origin, Fetch Metadata, or (when Fetch Metadata is absent) Referer; headerless cookie clients are denied. Bearer API clients without browser metadata remain supported, and `Sec-Fetch-Site: none` address-bar navigation remains supported.
- Each authenticated HTTP request resolves the current server-side user, so disabled, deleted, session-revoked, and recreated identities with stale generations fail on their next request. Before processing the next authenticated WebSocket message or sending the next authenticated realtime event, the server rejects a missing or elapsed JWT expiry, reloads the current user, and compares enabled/deleted state and `sessionVersion` with the socket identity.
- Server-side permissions, not `ROOTARK_AUTH` UI state, decide authorization. A failed active-WebSocket freshness check does not process the pending message or deliver the pending event, and closes the socket with `1008` and `Sessao revogada` for revocation or `Sessao expirada` for JWT expiry; no idle-connection polling is required.
- WebSocket upgrades must validate the expected Origin and current session before any protected realtime event is sent.
- `JWT_SECRET`, session cookies, CSRF values, and credentials must not be logged or tracked. `JWT_SECRET` must remain protected and at least 32 characters.
- Production relies on HTTPS termination and `NODE_ENV=production` for Secure cookies. Production startup fails if `SESSION_COOKIE_SECURE=false`; other HTTPS deployments can explicitly set `SESSION_COOKIE_SECURE=true`, and `/ready` reports false when the effective session cookie would not be Secure. Express `trust proxy` is disabled unless `TRUSTED_PROXIES` explicitly lists trusted peer IP addresses or supported CIDR ranges. Forwarded values from an untrusted direct socket peer are ignored. Configure the actual socket peer address for every proxy hop between the browser and the app; include Cloudflare only when Cloudflare is directly in that path. The parser has an explicit exception for Cloudflare's currently published IPv6 range `2a06:98c0::/29`; configuring it trusts the entire shared range. If Cloudflare is a direct peer, restrict origin ingress to Cloudflare's published source ranges and recheck the [official IP range list](https://www.cloudflare.com/ips/) when configuring and whenever the proxy path or allowlist changes. For each hop, verify that the proxy safely replaces or preserves `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-For`, rather than allowing caller-supplied values to become trusted. Restrict network access to the origin so only the intended proxy peers can reach it. Raw WebSocket upgrades use the same configured trust function to resolve the nearest untrusted client address for per-client upgrade and concurrent-connection budgets; a direct request without a trusted proxy is keyed by its socket peer, and untrusted forwarded headers cannot change that key. The proxy chain must safely remove, replace, or append forwarding headers, and the configured trusted ranges must match the live hop order. These limits are process-local, so deployments with multiple app instances also need an appropriate shared edge limit. The server does not validate the live deployment topology. Browser same-origin behavior and server/database availability are also assumed.

## Residual risks and validation gaps

- The login JSON response still contains a token even though browser pages do not persist it; same-origin JavaScript could read that response.
- HttpOnly prevents direct cookie reads but does not prevent same-origin XSS from sending CSRF-authorized actions with the readable CSRF token.
- The Phase 2.2 closure audit confirms that password, role, permissions, and disabled-state changes all share the `PUT /users/:username` `sessionChanged` decision and persisted generation increment. Focused regression tests therefore use permission removal as representative mutation evidence, while separate tests cover deleted/recreated identities, JSON restart persistence, repeated SQLite recreation, HTTP expiry, and active-WebSocket expiry. The audit also confirms no alternate active-user create/reactivate write path bypasses these controls.
- HTTPS, proxy-header, Host, Origin, or `JWT_SECRET` deployment mistakes can weaken the model. 2FA remains outside this issue #2 scope.

## Validation matrix

| Invariant | Existing evidence | Missing evidence | Smallest next test |
| --- | --- | --- | --- |
| Cookie state changes need CSRF | `test/auth-security.test.js` checks missing/matching CSRF | Cross-origin rejection through the real route | Submit one cookie-authenticated write with a foreign Origin |
| Current users revoke stale HTTP sessions | Focused tests reject disabled/version-mismatched users, an old browser cookie after `manageUsers` removal, deletion/recreation, and an expired browser cookie with `401` from `GET /storage/status`; the Phase 2.2 closure audit reconciles all session-affecting paths | None for issue #2 | Phase 2.3 regression-baseline work |
| Browser pages avoid persisted credentials and WS URL tokens | Focused source test covers browser pages | Login-response token exposure is not tested | Assert the login response omits the unused token before changing behavior |
| WebSocket upgrade uses current cookie session and Origin | Origin helper plus real-WebSocket permission-removal, deletion/recreation, and JWT-expiry regressions; the closure audit traces the shared active-WebSocket freshness boundary | None for issue #2 | Phase 2.3 regression-baseline work |
| Bootstrap identity is safe UI state only | `/auth/session.js` escapes `<`, remains authenticated/no-store, sets `Cross-Origin-Resource-Policy: same-origin`, and rejects a supplied foreign Origin; server authorization reloads user | Route regression asserts the foreign-Origin denial, CORP header, and authenticated same-origin response; a disposable sibling-port browser check reproduced exposure before the fix and confirmed the browser blocks the script after it | Preserve CORP and the client Origin through deployment proxies; reassess before allowing cross-origin consumers |

Repository: bielxdh3/root.ark
Version: 9c6de34187163700015fe04a61880ca85e9600df
