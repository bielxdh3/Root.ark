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
2. `createAuthenticate` verifies a bearer token or session cookie, then loads the current non-deleted user from the repository, rejects disabled users and mismatched session versions, and derives role and permissions from that current user. Cookie-authenticated non-safe requests additionally require a matching CSRF cookie/header and, when present, a matching Origin.
3. `/auth/session.js` is authenticated, no-store JavaScript that exports only current username, role, and permissions after escaping `<`. No tracked page includes this endpoint or `auth-bootstrap.js`. The endpoint emits no credentialed CORS headers; a cross-origin classic script request does not send same-origin credentials by default, and a credentialed cross-origin response cannot be read without the matching CORS headers. This reachability assessment is source/spec based; no dedicated sibling-origin browser test was completed. Reassess if deployment middleware or a reverse proxy enables credentialed CORS for untrusted origins.
4. `POST /auth/logout` is authenticated and clears both cookies for the current browser. It does not globally revoke independently copied JWTs unless a server-side identity change changes their generation. User updates increment `sessionVersion` when password, role, permissions, or disabled state changes; deleted users are absent from `loadUsers()`. JSON mode retains only a Git-ignored per-username generation ledger containing version metadata; SQLite retains `session_version` on the soft-deleted row. Recreating a deleted username receives a greater generation than its prior identity.
5. A `/ws` upgrade obtains `rootark_session` only from cookies, requires `Origin` to equal the expected request origin, then verifies the token and current user/session version before attaching `socket.user` with its internal expiry instant. No bearer credential is used in the WebSocket URL.

## Security invariants and assumptions

- Shipped browser pages must not store session credentials in browser storage or place them in URLs. The login response token must likewise not be retained or sent by browser code.
- Cookie-authenticated state-changing HTTP requests require matching CSRF evidence; bearer authentication is a separate API-client boundary.
- Each authenticated HTTP request resolves the current server-side user, so disabled, deleted, session-revoked, and recreated identities with stale generations fail on their next request. Before processing the next authenticated WebSocket message or sending the next authenticated realtime event, the server rejects a missing or elapsed JWT expiry, reloads the current user, and compares enabled/deleted state and `sessionVersion` with the socket identity.
- Server-side permissions, not `ROOTARK_AUTH` UI state, decide authorization. A failed active-WebSocket freshness check does not process the pending message or deliver the pending event, and closes the socket with `1008` and `Sessao revogada` for revocation or `Sessao expirada` for JWT expiry; no idle-connection polling is required.
- WebSocket upgrades must validate the expected Origin and current session before any protected realtime event is sent.
- `JWT_SECRET`, session cookies, CSRF values, and credentials must not be logged or tracked. `JWT_SECRET` must remain protected and at least 32 characters.
- Production relies on HTTPS termination and correct `NODE_ENV=production` for Secure cookies. Express `trust proxy` is disabled unless `TRUSTED_PROXIES` explicitly lists trusted peer IP addresses or supported CIDR ranges. Forwarded values from an untrusted direct socket peer are ignored. Configure the actual socket peer address for every proxy hop between the browser and the app; include Cloudflare only when Cloudflare is directly in that path. The parser has an explicit exception for Cloudflare's currently published IPv6 range `2a06:98c0::/29`; configuring it trusts the entire shared range. If Cloudflare is a direct peer, restrict origin ingress to Cloudflare's published source ranges and recheck the [official IP range list](https://www.cloudflare.com/ips/) when configuring and whenever the proxy path or allowlist changes. For each hop, verify that the proxy safely replaces or preserves `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-For`, rather than allowing caller-supplied values to become trusted. Restrict network access to the origin so only the intended proxy peers can reach it. The server does not validate the live deployment topology. Browser same-origin behavior and server/database availability are also assumed.

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
| Bootstrap identity is safe UI state only | `/auth/session.js` escapes `<`; tracked pages do not load it; server authorization reloads user | A future consumer or credentialed-CORS deployment could change the cross-origin boundary | Reassess before adding a consumer or enabling credentialed cross-origin access |

Repository: bielxdh3/root.ark
Version: 9c6de34187163700015fe04a61880ca85e9600df
