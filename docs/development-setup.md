# Local development setup

Root.ark loads values from `.env` at startup when that file is present. Copy `.env.example` to `.env` and set a private `JWT_SECRET`; never commit `.env` or other local secrets.

Generate a fresh secret and start the application:

```powershell
$env:JWT_SECRET = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
npm start
```

```sh
JWT_SECRET="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')" npm start
```

Set `PORT` separately if a port other than the default is needed.

## First user bootstrap

With no existing users, startup fails closed unless a valid seed or explicitly enabled development defaults are configured. For a clean install, prepare `data/users.json` with seed users whose usernames are unique after trimming and lowercasing, and whose passwords are bcrypt hashes with a cost of at least 10. Set `ROOTARK_BOOTSTRAP_USERS_FROM_SEED=true` for the one-time import in every environment. Without that explicit opt-in, startup fails before creating the local users file. Remove the opt-in after the seed has been imported; the seed file is not a substitute for protecting local credentials.

Disposable sample accounts are available only for local development or tests, and only when both `NODE_ENV=development` (or `test`) and `ROOTARK_DEV_BOOTSTRAP_DEFAULTS=true` are set. These accounts are local-only and must never be used for a deployment. Do not enable this option in production.

The seed import and local-default opt-in are separate paths: seed import always requires its explicit opt-in, while sample accounts require the development/test environment and their own explicit opt-in. Authentication throttles, login challenges, and TOTP replay state are process-local. Run exactly one application process; startup rejects `ROOTARK_RESTORE_INSTANCE_COUNT` values other than `1`. This setting is a declaration, not replica discovery, so deployment configuration must also prevent an unreported second process. Multi-process authentication remains unsupported until shared transactional auth state is implemented.

## Reverse proxy and client IP

Leave `TRUSTED_PROXIES` unset when clients connect directly. When a reverse proxy is used, list only the explicit IP addresses or CIDR ranges for trusted proxy peers in the request chain, including the immediate socket peer and any expected intermediate proxy hops; do not use a hop count or a catch-all range. Express uses this configured chain to derive the client IP and forwarded protocol used by authentication throttles, security audit attribution, WebSocket origin checks, and origin-sensitive share actions. The proxy chain must remove or safely replace caller-supplied forwarding headers, and the origin network must prevent untrusted clients from reaching the app around the proxy. Validate the actual multi-hop chain end to end. If Cloudflare is in the path, follow the current [browser session and proxy trust model](security/browser-session-threat-model.md), restrict origin ingress to the intended Cloudflare ranges, and recheck Cloudflare's published ranges when the topology or allowlist changes. Repository configuration cannot verify a live deployment's ingress.

The raw WebSocket upgrade is guarded before `101` and resolves upgrade-rate and concurrent-connection budgets through the same configured trust function as Express. Direct untrusted peers are keyed by their socket address; across a configured proxy chain the nearest untrusted forwarded hop identifies the client, while caller-supplied prefixes farther to the left are ignored. Ensure proxies strip, replace, or safely append `X-Forwarded-For` as described above. These limits are process-local, so multi-instance deployments also need a shared edge limit. Set `NODE_ENV=production` for production so session cookies use `Secure`; production startup rejects `SESSION_COOKIE_SECURE=false`, and `/ready` remains unavailable when the effective session-cookie policy is insecure.
