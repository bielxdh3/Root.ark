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

With no existing users, startup fails closed unless a valid seed or explicitly enabled development bootstrap is configured. For a clean install, prepare `data/users.json` with users whose usernames are unique after trimming and lowercasing and whose passwords are bcrypt hashes with a cost of at least 10. Use distinct, private passwords that are at least 16 characters long. Set `ROOTARK_BOOTSTRAP_USERS_FROM_SEED=true` for the one-time import in every environment, then remove the opt-in. Startup rejects the published sample passwords (`admin123` and `user123`) in every environment except `NODE_ENV=test`, regardless of username pairing. The `/users` create and update routes also reject attempts to set either sample password, and the shared user-save boundary enforces the same rule.

On a clean `NODE_ENV=development` install, enable `ROOTARK_DEV_BOOTSTRAP_DEFAULTS=true` and provide distinct, private passwords through `ROOTARK_DEV_BOOTSTRAP_ADMIN_PASSWORD` and `ROOTARK_DEV_BOOTSTRAP_USER_PASSWORD`. Each must be at least 16 characters long and must not equal either published sample password. Without both secure values, startup fails before creating the local users file. These values are hashed into the local account store; remove the bootstrap environment variables after creation. The predictable `admin`/`user` fixture passwords are available only when both `NODE_ENV=test` and `ROOTARK_DEV_BOOTSTRAP_DEFAULTS=true` are set. Never use test fixtures or development accounts for deployment.

For a production deployment, set `NODE_ENV=production` and import a secure, hashed user seed with `ROOTARK_BOOTSTRAP_USERS_FROM_SEED=true`. Verify the intended secure admin account can sign in, then remove the opt-in and seed file according to your deployment process. Fresh production startup without users remains fail-closed. The listener may be behind a reverse proxy, so loopback binding is not treated as protection from remote clients forwarded by that proxy. Use secure account passwords and restrict origin ingress at the network/proxy layer; a trusted-proxy setting only governs forwarded request metadata and does not restrict who can reach the proxy.

The seed import and local bootstrap are separate paths: seed import always requires its explicit opt-in, test fixtures require `NODE_ENV=test` plus their opt-in, and development bootstrap requires its own opt-in plus both secure passwords. Authentication throttles, login challenges, and TOTP replay state are process-local. Run exactly one application process; startup rejects `ROOTARK_RESTORE_INSTANCE_COUNT` values other than `1`. This setting is a declaration, not replica discovery, so deployment configuration must also prevent an unreported second process. Multi-process authentication remains unsupported until shared transactional auth state is implemented.

## Reverse proxy and client IP

Leave `TRUSTED_PROXIES` unset when clients connect directly. When a reverse proxy is used, list only the explicit IP addresses or CIDR ranges for trusted proxy peers in the request chain, including the immediate socket peer and any expected intermediate proxy hops; do not use a hop count or a catch-all range. Express uses this configured chain to derive the client IP and forwarded protocol used by authentication throttles, security audit attribution, WebSocket origin checks, and origin-sensitive share actions. The proxy chain must remove or safely replace caller-supplied forwarding headers, and the origin network must prevent untrusted clients from reaching the app around the proxy. Validate the actual multi-hop chain end to end. If Cloudflare is in the path, follow the current [browser session and proxy trust model](security/browser-session-threat-model.md), restrict origin ingress to the intended Cloudflare ranges, and recheck Cloudflare's published ranges when the topology or allowlist changes. Repository configuration cannot verify a live deployment's ingress. Neither trusted-proxy configuration nor loopback binding prevents remote access when a reachable proxy forwards requests; published sample passwords are therefore prohibited outside test regardless of the listener path.

The raw WebSocket upgrade is guarded before `101` and resolves upgrade-rate and concurrent-connection budgets through the same configured trust function as Express. Direct untrusted peers are keyed by their socket address; across a configured proxy chain the nearest untrusted forwarded hop identifies the client, while caller-supplied prefixes farther to the left are ignored. Ensure proxies strip, replace, or safely append `X-Forwarded-For` as described above. These limits are process-local, so multi-instance deployments also need a shared edge limit. Set `NODE_ENV=production` for production so session cookies use `Secure`; production startup rejects `SESSION_COOKIE_SECURE=false`, and `/ready` remains unavailable when the effective session-cookie policy is insecure.
