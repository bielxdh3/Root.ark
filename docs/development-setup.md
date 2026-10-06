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

With no existing users, startup fails closed unless a valid seed or explicitly enabled development defaults are configured. For a clean install, prepare `data/users.json` with seed users whose usernames are unique after trimming and lowercasing, and whose passwords are bcrypt hashes with a cost of at least 10. Set `ROOTARK_BOOTSTRAP_USERS_FROM_SEED=true` for the one-time import; production requires this explicit opt-in. Remove the opt-in after the seed has been imported; the seed file is not a substitute for protecting local credentials.

Disposable sample accounts are available only for local development or tests, and only when both `NODE_ENV=development` (or `test`) and `ROOTARK_DEV_BOOTSTRAP_DEFAULTS=true` are set. These accounts are local-only and must never be used for a deployment. Do not enable this option in production.

The seed import and local-default opt-in are separate paths: production requires an explicit seed import, while sample accounts require the development/test environment and their own explicit opt-in.
