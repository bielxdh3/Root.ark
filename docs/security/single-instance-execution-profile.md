# Root.ark R2 — supported single-instance execution profile

**Engineering scope:** one Node.js application process, one host, a reliable local staging volume. This is a reviewed configuration target, **not** a claim that an external server or production deployment was tested or approved. Multi-host, multi-replica and shared-user deployment are outside this profile.

## Minimal configuration

| Boundary | Required choice | Why |
| --- | --- | --- |
| Application | `NODE_ENV=production`; exactly one active Node process; `ROOTARK_RESTORE_INSTANCE_COUNT=1` | Auth throttling, TOTP replay, login challenges and other state are process-local; the instance count is an operator declaration, not discovery |
| Authentication | New private `JWT_SECRET` (32+ strong characters), securely hashed non-sample users, explicit TOTP policy | Startup already fails closed on invalid secrets, sample credentials or insecure production cookies |
| Browser ingress | HTTPS at a reviewed proxy; production `Secure` cookies; `TRUSTED_PROXIES` only for actual trusted proxy addresses | The proxy must strip untrusted forwarding headers and prevent direct public access to the origin |
| Chunk staging | `CHUNK_UPLOAD_STORAGE_TOPOLOGY=single-host-local-volume` only when topology is confirmed and the four mandatory per-account/system byte/entry quotas are sized | Unsupported or ambiguous staging stays disabled rather than risking writes; see [development setup](../development-setup.md#chunk-upload-staging-capacity) |
| Upload rate limiter | **Default** `UPLOAD_CHUNK_RATE_LIMIT_STORE=memory` for exactly one process. `sqlite` is an existing same-host option, not a multi-host solution | Both enforce the per-account sliding window before Multer; invalid mode now aborts startup instead of silently choosing a weaker store |
| Zero-Knowledge | Protected ZK-1 remains default-off; no migration or cutover without separate owner approval | CI cannot establish external key custody, provider durability or production trust anchors |
| Host filesystem | A service-owned local parent with safe directory ACLs/permissions; no unverified remote/mapped staging or writable ancestors | The existing Windows/POSIX admission guards remain mandatory; never relax them to make a test fixture start |

For a **single process**, the existing in-memory chunk limiter is sufficient; adding Redis, a coordinator or a distributed rate-limit service would add complexity without serving this supported topology. `sqlite` is available for on-host coordination but does **not** make the whole application multi-process safe. Do not run multiple instances simply because a shared chunk limiter exists.

## Acceptance before any deployment

1. Verify the actual process count, host volume, file permissions and ingress path, including any reverse proxy, on the intended environment. No current CI test discovers real replicas.
2. Confirm production startup fails for missing/weak secrets, insecure cookies, invalid rate-limit store and published sample credentials. Use disposable users only for tests.
3. Check `/ready`, login/TOTP, HTTP responses and client-origin behavior over the actual HTTPS proxy; HSTS is only emitted for trusted HTTPS requests.
4. Confirm authenticated chunk uploads respect account limits, return `429` and `Retry-After`, and create no denied-request staging artifacts; verify quota and timeout cleanup without removing accepted resumable chunks.
5. Recheck `npm audit --omit=dev` against the exact production lockfile when releasing. On 2026-11-06 it reported **0 advisories**; the previously tracked `sprintf-js` advisory [GHSA-hp3w-g68c-fv3c](https://github.com/advisories/GHSA-hp3w-g68c-fv3c) was **withdrawn by GitHub on 2026-10-22**. The `mammoth → argparse → sprintf-js` packages remain in the dependency tree, so the bounded Mammoth library-import tests are still useful; withdrawn status is not a blanket safety proof or a reason to disable exception handling.

## Evidence boundaries

- Already merged: active HTML/SVG protections and HTTP/browser security headers (#207), async credential/crypto hot paths (#220), bounded Mammoth import-boundary tests (#223), and local/shared SQLite upload-rate stores.
- This wave adds an invalid-mode fail-closed regression in `test/issue-94-sqlite-rate-store.test.js`; normal test and hosted CI results must be recorded against the exact commit, not inherited from previous PRs.
- The local Windows test volume currently has untrusted-principal permissions on ancestors; isolated server fixtures correctly fail before binding. **Do not weaken that guard or treat an ACL admission failure as an application vulnerability.** Hosted Windows/Linux CI is a separate gate.
- Issue #203 retains deployment-specific HTTP/concurrency acceptance; its former moderate advisory was withdrawn and is no longer an active `npm audit` finding at this HEAD. Issue #94 retains deployment topology acceptance. **Neither should be closed as fully proved by this document alone.** No production deployment, release, or global ZK enablement is authorized.
