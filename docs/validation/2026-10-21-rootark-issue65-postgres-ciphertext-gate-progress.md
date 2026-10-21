# Root.ark #65 — physical ciphertext writes inside disposable PostgreSQL gate laboratory

**Date:** 2026-10-21
**Starting HEAD:** `7ccfacd`
**Status:** TEST-ONLY PARTIAL; NOT a Root.ark production feature or approved provider selection

## Purpose and boundary

The previous Packet B lab used `allow_simulated_io` to return `ALLOW_SIMULATED_ONLY` when a permit/effect matched an OPEN head. That did **not** write a byte, so it could not demonstrate storage-side linearization. This milestone adds a **real PostgreSQL `bytea` ciphertext chunk write** in a disposable test database, guarded by the same transactional head lock as CAS `reserve_operation`.

`p65_lab.write_ciphertext_chunk` accepts one existing active effect, its exact account/compartment/keyring, expected revision/digest/epoch and fencing generation, a bounded object/chunk identity, and **1–1,048,576 bytes of synthetic ciphertext**. In a single PostgreSQL transaction, it:

1. Locks the authoritative scope head `FOR UPDATE`, then the existing effect; rejects unknown/mismatched scope/effect or stale revision/digest/epoch/generation.
2. Refuses writes unless `gate_state = OPEN` and effect `state = ACTIVE`; a real CAS reservation to PENDING closes the write gate under the exact same head lock.
3. Inserts immutable bytes into `ciphertext_chunks` once per scoped object/chunk index. An identical same-effect replay reports `CHUNK_REPLAY_UNCHANGED` without modifying the stored bytes; changed data or a different effect reports `CHUNK_CONFLICT`.
4. Leaves direct table reads/mutations unavailable to the `p65_gate` PostgreSQL role: access is through an allowlisted SECURITY DEFINER routine only.

## Adversarial evidence

The new tests were **RED** before the SQL routine existed: both physical-write and cross-session cases failed with `function p65_lab.write_ciphertext_chunk(...) does not exist`; the initial lab cleanup removed only its own labeled disposable container and volume. After implementation, real PostgreSQL exercised physical byte retention, unchanged replay, collision, wrong worker/generation/scope and oversized payload rejections, denied direct table access, and no post-reservation write.

The second test holds a physical chunk write uncommitted in PostgreSQL session A and simultaneously starts CAS `reserve_operation` in separate session B; it observes session B waiting for the same database row lock. After A commits, B closes the gate to PENDING, and a further chunk write is denied. The third test kills a database backend while it holds a completed but **uncommitted** chunk write and asserts PostgreSQL rolls back its bytes; the gate is available to a subsequent legitimate reservation. These tests use only random disposable database identities and synthetic ciphertext.

**Verified disposable PostgreSQL run:** `node lab/issue-65-packet-b/run-postgres-lab.js` exited **0** after the new disconnected-writer test, with **13/13 passing tests on Windows Node and 13/13 on WSL Node**, zero failures or skips in either provisioned lab run. The runner also executed its two pre-existing unsafe RED negative controls as expected, reinstalled the SQL schema between runs, and removed its own labeled container and volume after verifying their identities. Evidence log: `rootark_pg_physical_crash_green_20261021.log` in the host temporary directory. Earlier pre-implementation RED evidence is in `rootark_pg_physical_red_20261021.log`. No production database was accessed.

## What is *not* proved

- This is a **single PostgreSQL instance**, not a real shared GateAuthority deployed across independent operators, hosts, failure domains or status/witness roots. PostgreSQL transaction ordering on one database is not a distributed consensus deployment.
- The application does not call these SQL functions. Current Root.ark upload/download, chunk upload, WebDAV, backup/restore, sync, local disk, S3 and Google Drive paths still bypass this experimental gate. Their existing behavior is preserved; no real files were read, migrated, encrypted, deleted or overwritten.
- No secure physical **network egress** (already buffered bytes, per-chunk authorization/stream termination), worker stop attestation, genuine signed device auth, cryptographic object-to-effect binding, versioned wire proof, remote CAS/status verification, external audit, long-term storage bounds or independent rollback resistance is provided by this experiment.
- A compromised application/gateway or database administrator can bypass assumptions of the laboratory role isolation. This is **not** a claim of Zero-Knowledge production security, revocation of offline copies, or completion of issue #65.

The experiment can inform a later selected, independently operated backend and a provider-neutral interface. Such an interface, physical stop protocol and actual protected content and storage integration must be implemented, independently reviewed and tested before release.

## Independent review and repository-wide test snapshot

- An independent, READ-ONLY bounded reviewer found **no confirmed P1/P2** in the new SQL physical-write function, role permissions or the three new adversarial tests. The reviewer did **not** separately provision/rerun the Docker lab; the Windows/WSL 13/13 counts above are the primary execution evidence.
- `npm run validate:syntax` checked **298 files with 0 failures**; `npm run validate:artifacts` and `git diff --check` exited 0 (with the pre-existing line-ending conversion warning on a lab SQL file).
- `npm test` returned **1,829 total, 1,757 passed, 0 failed, 72 skipped, exit 0**, log `rootark_issue65_pg_physical_full_20261021.log` in the host temporary folder. **Caveat:** a separate actor was concurrently adding untracked shared GateAuthority files and changing `package.json` / `package-lock.json` in the same worktree. The broad run therefore is not guaranteed to represent an immutable exact-commit snapshot, and skipped opt-in tests are not passed integration checks. None of those concurrent changes was modified, staged or committed as part of this milestone.
