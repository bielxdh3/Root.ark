# Root.ark #65 — isolated GateAuthority pinned multi-host STOP policy

**Scope:** operator-only local reference; no production deployment or remote
multi-host acceptance. This additive feature preserves the existing single
`stopPinned` option.

## Trusted configuration

`createZk1OperatorPinnedStopHostPolicy({ hosts })` produces an opaque frozen
token backed by a module-private `WeakMap`. The factory requires **at least two
distinct** 16-byte host-key IDs and Ed25519 public keys. Each entry must name
one or more exact scope identities (account, compartment, keyring) and a status:

- `active`: a new supervised strict START is allowed in its configured scopes,
  and historical signed STOP proofs remain verifiable.
- `verify-only`: strict START is rejected; previously recorded STOP proofs may
  be verified for delayed FINISH, recovery and PENDING.
- `revoked`: strict START and historical STOP verification both fail closed.

Host IDs, public keys (SPKI DER), allowed scopes and statuses are copied into
private snapshots. Mutating the caller's original arrays, byte buffers, keys
or status objects cannot change the GateAuthority's policy. Duplicate host
IDs, reused public keys, duplicate scopes, unknown statuses and unbranded
policy objects are rejected. A legacy `stopPinned` and a multi-host policy
cannot be supplied together.

The trusted operator supplies this policy at GateAuthority construction.
Neither HTTP/IPC clients nor owner manifests enroll or rotate hosts. A new
strict START checks the pinned host ID, its *active* state and exact allowed
scope under the PostgreSQL head lock; a supplied worker/host ID is an identity
claim to check, never a source for trusted signing keys. Each supervisor and
independently preflighted STOP recorder must share the same pinned Ed25519
host key. For historical FINISH and PENDING, GateAuthority finds the
admission's recorded `host_key_id` in its operator snapshot, verifies the
Ed25519 signature and exact process, worker, scope and generation binding,
and rejects wrong-key, unknown, out-of-scope or revoked proofs.

## Focused evidence

The new `issue-65-multi-host-pinned-stop-postgres.test.js` verifies:

- private branded policy, deep-copy immutability, duplicate/reused key rejection;
- two separate **simulated** supervisors on the same Windows machine, each
  using a different Ed25519 signer, process epoch and restricted PostgreSQL
  STOP LOGIN, with two actual child-process STOP proofs and FINISH receipts;
- quiescence followed by a restarted GateAuthority accepting both historical
  proofs under an *explicit verify-only* rotated policy and then entering
  PENDING;
- rejection of a wrong public key with a matching host ID, revoked historical
  STOP, unknown host ID, out-of-scope host, verify-only and revoked new START,
  and host-key ID/public-key mismatch.

Executed the existing shared disposable runner with **Node 22.23.3** and the
official **PostgreSQL 18.6** Docker image: **41/41 PASS, 0 failed, 0 skipped**.
The runner confirmed its loopback-only binding and deleted its labeled,
identity-checked disposable container. No production schema was touched.
Earlier single-host and strict mTLS denial tests passed in the same runner.

## Security and deployment boundaries

Two processes running on one machine do **not** establish independent physical
hosts, geographic independence, consensus, distributed witness authority,
quorum, owner-authenticated policy distribution, durable anti-rollback, or
proven crash/partition behavior. PostgreSQL host IDs do not cryptographically
attest a running OS process; the trusted supervisor and independently pinned
STOP signer remain responsible for truthful termination observations.

The gate's SQL credential is still trusted to create admissions. A compromised
gate operator, private signing key, or PostgreSQL administrator is outside this
local proof. The policy does not prove independent physical STOP or durable
quiescence of cloud providers, HTTPS buffers, S3, Google Drive, WebDAV, GET
egress, remote jobs or descendants. No remote deployment, provider migration,
client authorization completion or Zero-Knowledge release is approved.

Next acceptance item: independently operated real hosts, separately provisioned
signers and revocation distribution, explicit multi-host trust/recovery policy,
and observed provider I/O fencing under restart and network partition.
