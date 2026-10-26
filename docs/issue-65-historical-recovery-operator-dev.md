# Issue #65: independent historical recovery ACK operator (opt-in)

This is an executable **development integration** for the strict historical
recovery nonce ACK. The witness remains the only signer of its own historical
nonce row and signed READY phase. The separate operator verifies the original
witness Ed25519 READY signature and independent PostgreSQL Ed25519 physical
readback, then commits a provisional ACK, and finally seals the ACK only when
the same stored proof, owner-policy generation and physical timestamp remain
current. The operator supplies the synchronous
`trustedRecoveryNonceAuthority` interface that the witness already requires.

## Provisioning and custody

Operate the server on a separately administered machine/VM under a private OS
user. Provision an operator-owned private directory (0700 on POSIX; protected,
owner-only NTFS DACL on Windows), and a single SQLite filename that **does not
already exist**. The operator process requires exclusive policy authority and
physical access independent of the witness/CAS administrator. The DB uses WAL,
`synchronous=FULL`, `BEGIN IMMEDIATE` CAS and persistent revocation. Keep the
DB and WAL/SHM on durable local storage with an operator-controlled backup and
restore protocol. Do not copy or share the witness's private signing key.

Server config (private JSON file) needs:

```json
{
  "operator": {
    "databasePath": "/operator/private/recovery.sqlite",
    "initialPolicy": {
      "username": "the signed owner username",
      "trustedDevicePublicKeys": { "device-id": "base64url-ed25519-spki" },
      "revokedDeviceIds": []
    },
    "witnessPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "physicalAttestorPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "witnessKeyId": "16-byte-base64url-id",
    "statusKeyId": "16-byte-base64url-id"
  },
  "server": {
    "host": "0.0.0.0",
    "port": 8443,
    "keyPath": "/operator/private/operator.key",
    "certPath": "/operator/private/operator.pem",
    "clientCaPath": "/operator/private/client-ca.pem",
    "witnessClientFingerprint": "AA:...:BB",
    "adminClientFingerprint": "CC:...:DD"
  }
}
```

The PEM values, 16-byte IDs and certificate SHA-256 fingerprints must be
**real provisioned values**; placeholders above are explanatory only. Bind to
an externally reachable interface only behind a restricted firewall. The
operator requires TLS 1.3, CA-validated client certificates, and distinct
exact leaf fingerprints for the witness and policy administrator. The admin
certificate can advance owner policy but cannot finalize or seal ACKs. The
witness certificate cannot revoke policy.

Start once, with an explicit irreversible bootstrap:

```sh
node scripts/zk1-historical-recovery-operator.js --serve /operator/private/server.json --bootstrap
```

Subsequent runs omit `--bootstrap`. The operator refuses bootstrap over an
existing DB and refuses a restart with changed pinned witness/PG public keys
or key IDs. A fresh empty database is **never** a recovery mechanism for a
lost operator disk.

On the witness host, provision a separate private JSON file:

```json
{
  "client": {
    "hostname": "recovery-operator.example.net",
    "port": 8443,
    "keyPath": "/witness/private/witness-client.key",
    "certPath": "/witness/private/witness-client.pem",
    "serverCaPath": "/witness/private/operator-server-ca.pem",
    "serverFingerprint": "AA:...:BB"
  }
}
```

Inject the adapter into the strict witness constructor, alongside its
existing independent PG attestor, owner device policy provider and historical
head pins:

```js
const { createSynchronousRecoveryOperatorClient } =
  require("./src/services/zk1HistoricalRecoveryOperatorHttps");
const trustedRecoveryNonceAuthority = createSynchronousRecoveryOperatorClient(
  "/witness/private/operator-client.json");
// Pass trustedRecoveryNonceAuthority to Zk1WitnessCasAnchorFloor options.
```

The synchronous interface runs a bounded subprocess per call so the witness
receives a confirmed remote HTTPS read/CAS before returning an ACK. Offline,
timeout, certificate mismatch, lost CAS reply or denied/ambiguous finalization
all fail closed. This bridge favors correctness over request throughput; deploy
only for the opt-in strict issuer, measure operator latency, and avoid running
the custodian on the witness host.

## Revocation, crash, and reconciliation

Use a separately provisioned admin client config (same JSON `client` shape,
with the **admin** certificate) to inspect the current monotonic generation:

```sh
node scripts/zk1-historical-recovery-operator.js --inspect /admin/private/client.json
node scripts/zk1-historical-recovery-operator.js --advance-policy /admin/private/client.json 0 /admin/private/new-policy.json
```

The first command shows owner generation and head; replace `0` in the second
with the exact currently expected generation. The policy JSON must contain
`username`, `trustedDevicePublicKeys`, `revokedDeviceIds`. On successful CAS,
the operator increments the generation **and durably quarantines all historical
admissions in the same FULL transaction**. A stale generation is rejected;
previous revocations cannot be undone. Re-enabling historical admissions after
revocation needs a **new, separately reviewed re-provision/recovery protocol**;
there is intentionally no reset or unquarantine API.

If a service or network failure occurs after `compareAndAdvance`, the operator
may hold a newer nonce head while the witness holds signed PENDING. Do not
replay that nonce, reset either database, or infer success from equal heads.
If `finalizeAck` commits but its reply is lost, the operator holds PROVISIONAL
and `loadFinalizedHead` refuses admission until sealing. After a verified seal,
its durable readback survives process restart. The witness's existing
`quarantineFinalizedAck` transition creates a separate monotonic veto for
stale or failed ACKs; all such states require operator-supervised inspection.
`sealAck` rechecks the original signed PG issuance time **inside** the SQLite
`BEGIN IMMEDIATE` transaction, both immediately before the SEALED update and
after that update but before FULL COMMIT. If SQLite lock contention makes the
proof older than 30 seconds, the transaction rolls back to PROVISIONAL and the
nonce remains unusable across restart. Once FULL COMMIT returns, the operator
checks freshness and retained owner/head/proof state again. If the post-commit
readback is stale, it durably quarantines the head and denies the seal ACK.
An operator crash between FULL COMMIT and that final compensating quarantine
remains a distributed ACK ambiguity: a durable SEALED head is evidence of a
fresh **commit**, not proof that the witness received the response. The witness
must still quarantine an interrupted/expired RPC and never infer positive ACK
from an equal historical head alone. No cross-host power-failure atomicity is
claimed.

## Verification and limits

`node --test test/issue-65-historical-recovery-independent-operator.test.js`
exercises original signature/PG validation, altered timestamp rejection,
an actual separate-process SQLite writer lock with virtual 31-second expiry,
after-COMMIT delayed ACK quarantine and durable restart denial,
distinct client identities, real localhost mTLS and child-process bridge,
crash/restart persistence, provisional/SEALED transitions, CAS stale head,
owner generation and revoked/quarantined restart. Local TLS and process
separation do **not** prove off-host custody, independent operator ownership,
multi-host durability, backup restoration, power-loss resistance or rollbacks
of the operator's **own** SQLite snapshot. The system still requires a real
separately operated host, audit-ready backups and independent deployment review.
This does not make PR #228 or Issue #65 production-ready.
