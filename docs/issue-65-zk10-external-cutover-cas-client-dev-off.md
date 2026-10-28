# Issue #65 / ZK10 — operator CAS / CURRENT client protocol (DEV-OFF)

Status: **NONAUTHORIZING PROTOCOL ONLY / PRODUCTION NO-GO**.
Base: local reviewed DEV-OFF candidate `958556cb6a4093f42864a0db75581243a4e52f4b`,
descended from published #236 `741fdcf6ce30f8b4228bbe92d7a24d812740507d`.

## Scope and seams

`src/services/zk10ExternalOwnerCutoverCasClient.js` exports only
`createZk10ExternalOwnerCutoverCasClient(config)`. No server, signing private
key, database schema, migration, production route, Docker service, socket,
issuer, TLS fixture, or cutover-enabling environment flag is created.

The caller supplies an externally pinned immutable 16-byte legacy account UUID,
canonical ZK account UUID and Ed25519 **owner public key**, separate operator
Ed25519 **signing public key**, operator host ID, TLS certificate fingerprint
and the already independently retained exact minimum:

```text
{sequence, headDigest, enrollmentRoot, physicalDigest,
 everEnrolled, ownerGeneration, ownerCutoverDigest}
```

The caller also supplies `transport.exchange(path, body)`, explicitly
identified by its expected operator host ID and TLS fingerprint. **These
properties only check that configuration agrees; they do not implement TLS
or independently authenticate a network peer.** A future operator-supplied
transport implementation must verify server certificate/hostname, trusted
CA, mTLS client role, certificate fingerprint, key custody, authenticated
endpoint, strict timeouts, request size and remote reachability before it
can be considered a real physical transport. No such implementation or
external authority is part of this slice.

The client requests `/v1/zk10/current` with a fresh unpredictable 32-byte
challenge, immutable account UUID, immutable server identity digest and
minimum head. The signed operator CURRENT must match the challenge/account/
identity, a contiguous signed HEAD chain descending from the exact retained
minimum, fresh bounded issued/expiry times, physical digest, enrollment root
and owner generation. A 256-level sparse Merkle membership/nonmembership
proof is validated by the existing `rootark-zk10-account-cutover-v1` primitive.
For `protected_enforced`, the owner statement must additionally validate
under the independently pinned owner key and account IDs. A signed
`never_enrolled` classification may never override a previously retained
`everEnrolled` floor. Equal-sequence conflicting heads are denied.

`submitCutover({ownerStatement, leaseId, fencingEpoch, leaseExpiresAtMs})`
accepts only an exactly owner-signed **initial** `protected_enforced` statement
with contiguous generation, no compatibility grants and matching account IDs.
An owner statement older than five minutes or more than one minute in the
future is rejected even when the signature is valid.
It demands a fresh CURRENT that exactly matches the retained minimum and
revalidates the bounded lease expiry **after** any readback delays. CAS intent
on `/v1/zk10/cutover/cas` carries the signed owner statement, immutable
account/identity, expected full floor, lease ID, fencing epoch, expiry and
fresh challenge. A signed operator receipt must bind those identifiers and
the expected generation **and exact lease expiry**. Whether the transport returns a valid receipt,
a partial packet, a timeout or a lost ACK, the request never grants access;
the instance is marked `uncertain` before the outbound request.

`reconcile()` performs a **separate signed CURRENT challenge**. The result is
`observed_protected` only when one contiguous successor head includes the
same owner-signed cutover and a valid Merkle membership. In addition, the
client requires a **separate**, new-nonce signed
`/v1/zk10/cutover/readback` receipt that binds the original lease ID,
fencing epoch, owner digest and expected HEAD to that exact successor HEAD
and physical digest and the original signed lease expiry. A substituted or
replayed operation readback quarantines.
Even this two-step readback is explicitly
`authorizesProductionCutover: false`. A still-old head is ambiguous because
the CAS may be delayed; no automatic resend occurs. A forged/forked/unknown
readback quarantines the instance. The returned head cannot be installed as
the new minimum by this client: an independently controlled operator must
validate and durably retain that new minimum out of band.

The client currently supports **only initial cutover, owner generation 1**.
Owner rotation, later protected generations, scoped migration grants,
revocation, rollback of independent custody, multi-owner consensus and
indefinite historical retention require separate protocols. A configured
`leaseId` and `fencingEpoch` are request parameters, **not proof** that
any authority reserved or physically enforces a lease.

## Missing production prerequisites

An actual independent operator must implement and prove an authenticated
CAS + signed CURRENT service, owner-key enrollment/rotation trust, durable
append-only history and irreversibly retained `everEnrolled` set. Its account
CAS must serialize lease acquisition, physical active-I/O drain and owner
cutover at one account-wide linearization point, with independent monotonic
head survival after application/PG/witness snapshots and physical power loss.
The `physicalDigest` here is a signed value, **not a validated PG18 STOP
receipt**; a future protocol must verify and commit an independently
attested stop/egress proof. PR234 PG18's scope-key `FOR UPDATE` protects
one compartment/keyring and cannot be reused as an account-wide lock.

The normal `server.js` bootstrap does not use this client or impose a ZK10
no-downgrade floor. Until all legacy Sync/file/search/preview/download/
WebDAV/backup/restore/background/WS and anonymous share paths enforce one
physical account lease, `protected_enforced` cannot be promised. Anonymous
share tokens require a trusted object/revision-to-immutable-owner UUID mapping.
Operator-owned real hosts, independently controlled signing keys, TLS/mTLS
credentials, append-only retained floor, crash/partition/power-loss testing and
complete corpus/disposition proof remain unavailable. No external service,
host or production key was accessed or provisioned.

## Disposable test boundary

`node --test test/issue-65-zk10-operator-cas-client.test.js` uses only
ephemeral Ed25519 wire vectors, a deliberately injected **in-memory response
function** and no HTTP server, Docker, database or production credential.
Tests cover fresh signed readback, bad challenge, swapped account/identity,
same-sequence fork, stale owner or generation, rollback below retained
protected floor, ACK loss, malformed partial CAS response, no automatic
retry, conflicting injected host pins, forbidden production flags, concurrent
submissions, signed ACK requiring follow-up CURRENT, and lease expiry while
preflight is delayed, replayed/swapped operation-specific readbacks and
stale but valid owner signatures. Passing verifies only local protocol decisions; it
provides zero evidence of off-host operational custody or real physical
fencing.
