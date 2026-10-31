# Issue #65 ZK10 — live external floor attestation (W170)

Scope: independently attested **legacy admission** at the existing ZK10
account-policy seam. This supplies one missing cryptographic boundary; it is
**not proof of physical custody, production cutover, or route completeness**.

## Security boundary

The legacy account authority can supply its own signed chain and a witness can
sign its corresponding CURRENT. Their signatures do not prove that a third
administrator retains the true monotonic minimum on durable media. A restored
set of their databases can replay an authentic old chain after client restart
if the minimum is supplied by the compromised application.

`createZk10ExternallyAttestedLegacyFence(config)` now requires a third
`independentFloor` mTLS HTTPS peer, including its separately pinned Ed25519
public key and server certificate fingerprint. All three peers must have
distinct endpoints, signing identities and TLS certificate fingerprints.
The existing `createZk10LegacyCutoverFence` remains DEV-OFF compatible and
rejects attempts to supply an unattested extra floor through its arguments.

After the signed owner/nonmembership proof and signed witness CURRENT agree,
the new gate challenges the external custodian on
`POST /v1/zk10/external-floor/current`. The custodian must sign the exact
canonical JSON fields below, prefixed by
`Root.ark/zk10/external-floor-current/v1\0`, with its pinned Ed25519 key:

```
type, sequence, head_digest, enrollment_root, immutable_account_id,
identity_digest, operation, nonce, lease_id, lease_expires_at_ms,
issued_at_ms, expires_at_ms
```

The response is `{"floor": { ...fields, "signature": "base64url" }}`.
The nonce originates from the app's fresh random challenge, the lease comes
from the separate account authority, and every signed floor field must match
the account policy proof before any caller callback runs. Missing, stale,
replayed, conflicting or invalid signed floors fail closed with 503. A
verified `protected_enforced` account remains forbidden with 403. The account
authority's bounded lease must prevent concurrent cutover until callback
completion; the third custodian does **not** replace that transaction fence.
The custodian's signed freshness expiry must cover the entire authority lease,
so a short-lived floor response cannot authorize a longer-running operation.
Both signed witness CURRENT and external custodian CURRENT must carry
`Number.isSafeInteger` millisecond issuance/expiry timestamps within the
bounded local clock interval; the verified expiry on **each** witness must
cover the authority lease. A correctly signed string such as `"invalid-date"`
cannot be used in JavaScript relational comparisons (it coerces to `NaN`,
causing both range comparisons to evaluate false). Malformed dates, including
numeric strings, `null`, fractional milliseconds and expired leases, deny
before the legacy callback is invoked. The independently pinned ZK10 operator
CAS client already validates its signed CURRENT timestamp types; no production
authority was enabled by this change.

## External operator obligations before any production enablement

- Provision the floor custodian on a separately administered self-hosted
  machine/storage with its signing private key outside the application,
  account authority and witness. Verify real topology and access isolation;
  distinct certificates and endpoints alone do not prove this.
- Implement durable, synchronous, monotonically increasing external head
  retention, an authenticated owner-approved genesis bootstrap, and a
  signed current floor that cannot be fabricated after restoring old state.
  Reject head regressions and ambiguous/failed fsync; use an independently
  retained high-water watermark across operator restart.
- Authorize each lease against the authoritative account head and coordinate
  with the issuer's lease serialization. Bind the lease, account identity,
  operation and nonce exactly as specified above; do not blindly reflect
  input fields while signing.
- Provision the pinned transport and owner identity bindings outside mutable
  application data. Audit remote roles, certificate revocation, signatures,
  crash recovery, strict no-fallback routing and all legacy/derived data sinks
  with actual independent hosts before declaring ZK10 production enabled.

The repository supplies a **cohosted disposable mTLS test**, which proves
wire verification and fail-closed behavior but cannot substitute for remote
custody, an implemented custodian service, proof of physical write fencing,
or actual production route admission. Accordingly the `independentOffServerCustodyProven`
flag remains `false` and ZK10 production readiness remains **NO-GO**.
