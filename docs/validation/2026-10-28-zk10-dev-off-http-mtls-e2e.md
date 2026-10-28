# ZK10 DEV-OFF: disposable signed-account HTTP admission E2E

Status: **development-only evidence; NOT approval to activate protected cutover**.
Base: the local integrated #236 candidate `4e09b49819574605f4d5a1265a06cb25823716ad`.

The additional Node 22 test in `test/issue-65-zk10-legacy-mtls.test.js`
starts the *actual* Express authentication and Sync v1 routes. Both account JWTs
are obtained via a real `POST /auth/login`; no direct `jwt.sign` test bypass
is used. The route uses a genuine factory-created
`createZk10LegacyCutoverFence` capability, not a duck-typed callback
substitute. Two disposable HTTPS services require TLS 1.3 and mutually
authenticated client certificates and issue separately Ed25519-signed
authority admissions and witness-current statements. Fresh nonmembership
proofs, the account's pinned durable identity, the signed authority head and
the witness's current signed floor are verified by the production *verifier
code path* (but against fixture signers and fixture storage).

The HTTP exercise observes successful `never_enrolled` list, encrypted
operation upload, durable sync-store JSON, individual GET, cross-account
isolation, and denied access after an owner-signed `protected_enforced`
cutover. The authority refuses cutover during an active lease, including at
the Express response `finish` event, and sees the written object in the
store **before accepting the lease release**. After the release, cutover
becomes possible. A fresh application and verifier still reject the legacy
account, while independent never-enrolled accounts remain readable.
Negative HTTP paths include omitted authority, invalid authority TLS
fingerprint, absent server-pinned identity binding, a fake duck-typed
capability, and a revoked JWT.

**Evidence boundary:** all services, TLS certificates, owner keys, and
authority/witness signers are cohosted under disposable local test control.
The test does not demonstrate that another party independently owns or
retains the witness, head, minimum monotonic floor, lease arbiter, signer
keys, server account mapping, or backend storage. The pinned
`independentOffServerCustodyProven` property is explicitly `false`.
Observing data in a file at release is not a physical fsync attestation by
an independent storage provider, nor proof of crash durability on another
machine. The assertion relies on the existing awaited Sync
`store.put`/durable-write code path, which must retain its sync barriers.

In particular, the current optional strict route flag is reversible and
**not an irreversible no-downgrade enrollment control**. A short-lived
external lease can also expire, lose its release acknowledgment or race a
multi-host operator without a physical custody-backed authorization fence.
The application has no production bootstrap wiring or independently
maintained off-host authority. Therefore **production ZK10 remains NO-GO**
even when all disposable tests pass. No CI timeout, TTL, protected-route
requirements, or operational gate was weakened.
