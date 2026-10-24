# Root.ark #65 — bounded remote CAS history + fresh witness head

**LOCAL SIGNATURE-CONSISTENCY EXPERIMENT. NON-AUTHORIZING; PRODUCTION NO-GO.**

The newly available `zk1CasManifestHttpsClient.getCommittedHistory()` returns
untrusted full v2 manifest bytes over pinned mutual TLS. The additive module
`src/services/zk1ExperimentalRemoteSignedHistory.js` binds those bytes to:

1. An independently supplied, explicitly pinned Ed25519 **genesis/base**
   witness receipt (not sourced from the CAS response).
2. The complete bounded, canonical RFC8949 CBOR signed v2 manifest chain,
   all public enrollment/rotation/revocation signatures, retained identities,
   package-activation envelope proofs when needed, and exact CAS-reported
   final revision/digest. Verification reuses the existing branded
   `verifyRecoveryHistoryPublicV2` and `isVerifiedPublicRecoveryHistoryV2`
   validators. The CAS's claimed digest alone cannot authenticate a fork.
3. A freshly generated 32-byte CSPRNG challenge sent to the independently
   configured witness `freshHead` transport. The existing nonce-bound
   Ed25519 `verifyWitnessHeadMatchesSignedHistoryV1` requires the signed
   current committed head, account/compartment/keyring, final manifest digest,
   monotonic revision floor and an externally pinned public witness key.
   The client checks the local receipt clock after HTTPS settles, not before.

Every untrusted byte buffer, pinned public key reference, scope, base receipt,
minimumHead and package-envelope byte array is validated/copied before the
first asynchronous operation. CAS history and optional recovery package
envelopes share one **64 MiB aggregate copy budget**. An adversarial
9×8 MiB envelope catalog is rejected before network I/O rather than cloning
72 MiB of attacker-influenced bytes or risking an unbounded heap allocation.
The result is deliberately restricted to
`signedPublicHistoryVerified:true`,
`freshWitnessHeadMatchesHistory:true`, a digest and revision,
`authorizesProtectedIo:false`, `authorizesRecovery:false` and
`independentlyOperatedAuthoritiesVerified:false`.
No code route to physical PUT/GET or device/recovery release is connected.

## Validation

`node --test test/issue-65-remote-history-head-mtls.test.js` brings up two
**actual pinned TLS 1.3 client-certified HTTPS servers** with distinct server
certificates and separately scoped client certificates. One runs a durable
CAS SQLite ledger, the other a durable witness SQLite ledger, both in
OS-disposable directories. Independent test Ed25519 keys sign the genesis
base receipt, current witness head and CAS status. Signed v2 genesis,
enrollment and revocation are committed through witness reservation, CAS
register/commit and witness terminal resolution, not by fabricating state
responses. Tests verify a full chain, then another live signed transition;
tampered history bytes (not a separately signed alternate fork), a genuinely
signed CAS revision rollback against
the newer witness head, a mismatched witness signature key, replay of an
earlier signed nonce-bound head, wrong mTLS pin at **each** service, alien
scope, and an unresolved live `PENDING` reservation all fail closed.

## Critical limitations

Both listeners, all test signing keys, both ledgers and their independent
transport pins are on the **same physical machine in the same test operator
trust domain**. Their administrative custody, hardware trust roots and
independent high-water witnesses are not independently established.
Therefore the test is **not** a true multi-host or multi-operator proof.

This module consumes an operator-provided genesis receipt and pinned key;
it does not independently provision them, prove offline owner consent,
certify a malicious operator's key lifecycle, or persist an externally
monotonic checkpoint resistant to a joint CAS+witness restore.
It does **not** obtain a linearizable admission committed in the same
operation as a protected provider effect, nor physically fence S3/Google
Drive/sockets and uncontrolled third-party egress. It validates public
history; no private recovery key or authorized client release follows.
The full #65 still requires independently governed CAS/witness/Gate,
separate host control, revocation and rollback resistance in production,
cross-provider PUT/GET/sync/WebDAV/version/trash/backup safety, dual
recovery consent and proofs, and reversible real-data migration.
No push, deploy, merge, production writes, real-data migration or unknown
volume cleanup was performed.
