# Issue #65 — atomic batch external CAS floor gate (DEV-OFF)

The protected WebDAV DELETE+MOVE remote batch may only advance its local
durable outbox if **both** distinct, externally pinned Ed25519 authorities
respond to **separate fresh challenges**:

1. The independent physical-admission witness signs the two exact operation
   IDs and canonical signed-envelope digests, account/store `scope`, distinct
   externally provisioned canonical `accountId`/`storeId` UUIDs, signed
   `username` and `compartmentId` from the original operation envelopes, new
   nonce, physical `commitId`, `storeHeadSha256`, positive fencing epoch, and
   `physicalDurable: true`.
2. A distinct off-host CAS floor authority independently signs the **current**
   `scope`, exact same `accountId`/`storeId`, a *second* nonce, exact same
   `commitId`, physical head and fencing epoch, with positive monotonic
   `sequence` and `current: true` under the
   `rootark-sync-atomic-batch-external-cas-floor-v2\0` signing domain.

Witness signatures use `rootark-sync-atomic-batch-witness-v2\0`. A v1 witness
or v1 CAS floor (even signed under the same otherwise trusted Ed25519 key)
cannot authorize a v2 ACK. Both identity UUIDs MUST be owner-provisioned by
the trusted embedding process; generating or reading them from mutable sync
configuration, a server response or the local journal is not authority.
The externally pinned username must equal current trusted device policy, and
the externally pinned compartment must match the selected local compartment.

Any absent/malformed/forged/stale/nonmatching CAS readback leaves **both**
signed operations pending. The local engine does not treat the sync server's
HTTP response, PostgreSQL readback, local journal, or a lone physical-witness
signature as an authoritative external floor. Same-key witness and CAS pins
are rejected. The embedding process must provision both pins and independent
readback callbacks outside mutable sync configuration; the CLI cannot enable
them merely through `.rootark-sync.json`.

**DEV/TEST limitation:** focused tests use two newly generated in-memory
Ed25519 signers and synthetic current-head replies. They validate client
signature checks and denial behavior, **not** externally retained monotonic
state or the physical custody of a real signer. The code does not ship an
operated independent CAS service, mTLS pin verification, failover recovery,
**operational provenance/custody of the provisioned UUID identity**, or proofs
that the external signers persist a nonrollbackable floor. The v2 validator
checks the binding of the externally supplied identifiers, **not** how a
future operator obtains or authenticates their provenance. Until these are
separately
implemented, independently audited, and adversarially validated, protected
production ACK/rollout remains **NO-GO**.
