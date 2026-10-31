# Issue #65 — atomic batch external CAS floor gate (DEV-OFF)

The protected WebDAV DELETE+MOVE remote batch may only advance its local
durable outbox if **both** distinct, externally pinned Ed25519 authorities
respond to **separate fresh challenges**:

1. The independent physical-admission witness signs the two exact operation
   IDs and canonical signed-envelope digests, account/store `scope`, new
   nonce, physical `commitId`, `storeHeadSha256`, positive fencing epoch, and
   `physicalDurable: true`.
2. A distinct off-host CAS floor authority independently signs the **current**
   `scope`, a *second* nonce, exact same `commitId`, physical head and fencing
   epoch, with positive monotonic `sequence` and `current: true` under the
   `rootark-sync-atomic-batch-external-cas-floor-v1\0` signing domain.

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
immutable owner-provisioned account/store UUID identity, or proofs that the
external signers persist a nonrollbackable floor. Until these are separately
implemented, independently audited, and adversarially validated, protected
production ACK/rollout remains **NO-GO**.
