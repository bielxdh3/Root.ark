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

The embedding must now also supply an **independently retained current owner
provision certificate digest**, a third pinned Ed25519 provisioner public key
and an exact signed certificate. The provisioner signs canonical JSON under
`Root.ark/sync-v2/atomic-owner-provisioning/v1\0`, with `type`, `version`,
`sequence`, `scope`, both canonical account/store UUIDs, `username`,
`compartmentId`, and the exact witness/CAS Ed25519 SPKI pins. The signed
certificate is valid only if its SHA-256 over domain plus canonical signed
certificate matches the **separately retained current** lowercase digest.
An older correctly signed certificate fails if the trusted operator advances
that digest. The provisioner, witness and CAS keys must all be distinct.
`SyncEngine` independently repeats verification, so constructing the engine
directly cannot bypass the certificate requirement. A certificate/digest/root
supplied solely by `.rootark-sync.json`, the server or the journal is NOT
trusted. The embedding process must establish the root and current digest
outside those writable trust domains.

Any absent/malformed/forged/stale/nonmatching CAS readback leaves **both**
signed operations pending. The local engine does not treat the sync server's
HTTP response, PostgreSQL readback, local journal, or a lone physical-witness
signature as an authoritative external floor. Same-key witness and CAS pins
are rejected. The embedding process must provision both pins and independent
readback callbacks outside mutable sync configuration; the CLI cannot enable
them merely through `.rootark-sync.json`.

**DEV/TEST limitation:** focused tests use three newly generated in-memory
Ed25519 signers and a synthetic retained certificate digest, plus synthetic
current-head replies. They validate client
signature checks and denial behavior, **not** externally retained monotonic
state or the physical custody of a real signer. A caller who can replace both
the provisioner root AND the separately retained current digest remains in
the trusted computing base; in-memory test pins are not an off-host operator.
The code does not ship an
operated independent CAS service, mTLS pin verification, failover recovery,
**operational provenance/custody of the provisioner root/current digest**, or
proofs that the external signers persist a nonrollbackable floor. The signed
mapping checks authenticity relative to an injected root/current digest, but
cannot prove the real-world operator who retains that root and digest. Until
these are
separately
implemented, independently audited, and adversarially validated, protected
production ACK/rollout remains **NO-GO**.
