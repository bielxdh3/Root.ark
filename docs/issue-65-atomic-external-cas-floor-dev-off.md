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

## Isolated durable Sync v2 CAS ledger prototype

`src/services/zk1SyncAtomicCasFloorLedgerDevOff.js` adds an intentionally
**unwired** v2 authority implementation. Unlike legacy ZK1 CAS, the signed
floor has the exact `rootark-sync-atomic-batch-external-cas-floor-v2\0`
domain and client-required fields. It uses a private SQLite location,
verified WAL mode and synchronous=FULL (refusing SQLite fallback to rollback
journaling), hash-linked append history, a positive monotonic
sequence, a strictly advancing fencing epoch for each different physical
head, separately pinned CAS/witness/anchor Ed25519 identities and mandatory
fresh-signed verification. An ambiguous external advance latches denial;
readback signs a fresh nonce only while a separate physical read fence and
signed retained high-water check both succeed. Restart with an older local
SQLite snapshot fails against the external floor.

The append history now retains the original exact canonical pair IDs and
envelope digests for **every** sequence. Each trusted local current-head
inspection streams and rehashes the full history from the fixed genesis,
requiring contiguous sequences, identical predecessor hashes, increasing
fencing epochs and agreement with the signed external tip. A tampered older
row, deleted historical row, mismatched pair or unattached history is denied;
this checks local history integrity, not historical physical durability.
On existing ledgers, identity, mandatory schema columns and uniqueness,
all historical links are verified in one SQLite **read-only transaction before**
opening the database with write access. Fresh signed external retained heads
are obtained **before** entering that transaction, so a slow or unresponsive
operator cannot pin the WAL/checkpoint. In one synchronous read-only snapshot,
the full chain, persisted signer-identity constraints and required CAS schema
must exactly match those signed heads before any
writable SQLite connection is created. The post-open full-history audit also
denies intervening changes before a usable signer can escape. The service
never adopts a SQLite file first materialized while the signed bootstrap
genesis check is waiting; a new file must be created with exclusive creation,
whereas a pre-existing file must retain its inspected device/inode identity.
It also rejects a reused historical physical commit or store head before
entering any irreversible CAS mutation;
SQLite uniqueness constraints remain a second guard against racing replays.
Prior DEV-OFF ledger files without the per-entry pair columns are refused
without automatic reconstruction: missing historical signed input cannot
be safely inferred from the latest head. Operators must retain the old file
and separately verify a new authority bootstrap, not silently rewrite it.
Full-history validation is intentionally linear in retained entries; a
bounded checkpoint and externally signed compaction contract are future
development requirements for high-volume authorities.

Its constructor **requires** a separately custody-protected
`physicalFence.withCurrentRead` callback holding the real physical writer
fence across verification, the SQLite transaction, the independent retained
anchor advance/readback and signing. The provider must await the complete
continuation and return its exact result without releasing the fence first;
the continuation also requires an externally trustworthy synchronous
`lease.assertHeld() === true` throughout the critical section (including
after each full-history audit and asynchronous retained-anchor calls).
In particular, a physical lease expiring during an O(N) audit denies any
subsequent external CAS advance or positive acknowledgment. This detects the common mistaken
`try { return continuation(...); } finally { unlock(); }` pattern; an adapter
that lies about the lease remains outside what this prototype can prove.
An early return or release error causes fail-closed quarantine. Each changed physical head
also requires a distinct signed previous-to-current physical lineage receipt;
the local CAS ledger cannot infer physical ancestry from a freshly signed
current head. It additionally requires a separately monotonic retained
anchor implementing `readSignedHead` and `compareAndAdvance`.
Injecting callback objects does not prove their independence. In any real
deployment, those services, their Ed25519 private keys, the owner provision
certificate digest and the signed retained floor must be kept outside the
writer/CAS trust domains. The tests use genuine SQLite/Ed25519 but **synthetic**
implementations of the off-host authorities, not actual independently
operated physical stores.

The prototype is NOT routed over HTTP or wired to the SyncEngine. It does
not assert a physical durable receipt from PostgreSQL, establish independent
custody, prove multi-host fencing, or authorize client ACK. A stronger-than-
device-epoch rule requires a strictly newer witness fencing epoch for **each
different commit**. The physical operator needs a per-batch fencing allocator
to satisfy this rule safely; merely re-signing an old physical head must
never advance it. Actual off-host physical/WAL/fsync verification, anchor
custody, crash recovery, failover, and end-to-end Sync v2 integration remain
DEV work, not production release approval.
