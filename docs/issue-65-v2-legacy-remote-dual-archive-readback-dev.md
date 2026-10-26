# Issue #65 — Legacy V2 dual-archive signed stage readback (DEV)

Status: **BOUNDED PREFLIGHT ONLY / NO-GO**. Follows the irreversible
phase-1 write quarantine described in
`issue-65-v2-legacy-remote-dual-archive-migration-phase1-dev.md`.
It neither relocates a single archived byte nor changes the V2 predecessor
of signed legacy #129+ intents. **No restore, V2 write reactivation, source
deletion, dual-authority activation or production cutover is authorized.**

For each **already staged** independent CAS and FLOOR authority, the opt-in
`POST /v2/legacy-readback` endpoint requires the existing TLS 1.3 mutual
certificate trust and peer certificate pin. It checks the immutable native
SQLite stage/table/triggers, signed owner consent, and locally verifies the
original signed V2 transition history. It returns a fresh, nonce-bound
Ed25519 statement signed under the authority's distinct pinned role key.
This binds the original last-head-only V1 checkpoint, current legacy
sequence/head/checkpoint/operation, independently different **full** V1
1..128 archival root and checkpoint, SHA-256 of the exact historical
owner consent/signature, and a separately signed terminal receipt.
No plaintext, ciphertext payload, backup, stored file or private key is
returned. Unstaged peers return failure.

The operator-local `verifyLegacyArchiveDualReadback({ ... })` requires
the same exact owner consent/signature and independently supplied
`operatorPins` for the owner, archive checkpoint, V1 CAS/FLOOR, and V2
CAS/FLOOR keys. All four authority clients must be independently configured
and pinned HTTPS clients; caller-created `head()` stand-ins cannot satisfy
the check. The verifier cryptographically checks the supplied complete V1
128-head archive and checkpoint, the owner-signed full-root handoff,
independently signed V1 CAS/FLOOR heads, each new V2 role's fresh stage
attestation and terminal receipt, a fresh independent witnessed owner
head, then re-reads BOTH staged authorities and repeats full V1 archive
preflight before one last two-authority signed read. The same consent hash, scope,
signer pins, original baseline and immutable head must agree throughout.
An owner revision advance, missing stage, rollback of either V1 provider
head, changed checkpoint, foreign operator pin, altered receipt or
signature, or partial CAS/FLOOR stage fails closed. Historical consent can
be expired because the verifier is only a read-only forensic check; the
original V1 handoff still needs to be **fresh and valid** for the existing
128-archive verifier. Its owner may need to issue a fresh independently
witnessed handoff bound to the same two archival roots.

Follow-up liveness fence: the owner witness is challenged **again after**
the final V1 archival preflight and CAS/FLOOR signed stage readbacks. An
owner revocation or manifest advance committed during the asynchronous
readback window invalidates the result. This additional freshness check
is a bounded race mitigation, **not an atomic witness reservation**;
revocation immediately after the final observed head still requires
the independent monotonic migration fence described below.

Readback caps the legacy V2 suffix at **1,024 signed transitions** beyond
the V1 absolute #128; beyond that bound the operator must use a separately
reviewed paginated proof protocol. Normal historical `head()` remains
available after phase-1 staging. The independent owner/witness/key pins
must truly originate from separate operator custody, never a
server-provided enrollment blob. Two signed live responses prove only that
the configured private keys participated in this local protocol; they
do **not** prove physical host separation or durable independent custody.

Outstanding prerequisites remain: immutable independent witness/physical
monotonic anchor binding **both** stage receipts, cross-host crash-safe
two-authority reconciliation, signed and paginated historical V2 suffix
export for externally reproducible verification, genuine multi-provider
ciphertext/source readback and safe restoration to a disposable target,
and a reviewed versioned successor protocol binding BOTH archival roots.
A locally restored old SQLite image or a compromised signer can still
roll the stage back unless the missing independent monotonic anchor is
provided. Until then the verified result always reports
`v2WriteAuthorized:false`, `restoreAuthorized:false`,
`destructiveCutoverAuthorized:false`, and
`independentMonotonicStageWitnessProven:false`.
