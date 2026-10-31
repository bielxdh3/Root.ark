# Issue #65 ZK15 — externally pinned owner corpus acceptance gate (DEV-OFF)

**Status:** standalone read-only verifier and disposable adversarial tests. No
runtime route, backup scheduler, migration executor, production release, or
automatic cutover is enabled. The verifier deliberately reports
`globalAccountCompletenessProven: false` and
`accountWideRecoveryAuthorized: false` even when all externally listed entries
decrypt successfully.

## Authority required *before* calling the verifier

The owner must obtain a genuinely complete, immutable object/version/keyring
inventory **from an independently controlled source**, not from a server,
database listing, cloud object list, REST response, browser IndexedDB cache,
legacy migration journal, or subset archive that the attacker can omit from.
The producer must independently enumerate every account keyring (including
empty keyrings), immutable object ownership/account generation, all historical
version IDs and their parent/epoch chain, and all recoverable ciphertext/CEK
versions. No producer meeting that prerequisite is implemented here. If the
producer cannot establish completeness without trusting the same mutable
server-controlled corpus, **ZK15 global acceptance is a hard NO-GO**.

The owner-controlled producer serializes a canonical JSON `manifest` in this
exact field order: `schema` =
`rootark-zk1-externally-pinned-owner-corpus/v1`, `accountId` (16 bytes
base64url), `ownerGenerationId` (16 bytes base64url), `sequence` (positive
monotonic integer), `previousCorpusSha256` (null at genesis or previous full
manifest SHA-256 base64url), sorted unique `keyrings` (each 16-byte base64url),
sorted `entries`, and `signature` (64-byte Ed25519 base64url). Each entry is
`metadata`, `objectRevision`, `ciphertextSha256`, `cekSha256` in that order;
`metadata` has the eight fields from `rootark-zk1-file-content.js`, in its
canonical order. `entries` are sorted by keyring ID, object ID, revision.
Each object starts at revision 1, has unique account-wide object/version IDs,
immutable account/compartment/keyring ownership across all revisions,
contiguous revisions and authentic parent version/epoch ancestry; each
version must use a distinct random 256-bit CEK.

The owner signs the UTF-8 bytes of the JSON body **excluding** `signature`,
prefixed with the bytes `Root.ark/zk-1/externally-pinned-owner-corpus/v1\0`.
The independently provisioned pin is SHA-256 of the entire canonical manifest
including signature. The signature proves owner endorsement **only**, and
cannot certify that the producer enumerated unknown objects. All CEK digests
are commitments to high-entropy randomly generated CEKs; never apply this
scheme to human-chosen or low-entropy keys. Keep the CEK commitments and the
corpus document within the owner's independent trusted storage, outside the
server-readable backup/provider data plane.

The owner must independently retain the current full-manifest digest,
account ID, **owner generation ID**, Ed25519 SPKI SHA-256, and predecessor
`{ sequence, corpusSha256, accountId, ownerGenerationId, ownerSpkiSha256 }`
where applicable, across device loss and process
restart, in a different trust domain from the backup provider. A mutable
same-server witness or a pin supplied by the same provider does not establish
an independent floor. For a successor, the trusted previous sequence must be
exactly one less and the previous digest must match the signed predecessor.
No implicit anchor discovery, fallback to genesis, or automatic journal repair
is permitted. A lost owner-held floor blocks continuation; external custody
and future monotonicity remain outside this module.

## Opt-in verification boundary

`src/crypto/zk1OwnerPinnedCorpusVerifier.js` exports
`verifyPinnedOwnerCorpus({ manifest, independentlyPinnedCorpusSha256,
ownerPublicKey, independentOwnerSpkiSha256, expectedAccountId,
expectedOwnerGenerationId, previousPinnedCorpus, recoveredFiles })`.
`recoveredFiles` contains **all** recovered versions, each with exact zk-1
`metadata`, `objectRevision`, binary `ciphertext`, and 32-byte `cek`. The
verifier copies these values before async crypto, rejects absent/extra rows,
authenticates external Ed25519/owner/pin/predecessor, enforces version lineage
and fresh CEKs, and decrypts each ciphertext under its exact CEK and metadata.
It releases no CEK or plaintext. Failures all return
`ZK_OWNER_PINNED_CORPUS_DENIED`. Limits: 32 signed keyrings, 64 versions,
16 MiB aggregate ciphertext; oversized real accounts need a separately
reviewed pagination/accumulator protocol, not truncated input.

The result `allExternallyPinnedCorpusEntriesRecovered: true` means **only**
that every version in the separately signed/pinned corpus had matching
ciphertext and working CEK at verification time. It does **not** prove the
producer's global source completeness, future storage availability, physical
provider durability, remote revocation, custody, current freshness, or safe
production migration. In particular, a signer that knowingly creates an A-only
subset and independently pins that new subset will still yield a successful
*relative* comparison; the result never upgrades to global account truth.

## Interrupted migration and historical data

An interrupted import with one signed version absent is rejected. After a
restart the verifier reconstructs its evidence from independent pins and
rechecks **every** recovered version rather than trusting an in-process cache
or incomplete local journal. A newly signed successor cannot be replayed or
accepted with a missing/mismatched external predecessor. Tests exercise this
boundary in a fresh Node child process.

Historical legacy objects with missing authenticated owner UUID/generation,
version lineage, wrapped CEK, or complete immutable external source cannot be
backfilled cryptographically from unsigned SQLite/backup records. Mark such
objects `mixed` / `blocked` / `migration-failed`; preserve legacy recovery and
original data, avoid key destruction, and do not authorize a ZK cutover. The
independent operator/corpus issuer and its non-server custody, pagination for
large accounts, authenticated enrollment/revocation, and production migration
orchestration remain separate prerequisites.

Focused disposable validation:
`node --test test/issue-65-owner-pinned-whole-corpus.test.js`.
