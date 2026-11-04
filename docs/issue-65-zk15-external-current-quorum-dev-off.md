# Issue #65 — externally provisioned corpus CURRENT claim (DEV-OFF)

This is a **conditional, nonauthorizing cryptographic building block**. It
targets the missing freshness boundary adjacent to
`zk1OwnerPinnedCorpusVerifier.verifyPinnedOwnerCorpus`: the existing complete
owner-signed corpus verifier accepts an *independently supplied* corpus digest
and predecessor floor, but cannot know when a source replaces that digest or
omits an object absent independent external inventory. The new module
`src/crypto/zk15ExternalCorpusCurrentQuorum.js` checks a current claim
against two separately pinned Ed25519 witness identities and a pre-existing,
independently retained minimum. It does not fetch or retain keys/floors.

## Exact provisioning contract

The provisioning operator, outside the Root.ark host/process/DB, must
independently bind the following to the same real account and ownership
generation: `accountId` (16-byte base64url), `ownerGenerationId` (16-byte
base64url), `ownerSpkiSha256` (32-byte base64url), and a monotonic
`independentlyRetainedFloor`. The floor has exactly these three identities,
`sequence` (positive integer), `corpusSha256` (32-byte base64url) and
`previousCorpusSha256` (32-byte base64url, or null exclusively at sequence 1).
The first floor **must already exist externally**; this module cannot
bootstrap a trusted genesis from the application's own files or signed subset.
Owner generation rotation requires a separate externally authenticated
transition protocol and is deliberately rejected here.

Each independent witness obtains a fresh caller-generated 32-byte nonce and
issues the exact canonical JSON object signed over:

`Root.ark/zk15/external-corpus-current/v1\0 || UTF8(JSON.stringify(body))`

where `body` has, in this exact order:

```text
type: "rootark-zk15-external-corpus-current/v1"
witness_id: provisioned witness identifier
account_id: account ID (base64url, 16 bytes)
owner_generation_id: owner generation ID (base64url, 16 bytes)
owner_spki_sha256: owner Ed25519 SPKI SHA-256 (base64url, 32 bytes)
sequence: positive safe integer
corpus_sha256: full owner-signed corpus manifest SHA-256 (base64url, 32 bytes)
previous_corpus_sha256: previous manifest SHA-256 or null only at sequence 1
request_nonce: caller-supplied nonce (base64url, 32 bytes)
issued_at: witness timestamp, Unix seconds
expires_at: witness expiry, Unix seconds
signature: Ed25519 signature over the domain-separated canonical body (base64url, 64 bytes)
```

The two externally pinned witness public keys must differ, their configured
identifiers must differ, and neither may be the owner signing key. Both
statements must agree on **every** signed field except `witness_id`. They must
echo the one fresh nonce, match independent account/generation/owner pins, and
pass bounded validity checks using the **caller-supplied trustworthy clock**.
Any witness outage, key mismatch, fork or stale signature rejects the whole
claim. A matching floor at sequence N may remain unchanged; advancement is
restricted to exactly N+1 with the predecessor digest equal to the retained N
digest. A sequence gap, rollback, same-sequence fork, reset to a new genesis or
silent owner generation change fails closed.

The immutable result includes `candidateRetainedFloor` for independent
operator inspection and external monotonic durable retention. This method
does **not** persist that floor, does **not** claim that two keys correspond to
different organizations or machines, and does **not** authorize using that
candidate in a live route. The returned flags are always:
`authorizesIo:false`, `independentOffHostCustodyProven:false`,
`globalAccountCompletenessProven:false`, and
`currentnessGuaranteeWithoutExternalCustody:false`. Reusing a locally
attacker-controlled input as an "independent" floor remains unsafe.

The W129 corpus verifier remains responsible for checking the exact signed
full manifest, recovered ciphertext and all CEKs. If this contract is ever
adopted, the separately operated witness must sign the digest of the **actual
owner-signed corpus manifest**, not only a locally selected subset. A real
off-host issuer, independent witness operators, verified TLS/mTLS provider
identity, audited key provisioning, durable monotonic floor update, crash
recovery, signed owner succession and complete live-owner inventory still need
separate implementation and evidence. In particular, this module does not
replace the ZK10 issuer bridge, identify a legacy link creator as an owner,
or amend existing anonymous `/share` / `/open-file` authorization.

## Local validation scope

Focused test `test/issue-65-zk15-external-current-quorum.test.js` uses
synthetic in-process Ed25519 keys only to exercise cryptographic parsing and
adversarial rejection. Passing test signatures on one machine is **not**
evidence of independent custody or freshness in production.
