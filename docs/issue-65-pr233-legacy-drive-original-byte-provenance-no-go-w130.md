# Issue #65 / PR233 — original-byte provenance for unlimited legacy Drive uploads

**Decision (2026-10-28): NO SAFE PATCH to the existing legacy upload route.**
This is a design/acceptance contract, **not** implemented code, a migration,
an assertion of original-byte recovery, or production/merge authorization.
Keep all ordinary Google Drive streams unlimited and unchanged. The W130
protected-options validation already integrated as `bd571de1` is independent.

## The missing authority is prior to all file I/O

The actual legacy route is
`services/restoreService.js:716-729,1200-1243` ->
`services/cloudStorage.js:497-682`. `sourceHash` is derived from the **same
mutable file**, and the upload media is an open but still mutable source FD.
A different UID retaining a writable FD can provide B to the Drive SDK while
restoring A before a later local hash. This is already reproduced by
`test/issue-65-cloud-verified-upload-other-uid.test.js`; its legacy
demonstration is **not** a secure-upload pass. Do not rerun it as discovery.

Neither inode/mtime pinning, an additional SHA-256 of the same file, an
after-the-fact backup digest, nor a copied snapshot independently attests that
**A was the bytes the owner originally authorized**. A private spool created
from B would merely freeze B. A successful Drive PUT, a matching GET, or a
provider `md5Checksum` would only describe the remotely observed B.

Existing `src/services/zk1OwnerProviderVersionPin.js` signs an
**operation-specific remote locator** using an externally pinned owner key:
S3 requires a `VersionId`, WebDAV binds an ETag, and **Google Drive binds only
the `fileId`** (its claim requires `providerVersionId === null` and
`providerEtag === null`). A Drive `fileId` is **not** an immutable historical
revision. That is useful *post-upload* locator binding, but it cannot
reconstruct a **pre-upload original-byte authorization** for historical legacy files.
Existing `zk1ExpectedSha256` + `zk1BoundedBytes` accepts independently
committed ciphertext but is intentionally restricted to 1–16 MiB. The
readback's `constraints.maxBytes` has the same 16 MiB bound; raising either
limit alone is not this protocol.

## Required NEW opt-in trust contract (not presently provisioned)

The owner (or a currently authorized device backed by a fresh, independently
authenticated owner-state grant) must sign **before the mutable source is
exposed to an attacker**, or sign after independently comparing with an
uncompromised owner-held original. The signature must commit to original
ciphertext bytes, not bytes that the server chose when it initiated the upload.
A historical legacy file lacking either earlier commitment or independent
owner-held original **cannot be retroactively certified** by server code or
by a signature that merely approves its current contents.

1. A separate trust component pins the owner's Ed25519 **public key**, current
   owner HEAD and monotonic generation/floor outside server-controlled DB,
   filesystem, restore metadata or the request supplying the signed claim.
   Device authority requires an owner-signed enrollment and independently
   verified *current* nonrevocation; the same server must not self-attest
   these prerequisites. The adapter must not accept a public key, signing
   callback or `trusted: true` from the untrusted upload caller.
2. A new **versioned, domain-separated, canonical** signed claim binds all of:
   account ID, compartment ID, keyring ID, object ID, file incarnation,
   original owner-approved object revision, epoch, operation ID, ciphertext
   SHA-256 (32 bytes), exact byte length (positive safe integer with no 16 MiB
   cap), owner HEAD revision/digest/epoch, provider `gdrive`, writer namespace
   identity, authenticated provider principal, canonical cloud object key,
   and a previously reserved/pinned Drive file ID. Bind the intended action
   (create vs overwrite) and an explicit schema version; do not misrepresent a
   Drive file ID as an immutable version identifier.
   Exclude prototype/accessor fields, duplicate/noncanonical encodings,
   extra keys, mismatched sizes or unknown signers.
3. The verifier authenticates that exact signature against the **externally
   pinned key** and checks the claim against the independently established
   current account/object/owner-head/epoch/operation/target; it cannot simply
   trust those fields from the same claim. An anti-replay/monotonic witness
   and a revocation/fencing check must be provided by the actual external
   authority. No signed claim, stale grant, failed pin, uncertain trust or
   unavailable authority -> **fail closed before provider PUT**. Retries must
   use the same frozen signed original commitment and target identity.

## Required new >16 MiB implementation sequence, once authority exists

**This is a new explicit ZK ciphertext-copy operation, not an implicit legacy
upgrade or replacement of the existing 16 MiB API.** There is no user-data
plaintext staging permission.

1. Before reading the local path, fully validate owner/device provenance,
   signed length/digest and separately pinned destination. Reserve disk quota,
   retry budget, deadline, and source-object length. Refuse unavailable space,
   unsafe Windows DACL/ancestors and unsafe POSIX ownership/ancestors; never
   recover with a public temp directory or a less-verified legacy upload.
2. Pin the authorized source inode and ancestor identities. Open once with
   `O_RDONLY|O_NOFOLLOW`; reject symlinks, hardlinks, replacement and
   unexpected size. Another UID may still hold a writable descriptor:
   **do not rely on the source FD being immutable**.
3. Create an exclusive, nonce-named private encrypted staging file under
   a verified private directory. Write a sequential fixed-size (e.g. 64 KiB)
   capture from the pinned FD, enforcing total bytes <= **signed length**
   and detecting truncation or growth without allocating the entire file in
   RAM. Encrypt at rest with a stage-only key managed outside that file;
   securely retire the key on every exit. Check complete captured length and
   SHA-256 against the **earlier owner signature** before the first cloud PUT,
   fsync the staged ciphertext, recheck parent/inode identities and close the
   original FD. Delete and quarantine the stage on mismatch/ENOSPC/fault.
   A→B→A during capture is rejected if B enters the captured stream; mutation
   after capture cannot alter the private staged body.
4. Serve the upload only from that private immutable **captured version**
   through a pinned FD or a cryptographically authenticated decryption
   stream, never by reopening the original pathname or replaying the
   mutable original source on Drive create->409->update. Enforce exact
   signed byte count and digest at the provider body boundary. An SDK
   resolving its Promise before actually consuming a request body does not
   authorize early staging cleanup or success.
5. Pin the Drive file ID and parent/appProperties; these identify the
   **current file**, not the immutable content revision. The existing adapter
   performs `files.get({ fileId, alt: "media" })`, which reads current bytes
   only. Before any claim of remote verified-original authorization, require
   an actually supported, independently checkable version-addressed complete
   readback of the exact PUT. **If the provider/adapter cannot address and
   reread that exact historical representation, fail closed: no
   verified-original authorization or success claim**, even when a current
   `fileId` GET matches the signed digest. Do not invent a Drive version or
   treat a metadata revision as proof that `alt:media` returned its bytes.
   Reject 206/Content-Range, compressed/partial representations,
   unexpected content-length, truncated or overlong streams, wrong physical
   ID, missing required version address or changed metadata. Hash the
   **entire** streamed GET with constant memory and match signed length/SHA;
   do not substitute
   metadata `md5Checksum`, remote ETag, SDK ACK or first 16 MiB.
6. On lost ACK or any ambiguous remote effect, report **uncertain/failed**,
   not `verified`; remote corruption may have occurred even if local
   state stayed A. Idempotent retry is permitted only with the same signed
   object/locator claim, immutable stage and independent fencing. Preserve
   the source of truth and perform explicit cleanup/compensation separately.
7. A matching current-Drive-file GET may state **only** that the selected
   file's current representation matched at that observation; it does **not**
   authorize the remote verified-original operation without an exact
   version-addressed complete readback. It also does NOT prove Google
   Drive durability, off-host custody, future immutability, owner cutover,
   remote CAS/witness acceptance, or that the server will not roll back its
   own untrusted database.

## Minimum RED->GREEN acceptance gate for the future implementation

- **RED on old legacy route, GREEN on NEW signed route:** genuine foreign-UID
  retained writable FD A→B→A while provider consumes the body; with prior
  independent owner signature of A, remote PUT must never receive B. Test
  mutation during capture, after capture and during Drive 409 retry.
- Genuine fixture Ed25519 owner signs A *before* attack; wrong signer,
  self-declared new owner key, substituted object/epoch/account/revision,
  changed byte length, provider ID, destination, stale owner HEAD, revoked
  device and replay all reject **before provider write**. A new signature
  over attacker-chosen B does **not** retroactively attest historical A.
- Files larger than 16 MiB, including multi-GB sparse fixtures, must use
  bounded-memory streaming with exact signed byte counts and quota-limited
  private encrypted disk. No unbounded `readFileSync`, new 16 MiB cap,
  unsafe source-path reopen or opportunistic fallback.
- Exercise native Windows ACL and real Linux foreign UID/sticky-ancestor
  protections, same-UID staging-path swaps, held spool handles, cleanup
  races, ENOSPC, worker crash, partial capture and memory pressure.
- Test real streaming provider consumption, delayed SDK settlement,
  deceptive early ACK, repeated create->409->update, corrupt/partial
  readback, 206, ranged/compressed response, overlong/truncated GET and
  mismatched Drive file identity or unverified/missing historical version
  address. A transient matching current GET must never be labeled durable or
  independently authorized.
- Separately preserve ordinary unlimited legacy and existing bounded
  signed-copy contracts with their exact return values and routes; neither
  gets silently promoted to the new signed-large contract.

## Decision and next dependency

**Blocked:** no owner/device-signed *historical original* digest and exact
scope/object-revision/size is delivered to the legacy restore/Drive upload adapter,
and no independently anchored owner key/current grant/fencing contract is
wired to that path. The existing owner provider-version pin is downstream.
No amount of server-controlled hashing, metadata or private spooling can
bridge that original authorization gap. Therefore there is **no sound
production code change** to the existing legacy upload from current inputs.

First implement and independently security-review the upstream owner/device
signed-original commitment + external trust and replay/floor interface.
Then establish real provider support for version-addressed complete readback
(not present for Google Drive in this adapter), implement private encrypted
streaming stage + that exact readback in a **new opt-in API**, and complete the
full native adversarial gate before proposing a PR233 integration. The legacy route is unchanged
until an explicit migration; no production cutover authorization is implied.
