# Issue #65 / PR233 — signed large-file preimage capture (DEV-OFF)

**Scope:** new, independent module and adversarial fixture only. This is
**not** a Google Drive upload implementation, readback, server route, feature
flag enabled by default, production authorization, or a verified historical
original. The existing unlimited legacy upload and 1–16 MiB protected upload
remain untouched.

## Implemented

- `src/services/zk1DevOffSignedLargeCloudCapture.js` exports only
  `verifyDevOffSignedLargeCapture({ sourcePath, signedClaim,
  pinnedOwnerPublicKey, expected })`. It exposes no cloud writer, callback,
  media stream, captured plaintext, private staging path, or encryption key.
  No provider SDK or network operation is performed.
- A dedicated domain-separated Ed25519 signing payload with exact canonical
  field ordering binds account, object, object revision and epoch, unique
  operation ID, SHA-256 of **original** ciphertext, exact byte count, owner
  HEAD revision/digest/epoch, provider `gdrive`, namespace, principal context,
  canonical cloud key and pinned Drive file ID. Strict own-data/plain-object
  parsing rejects accessors, unknown keys and noncanonical signatures. The
  `expected` fields must match the signed claim before source I/O.
- Checks a signed time window of at most 60 seconds and a bounded process-
  local duplicate-operation fence. Both are useful fail-closed checks but
  **neither** is an independent owner-state grant or durable anti-replay
  witness. A caller-supplied public key can prove that someone signed those
  bytes; it **does not** establish the signer is the true owner.
- The module snapshots Node native `verify`, SHA-256, random bytes,
  AES-256-GCM cipher/decipher, constant-time tag comparison and Ed25519 key
  class at module initialization. Its Windows private-staging helper also
  snapshots the RNG used for random directory names. After-`require`
  modifications to the shared `node:crypto` exports cannot silently replace
  signature verification or ciphertext hashing. A real wrong-domain 64-byte
  signature and a B-for-A preimage with a spoofed `createHash` both reproduced
  **RED** before the fix and **GREEN** after native-function capture.
- Opens a pinned regular source FD without following the leaf symlink,
  requires one link and an exact signed byte length; hashes ciphertext
  in 64 KiB blocks while writing a private exclusive AES-256-GCM encrypted
  staging file. Staging uses the existing native Windows private DACL helper
  or a POSIX owner-only temporary directory. The ephemeral key is kept out
  of the staging file; its JavaScript buffer is zeroed during cleanup, but
  native cipher internals need a separate key-lifecycle security review.
  Disk contains no user plaintext.
  All source bytes and metadata are checked against the signed preimage
  **before any possible cloud PUT**. No 16 MiB size limit is introduced;
  byte count is restricted to a JavaScript safe integer minus the GCM tag
  and available private disk space. **Disk quota is not yet enforced.**
- Fsyncs the encrypted stage and independently rereads its **entire**
  encrypted ciphertext plus on-disk authentication tag through a pinned FD.
  Verifies AES-GCM authentication and complete SHA-256. File/parent identity
  checks and cleanup are fail-closed. All results explicitly contain
  `authorizesCloudUpload: false`,
  `externalOwnerCustodyVerified: false`,
  `durableReplayFenceVerified: false` and
  `providerVersionedReadbackVerified: false`.

## Concrete adversarial validation

`test/issue-65-pr233-signed-large-capture-dev-off.test.js` uses fresh,
ephemeral test Ed25519 keys, disposable ciphertext and mock/real native file
descriptors. It checks a >16 MiB positive capture, a real retained writable
FD A→B→A during read (same inode and post-attack original contents), invalid
signature/scope/object/revision/operation, expiry, same-size source B, local
replay, attacker-generated signing key that still does **not** establish
external owner custody, encrypted-spool byte corruption, and malicious input
accessors. On native Linux **root**, `runuser -u nobody` opens a second-UID
writable FD before `chmod 0644` and performs A→B→A at the exact read
boundary. The signed A preimage rejects B; no provider SDK receives bytes.
That test skips on Windows or unprivileged Linux, without claiming native
foreign-UID coverage there.

## Remaining barriers — do not lift DEV-OFF

1. The passed `pinnedOwnerPublicKey` and `expected` are supplied to this
   standalone component. No independently operated off-host owner public
   key custody, current owner HEAD/floor, authorized-device enrollment,
   revocation, signer provenance or historical pre-attack authorization
   exists in the legacy upload path. A malicious server may present its own
   signature over B: this module will verify the cryptography but **never**
   grant a cloud upload. To establish a historical original, the commitment
   must predate compromise or be re-approved against an independently held
   owner original.
2. Process-local replay protection is not a persisted or off-host witness.
   A restart resets it; exhausted entries deny all new operations rather
   than evicting unaudited history. A true external monotonic/fencing CAS and
   fresh state check must precede any authorizing upload.
3. No provider SDK sends the encrypted stage, and **no** version-addressed
   full Google Drive readback exists. The current Drive adapter reads current
   bytes by `fileId`, which is not a historical immutable version. A
   matching current GET cannot authorize remotely verified-original bytes.
4. The 64 KiB synchronous capture is a DEV-only bounded-memory prototype,
   not an operated large-file queue. A production proposal needs disk quota,
   cancellable asynchronous I/O, stall deadlines, crash/restart cleanup,
   private path ancestry confinement, memory/key-lifecycle review, native
   anti-tamper spool checks, corrupt/partial provider readback negatives,
   truly version-addressable provider GET, and no downgrade on any failure.
5. An SDK ACK, local capture, encrypted spool, or signed digest alone never
   proves provider fsync, off-host custody, durability, physical quorum,
   monotonic owner authorization or production cutover.
6. Pinned Node crypto export functions defend only against post-module-load
   **export substitution**. They do not create a trusted JavaScript runtime:
   injection before module load, in-process modification of built-in prototypes,
   the native ACL helper's own dependencies, shared `fs` functions or memory
   tampering can still cause failure or require additional isolation. DEV-OFF
   never grants provider authorization even if local captured bytes match.

**Decision:** legitimate code progress for a bounded-memory, owner-*signature*
verified encrypted local capture. **NO-GO** for remote Google Drive PUT,
historical owner identity, remote version-specific readback, merge/deploy or
production until independently anchored original authorization and the
provider/version/custody contract are implemented and peer reviewed.
