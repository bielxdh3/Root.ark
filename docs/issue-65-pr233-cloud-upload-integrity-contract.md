# Issue #65 / PR233 — cloud upload byte-integrity boundary

Status: **bounded, explicit ZK ciphertext copy only**. Not a general legacy
stream integrity fix, a production cutover, a remote CAS authorization grant,
or proof of S3/Drive durability.

## Two distinct upload contracts

1. **Authenticated bounded ciphertext (opt-in):** the caller supplies an
   independently authenticated `zk1ExpectedSha256` (lowercase 64-character
   SHA-256 hex string) and exact `zk1BoundedBytes` (1–16 MiB) together.
   The cloud adapter pins a regular source inode, captures at most that many
   bytes into a detached Buffer, checks exact length, file identity and the
   expected digest **before** the first provider PUT. Invalid/missing/orphan
   ZK options fail closed. The digest must originate from a signed ciphertext
   root or other independently trusted commitment — **never** from hashing the
   potentially compromised file immediately before calling `upload`.
   The owner-side ZK ciphertext publisher and signed-catalog sidecar provide
   this information; pinned Drive uploads also supply `providerFileId`.

2. **Legacy / no independent digest:** existing ordinary cloud callers
   (including `server.js`, the cloud temp mutation queue and legacy restore)
   remain legacy streams, not silently upgraded or blocked. File-descriptor,
   inode, mode and timestamp checks prevent some path-substitution races but
   **do not establish immutable bytes**. A different UID can retain a writable
   FD opened before a chmod; A→B→A can make the provider receive B while
   the local source returns to A. Hashing the same mutable source before and
   after upload is not an independent check. These flows must never be
   advertised as satisfying ZK verified-integrity acceptance.

## Retries and authority

- A bounded S3 upload that loses its ACK may have written bytes remotely;
  the same independently pinned digest must be checked again before a retry.
  A changed source is rejected before a new PUT.
- The pinned Google Drive create→409→update path reuses the **same detached,
  verified** Buffer; it does not reread a mutated file during that attempt.
- An SDK ACK or ciphertext hash by itself does **not** prove physical custody,
  durable storage, a current owner grant or monotonic witness/CAS admission.
  Those checks remain separate and mandatory.
- For ciphertext larger than 16 MiB, do not bypass the bound or stream an
  unverified FD under a ZK flag. A future independently versioned immutable
  source or authenticated, quota-controlled **encrypted** staging protocol
  would need separate design, threat review and negative tests. No plaintext
  disk spool or implicit legacy downgrade is authorized.

Native Linux adversarial fixture:
`node --test test/issue-65-cloud-verified-upload-other-uid.test.js` as root,
with `runuser` and an unprivileged `nobody` process. This reproduces the
historical legacy weakness (a *diagnostic*, not a security PASS), then verifies
the bounded mode resists the same other-UID held-FD attack. No production keys,
cloud credentials or external provider writes are used.
