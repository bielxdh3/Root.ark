# Issue #66: CFAPI positive hydration — source NO-GO and executable acceptance plan (W46)

Source checkpoint: published Draft PR #300 `03cac3a9f33975af403c231ce4ffc62e4e7a4d52`,
tree `fa384be7e173db68ca3da33d882eb2f3f5cbd800`. This document is a
design/test specification; it does not register a Cloud Files sync root or
authorize any positive `TRANSFER_DATA`.

## What the source actually implements

- `sync-client/rootark-sync-windows-cfapi-deny-callback.cpp:22-46,76-95`
  registers a `FETCH_DATA` function in an **in-process self-test table**.
  The only `CfExecute` call uses `STATUS_CLOUD_FILE_UNSUCCESSFUL` and
  `Buffer = nullptr`; the executable accepts `--self-test` only. It has no
  `CfRegisterSyncRoot`, `CfConnectSyncRoot`, placeholder creation, or
  attached user-mode provider process.
- `sync-client/rootark-sync-windows-cfapi-fetch-gate.js:98-248` is a
  bounded **deny-only** contract around an injected native interface.
  `fetchData` always calls `failOnce`; simulated `signedAdmission`,
  CAS, journal, or placeholder metadata cannot grant positive transfer.
  `inspectNoLink` uses pathname checks and expressly is not a native,
  handle-relative identity lock (`:72-96`).
- `sync-client/rootark-sync-engine.js:2396-2474` gets a full remote
  envelope by `adapter.list(objectId)` and invokes `_apply()`.
  `_apply` decrypts with a caller-supplied local `fileKeyResolver` and
  writes an ordinary temporary file followed by rename
  (`:1778-1782,1932-1937`). This cannot safely hydrate an existing CFAPI
  placeholder at its native file identity.
- `sync-client/rootark-sync-authorization.js:122-158` has real
  Ed25519-envelope verification **when an independently supplied device-key
  pin, username and current revocation list exist**. The engine takes
  `verifyIncoming`, local key resolution, witness and CAS-floor readers
  from its embedding caller (`rootark-sync-engine.js:423-515,676-731`).
  There is no proven owner-issued placeholder/object digest binding to an
  independently pinned, retained CURRENT head in the native callback.
  A signed client envelope, metadata inventory, local pin or journal entry
  alone cannot supply that missing external trust.

## Real platform evidence (2026-11-08 UTC)

The inspected host reports **Microsoft Windows 11 Pro, OS build 26300**
via `Win32_OperatingSystem`. The backward-compatible
`HKLM/.../CurrentVersion.ProductName` string says `Windows 10 Pro`;
that string is **not** proof of a physical Windows 10 test.
`CldFlt` is running and `CldApi.dll` is present. The repository's
read-only P/Invoke probe, executed on a tracked ordinary source file
without registering a provider, returned
`nativeAvailable=true`, CFAPI **platform** build `26100`,
`placeholderState=0`, `placeholder=false`,
`syncRoot=false`. The platform API version and OS build are distinct.

Existing regression gates on this exact source:

- Windows Node **24.14.1**:
  `node --test test/issue-66-cfapi-fetch-gate.test.js test/issue-66-cfapi-deny-callback-native.test.js`
  — **23 PASS / 0 FAIL**, including real MSVC/SDK compilation and a
  mock-`CfExecute` denial completion. The SDK self-test is not a
  Windows kernel `FETCH_DATA` callback.
- WSL Ubuntu Node **22.22.1**, same two suites:
  **21 PASS / 0 FAIL / 2 platform SKIP** (native Windows compilation
  and Windows case-fold test). These are source-gate tests only.
- **Not run / unavailable:** Windows Node22 execution, Windows 10
  physical machine, registered disposable sync root, positive kernel
  callback, client-enrolled owner key custody, independent off-host R1
  floor/issuer, and positive end-to-end object hydration.

## Minimum positive design: one bounded, regular file

Do not enable positive transfer until the following interfaces and proofs
exist **in the same source tree**, with exact independent review.

1. **Owner-approved trust root.** Provision, outside the untrusted sync
   server, immutable owner/account/store and trusted device Ed25519 public
   keys, current device revocations, key epoch and an independent monotonic
   CURRENT-head/floor reader. Verify an owner-signed descriptor binding
   `account/store + objectId + fileId + versionId + operationId + revision
   + path + keyEpoch + ciphertext digest + declared plaintext size`
   to the retained head and externally provisioned device scope.
   Reject absent, stale, replaced, revoked or equivocated evidence before
   requesting the CEK. The current `listInventory` is advisory, never an
   issuance or owner-authority proof.
2. **Stable native placeholder identity.** After that signed descriptor
   is accepted, create a placeholder only in an explicitly approved,
   disposable registered sync root. Embed an opaque, versioned and
   authenticated descriptor reference in `FileIdentity`; retain a
   durable per-placeholder identity/pin record across restart. On each
   `FETCH_DATA`, validate callback connection/transfer/request keys,
   caller-bound sync-root identity, placeholder `FileIdentity` and file
   size against an open `HANDLE` with no reparse traversal. Keep that
   same native identity pinned through `CfExecute`; reject path swaps,
   hardlinks, junctions, aliasing, foreign provider roots and deleted or
   replaced placeholders.
3. **Detached immutable ciphertext.** Resolve the exact object/version
   from a content-addressed immutable blob/handle. Independently verify
   ciphertext digest, owner/device signature, epoch, live revocation,
   CURRENT head, retained monotonic floor and journal restart state.
   Recheck current authority immediately before transfer and fail on
   any change during network fetch, decryption, native validation or ACK.
   Reject partial/unsigned blobs, same-size replacements, clock rollback,
   concurrent delete/revoke and offline/unavailable authority.
4. **Local-only authenticated plaintext.** The provider-owned local
   verifier may resolve the CEK **after** admission and AEAD-verify the
   **entire** detached encrypted object into a bounded ephemeral buffer.
   Never send the CEK or plaintext to the server, log them, store a
   plaintext temp file or pass them to `_apply()`. For a first milestone,
   cap the entire file to **1 MiB** and fail larger files closed: the
   current single-tag AEAD format does not justify releasing unverified
   streamed chunks. Hold the buffer stable until the native transfer
   completes; zeroize key/plaintext on every completion, cancellation,
   error and shutdown.
5. **Native positive completion.** For a matching active request only,
   issue `CfExecute(CF_OPERATION_TYPE_TRANSFER_DATA)` with
   `CompletionStatus=STATUS_SUCCESS`, a valid buffer and an offset aligned
   to **4096 bytes**. Length is 4096-aligned except for a range ending
   at/beyond the exact logical EOF. Support independently bounded
   repeated ranges, EOF and a verified empty file. On timeout, replay,
   cancellation, identity change, revocation or error, complete the
   request once with a proper `STATUS_CLOUD_FILE_*` failure, and never
   transfer stale or unverified bytes. A native watchdog must own failure
   completion if the JS bridge stalls or exits; abort signals alone do
   not force native APIs to finish.

## Acceptance tests and evidence labels

**First TDD RED (native in-process contract, no registration):**
an owner-signed, externally pinned exact 1-byte and 4097-byte fixture
should deliver correct aligned CFAPI buffer/range only after independently
verifying ciphertext/AEAD and live head. Today **no such positive
provider exists**, so do not mark these tests GREEN merely by invoking
a mock success. Negative cases: forged owner descriptor/device pin,
tampered ciphertext/tag, same-size content swap, rollback/stale CAS
floor, replayed version or epoch, revoked device before CEK and
revocation during stalled fetch, duplicate key, callback cancellation,
bad/oversized range, 0-byte object, inaccessible external witness,
non-cooperative inspector and bounded pending ACK exhaustion.

**Second TDD RED (native identity/crash):** handle-relative source/target
swap after each admission boundary; symlink, junction/reparse, ADS,
hardlink and foreign sync-root alias; power-loss/restart between
signed pin, placeholder creation, journal fsync, transfer and final ACK;
concurrent writer/delete, stale CEK, partial hydration and eviction.
Assert **zero bytes transferred** and no stale success on every denial.
All tests must prove one exact signed object identity survives restart.

**Physical acceptance (separate owner-approved sandbox):** genuine
Windows **10 22H2** and Windows **11** with actual
`CfRegisterSyncRoot`/`CfConnectSyncRoot`, OS-created callback after
ordinary Explorer/open/read access, exact contents/byte ranges/EOF,
cancel/disconnect/restart/re-registration, user lock and failure
recovery; remove only the disposable registration. Capture source SHA,
physical OS build, CFAPI platform version, native traces and denial
results. In-process callback invocation, P/Invoke attribute probing,
mock `CfExecute`, PowerShell `Out-GridView` hydration and successful
Linux/Windows Node tests are **not** substitutes for this gate.

Current conclusion: **SOURCE NO-GO for positive CFAPI hydration**.
The compiled deny-only callback and platform probe remain valid limited
milestones. Do not claim a working provider, Windows 10 proof, global
Zero-Knowledge cutover, Ready, or production authority based on this
document. Independent exact-SHA peer review is required before publishing
even this documentation.

Native API reference:
<https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_operation_parameters>
and
<https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfgetplatforminfo>.
