# Issue #66 — native CFAPI range shape probe (W17; DEV-OFF, no hydration)

Baseline: published Draft #300
`f77cf6396fda42b6b9730751e27390db598a02db`. This is a
test-only source increment, **not** a working positive Cloud Files provider.
It does not weaken the `SOURCE NO-GO` for actual positive hydration stated
in `docs/issue-66-cfapi-positive-hydration-readiness-w46.md`.

## Physical Windows capability established

- This host is **Windows 11 Pro**, `Win32_OperatingSystem` build **26300**;
  the legacy registry `ProductName = Windows 10 Pro` does not prove a
  physical Windows 10 run.
- `CldFlt` is running, `CldApi.dll` exists, and Windows SDK 26100
  provides `cfapi.h` / `cldapi.lib` with working MSVC x64 tools.
- The read-only file-attribute probe and `CfGetPlatformInfo` establish API
  availability, not a registered Root.ark sync root or a working callback.
- The in-process executable obtains, but **never calls**, the addresses of
  `CfRegisterSyncRoot`, `CfConnectSyncRoot` and
  `CfHydratePlaceholder`. No registration, sync-root lookup mutation, file
  decryption, network access, browser operation or Cloud Files transfer occurs.

## Exact limited contract

- `sync-client/rootark-sync-windows-cfapi-positive-shape.cpp` accepts
  **only** `--self-test`. All other arguments return a nonzero exit code.
- It builds `CF_OPERATION_INFO` and `CF_OPERATION_PARAMETERS.TransferData`
  in process from disposable byte vectors and checks their SDK field sizes,
  `CF_OPERATION_TYPE_TRANSFER_DATA`, `STATUS_SUCCESS` representation,
  nonnull buffer, 4096-aligned offset and bounded length.
- Success-shaped **mock parameters** cover an exact **1-byte** file and a
  **4097-byte** file split at offset 4096 (4096 plus one-byte EOF remainder).
  Nine invalid ranges are rejected. A verified empty object requires a
  different physical no-transfer path and is not treated as an authorized
  positive `TRANSFER_DATA`.
- The mock increments its **local** counter for three inspected structures
  (4098 total inspected bytes). It does **not** call `CfExecute`, register
  `CF_CALLBACK_TYPE_FETCH_DATA`, or transfer any bytes through the OS.
  Output always labels `positiveHydrationAuthorized: false`,
  `syncRootRegistered: false`, `providerConnected: false`,
  `kernelCallbackInvoked: false` and
  `cloudDataBytesTransferred: 0`.
- The first milestone deliberately rejects files above **1 MiB**; no
  speculative chunk-wise AEAD release or ordinary plaintext temp writes.
  This mock has **no owner-signed descriptor, no trusted CEK, no R1 witness
  or independent monotonic floor**. Passing it is not an authorization proof.

## Reproducible tests, bounded cleanup

```powershell
node --test test/issue-66-cfapi-positive-shape-native.test.js
node --test test/issue-66-cfapi-fetch-gate.test.js test/issue-66-cfapi-deny-callback-native.test.js
```

The new Node test rejects any code attempting to invoke sync-root
registration, provider connection, native hydration or real `CfExecute`.
On Windows, it builds the C++ ABI probe with the installed MSVC/SDK in a new
OS temporary directory; `t.after` removes that disposable build after
normal test completion, including ordinary test failures. A forced process
kill may leave harmless compiler artifacts, **never a registered provider**.
On WSL/Linux the native compile test is explicitly skipped, not counted
as positive physical evidence.

Original Windows test baseline: Node **24.14.1**; WSL Ubuntu Node
**22.22.1**. Native Windows Node22 is not installed in the inspected PATH.
The new contract followed missing-source RED and green real-SDK compilation.

## Remains unproven — do not deploy

Actual positive `FETCH_DATA` requires a disposable *owner-approved* sync
root with guaranteed registration cleanup, genuine kernel callbacks on
Windows 10 22H2 and Windows 11, independently owner-signed object/placeholder
identity, live off-host R1 CURRENT/floor and revocation proofs, CEK admission,
whole-object AEAD verification, pinned native HANDLE, cancellation/watchdog,
safe zeroization, crash recovery and exact EOF/range replay tests. None of
those physical or custody gates is established by this mock.
