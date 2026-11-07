# Issue #66 — native Windows CFAPI deny-only callback boundary (W12)

Base: Draft PR #300 `9f3e3ffa8213dd3be310790485c1f3c6708455d6`,
parent `0b39561164074c83efe31b37b57ae088c379c826`.

The Windows Cloud Files API exists on this host: Windows **11** build 26300,
Windows SDK `10.0.26100.0` with `cfapi.h`/`CldApi.lib`, and native `CldApi.dll`.
Visual Studio 18 Insiders MSVC x64 can compile the actual callback ABI.
This does **not** validate Windows 10 or exercise an actual registered sync root.

## Executable change

- `rootark-sync-windows-cfapi-deny-callback.cpp` includes the **actual**
  `cfapi.h`, links `CldApi.lib`, calls `CfGetPlatformInfo`, defines a native
  `CF_CALLBACK_TYPE_FETCH_DATA` registration table and constructs the proper
  `CF_OPERATION_TYPE_TRANSFER_DATA` failure completion with
  `STATUS_CLOUD_FILE_UNSUCCESSFUL`, a null buffer and the requested range.
  Only `--self-test` is executable. The test invokes the callback against a
  mocked `CfExecute` function in-process and checks the status, type, range,
  and absence of content bytes. There is **no** `CfRegisterSyncRoot`,
  `CfConnectSyncRoot`, hydration, runtime integration, CEK or plaintext.
- `rootark-sync-windows-cfapi-fetch-gate.js` defines the provisional Node
  callback ingress contract: strictly-shaped `FETCH_DATA`, bounded offset and
  length, portable path restrictions, lstat on each component, no symlinks,
  hardlinks, reparse redirection or ordinary-file claims, a native inspection
  result that must positively identify a placeholder in the expected sync
  root, cancellation, duplicate request identity and draining shutdown.
  All requests end in `native.failFetch`; a spoofed `signedAdmission`, local
  journal flag or CAS number cannot create authorization. `native` is an
  injected **mock interface**, not a connected production provider.

Both surfaces deliberately fail every request. They cannot create, overwrite,
evict, pin, unpin, register, hydrate or transfer plaintext. Native path checks
are advisory and cannot defend against a live handle/path swap; they are
therefore never used as a positive authorization signal.

## Bounded callback lifetime (follow-up to W2 P2)

The mock-boundary JS gate now uses an abortable request state machine. Its
defaults are **1,500 ms inspection deadline**, **250 ms failure-ACK deadline**,
**32 concurrently admitted requests**, and **4,096 distinct lifetime request
keys** (constructor options are validated and capped). On cancellation,
shutdown, or inspection timeout it aborts an `AbortSignal` supplied as the
second `native.inspectPlaceholder(path, { signal })` argument. The gate returns
after an attempted failure completion even if the inspector ignores cancellation.

The entire asynchronous inspection, including filesystem path checks, keeps
one inspection slot until it actually settles, so non-cooperative operations
cannot accumulate without a bound by timing out repeatedly. An admitted
request triggers **one** best-effort `native.failFetch(key, code, { signal })`;
an unresponsive ACK returns `failure_ack_timeout` and is never retried under
the same request key. `shutdown()` aborts outstanding inspection requests and
awaits only their bounded failure ACKs, then refuses new callbacks. Late
positive inspection results are ignored and do not transfer data.

When an unadmitted request exceeds concurrency or the lifetime key limit,
`fetchData` returns `capacity_exceeded` without calling `failFetch`: the
future native dispatcher must complete such CFAPI requests with its **own**
fail-closed error, as no callback has been admitted by the mock JS gate.
Similarly, this interface cannot guarantee a native failure completion if
the callback process crashes, the native adapter hangs, or an ACK times out.
Cooperative cancellation and an independent bounded native fallback are still
required before any real registration. A JavaScript AbortSignal cannot forcibly
stop a non-cooperative native operation, so those operations retain their
inspection budget until they settle or the process exits.
The JavaScript deadline also cannot preempt a synchronous native call that
blocks the event loop; an actual native dispatcher needs a separate watchdog.

## Verification

Windows tests (native compiler discovered using `vswhere -prerelease`):

```powershell
node --test test/issue-66-cfapi-fetch-gate.test.js test/issue-66-cfapi-deny-callback-native.test.js
```

Native binary and build artifacts are created in a disposable system temp
directory and removed after testing. Test code does not register a root or
connect a provider. On Linux, the native compilation case skips; the Node
callback contract is portable.

Microsoft's CFAPI contract requires the `TRANSFER_DATA` operation with a
failing `STATUS_CLOUD_FILE_*` completion status when a `FETCH_DATA` request
cannot be hydrated. See:
https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_operation_parameters

## Remaining authority blockers

1. Map each placeholder's **native immutable identity** to a trusted owner
   signed object/version and independently pinned current device permission.
   The paginated metadata inventory is advisory and insufficient.
2. Verify independent witness admission and monotonic CAS head/floor and
   reconcile durable journal repairs/restarts **before** any owner CEK release.
   Signed envelopes and local snapshot/pin flags are insufficient on their own.
3. Decode and verify AEAD into an ephemeral bounded buffer without writing to
   the placeholder path. `_materializeOnDemand()` currently calls `_apply()`
   and writes an ordinary path; it is incompatible with native placeholders.
4. Build an approved native connection lifetime with handle-relative
   no-reparse validation, cancellation, file identity and write race checks,
   exact offsets/EOF/4KiB semantics and failure propagation. Review with a
   genuinely registered disposable sync root on **Windows 10 and 11**, and
   independently audit a signed/success path before shipping any provider.

**Status: fail-closed contract only.** Issue #66 native Files On-Demand remains
NO-GO for registration, deployment, Ready or real hydration.
