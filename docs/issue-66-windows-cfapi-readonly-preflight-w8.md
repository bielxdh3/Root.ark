# Issue #66: Windows Cloud Files native preflight (limited)

Scope: local, read-only CFAPI interoperability on a disposable fixture. This
does **not** implement Files On-Demand native placeholders, a Windows sync
provider, on-access fetch, or automatic hydration. Issue #66 remains open.

## What is executable

On a Windows host, explicitly run:

```powershell
powershell.exe -NoProfile -NonInteractive -File sync-client/rootark-sync-windows-cfapi-probe.ps1 -AllowNativeProbe -LiteralPath <existing-disposable-file>
```

The PowerShell script compiles a short C# P/Invoke type with the installed .NET
Framework compiler. It calls the **actual OS** `cldapi.dll` exports
`CfGetPlatformInfo`, `CfGetPlaceholderStateFromAttributeTag`, and (for
non-reparse paths) `CfGetSyncRootInfoByPath`. Its attribute/tag pair comes from
`GetFileInformationByHandleEx(FileAttributeTagInfo)` on a handle opened with
`FILE_READ_ATTRIBUTES`, `FILE_FLAG_OPEN_REPARSE_POINT`, and sharing enabled.
The probe never opens file contents, writes bytes, registers a sync root,
creates a placeholder, or connects a provider. Output has no inspected path,
content, credentials, tokens, or file identity. No positive result authorizes
hydration, deletion, eviction, or pinning.

For an absent file, unavailable API, invalid native state, or missing opt-in,
the command exits unsuccessfully with no success-shaped JSON. The `placeholder`
and `syncRoot` fields describe only flags derived from the inspected object's
native attribute/tag pair. `syncRootLookupSucceeded` reflects the OS query;
failure is not an authorization or proof that a device is not managed by a
provider. Reparse points are not followed or used for sync root lookup.

## Host evidence and limits

- Host inspected 2026-11-07: Windows 11 Pro kernel build 26300 with
  `C:\Windows\System32\CldApi.dll`, SDK
  `10.0.26100.0\um\cfapi.h` and `x64\cldapi.lib` installed.
  Build 26100 is Windows **11**; this is not Windows 10 hardware validation.
- Native P/Invoke from Windows PowerShell 5.1/.NET Framework succeeded on an
  ordinary file. Node's executable in PATH was **v24.14.1**, not Node 22.
- WSL Ubuntu Node **v22.22.1** ran the selective-sync baseline successfully;
  the Windows-native CFAPI tests correctly skip on Linux.
- The harness has no registered Root.ark sync root or Cloud Files callbacks.
  A Windows symlink negative-control test requires local symlink privilege and
  may be skipped. Real CFAPI placeholder and kernel callback tests remain open.

## Required to deliver on-open native hydration

1. Isolated provider process with a verified, explicitly approved sync-root
   registration lifecycle (`CfRegisterSyncRoot`, `CfConnectSyncRoot`, callbacks,
   disconnect/unregister), safe restarts and OS notifications. Persistent
   registration in the user's Windows profile requires separate approval.
2. Define a signed object identity mapped to each native placeholder. The
   existing paginated `listInventory` is **advisory metadata**, not a signed
   trust anchor. Do not create filesystem placeholders from it as authority.
3. Refactor the portable verifier to return owner/device-authorized, AEAD
   verified exact bytes into a provider-owned ephemeral buffer before issuing
   `CfExecute(TRANSFER_DATA)` for `FETCH_DATA`. The current
   `SyncEngine._materializeOnDemand` instead writes to the regular local path
   through `_apply`, so it cannot safely be called with an existing native
   placeholder at that path.
4. Implement zero-byte and chunked range handling, cancellation and restart,
   concurrent request identity binding, revocation checks, deterministic
   offline failures, and correct pin/eviction journal recovery. Validate no
   implicit filesystem or foreign-provider hydration before signed
   verification. Test with a **disposable registered sync root** on actual
   Windows 10 and 11, including modified ciphertext and revoked devices.

Until these boundaries have implementation and real tests, **NO-GO** for a
native Files On-Demand provider, production integration, `Ready`, or PR
publication of a provider claim. This probe is a read-only platform primitive
that can be reviewed independently while those gaps remain.
