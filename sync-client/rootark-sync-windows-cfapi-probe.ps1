# Read-only Windows Cloud Files platform/attribute probe. This is NOT a
# sync-root provider. Do not register a sync root or turn on implicit hydration.
# The caller must opt in explicitly. No private sync config, tokens or file
# contents are read. FILE_FLAG_OPEN_REPARSE_POINT prevents following a link.
[CmdletBinding()]
param(
  [switch]$AllowNativeProbe,
  [Parameter(Mandatory = $true)][string]$LiteralPath
)

$ErrorActionPreference = 'Stop'
if (-not $AllowNativeProbe) { throw 'Native CFAPI probe requires -AllowNativeProbe.' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw 'Native CFAPI probe requires Windows.'
}

$native = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class RootarkCfapiReadOnly {
    [StructLayout(LayoutKind.Sequential)]
    public struct PlatformInfo {
        public uint BuildNumber;
        public uint RevisionNumber;
        public uint IntegrationNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    public struct NativeState {
        public uint Attributes;
        public uint ReparseTag;
        public uint PlaceholderState;
        public int SyncRootLookupHresult;
    }

    [DllImport("cldapi.dll", ExactSpelling = true)]
    private static extern int CfGetPlatformInfo(out PlatformInfo info);

    [DllImport("cldapi.dll", ExactSpelling = true)]
    private static extern uint CfGetPlaceholderStateFromAttributeTag(uint attributes, uint tag);

    [DllImport("cldapi.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int CfGetSyncRootInfoByPath(
        string path, int infoClass, IntPtr infoBuffer, uint bufferLength, out uint returnedLength);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string path, uint access, uint share, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle, int infoClass, out FileAttributeTagInfo info, uint size);

    public static PlatformInfo GetPlatform() {
        PlatformInfo info;
        int result = CfGetPlatformInfo(out info);
        if (result < 0) Marshal.ThrowExceptionForHR(result);
        return info;
    }

    public static NativeState GetState(string path) {
        // FILE_READ_ATTRIBUTES / FILE_SHARE_READ|WRITE|DELETE / OPEN_EXISTING
        // FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS: do not open
        // the contents and do not follow reparse-point targets.
        using (SafeFileHandle handle = CreateFile(path, 0x80, 0x7, IntPtr.Zero,
            3, 0x02200000, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            FileAttributeTagInfo tag;
            if (!GetFileInformationByHandleEx(handle, 9, out tag, 8)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint state = CfGetPlaceholderStateFromAttributeTag(tag.FileAttributes, tag.ReparseTag);
            if (state == UInt32.MaxValue) throw new InvalidOperationException("CFAPI returned an invalid placeholder state");
            int lookup = unchecked((int)0x80004005); // Do not resolve reparse points.
            if ((tag.FileAttributes & 0x400) == 0) {
                IntPtr buffer = Marshal.AllocHGlobal(8);
                try {
                    uint required;
                    lookup = CfGetSyncRootInfoByPath(path, 0, buffer, 8, out required);
                } finally { Marshal.FreeHGlobal(buffer); }
            }
            return new NativeState { Attributes = tag.FileAttributes,
                ReparseTag = tag.ReparseTag, PlaceholderState = state,
                SyncRootLookupHresult = lookup };
        }
    }
}
'@

try {
  Add-Type -TypeDefinition $native -ErrorAction Stop
  $platform = [RootarkCfapiReadOnly]::GetPlatform()
  $nativeState = [RootarkCfapiReadOnly]::GetState($LiteralPath)
  $state = [uint32]$nativeState.PlaceholderState
  # Intentionally omit the inspected absolute path from stdout.
  [pscustomobject]@{
    api = 'Windows Cloud Files CFAPI'
    readOnly = $true
    nativeAvailable = $true
    platformBuild = [uint32]$platform.BuildNumber
    platformRevision = [uint32]$platform.RevisionNumber
    platformIntegration = [uint32]$platform.IntegrationNumber
    placeholderState = [uint32]$state
    reparsePoint = ($nativeState.Attributes -band 0x400) -ne 0
    syncRootLookupSucceeded = ($nativeState.SyncRootLookupHresult -eq 0)
    placeholder = ($state -band 1) -ne 0
    syncRoot = ($state -band 2) -ne 0
    inSync = ($state -band 8) -ne 0
    partial = ($state -band 16) -ne 0
    partiallyOnDisk = ($state -band 32) -ne 0
  } | ConvertTo-Json -Compress
} catch {
  # Never report a success-shaped result on missing entry points or errors.
  [Console]::Error.WriteLine('Native CFAPI inspection failed: ' + $_.Exception.GetType().Name)
  exit 1
}
