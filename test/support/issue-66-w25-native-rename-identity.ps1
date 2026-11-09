param(
  [ValidateSet('RW', 'NONE')][string]$Share,
  [ValidateSet('DOTNET', 'WIN32')][string]$Move,
  [string]$Scratch
)

$ErrorActionPreference = 'Stop'
try {
  if ($env:ROOTARK_ISSUE66_W25_NATIVE_IO_LAB -ne '1') { throw 'LAB_DISABLED' }
  $local = [System.IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)).TrimEnd('\')
  $directory = [System.IO.DirectoryInfo]::new($Scratch)
  if (-not $directory.Exists -or
      $directory.Name -notmatch '^rootark-w25-rename-identity-[A-Za-z0-9_-]{6,}$' -or
      -not [string]::Equals($directory.Parent.FullName.TrimEnd('\'), $local,
        [StringComparison]::OrdinalIgnoreCase) -or
      ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $directory.GetFileSystemInfos().Count -ne 0 -or
      (([System.IO.DirectoryInfo]::new($local)).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'UNTRUSTED_SCRATCH'
  }

  Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class RootarkW25RenameIdentityProof {
  [StructLayout(LayoutKind.Sequential)]
  private struct FILE_ID_INFO {
    public ulong VolumeSerialNumber;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] FileId;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct UNICODE_STRING {
    public ushort Length, MaximumLength;
    public IntPtr Buffer;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct OBJECT_ATTRIBUTES {
    public int Length;
    public IntPtr RootDirectory, ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor, SecurityQualityOfService;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct IO_STATUS_BLOCK {
    public IntPtr Status, Information;
  }

  [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
    SetLastError = true)]
  private static extern SafeFileHandle CreateFile(string filename, uint access, uint share,
    IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetInfo(SafeFileHandle handle, int klass,
    out FILE_ID_INFO info, uint size);
  [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW",
    CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern uint GetName(SafeFileHandle handle, StringBuilder output,
    uint outputLength, uint flags);
  [DllImport("kernel32.dll", EntryPoint = "GetHandleInformation", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool HandleInfo(SafeFileHandle handle, out uint flags);
  [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode,
    SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool MoveFileEx(string source, string target, uint flags);
  [DllImport("ntdll.dll", EntryPoint = "NtCreateFile", ExactSpelling = true)]
  private static extern int NtCreateFile(out SafeFileHandle result, uint access,
    ref OBJECT_ATTRIBUTES attributes, out IO_STATUS_BLOCK status,
    IntPtr allocationSize, uint fileAttributes, uint share, uint disposition,
    uint options, IntPtr ea, uint eaSize);

  private static FILE_ID_INFO Id(SafeFileHandle handle) {
    FILE_ID_INFO result;
    if (!GetInfo(handle, 18 /* FileIdInfo */, out result,
        (uint)Marshal.SizeOf(typeof(FILE_ID_INFO))) || result.FileId == null ||
        result.FileId.Length != 16)
      throw new InvalidOperationException("GET_FILE_ID_FAILED");
    return result;
  }
  private static bool Same(FILE_ID_INFO left, FILE_ID_INFO right) {
    if (left.VolumeSerialNumber != right.VolumeSerialNumber) return false;
    for (int i = 0; i < 16; ++i)
      if (left.FileId[i] != right.FileId[i]) return false;
    return true;
  }
  private static string CanonicalPath(SafeFileHandle handle) {
    var output = new StringBuilder(4096);
    uint count = GetName(handle, output, (uint)output.Capacity, 0);
    if (count == 0 || count >= output.Capacity)
      throw new InvalidOperationException("GET_FINAL_PATH_FAILED");
    return output.ToString();
  }
  private static SafeFileHandle OpenDirectory(string path, uint share) {
    var h = CreateFile(path, 0x00020080 /* READ_CONTROL | READ_ATTRIBUTES */,
      share, IntPtr.Zero, 3 /* OPEN_EXISTING */,
      0x02200000 /* OPEN_REPARSE_POINT|BACKUP_SEMANTICS */, IntPtr.Zero);
    if (h == null || h.IsInvalid) throw new InvalidOperationException("CREATE_FILE_FAILED");
    return h;
  }
  private static SafeFileHandle OpenChild(SafeFileHandle parent, out int nativeStatus) {
    const string leaf = "child"; // NO absolute path and NO caller-supplied leaf
    IntPtr buffer = Marshal.StringToHGlobalUni(leaf);
    IntPtr unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    try {
      var u = new UNICODE_STRING { Length = (ushort)(leaf.Length * 2),
        MaximumLength = (ushort)((leaf.Length + 1) * 2), Buffer = buffer };
      Marshal.StructureToPtr(u, unicode, false);
      var attributes = new OBJECT_ATTRIBUTES {
        Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
        RootDirectory = parent.DangerousGetHandle(), ObjectName = unicode,
        Attributes = 0x00001040 /* OBJ_DONT_REPARSE|OBJ_CASE_INSENSITIVE */
      };
      IO_STATUS_BLOCK status;
      SafeFileHandle child;
      nativeStatus = NtCreateFile(out child, 0x00020080,
        ref attributes, out status, IntPtr.Zero, 0,
        3 /* SHARE_READ|SHARE_WRITE */, 1 /* FILE_OPEN */,
        0x00200001 /* FILE_OPEN_REPARSE_POINT|FILE_DIRECTORY_FILE */,
        IntPtr.Zero, 0);
      if (nativeStatus != 0) {
        if (child != null) child.Dispose();
        throw new InvalidOperationException("ROOT_RELATIVE_OPEN_FAILED");
      }
      return child;
    } finally {
      Marshal.FreeHGlobal(unicode);
      Marshal.FreeHGlobal(buffer);
    }
  }

  public static string Probe(string scratch, string shareMode, string moveMode) {
    uint share = shareMode == "NONE" ? 0U : 3U;
    string oldPath = Path.Combine(scratch, "held-ancestor");
    string movedPath = Path.Combine(scratch, "moved-ancestor");
    Directory.CreateDirectory(Path.Combine(oldPath, "child")); // setup pathname
    using (var root = OpenDirectory(oldPath, share)) {
      uint handleFlags;
      if (!HandleInfo(root, out handleFlags))
        throw new InvalidOperationException("INVALID_HANDLE");
      FILE_ID_INFO before = Id(root);
      string beforeName = CanonicalPath(root);
      if (!beforeName.EndsWith("\\held-ancestor", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("WRONG_INITIAL_HANDLE");

      bool moved = false;
      // For MoveFileExW this is the *actual* Marshal/GetLastError result.
      // Win32 GetLastError is only meaningful when the API fails; an observed
      // zero after success is data, not a separate security assurance.
      int win32LastError = 0;
      string win32Status = "NA_DOTNET";
      if (moveMode == "WIN32") {
        moved = MoveFileEx(oldPath, movedPath, 0);
        win32LastError = Marshal.GetLastWin32Error();
        win32Status = win32LastError.ToString();
      } else {
        try {
          Directory.Move(oldPath, movedPath);
          moved = true;
        } catch (IOException error) {
          win32LastError = error.HResult & 0x0000ffff;
          win32Status = "HRESULT_" + ((uint)error.HResult).ToString("X8");
        }
      }
      if (!moved) {
        return "ROOTARK_W25_RENAME_V2 mode=" + moveMode + " share=" + share +
          " handle=VALID move=DENIED win32LastError=" + win32Status +
          " ntstatus=NA identity=UNMOVED";
      }

      // Act as a separate untrusted pathname observer. A new directory at the
      // original name must NOT cause the old root HANDLE to change identity.
      Directory.CreateDirectory(Path.Combine(oldPath, "child")); // adversarial
      FILE_ID_INFO after = Id(root);
      uint afterHandleFlags;
      if (root.IsInvalid || root.IsClosed || !HandleInfo(root, out afterHandleFlags))
        throw new InvalidOperationException("ROOT_HANDLE_NO_LONGER_VALID");
      string afterName = CanonicalPath(root);
      using (var movedRoot = OpenDirectory(movedPath, 3))
      using (var replacement = OpenDirectory(oldPath, 3)) {
        FILE_ID_INFO movedId = Id(movedRoot);
        FILE_ID_INFO replacementId = Id(replacement);
        int nativeStatus;
        using (var child = OpenChild(root, out nativeStatus)) {
          FILE_ID_INFO oldChild = Id(child);
          string childName = CanonicalPath(child);
          using (var replacementChild = OpenDirectory(Path.Combine(oldPath, "child"), 3)) {
            if (!Same(before, after) || !Same(before, movedId) ||
                Same(before, replacementId) || Same(oldChild, Id(replacementChild)) ||
                !afterName.EndsWith("\\moved-ancestor", StringComparison.OrdinalIgnoreCase) ||
                !childName.EndsWith("\\moved-ancestor\\child", StringComparison.OrdinalIgnoreCase))
              throw new InvalidOperationException("ROOT_HANDLE_IDENTITY_MISMATCH");
          }
          // O1/O2 are mapped object identifiers from actual FileIdInfo bytes.
          // Never reveal filesystem paths, raw file IDs or volume serials.
          return "ROOTARK_W25_RENAME_V2 mode=" + moveMode + " share=" + share +
            " handle=VALID move=SUCCESS win32LastError=" + win32Status + " ntstatus=0x" +
            ((uint)nativeStatus).ToString("X8") +
            " rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL";
        }
      }
    }
  }
}
'@ | Out-Null

  [Console]::Out.WriteLine([RootarkW25RenameIdentityProof]::Probe(
    $directory.FullName, $Share, $Move))
  exit 0
} catch {
  [Console]::Error.WriteLine('ROOTARK_W25_RENAME_REJECTED')
  exit 41
}
