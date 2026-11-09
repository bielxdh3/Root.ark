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
  private struct FILE_ATTRIBUTE_TAG_INFO {
    public uint Attributes, ReparseTag;
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
  [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx",
    SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetTag(SafeFileHandle handle, int klass,
    out FILE_ATTRIBUTE_TAG_INFO info, uint size);
  [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationByHandleW",
    CharSet = CharSet.Unicode, SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetVolume(SafeFileHandle handle,
    StringBuilder volumeName, uint volumeNameCapacity, IntPtr serial,
    IntPtr maxComponent, IntPtr flags, StringBuilder fileSystem, uint fsCapacity);
  [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode)]
  private static extern uint GetDriveType(string rootPath);
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
  private static void RequireLocalNtfs(SafeFileHandle handle) {
    var fs = new StringBuilder(32);
    if (!GetVolume(handle, null, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
        fs, (uint)fs.Capacity) ||
        !string.Equals(fs.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase))
      throw new InvalidOperationException("NTFS_REQUIRED");
    string name = CanonicalPath(handle);
    // Exclude UNC/network volumes and remapped paths; only fixed local drives.
    if (name.Length < 7 ||
        !name.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ||
        !char.IsLetter(name[4]) || name[5] != ':' || name[6] != '\\' ||
        GetDriveType(name.Substring(4, 3)) != 3 /* DRIVE_FIXED */)
      throw new InvalidOperationException("LOCAL_FIXED_NTFS_REQUIRED");
  }
  private static void RequirePlainDirectory(SafeFileHandle handle) {
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (!GetTag(handle, 9 /* FileAttributeTagInfo */, out tag,
        (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))) ||
        (tag.Attributes & 0x10 /* DIRECTORY */) == 0 ||
        (tag.Attributes & 0x400 /* REPARSE_POINT */) != 0)
      throw new InvalidOperationException("NOT_PLAIN_DIRECTORY");
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
  private static void RequireScratchBinding(
      SafeFileHandle retained, string scratch, FILE_ID_INFO originalId) {
    RequirePlainDirectory(retained);
    if (!Same(originalId, Id(retained)))
      throw new InvalidOperationException("SCRATCH_HANDLE_CHANGED");
    using (var current = OpenDirectory(scratch, 7)) {
      RequirePlainDirectory(current);
      if (!Same(originalId, Id(current)))
        throw new InvalidOperationException("SCRATCH_PATH_CHANGED");
    }
  }
  private static SafeFileHandle OpenRelativeDirectory(
      SafeFileHandle parent, string leaf, uint share, bool create,
      out int nativeStatus) {
    // Only literal names from this test. Never allow user-provided paths.
    if (leaf != "held-ancestor" && leaf != "moved-ancestor" && leaf != "child")
      throw new InvalidOperationException("UNTRUSTED_LEAF");
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
        ref attributes, out status, IntPtr.Zero, 0x10 /* DIRECTORY */,
        share, create ? 2U /* FILE_CREATE */ : 1U /* FILE_OPEN */,
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
  private static SafeFileHandle OpenChild(SafeFileHandle parent, out int nativeStatus) {
    return OpenRelativeDirectory(parent, "child", 3, false, out nativeStatus);
  }

  public static string Probe(string scratch, string shareMode, string moveMode) {
    uint share = shareMode == "NONE" ? 0U : 3U;
    string oldPath = Path.Combine(scratch, "held-ancestor");
    string movedPath = Path.Combine(scratch, "moved-ancestor");
    // Retain the actual disposable scratch object and create fixture children
    // by NtCreateFile relative to its HANDLE, never by joined absolute path.
    using (var scratchRoot = OpenDirectory(scratch, 7)) {
      RequireLocalNtfs(scratchRoot);
      RequirePlainDirectory(scratchRoot);
      FILE_ID_INFO scratchId = Id(scratchRoot);
      RequireScratchBinding(scratchRoot, scratch, scratchId);
      int setupStatus;
      using (var initial = OpenRelativeDirectory(
          scratchRoot, "held-ancestor", 7, true, out setupStatus)) {
        RequirePlainDirectory(initial);
        using (var initialChild = OpenRelativeDirectory(
            initial, "child", 7, true, out setupStatus))
          RequirePlainDirectory(initialChild);
      }
      RequireScratchBinding(scratchRoot, scratch, scratchId);
      int rootStatus;
      using (var root = OpenRelativeDirectory(
          scratchRoot, "held-ancestor", share, false, out rootStatus)) {
      RequirePlainDirectory(root);
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
      // A same-principal actor can still race the following path-based rename.
      // The identity checks catch many swaps but are NOT an atomic authorization.
      RequireScratchBinding(scratchRoot, scratch, scratchId);
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

      RequireScratchBinding(scratchRoot, scratch, scratchId);
      // Replacement is also rooted under the original scratch HANDLE.
      int replacementStatus;
      using (var setupReplacement = OpenRelativeDirectory(
          scratchRoot, "held-ancestor", 7, true, out replacementStatus)) {
        RequirePlainDirectory(setupReplacement);
        using (var replacementChild = OpenRelativeDirectory(
            setupReplacement, "child", 7, true, out replacementStatus))
          RequirePlainDirectory(replacementChild);
      }
      FILE_ID_INFO after = Id(root);
      uint afterHandleFlags;
      if (root.IsInvalid || root.IsClosed || !HandleInfo(root, out afterHandleFlags))
        throw new InvalidOperationException("ROOT_HANDLE_NO_LONGER_VALID");
      string afterName = CanonicalPath(root);
      RequireScratchBinding(scratchRoot, scratch, scratchId);
      int lookupStatus;
      using (var movedRoot = OpenRelativeDirectory(
          scratchRoot, "moved-ancestor", 3, false, out lookupStatus))
      using (var replacement = OpenRelativeDirectory(
          scratchRoot, "held-ancestor", 3, false, out lookupStatus)) {
        RequirePlainDirectory(movedRoot);
        RequirePlainDirectory(replacement);
        FILE_ID_INFO movedId = Id(movedRoot);
        FILE_ID_INFO replacementId = Id(replacement);
        int nativeStatus;
        using (var child = OpenChild(root, out nativeStatus)) {
          FILE_ID_INFO oldChild = Id(child);
          string childName = CanonicalPath(child);
          using (var replacementChild = OpenChild(replacement, out lookupStatus)) {
            RequirePlainDirectory(replacementChild);
            if (!Same(before, after) || !Same(before, movedId) ||
                Same(before, replacementId) || Same(oldChild, Id(replacementChild)) ||
                !afterName.EndsWith("\\moved-ancestor", StringComparison.OrdinalIgnoreCase) ||
                !childName.EndsWith("\\moved-ancestor\\child", StringComparison.OrdinalIgnoreCase))
              throw new InvalidOperationException("ROOT_HANDLE_IDENTITY_MISMATCH");
          }
          // O1/O2 are mapped object identifiers from actual FileIdInfo bytes.
          // Never reveal filesystem paths, raw file IDs or volume serials.
          return "ROOTARK_W25_RENAME_V2 mode=" + moveMode + " share=" + share +
            " filesystem=NTFS storage=LOCAL" +
            " handle=VALID move=SUCCESS win32LastError=" + win32Status + " ntstatus=0x" +
            ((uint)nativeStatus).ToString("X8") +
            " rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL";
        }
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
