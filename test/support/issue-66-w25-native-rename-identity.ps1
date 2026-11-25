param(
  [ValidateSet('RW', 'NONE')][string]$Share,
  [ValidateSet('INFO', 'INFO_EX')][string]$Move,
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
  [DllImport("ntdll.dll", EntryPoint = "NtSetInformationFile", ExactSpelling = true)]
  private static extern int NtSetInformationFile(SafeFileHandle source,
    out IO_STATUS_BLOCK ioStatus, IntPtr data, uint dataLength,
    int fileInformationClass);
  [DllImport("ntdll.dll", EntryPoint = "NtCreateFile", ExactSpelling = true)]
  private static extern int NtCreateFile(out SafeFileHandle result, uint access,
    ref OBJECT_ATTRIBUTES attributes, out IO_STATUS_BLOCK status,
    IntPtr allocationSize, uint fileAttributes, uint share, uint disposition,
    uint options, IntPtr ea, uint eaSize);
  [DllImport("ntdll.dll", EntryPoint = "NtQueryDirectoryFile", ExactSpelling = true)]
  private static extern int NtQueryDirectoryFile(SafeFileHandle directory,
    IntPtr completionEvent, IntPtr apcRoutine, IntPtr apcContext,
    out IO_STATUS_BLOCK status, IntPtr buffer, uint length, int informationClass,
    [MarshalAs(UnmanagedType.U1)] bool singleEntry, IntPtr filter,
    [MarshalAs(UnmanagedType.U1)] bool restartScan);
  [DllImport("kernel32.dll", EntryPoint = "WriteFile", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool WriteFile(SafeFileHandle file, byte[] buffer,
    uint length, out uint written, IntPtr overlapped);
  [DllImport("kernel32.dll", EntryPoint = "ReadFile", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool ReadFile(SafeFileHandle file, [Out] byte[] buffer,
    uint length, out uint read, IntPtr overlapped);

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
  private static void RequirePlainFile(SafeFileHandle handle) {
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (!GetTag(handle, 9 /* FileAttributeTagInfo */, out tag,
        (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))) ||
        (tag.Attributes & 0x10 /* DIRECTORY */) != 0 ||
        (tag.Attributes & 0x400 /* REPARSE_POINT */) != 0)
      throw new InvalidOperationException("NOT_PLAIN_FILE");
  }
  private static string CanonicalPath(SafeFileHandle handle) {
    var output = new StringBuilder(4096);
    uint count = GetName(handle, output, (uint)output.Capacity, 0);
    if (count == 0 || count >= output.Capacity)
      throw new InvalidOperationException("GET_FINAL_PATH_FAILED");
    return output.ToString();
  }
  private static SafeFileHandle OpenDirectory(
      string path, uint share, uint extraAccess = 0) {
    var h = CreateFile(path, 0x00020080 /* READ_CONTROL | READ_ATTRIBUTES */ |
      extraAccess,
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
      out int nativeStatus, uint extraAccess = 0, bool synchronous = false) {
    // Only literal names from this test. Never allow user-provided paths.
    if (leaf != "held-ancestor" && leaf != "moved-ancestor" &&
        leaf != "replacement-ancestor" && leaf != "child")
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
      nativeStatus = NtCreateFile(out child,
        0x00020080 | extraAccess | (synchronous ? 0x00100000U : 0U),
        ref attributes, out status, IntPtr.Zero, 0x10 /* DIRECTORY */,
        share, create ? 2U /* FILE_CREATE */ : 1U /* FILE_OPEN */,
        0x00200001 | (synchronous ? 0x20U : 0U)
        /* FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE | optionally SYNCHRONOUS */,
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

  private static int RenameByHandle(SafeFileHandle source, SafeFileHandle targetRoot,
      string mode, string leaf = "moved-ancestor") {
    if (mode != "INFO" && mode != "INFO_EX")
      throw new InvalidOperationException("UNTRUSTED_RENAME_MODE");
    if (leaf != "moved-ancestor" && leaf != "test-relocated-ancestor" &&
        leaf != "replacement-ancestor" && leaf != "held-ancestor")
      throw new InvalidOperationException("UNTRUSTED_RENAME_LEAF");
    // NtSetInformationFile FileRenameInformation (10) / Ex (65), relative to
    // the held scratch root. Win32 SetFileInformationByHandle(FileRenameInfo)
    // returned ERROR_INVALID_PARAMETER (87) for non-null RootDirectory on
    // this machine, and no by-name or full-path fallback is permitted.
    byte[] name = Encoding.Unicode.GetBytes(leaf);
    int rootOffset = IntPtr.Size == 8 ? 8 : 4;
    int nameLengthOffset = rootOffset + IntPtr.Size;
    int filenameOffset = nameLengthOffset + 4;
    // Include WCHAR terminator and trailing struct alignment bytes.
    int byteCount = filenameOffset + name.Length + 4;
    IntPtr data = Marshal.AllocHGlobal(byteCount);
    try {
      Marshal.Copy(new byte[byteCount], 0, data, byteCount);
      Marshal.WriteInt32(data, 0, 0); // REPLACE_IF_EXISTS=0 / flags=0
      Marshal.WriteIntPtr(data, rootOffset, targetRoot.DangerousGetHandle());
      Marshal.WriteInt32(data, nameLengthOffset, name.Length);
      Marshal.Copy(name, 0, IntPtr.Add(data, filenameOffset), name.Length);
      Marshal.WriteInt16(data, filenameOffset + name.Length, 0);
      IO_STATUS_BLOCK io;
      int ntstatus = NtSetInformationFile(source, out io, data,
        (uint)byteCount,
        mode == "INFO_EX" ? 65 /* FileRenameInformationEx */ :
        10 /* FileRenameInformation */);
      if (ntstatus != 0)
        throw new InvalidOperationException("HANDLE_RENAME_NTSTATUS_FAILED");
      return ntstatus;
    } finally {
      Marshal.FreeHGlobal(data);
    }
  }

  // ASCII-only C# source escapes avoid Windows PowerShell 5.1 ANSI script
  // decoding while constructing exact UTF-16 surrogate pairs at runtime.
  private const string MarkerName = "marcador-\u00C1rvore-\uD83E\uDDED.txt";
  private const string MarkerA = "A | mem\u00F3ria original | a\u00E7\u00E3o \uD83C\uDF3F";
  private const string MarkerB = "B | substitui\u00E7\u00E3o distinta | \u00F3bice \uD83E\uDDED";

  private static SafeFileHandle OpenMarker(SafeFileHandle parent, bool create,
      out int statusCode) {
    // A fixed Unicode leaf, never an absolute path or caller-provided name.
    IntPtr text = Marshal.StringToHGlobalUni(MarkerName);
    IntPtr unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    try {
      var name = new UNICODE_STRING {
        Length = (ushort)(MarkerName.Length * 2),
        MaximumLength = (ushort)((MarkerName.Length + 1) * 2),
        Buffer = text
      };
      Marshal.StructureToPtr(name, unicode, false);
      var attributes = new OBJECT_ATTRIBUTES {
        Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
        RootDirectory = parent.DangerousGetHandle(),
        ObjectName = unicode,
        Attributes = 0x00001040 /* OBJ_DONT_REPARSE|OBJ_CASE_INSENSITIVE */
      };
      IO_STATUS_BLOCK status;
      SafeFileHandle file;
      statusCode = NtCreateFile(out file,
        0x00100081U | (create ? 0x2U : 0U)
        /* SYNCHRONIZE|READ_DATA|READ_ATTRIBUTES, optionally WRITE_DATA */,
        ref attributes, out status, IntPtr.Zero,
        0x80 /* FILE_ATTRIBUTE_NORMAL */, 7 /* share all */,
        create ? 2U /* FILE_CREATE; never overwrite */ : 1U /* FILE_OPEN */,
        0x00200060 /* OPEN_REPARSE_POINT|NON_DIRECTORY|SYNCHRONOUS_IO_NONALERT */,
        IntPtr.Zero, 0);
      if (statusCode == unchecked((int)0xC0000035) && create) {
        if (file != null) file.Dispose();
        return null; // STATUS_OBJECT_NAME_COLLISION; no writes
      }
      if (statusCode != 0 || file == null || file.IsInvalid) {
        if (file != null) file.Dispose();
        throw new InvalidOperationException("ROOTED_MARKER_OPEN_FAILED");
      }
      RequirePlainFile(file);
      return file;
    } finally {
      Marshal.FreeHGlobal(unicode);
      Marshal.FreeHGlobal(text);
    }
  }

  private static void WriteMarker(SafeFileHandle file, string marker) {
    byte[] expected = Encoding.Unicode.GetBytes(marker);
    uint written;
    if (!WriteFile(file, expected, (uint)expected.Length, out written,
        IntPtr.Zero) || written != expected.Length)
      throw new InvalidOperationException("ROOTED_WRITE_FAILED");
  }
  private static void RequireMarker(SafeFileHandle directory, string expected) {
    int status;
    using (var file = OpenMarker(directory, false, out status)) {
      byte[] expectedUtf16 = Encoding.Unicode.GetBytes(expected);
      byte[] observed = new byte[expectedUtf16.Length + 2];
      uint count;
      if (!ReadFile(file, observed, (uint)observed.Length, out count,
          IntPtr.Zero) || count != expectedUtf16.Length)
        throw new InvalidOperationException("ROOTED_READ_LENGTH_FAILED");
      for (int i = 0; i < expectedUtf16.Length; ++i)
        if (observed[i] != expectedUtf16[i])
          throw new InvalidOperationException("ROOTED_READ_BYTES_MISMATCH");
    }
  }

  private static void RequireSingleMarkerEntry(SafeFileHandle directory) {
    const int capacity = 1024;
    IntPtr buffer = Marshal.AllocHGlobal(capacity);
    try {
      Marshal.Copy(new byte[capacity], 0, buffer, capacity);
      IO_STATUS_BLOCK info;
      int status = NtQueryDirectoryFile(directory, IntPtr.Zero, IntPtr.Zero,
        IntPtr.Zero, out info, buffer, capacity,
        12 /* FileNamesInformation */, false, IntPtr.Zero, true);
      long length = info.Information.ToInt64();
      if (status != 0 || length < 12 || length > capacity)
        throw new InvalidOperationException("NATIVE_ENUM_FAILED");
      int offset = 0, markers = 0, entries = 0;
      while (true) {
        if (++entries > 8 || offset + 12 > length)
          throw new InvalidOperationException("ENUM_BOUNDS_FAILED");
        int next = Marshal.ReadInt32(buffer, offset);
        int nameBytes = Marshal.ReadInt32(buffer, offset + 8);
        if (nameBytes <= 0 || (nameBytes & 1) != 0 ||
            nameBytes > 512 || offset + 12 + nameBytes > length)
          throw new InvalidOperationException("ENUM_NAME_BOUNDS_FAILED");
        string name = Marshal.PtrToStringUni(
          IntPtr.Add(buffer, offset + 12), nameBytes / 2);
        if (string.Equals(name, MarkerName, StringComparison.Ordinal)) ++markers;
        else if (name != "." && name != "..")
          throw new InvalidOperationException("UNEXPECTED_ENUM_NAME");
        if (next == 0) break;
        if (next % 4 != 0 || next < 12 + nameBytes ||
            offset + next >= length)
          throw new InvalidOperationException("ENUM_NEXT_OFFSET_FAILED");
        offset += next;
      }
      if (markers != 1) throw new InvalidOperationException("MARKER_ENUM_COUNT");
      // A second call must not return further entries after this bounded batch.
      int last = NtQueryDirectoryFile(directory, IntPtr.Zero, IntPtr.Zero,
        IntPtr.Zero, out info, buffer, capacity, 12,
        false, IntPtr.Zero, false);
      if (last != unchecked((int)0x80000006) /* STATUS_NO_MORE_FILES */)
        throw new InvalidOperationException("ENUM_NOT_EXHAUSTED");
    } finally {
      Marshal.FreeHGlobal(buffer);
    }
  }

  public static string ProbeHeldRead(string scratch) {
    int status;
    using (var scratchRoot = OpenDirectory(
        scratch, 7, 0x4 /* FILE_ADD_SUBDIRECTORY */)) {
      RequireLocalNtfs(scratchRoot);
      RequirePlainDirectory(scratchRoot);
      FILE_ID_INFO scratchId = Id(scratchRoot);
      RequireScratchBinding(scratchRoot, scratch, scratchId);
      using (var original = OpenRelativeDirectory(
          scratchRoot, "held-ancestor", 7, true, out status,
          0x00010001 /* DELETE|FILE_LIST_DIRECTORY */, true)) {
        RequirePlainDirectory(original);
        FILE_ID_INFO originalId = Id(original);
        if (originalId.VolumeSerialNumber != scratchId.VolumeSerialNumber)
          throw new InvalidOperationException("ORIGINAL_VOLUME_MISMATCH");

        FILE_ID_INFO markerAId;
        using (var markerA = OpenMarker(original, true, out status)) {
          if (markerA == null) throw new InvalidOperationException("A_ALREADY_EXISTS");
          markerAId = Id(markerA);
          WriteMarker(markerA, MarkerA);
        }
        // Negative: FILE_CREATE must never overwrite the existing A marker.
        using (var collision = OpenMarker(original, true, out status)) {
          if (collision != null || status != unchecked((int)0xC0000035))
            throw new InvalidOperationException("COLLISION_NOT_DENIED");
        }
        RequireSingleMarkerEntry(original);
        RequireMarker(original, MarkerA);
        if (!Same(originalId, Id(original)))
          throw new InvalidOperationException("ORIGINAL_SOURCE_CHANGED");
        RequireScratchBinding(scratchRoot, scratch, scratchId);
        RenameByHandle(original, scratchRoot, "INFO", "moved-ancestor");

        // Phase B owns the old name. A remains open for native enumeration
        // and read; neither operation opens an absolute pathname.
        using (var replacement = OpenRelativeDirectory(
            scratchRoot, "held-ancestor", 7, true, out status,
            0x00010001 /* DELETE|FILE_LIST_DIRECTORY */, true)) {
          RequirePlainDirectory(replacement);
          FILE_ID_INFO replacementId = Id(replacement);
          if (replacementId.VolumeSerialNumber != scratchId.VolumeSerialNumber ||
              Same(originalId, replacementId))
            throw new InvalidOperationException("REPLACEMENT_ID_NOT_DISTINCT");
          FILE_ID_INFO markerBId;
          using (var markerB = OpenMarker(replacement, true, out status)) {
            if (markerB == null) throw new InvalidOperationException("B_ALREADY_EXISTS");
            markerBId = Id(markerB);
            WriteMarker(markerB, MarkerB);
          }
          if (Same(markerAId, markerBId) ||
              markerAId.VolumeSerialNumber != scratchId.VolumeSerialNumber ||
              markerBId.VolumeSerialNumber != scratchId.VolumeSerialNumber)
            throw new InvalidOperationException("MARKER_IDS_NOT_DISTINCT");
          RequireScratchBinding(scratchRoot, scratch, scratchId);
          RequireSingleMarkerEntry(original);
          RequireSingleMarkerEntry(replacement);
          RequireMarker(original, MarkerA);
          RequireMarker(replacement, MarkerB);
          using (var rereadA = OpenMarker(original, false, out status))
          using (var rereadB = OpenMarker(replacement, false, out status)) {
            if (!Same(Id(rereadA), markerAId) ||
                !Same(Id(rereadB), markerBId))
              throw new InvalidOperationException("MARKER_ID_CHANGED");
          }
          // Phase A returns: relocate B away, restore the *same* A handle
          // to the old name; no reparse following or replace-if-exists.
          RenameByHandle(replacement, scratchRoot, "INFO", "replacement-ancestor");
          RenameByHandle(original, scratchRoot, "INFO", "held-ancestor");
          RequireScratchBinding(scratchRoot, scratch, scratchId);
          using (var restored = OpenRelativeDirectory(
              scratchRoot, "held-ancestor", 3, false, out status))
          using (var relocated = OpenRelativeDirectory(
              scratchRoot, "replacement-ancestor", 3, false, out status)) {
            RequirePlainDirectory(restored);
            RequirePlainDirectory(relocated);
            if (!Same(originalId, Id(restored)) ||
                !Same(replacementId, Id(relocated)) ||
                !Same(originalId, Id(original)) ||
                !Same(replacementId, Id(replacement)))
              throw new InvalidOperationException("ABA_ID_MISMATCH");
          }
          RequireSingleMarkerEntry(original);
          RequireMarker(original, MarkerA);
          RequireMarker(replacement, MarkerB);
        }
      }
    }
    // No marker bytes, file IDs, absolute paths or private ACLs in output.
    return "ROOTARK_W25_HELD_READ_V1 filesystem=NTFS storage=LOCAL" +
      " rename=HANDLE phases=A_B_A original=READ_A replacement=READ_B" +
      " rebound=READ_A utf16=EXACT enumeration=EXACT collision=DENIED" +
      " identity=PINNED reparse=CHECKED";
  }

  public static string Probe(string scratch, string shareMode, string moveMode,
      bool injectSourceSwap) {
    uint share = shareMode == "NONE" ? 0U : 3U;
    // Retain the actual disposable scratch object and create fixture children
    // by NtCreateFile relative to its HANDLE, never by joined absolute path.
    using (var scratchRoot = OpenDirectory(
        scratch, 7, 0x4 /* FILE_ADD_SUBDIRECTORY for destination */)) {
      RequireLocalNtfs(scratchRoot);
      RequirePlainDirectory(scratchRoot);
      FILE_ID_INFO scratchId = Id(scratchRoot);
      RequireScratchBinding(scratchRoot, scratch, scratchId);
      int setupStatus;
      FILE_ID_INFO createdSourceId;
      using (var initial = OpenRelativeDirectory(
          scratchRoot, "held-ancestor", 7, true, out setupStatus,
          0x00010000 /* DELETE on test-owned source */)) {
        RequirePlainDirectory(initial);
        createdSourceId = Id(initial);
        if (createdSourceId.VolumeSerialNumber != scratchId.VolumeSerialNumber)
          throw new InvalidOperationException("SOURCE_WRONG_VOLUME");
        using (var initialChild = OpenRelativeDirectory(
            initial, "child", 7, true, out setupStatus))
          RequirePlainDirectory(initialChild);
        if (injectSourceSwap) {
          // Deterministic owned-fixture ABA: relocate ONLY the just-created
          // source by HANDLE, then create a separate test-owned same-name
          // replacement by the retained scratch HANDLE. No arbitrary paths,
          // deletion, or outside process is involved.
          RequireScratchBinding(scratchRoot, scratch, scratchId);
          RenameByHandle(initial, scratchRoot, "INFO", "test-relocated-ancestor");
          using (var replacement = OpenRelativeDirectory(
              scratchRoot, "held-ancestor", 7, true, out setupStatus)) {
            RequirePlainDirectory(replacement);
            FILE_ID_INFO replacementId = Id(replacement);
            if (replacementId.VolumeSerialNumber != scratchId.VolumeSerialNumber ||
                Same(createdSourceId, replacementId))
              throw new InvalidOperationException("INVALID_SOURCE_SWAP_FIXTURE");
            using (var replacementChild = OpenRelativeDirectory(
                replacement, "child", 7, true, out setupStatus))
              RequirePlainDirectory(replacementChild);
          }
        }
      }
      RequireScratchBinding(scratchRoot, scratch, scratchId);
      int rootStatus;
      using (var root = OpenRelativeDirectory(
          scratchRoot, "held-ancestor", share, false, out rootStatus,
          0x00010000 /* DELETE on source handle */)) {
      RequirePlainDirectory(root);
      FILE_ID_INFO before = Id(root);
      // Closing the initial CREATE handle is required before reopening with
      // share=0. Its immutable FileIdInfo evidence must bind this new handle
      // to the original fixture, including the source volume identity.
      if (before.VolumeSerialNumber != scratchId.VolumeSerialNumber ||
          !Same(createdSourceId, before))
        throw new InvalidOperationException("SOURCE_ID_MISMATCH");
      uint handleFlags;
      if (!HandleInfo(root, out handleFlags))
        throw new InvalidOperationException("INVALID_HANDLE");
      string beforeName = CanonicalPath(root);
      if (!beforeName.EndsWith("\\held-ancestor", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("WRONG_INITIAL_HANDLE");

      // No pathname-resolved source/destination: the kernel receives the
      // authenticated source handle and destination RootDirectory HANDLE.
      RequireScratchBinding(scratchRoot, scratch, scratchId);
      int renameStatus = RenameByHandle(root, scratchRoot, moveMode);

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
          return "ROOTARK_W25_RENAME_V3 mode=" + moveMode + " share=" + share +
            " filesystem=NTFS storage=LOCAL" +
            " handle=VALID rename=HANDLE move=SUCCESS renameNtstatus=0x" +
            ((uint)renameStatus).ToString("X8") + " ntstatus=0x" +
            ((uint)nativeStatus).ToString("X8") +
            " rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL";
        }
      }
    }
    }
  }
}
'@ | Out-Null

  if ($env:ROOTARK_W25_HELD_UTF16_PROOF -eq '1') {
    if ($env:ROOTARK_W25_SOURCE_SWAP_TEST -eq '1') { throw 'CONFLICTING_LABS' }
    [Console]::Out.WriteLine(
      [RootarkW25RenameIdentityProof]::ProbeHeldRead($directory.FullName))
  } else {
    [Console]::Out.WriteLine([RootarkW25RenameIdentityProof]::Probe(
      $directory.FullName, $Share, $Move, ($env:ROOTARK_W25_SOURCE_SWAP_TEST -eq '1')))
  }
  exit 0
} catch {
  $failure = $_.Exception
  while ($failure.InnerException -ne $null) {
    $failure = $failure.InnerException
  }
  if ($failure.Message -eq 'SOURCE_ID_MISMATCH') {
    [Console]::Error.WriteLine('ROOTARK_W25_SOURCE_ID_REJECTED')
    exit 42
  }
  [Console]::Error.WriteLine('ROOTARK_W25_RENAME_REJECTED')
  exit 41
}
