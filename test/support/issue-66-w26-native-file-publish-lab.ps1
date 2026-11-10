param(
  [ValidateSet('NORMAL', 'COLLISION', 'SOURCE_SWAP', 'ROOT_SWAP',
               'PRE_LINK_HARD_EXIT', 'POST_LINK_HARD_EXIT', 'TXN_COMPLETE',
               'COLD_INSPECT')]
  [string]$Mode,
  [string]$Scratch
)

$ErrorActionPreference = 'Stop'
try {
  # This is a disposable physical NTFS lab, never a production RootSession.
  if ($env:ROOTARK_ISSUE66_W26_NATIVE_PUBLISH_LAB -ne '1') { throw 'LAB_DISABLED' }
  $local = [System.IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)).TrimEnd('\')
  $directory = [System.IO.DirectoryInfo]::new($Scratch)
  $coldInspect = $Mode -eq 'COLD_INSPECT'
  $entries = if ($directory.Exists) { @($directory.GetFileSystemInfos()) } else { @() }
  if (-not $directory.Exists -or
      $directory.Name -notmatch '^rootark-w26-native-publish-[A-Za-z0-9_-]{6,}$' -or
      -not [string]::Equals($directory.Parent.FullName.TrimEnd('\'), $local,
        [StringComparison]::OrdinalIgnoreCase) -or
      ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      ($coldInspect -and $env:ROOTARK_ISSUE66_W26_COLD_INSPECT_LAB -ne '1') -or
      ($coldInspect -and ($entries.Count -ne 1 -or $entries[0].Name -cne 'held' -or
        -not ($entries[0] -is [System.IO.DirectoryInfo]) -or
        ($entries[0].Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) -or
      (-not $coldInspect -and $entries.Count -ne 0) -or
      (([System.IO.DirectoryInfo]::new($local)).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'UNTRUSTED_LAB_SCRATCH'
  }

  Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class RootarkW26NativeFilePublishLab {
  [StructLayout(LayoutKind.Sequential)]
  private struct FILE_ID_INFO {
    public ulong VolumeSerialNumber;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] FileId;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct FILE_STANDARD_INFO {
    public long AllocationSize, EndOfFile;
    public uint NumberOfLinks;
    [MarshalAs(UnmanagedType.Bool)] public bool DeletePending;
    [MarshalAs(UnmanagedType.Bool)] public bool Directory;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct FILE_BASIC_INFO {
    public long CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
    public uint FileAttributes;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct FILE_ATTRIBUTE_TAG_INFO { public uint Attributes, ReparseTag; }
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
  private struct IO_STATUS_BLOCK { public IntPtr Status, Information; }

  [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern SafeFileHandle OpenDirectory(string name, uint access, uint share,
    IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("ntdll.dll", EntryPoint = "NtCreateFile", ExactSpelling = true)]
  private static extern int OpenRelative(out SafeFileHandle output, uint access,
    ref OBJECT_ATTRIBUTES attributes, out IO_STATUS_BLOCK status,
    IntPtr allocationSize, uint attrs, uint share, uint disposition,
    uint options, IntPtr ea, uint eaSize);
  [DllImport("ntdll.dll", EntryPoint = "NtSetInformationFile", ExactSpelling = true)]
  private static extern int SetNativeInfo(SafeFileHandle file, out IO_STATUS_BLOCK status,
    IntPtr buffer, uint size, int klass);
  [DllImport("kernel32.dll", EntryPoint = "WriteFile", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool WriteFile(SafeFileHandle file, byte[] data, uint size,
    out uint written, IntPtr overlapped);
  [DllImport("kernel32.dll", EntryPoint = "ReadFile", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool ReadFile(SafeFileHandle file, byte[] data, uint size,
    out uint read, IntPtr overlapped);
  [DllImport("kernel32.dll", EntryPoint = "FlushFileBuffers", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool Flush(SafeFileHandle file);
  [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetId(SafeFileHandle file, int klass, out FILE_ID_INFO id, uint size);
  [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetStandard(SafeFileHandle file, int klass,
    out FILE_STANDARD_INFO info, uint size);
  [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetBasic(SafeFileHandle file, int klass,
    out FILE_BASIC_INFO info, uint size);
  [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetTag(SafeFileHandle file, int klass,
    out FILE_ATTRIBUTE_TAG_INFO info, uint size);
  [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool Volume(SafeFileHandle file, StringBuilder name, uint size,
    IntPtr serial, IntPtr maxComponent, IntPtr flags, StringBuilder filesystem, uint capacity);
  [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode)]
  private static extern uint DriveType(string rootPath);
  [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcess")]
  private static extern IntPtr CurrentProcess();
  [DllImport("kernel32.dll", EntryPoint = "TerminateProcess", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool Terminate(IntPtr process, uint exitCode);

  private static readonly string Trusted = "ORIGINAL_OPENED_STAGE_BYTES";
  private static readonly string Foreign = "FOREIGN_UNTRUSTED_TARGET_BYTES";
  private static FILE_ID_INFO Id(SafeFileHandle file) {
    FILE_ID_INFO id;
    if (!GetId(file, 18, out id, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO))) || id.FileId == null)
      throw new InvalidOperationException("FILE_ID_UNAVAILABLE");
    return id;
  }
  private static bool Same(FILE_ID_INFO a, FILE_ID_INFO b) {
    if (a.VolumeSerialNumber != b.VolumeSerialNumber) return false;
    for (int i = 0; i < 16; i++) if (a.FileId[i] != b.FileId[i]) return false;
    return true;
  }
  private static void Plain(SafeFileHandle file, bool directory) {
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (!GetTag(file, 9, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))) ||
        (tag.Attributes & 0x400) != 0 || ((tag.Attributes & 0x10) != 0) != directory)
      throw new InvalidOperationException("REPARSE_OR_WRONG_TYPE");
  }
  private static SafeFileHandle Root(string directory, bool readOnly = false) {
    SafeFileHandle root = OpenDirectory(directory,
      readOnly ? 0x00100081U /* SYNC | LIST_DIRECTORY | READ_ATTR */ : 0x001F01FFU,
      7, IntPtr.Zero, 3,
      0x02200000 /* OPEN_REPARSE_POINT | BACKUP_SEMANTICS */, IntPtr.Zero);
    if (root == null || root.IsInvalid) throw new InvalidOperationException("ROOT_OPEN_FAILED");
    try {
      Plain(root, true);
      var fs = new StringBuilder(32);
      if (!Volume(root, null, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, fs, 32) ||
          !string.Equals(fs.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("LOCAL_NTFS_REQUIRED");
      return root;
    } catch { root.Dispose(); throw; }
  }
  private static SafeFileHandle File(SafeFileHandle root, string leaf, bool create) {
    if (leaf != "stage.bin" && leaf != "published.bin" && leaf != "parked-stage.bin"
      && leaf != "prepared.bin" && leaf != "commit.bin")
      throw new InvalidOperationException("UNTRUSTED_LEAF");
    IntPtr name = Marshal.StringToHGlobalUni(leaf);
    IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    try {
      var u = new UNICODE_STRING { Length = (ushort)(leaf.Length * 2),
        MaximumLength = (ushort)((leaf.Length + 1) * 2), Buffer = name };
      Marshal.StructureToPtr(u, ptr, false);
      var attr = new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
        RootDirectory = root.DangerousGetHandle(), ObjectName = ptr,
        Attributes = 0x00001040 /* DONT_REPARSE | CASE_INSENSITIVE */ };
      IO_STATUS_BLOCK status;
      SafeFileHandle file;
      int code = OpenRelative(out file, 0x00110083 /* SYNC | DELETE | READ+WRITE | ATTR */,
        ref attr, out status, IntPtr.Zero, 0x80, 7,
        create ? 2U /* FILE_CREATE (exclusive) */ : 1U /* FILE_OPEN */,
        0x00200060 /* OPEN_REPARSE_POINT | NON_DIRECTORY | SYNCHRONOUS */, IntPtr.Zero, 0);
      if (code != 0 || file == null || file.IsInvalid) {
        if (file != null) file.Dispose();
        throw new InvalidOperationException("ROOTED_FILE_OPEN_FAILED");
      }
      try { Plain(file, false); return file; }
      catch { file.Dispose(); throw; }
    } finally {
      Marshal.FreeHGlobal(ptr);
      Marshal.FreeHGlobal(name);
    }
  }
  // New-process, read-only observation of the three unsigned laboratory
  // phases. No pathname reopen and NO authority to replay, repair or delete.
  // The same-SID writable parent cannot provide authenticated cold custody.
  private static string ColdLeaf(SafeFileHandle root, string leaf) {
    if (leaf != "stage.bin" && leaf != "published.bin" &&
        leaf != "prepared.bin" && leaf != "commit.bin")
      throw new InvalidOperationException("COLD_LEAF_REJECTED");
    IntPtr name = Marshal.StringToHGlobalUni(leaf);
    IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    SafeFileHandle file = null;
    try {
      var u = new UNICODE_STRING { Length = (ushort)(leaf.Length * 2),
        MaximumLength = (ushort)((leaf.Length + 1) * 2), Buffer = name };
      Marshal.StructureToPtr(u, ptr, false);
      var attr = new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
        RootDirectory = root.DangerousGetHandle(), ObjectName = ptr,
        Attributes = 0x00001040 /* DONT_REPARSE | CASE_INSENSITIVE */ };
      IO_STATUS_BLOCK status;
      int code = OpenRelative(out file, 0x00100081 /* SYNC | READ | ATTR */,
        ref attr, out status, IntPtr.Zero, 0, 7,
        1U /* FILE_OPEN only */, 0x00200060, IntPtr.Zero, 0);
      if (code == unchecked((int)0xC0000034) || code == unchecked((int)0xC000003A))
        return null; // Only a kernel-confirmed missing leaf is absent.
      if (code != 0 || file == null || file.IsInvalid)
        throw new InvalidOperationException("COLD_OPEN_UNVERIFIED");
      Plain(file, false);
      FILE_ID_INFO id = Id(file);
      if (id.FileId == null || id.FileId.Length != 16)
        throw new InvalidOperationException("COLD_ID_UNVERIFIED");
      FILE_STANDARD_INFO standard;
      if (!GetStandard(file, 1 /* FileStandardInfo */, out standard,
            (uint)Marshal.SizeOf(typeof(FILE_STANDARD_INFO))) ||
          standard.Directory || standard.DeletePending ||
          standard.NumberOfLinks != 1 || standard.EndOfFile < 0 ||
          standard.EndOfFile > 128)
        throw new InvalidOperationException("COLD_INODE_UNVERIFIED");
      FILE_BASIC_INFO basic;
      if (!GetBasic(file, 0 /* FileBasicInfo */, out basic,
            (uint)Marshal.SizeOf(typeof(FILE_BASIC_INFO))))
        throw new InvalidOperationException("COLD_VERSION_UNVERIFIED");
      byte[] bytes = new byte[129]; // A bounded native read: no File.ReadAllText(path).
      uint read;
      if (!ReadFile(file, bytes, (uint)bytes.Length, out read, IntPtr.Zero)
          || read > 128 || read != (uint)standard.EndOfFile)
        throw new InvalidOperationException("COLD_READ_UNVERIFIED");
      FILE_STANDARD_INFO after;
      FILE_BASIC_INFO versionAfter;
      if (!GetStandard(file, 1, out after,
            (uint)Marshal.SizeOf(typeof(FILE_STANDARD_INFO))) ||
          !GetBasic(file, 0, out versionAfter,
            (uint)Marshal.SizeOf(typeof(FILE_BASIC_INFO))) ||
          !Same(id, Id(file)) || after.EndOfFile != standard.EndOfFile ||
          after.NumberOfLinks != standard.NumberOfLinks ||
          after.DeletePending || after.Directory ||
          basic.CreationTime != versionAfter.CreationTime ||
          basic.LastWriteTime != versionAfter.LastWriteTime ||
          basic.ChangeTime != versionAfter.ChangeTime)
        throw new InvalidOperationException("COLD_READ_CHANGED");
      return Encoding.UTF8.GetString(bytes, 0, (int)read);
    } finally {
      if (file != null) file.Dispose();
      Marshal.FreeHGlobal(ptr);
      Marshal.FreeHGlobal(name);
    }
  }
  private static string InspectCold(string scratch) {
    string parent = Path.Combine(scratch, "held");
    using (SafeFileHandle root = Root(parent, true)) {
      string stage = ColdLeaf(root, "stage.bin");
      string published = ColdLeaf(root, "published.bin");
      string prepared = ColdLeaf(root, "prepared.bin");
      string commit = ColdLeaf(root, "commit.bin");
      if (prepared != "PREPARED_V1" ||
          (stage != null && stage != Trusted) ||
          (published != null && published != Trusted) ||
          (commit != null && commit != "COMMITTED_V1"))
        throw new InvalidOperationException("COLD_BYTES_UNVERIFIED");
      string phase;
      if (stage == Trusted && published == null && commit == null)
        phase = "PREPARED_ONLY";
      else if (stage == null && published == Trusted && commit == null)
        phase = "PUBLISHED_NO_COMMIT";
      else if (stage == null && published == Trusted && commit == "COMMITTED_V1")
        phase = "COMMIT_OBSERVED";
      else throw new InvalidOperationException("COLD_PHASE_UNVERIFIED");
      return "ROOTARK_W26_COLD_INSPECT phase=" + phase +
        " authority=LAB_ONLY_NO_GO";
    }
  }
  private static void Write(SafeFileHandle file, string content) {
    byte[] data = Encoding.UTF8.GetBytes(content);
    uint written;
    if (!WriteFile(file, data, (uint)data.Length, out written, IntPtr.Zero)
        || written != (uint)data.Length || !Flush(file))
      throw new InvalidOperationException("HELD_STAGE_FLUSH_FAILED");
  }
  private static void PlantForeign(string filename, string content) {
    // The deterministic same-SID writer uses pathnames on purpose, but must
    // never truncate an object which unexpectedly wins this laboratory name.
    byte[] bytes = Encoding.UTF8.GetBytes(content);
    using (var stream = new FileStream(filename, FileMode.CreateNew,
        FileAccess.Write, FileShare.None, 4096, false)) {
      stream.Write(bytes, 0, bytes.Length);
      stream.Flush(true);
    }
  }
  private static string ReadFixture(string filename) {
    // Diagnostic assertions only: the held writer HANDLE remains open, so
    // File.ReadAllText(FileShare.Read) would spuriously fail with sharing 32.
    using (var stream = new FileStream(filename, FileMode.Open, FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete))
    using (var reader = new StreamReader(stream, Encoding.UTF8, true)) {
      return reader.ReadToEnd();
    }
  }
  private static int Rename(SafeFileHandle source, SafeFileHandle targetRoot, string leaf) {
    if (leaf != "published.bin") throw new InvalidOperationException("UNTRUSTED_TARGET");
    byte[] name = Encoding.Unicode.GetBytes(leaf);
    int rootOffset = IntPtr.Size == 8 ? 8 : 4;
    int lengthOffset = rootOffset + IntPtr.Size;
    int nameOffset = lengthOffset + 4;
    int bufferLength = nameOffset + name.Length + 4;
    IntPtr data = Marshal.AllocHGlobal(bufferLength);
    try {
      Marshal.Copy(new byte[bufferLength], 0, data, bufferLength);
      Marshal.WriteInt32(data, 0, 0); // ReplaceIfExists=FALSE; NEVER overwrite
      Marshal.WriteIntPtr(data, rootOffset, targetRoot.DangerousGetHandle());
      Marshal.WriteInt32(data, lengthOffset, name.Length);
      Marshal.Copy(name, 0, IntPtr.Add(data, nameOffset), name.Length);
      IO_STATUS_BLOCK status;
      return SetNativeInfo(source, out status, data, (uint)bufferLength,
        10 /* FileRenameInformation */);
    } finally { Marshal.FreeHGlobal(data); }
  }
  private static void ExitImmediately(uint code) {
    // The opted-in PowerShell child only. This bypasses managed finally and
    // represents process termination, never powercut or directory durability.
    if (!Terminate(CurrentProcess(), code))
      throw new InvalidOperationException("HARD_EXIT_FAILED");
    throw new InvalidOperationException("UNEXPECTED_HARD_EXIT_RETURN");
  }

  public static string Run(string scratch, string mode) {
    if (mode == "COLD_INSPECT") {
      if (DriveType(Path.GetPathRoot(scratch)) != 3 /* DRIVE_FIXED */)
        throw new InvalidOperationException("LOCAL_FIXED_NTFS_REQUIRED");
      return InspectCold(scratch);
    }
    bool crashBefore = mode == "PRE_LINK_HARD_EXIT";
    bool crashAfter = mode == "POST_LINK_HARD_EXIT";
    bool complete = mode == "TXN_COMPLETE";
    if ((crashBefore || crashAfter || complete) &&
        Environment.GetEnvironmentVariable("ROOTARK_ISSUE66_W26_HARD_EXIT_LAB") != "1")
      throw new InvalidOperationException("HARD_EXIT_TEST_DISABLED");
    if (DriveType(Path.GetPathRoot(scratch)) != 3 /* DRIVE_FIXED */)
      throw new InvalidOperationException("LOCAL_FIXED_NTFS_REQUIRED");
    string parent = Path.Combine(scratch, "held");
    Directory.CreateDirectory(parent);
    using (SafeFileHandle root = Root(parent)) {
      string visibleParent = parent;
      if (mode == "ROOT_SWAP") {
        // Rebind the root pathname before opening a child file: on Windows,
        // ordinary Directory.Move refuses an ancestor with a live file HANDLE.
        // The retained directory HANDLE must nevertheless keep opening and
        // publishing within A after a foreign B appears at A's former name.
        visibleParent = Path.Combine(scratch, "moved-held");
        Directory.Move(parent, visibleParent);
        Directory.CreateDirectory(parent);
        PlantForeign(Path.Combine(parent, "published.bin"), Foreign);
      }
      using (SafeFileHandle source = File(root, "stage.bin", true)) {
        Write(source, Trusted);
        if (crashBefore || crashAfter || complete) {
          using (SafeFileHandle prepared = File(root, "prepared.bin", true))
            Write(prepared, "PREPARED_V1");
          if (crashBefore) ExitImmediately(74);
        }
        FILE_ID_INFO original = Id(source);
        string stage = Path.Combine(parent, "stage.bin");
        string target = Path.Combine(parent, "published.bin");
        if (mode == "COLLISION") {
          // Physical foreign destination inserted before the no-replace syscall.
          PlantForeign(target, Foreign);
        } else if (mode == "SOURCE_SWAP") {
          // Real rename AFTER holding original stage HANDLE. Equal bytes do
          // not make the newly occupying inode the original FD.
          System.IO.File.Move(stage, Path.Combine(parent, "parked-stage.bin"));
          PlantForeign(stage, Trusted);
          using (SafeFileHandle other = File(root, "stage.bin", false)) {
            if (Same(original, Id(other)))
              throw new InvalidOperationException("SOURCE_SWAP_NOT_PHYSICAL");
          }
        } else if (mode != "ROOT_SWAP" && mode != "NORMAL" && !crashAfter && !complete) {
          throw new InvalidOperationException("UNTRUSTED_MODE");
        }
        int code = Rename(source, root, "published.bin");
        if (mode == "COLLISION") {
          // A generic NT failure could otherwise fool the no-clobber proof.
          // The actual NTFS syscall must report STATUS_OBJECT_NAME_COLLISION.
          if (code != unchecked((int)0xC0000035) || ReadFixture(target) != Foreign ||
              !System.IO.File.Exists(stage) ||
              ReadFixture(stage) != Trusted)
            throw new InvalidOperationException("DESTINATION_CLOBBERED");
          return "ROOTARK_W26_HANDLE_PUBLISH mode=COLLISION result=DENIED foreign=INTACT stage=INTACT collisionNtstatus=0x" +
            unchecked((uint)code).ToString("X8");
        }
        if (code != 0) throw new InvalidOperationException("NATIVE_RENAME_FAILED");
        if (crashAfter) ExitImmediately(73);
        string published = Path.Combine(visibleParent, "published.bin");
        using (SafeFileHandle actual = File(root, "published.bin", false)) {
          if (!Same(original, Id(source)) || !Same(original, Id(actual)) ||
              ReadFixture(published) != Trusted)
            throw new InvalidOperationException("OPENED_INODE_NOT_PUBLISHED");
        }
        if (mode == "SOURCE_SWAP" &&
            (!System.IO.File.Exists(stage) ||
              ReadFixture(stage) != Trusted ||
              System.IO.File.Exists(Path.Combine(visibleParent, "parked-stage.bin"))))
          throw new InvalidOperationException("FOREIGN_SOURCE_NOT_PRESERVED");
        if (mode == "NORMAL" && System.IO.File.Exists(stage))
          throw new InvalidOperationException("STAGE_NAME_NOT_RETIRED");
        if (mode == "ROOT_SWAP" &&
            ReadFixture(Path.Combine(parent, "published.bin")) != Foreign)
          throw new InvalidOperationException("FOREIGN_ANCESTOR_MUTATED");
        if (complete) {
          // Only the fully completed opt-in rehearsal writes this marker.
          // Windows namespace durability and cold recovery are NOT proven.
          using (SafeFileHandle marker = File(root, "commit.bin", true))
            Write(marker, "COMMITTED_V1");
        }
        return "ROOTARK_W26_HANDLE_PUBLISH mode=" + mode +
          " result=ORIGINAL_HANDLE inode=PINNED no_replace=YES";
      }
    }
  }
}
'@ | Out-Null

  [Console]::Out.WriteLine([RootarkW26NativeFilePublishLab]::Run($directory.FullName, $Mode))
  exit 0
} catch {
  # Keep paths, ACLs and identifiers out of the public test signal.
  [Console]::Error.WriteLine('ROOTARK_W26_HANDLE_PUBLISH_REJECTED')
  exit 41
}
