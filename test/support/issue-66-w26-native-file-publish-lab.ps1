param(
  [ValidateSet('NORMAL', 'COLLISION', 'EXTERNAL_COLLISION', 'SOURCE_SWAP', 'ROOT_SWAP',
               'HELD_REBIND', 'HELD_JUNCTION', 'PRECREATE_SCRATCH_JUNCTION',
               'PRECREATE_SCRATCH_DIRECTORY', 'PRECREATE_SCRATCH_JUNCTION_NO_ACK',
               'PRECREATE_SCRATCH_DIRECTORY_NO_ACK',
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
  # LAB_ONLY_NO_GO: this managed DirectoryInfo preflight does NOT pin scratch.
  # Add-Type and the subsequent native first open leave a same-SID swap window.
  # A plain foreign directory B inserted before that FIRST native pin can pass
  # this preflight; Run(NORMAL) may then create held/publish into B. There is
  # no trusted original-A FileId witness across this boundary. RootSession OFF.
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
using System.Collections.Generic;
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
    // FILE_STANDARD_INFO uses NT BOOLEAN (one byte), NOT Win32 BOOL (4).
    [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
    [MarshalAs(UnmanagedType.U1)] public bool Directory;
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
  private static string ExactId(FILE_ID_INFO id) {
    if (id.FileId == null || id.FileId.Length != 16)
      throw new InvalidOperationException("NATIVE_FILE_ID_INVALID");
    return id.VolumeSerialNumber.ToString("X16") + "-" +
      BitConverter.ToString(id.FileId).Replace("-", "");
  }
  private sealed class ColdObservation {
    internal string Bytes;
    internal string Inode;
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
  private static SafeFileHandle DirectoryChild(SafeFileHandle parent, string component,
      bool readOnly, bool create = false) {
    if (create && readOnly) throw new InvalidOperationException("CREATION_MUST_BE_WRITABLE");
    if (string.IsNullOrEmpty(component) || component == "." || component == ".." ||
        component.IndexOfAny(new char[] { '\\', '/', ':' }) != -1)
      throw new InvalidOperationException("UNTRUSTED_ANCESTOR_COMPONENT");
    IntPtr name = Marshal.StringToHGlobalUni(component);
    IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    try {
      var u = new UNICODE_STRING { Length = (ushort)(component.Length * 2),
        MaximumLength = (ushort)((component.Length + 1) * 2), Buffer = name };
      Marshal.StructureToPtr(u, ptr, false);
      var attr = new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
        RootDirectory = parent.DangerousGetHandle(), ObjectName = ptr,
        Attributes = 0x00001040 /* OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE */ };
      IO_STATUS_BLOCK status;
      SafeFileHandle opened;
      int code = OpenRelative(out opened,
        readOnly ? 0x001000A1U /* SYNC | READ_ATTR | TRAVERSE | LIST */ : 0x001F01FFU,
        ref attr, out status, IntPtr.Zero, 0x80, 7,
        create ? 2U /* FILE_CREATE exclusive */ : 1U /* FILE_OPEN only */,
        0x00200021U /* OPEN_REPARSE_POINT | DIRECTORY_FILE | SYNCHRONOUS */,
        IntPtr.Zero, 0);
      if (code != 0 || opened == null || opened.IsInvalid) {
        if (opened != null) opened.Dispose();
        throw new InvalidOperationException("ANCESTOR_RELATIVE_OPEN_FAILED");
      }
      try { Plain(opened, true); return opened; }
      catch { opened.Dispose(); throw; }
    } finally {
      Marshal.FreeHGlobal(ptr);
      Marshal.FreeHGlobal(name);
    }
  }
  // LAB_ONLY_NO_GO: these HANDLEs pin the objects first opened NATIVELY, not
  // necessarily the original A checked by the earlier managed PS preflight.
  // A same-SID ordinary B installed before this constructor's first native
  // scratch open is indistinguishable without an independent original FileId
  // witness; later relative checks cannot repair that missing provenance.
  // Only AFTER this native pin do tests swap A->B and verify rooted behavior.
  // No production RootSession authority, cold/off-host custody, ABA exclusion.
  private sealed class AncestorCustody : IDisposable {
    private readonly string volumePath;
    private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
    private readonly List<FILE_ID_INFO> identities = new List<FILE_ID_INFO>();
    private readonly List<string> components = new List<string>();
    private bool heldReady;
    internal SafeFileHandle Scratch { get { return handles[handles.Count - (heldReady ? 2 : 1)]; } }
    internal SafeFileHandle Held { get { return handles[handles.Count - 1]; } }

    internal AncestorCustody(string scratch, bool heldReadOnly, bool createHeld = false,
        bool deferHeld = false) {
      string full = Path.GetFullPath(scratch).TrimEnd('\\');
      volumePath = Path.GetPathRoot(full);
      if (string.IsNullOrEmpty(volumePath) || volumePath.Length != 3 ||
          volumePath[1] != ':' || volumePath[2] != '\\')
        throw new InvalidOperationException("LOCAL_VOLUME_ROOT_REQUIRED");
      string relative = full.Substring(volumePath.Length);
      string[] parts = relative.Split(new char[] { '\\' }, StringSplitOptions.None);
      try {
        SafeFileHandle volume = Root(volumePath, true);
        handles.Add(volume);
        identities.Add(Id(volume));
        components.Add(null);
        for (int i = 0; i < parts.Length; i++) {
          string component = parts[i];
          // Only the original scratch directory can create held. All other
          // ancestors need read-only directory traversal rights.
          SafeFileHandle child = DirectoryChild(handles[handles.Count - 1], component,
            !(createHeld && i == parts.Length - 1));
          handles.Add(child);
          identities.Add(Id(child));
          components.Add(component);
        }
        // NtCreateFile resolves this single leaf against the pinned scratch
        // HANDLE, without any pathname mkdir through a replaceable junction.
        // No other child or ancestor may be created as a side effect.
        if (!deferHeld) OpenHeld(heldReadOnly, createHeld);
      } catch { Dispose(); throw; }
    }
    internal void OpenHeld(bool readOnly, bool create) {
      if (heldReady) throw new InvalidOperationException("HELD_ALREADY_OPENED");
      Validate();
      SafeFileHandle held = DirectoryChild(Scratch, "held", readOnly, create);
      handles.Add(held);
      identities.Add(Id(held));
      components.Add("held");
      heldReady = true;
      Validate();
    }
    internal void Validate() {
      // Reacquire only the drive volume root by pathname, then every other
      // component through its original retained parent (no descendant paths).
      using (SafeFileHandle volume = Root(volumePath, true)) {
        if (!Same(identities[0], Id(volume)))
          throw new InvalidOperationException("VOLUME_REBOUND");
      }
      for (int i = 1; i < handles.Count; i++) {
        Plain(handles[i - 1], true);
        if (!Same(identities[i - 1], Id(handles[i - 1])))
          throw new InvalidOperationException("RETAINED_ANCESTOR_CHANGED");
        using (SafeFileHandle current = DirectoryChild(handles[i - 1], components[i], true)) {
          if (!Same(identities[i], Id(current)))
            throw new InvalidOperationException("ANCESTOR_REBOUND");
        }
      }
      Plain(Held, true);
      if (!Same(identities[handles.Count - 1], Id(Held)))
        throw new InvalidOperationException("HELD_ANCESTOR_CHANGED");
    }
    public void Dispose() {
      for (int i = handles.Count - 1; i >= 0; i--) handles[i].Dispose();
      handles.Clear();
    }
  }
  private static SafeFileHandle File(SafeFileHandle root, string leaf, bool create) {
    if (leaf != "stage.bin" && leaf != "published.bin" && leaf != "parked-stage.bin"
      && leaf != "prepared.bin" && leaf != "commit.bin" &&
      leaf != "precreate-ready.signal" && leaf != "ancestor-ready.signal" &&
      leaf != "publisher-ready.signal" && leaf != "postattack-ready.signal")
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
  private static ColdObservation ColdLeaf(SafeFileHandle root, string leaf) {
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
      return new ColdObservation { Bytes = Encoding.UTF8.GetString(bytes, 0, (int)read),
        Inode = ExactId(id) };
    } finally {
      if (file != null) file.Dispose();
      Marshal.FreeHGlobal(ptr);
      Marshal.FreeHGlobal(name);
    }
  }
  private static string InspectCold(string scratch) {
    // Fail on an incorrect managed ABI before opening any fixture leaf:
    // LARGE_INTEGER*2 + DWORD + BOOLEAN*2 + padding = 24 bytes on NTFS.
    if (Marshal.SizeOf(typeof(FILE_STANDARD_INFO)) != 24 ||
        Marshal.OffsetOf(typeof(FILE_STANDARD_INFO), "NumberOfLinks").ToInt32() != 16 ||
        Marshal.OffsetOf(typeof(FILE_STANDARD_INFO), "DeletePending").ToInt32() != 20 ||
        Marshal.OffsetOf(typeof(FILE_STANDARD_INFO), "Directory").ToInt32() != 21 ||
        Marshal.SizeOf(typeof(FILE_BASIC_INFO)) != 40 ||
        Marshal.OffsetOf(typeof(FILE_BASIC_INFO), "ChangeTime").ToInt32() != 24)
      throw new InvalidOperationException("COLD_NATIVE_ABI_UNVERIFIED");
    using (var custody = new AncestorCustody(scratch, true)) {
      custody.Validate();
      SafeFileHandle root = custody.Held;
      FILE_ID_INFO originalRoot = Id(root);
      ColdObservation stage = ColdLeaf(root, "stage.bin");
      ColdObservation published = ColdLeaf(root, "published.bin");
      ColdObservation prepared = ColdLeaf(root, "prepared.bin");
      ColdObservation commit = ColdLeaf(root, "commit.bin");
      string rootPrefix = "PREPARED_V2:" + ExactId(originalRoot) + ":";
      if (prepared == null || !prepared.Bytes.StartsWith(rootPrefix, StringComparison.Ordinal)
          || prepared.Bytes.Length != rootPrefix.Length + 49 ||
          (stage != null && stage.Bytes != Trusted) ||
          (published != null && published.Bytes != Trusted) ||
          (stage != null && stage.Inode != prepared.Bytes.Substring(rootPrefix.Length)) ||
          (published != null && published.Inode != prepared.Bytes.Substring(rootPrefix.Length)) ||
          (commit != null && commit.Bytes != "COMMITTED_V2:" +
            prepared.Bytes.Substring("PREPARED_V2:".Length)) ||
          !Same(originalRoot, Id(root)))
        throw new InvalidOperationException("COLD_BYTES_UNVERIFIED");
      custody.Validate();
      string phase;
      if (stage != null && published == null && commit == null)
        phase = "PREPARED_ONLY";
      else if (stage == null && published != null && commit == null)
        phase = "PUBLISHED_NO_COMMIT";
      else if (stage == null && published != null && commit != null)
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
  private static void Ready(SafeFileHandle scratch, string name, string content) {
    if (name != "precreate-ready.signal" && name != "ancestor-ready.signal" &&
        name != "publisher-ready.signal" && name != "postattack-ready.signal")
      throw new InvalidOperationException("UNTRUSTED_LAB_SIGNAL");
    // The signal is created against the original retained scratch HANDLE.
    // No pathname writer can follow a same-SID junction into a foreign dir.
    using (SafeFileHandle signal = File(scratch, name, true)) Write(signal, content);
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
    bool precreateAttack = mode.StartsWith("PRECREATE_SCRATCH_", StringComparison.Ordinal);
    bool noAck = mode.EndsWith("_NO_ACK", StringComparison.Ordinal);
    bool ancestorAttack = mode == "HELD_REBIND" || mode == "HELD_JUNCTION" ||
      precreateAttack;
    if (ancestorAttack &&
        Environment.GetEnvironmentVariable("ROOTARK_ISSUE66_W26_ANCESTOR_ATTACK_LAB") != "1")
      throw new InvalidOperationException("ANCESTOR_ATTACK_LAB_DISABLED");
    if (mode == "EXTERNAL_COLLISION" &&
        Environment.GetEnvironmentVariable("ROOTARK_ISSUE66_W26_EXTERNAL_WRITER_LAB") != "1")
      throw new InvalidOperationException("EXTERNAL_WRITER_LAB_DISABLED");
    if ((crashBefore || crashAfter || complete) &&
        Environment.GetEnvironmentVariable("ROOTARK_ISSUE66_W26_HARD_EXIT_LAB") != "1")
      throw new InvalidOperationException("HARD_EXIT_TEST_DISABLED");
    if (DriveType(Path.GetPathRoot(scratch)) != 3 /* DRIVE_FIXED */)
      throw new InvalidOperationException("LOCAL_FIXED_NTFS_REQUIRED");
    // Run(NORMAL) is NOT safe against a plain B already substituted before
    // the first native pin below: B may receive held and published bytes.
    // PRECREATE tests start the adversary only AFTER that pin, so their GREEN
    // proves the narrower post-pin boundary only. RootSession remains OFF.
    string parent = Path.Combine(scratch, "held");
    using (var custody = new AncestorCustody(scratch, false, true, precreateAttack)) {
      if (precreateAttack) {
        // Real native scratch custody already exists. The external attacker
        // now attempts the exact early rebind before creating held.
        custody.Validate();
        Ready(custody.Scratch, "precreate-ready.signal", "PRECREATE_READY_V1");
        string ack = Path.Combine(scratch + "-parked", "precreate-ack.signal");
        DateTime deadline = DateTime.UtcNow.AddSeconds(noAck ? 2 : 10);
        while (!System.IO.File.Exists(ack)) {
          if (DateTime.UtcNow > deadline)
            throw new InvalidOperationException("PRECREATE_ATTACK_TIMEOUT");
          System.Threading.Thread.Sleep(10);
        }
        if (ReadFixture(ack) != "PRECREATE_JUNCTION_PHYSICAL_V1")
          throw new InvalidOperationException("PRECREATE_ATTACK_NOT_PHYSICAL");
        // After the attacker rebound scratch to foreign B, this extra probe
        // must reach only original A via the retained native scratch HANDLE.
        Ready(custody.Scratch, "postattack-ready.signal", "POSTATTACK_READY_V1");
        custody.Validate();
        custody.OpenHeld(false, true);
      }
      SafeFileHandle root = custody.Held;
      custody.Validate();
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
      if (ancestorAttack) {
        // A second same-SID process rebinds held inside disposable scratch
        // while its original native HANDLE is live, before opening stage.
        Ready(custody.Scratch, "ancestor-ready.signal", "ANCESTOR_READY_V1");
        string ack = Path.Combine(scratch, "ancestor-ack.signal");
        DateTime deadline = DateTime.UtcNow.AddSeconds(10);
        while (!System.IO.File.Exists(ack)) {
          if (DateTime.UtcNow > deadline)
            throw new InvalidOperationException("ANCESTOR_ATTACK_TIMEOUT");
          System.Threading.Thread.Sleep(10);
        }
        if (ReadFixture(ack) != "ANCESTOR_REBOUND_V1")
          throw new InvalidOperationException("ANCESTOR_ATTACK_NOT_PHYSICAL");
      }
      using (SafeFileHandle source = File(root, "stage.bin", true)) {
        Write(source, Trusted);
        FILE_ID_INFO original = Id(source);
        FILE_ID_INFO initialRoot = Id(root);
        string originalIdentity = ExactId(initialRoot) + ":" + ExactId(original);
        // ROOT_SWAP is the older explicit handle-versus-path demonstration:
        // it intentionally succeeds in detached A. All other modes must
        // reject a rebounded ancestor before PREPARE or any publication.
        if (mode != "ROOT_SWAP") custody.Validate();
        if (crashBefore || crashAfter || complete) {
          using (SafeFileHandle prepared = File(root, "prepared.bin", true))
            Write(prepared, "PREPARED_V2:" + originalIdentity);
          if (crashBefore) ExitImmediately(74);
        }
        string stage = Path.Combine(parent, "stage.bin");
        string target = Path.Combine(parent, "published.bin");
        if (mode == "COLLISION") {
          // Physical foreign destination inserted before the no-replace syscall.
          PlantForeign(target, Foreign);
        } else if (mode == "EXTERNAL_COLLISION") {
          // A separately spawned SAME-SID process must create+fsync a foreign
          // destination AFTER our stage/root HANDLEs are opened, but BEFORE
          // native no-replace. The disposable rendezvous files grant no root
          // custody, and this test makes no claims about hostile writer
          // exclusion or real power loss.
          Ready(custody.Scratch, "publisher-ready.signal", "PUBLISHER_READY_V1");
          string ack = Path.Combine(scratch, "writer-ack.signal");
          DateTime deadline = DateTime.UtcNow.AddSeconds(10);
          while (!System.IO.File.Exists(ack)) {
            if (DateTime.UtcNow > deadline)
              throw new InvalidOperationException("EXTERNAL_WRITER_TIMEOUT");
            System.Threading.Thread.Sleep(10);
          }
          if (ReadFixture(ack) != "WRITER_READY_V1" ||
              ReadFixture(target) != Foreign)
            throw new InvalidOperationException("EXTERNAL_WRITER_NOT_PHYSICAL");
          using (SafeFileHandle foreign = File(root, "published.bin", false)) {
            if (Same(original, Id(foreign)))
              throw new InvalidOperationException("EXTERNAL_WRITER_SAME_INODE");
          }
        } else if (mode == "SOURCE_SWAP") {
          // Real rename AFTER holding original stage HANDLE. Equal bytes do
          // not make the newly occupying inode the original FD.
          System.IO.File.Move(stage, Path.Combine(parent, "parked-stage.bin"));
          PlantForeign(stage, Trusted);
          using (SafeFileHandle other = File(root, "stage.bin", false)) {
            if (Same(original, Id(other)))
              throw new InvalidOperationException("SOURCE_SWAP_NOT_PHYSICAL");
          }
        } else if (mode != "ROOT_SWAP" && mode != "NORMAL" && !crashAfter && !complete && !ancestorAttack) {
          throw new InvalidOperationException("UNTRUSTED_MODE");
        }
        if (mode != "ROOT_SWAP") custody.Validate();
        int code = Rename(source, root, "published.bin");
        if (mode == "COLLISION" || mode == "EXTERNAL_COLLISION") {
          // A generic NT failure could otherwise fool the no-clobber proof.
          // The actual NTFS syscall must report STATUS_OBJECT_NAME_COLLISION.
          if (code != unchecked((int)0xC0000035) || ReadFixture(target) != Foreign ||
              !System.IO.File.Exists(stage) ||
              ReadFixture(stage) != Trusted)
            throw new InvalidOperationException("DESTINATION_CLOBBERED");
          return "ROOTARK_W26_HANDLE_PUBLISH mode=" + mode + " result=DENIED foreign=INTACT stage=INTACT collisionNtstatus=0x" +
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
          custody.Validate();
          // Only the fully completed opt-in rehearsal writes this marker.
          // Windows namespace durability and cold recovery are NOT proven.
          using (SafeFileHandle marker = File(root, "commit.bin", true))
            Write(marker, "COMMITTED_V2:" + originalIdentity);
        }
        if (mode != "ROOT_SWAP") custody.Validate();
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
