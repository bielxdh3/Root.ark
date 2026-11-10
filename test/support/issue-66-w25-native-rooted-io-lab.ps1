param([string]$Scratch)

$ErrorActionPreference = 'Stop'
try {
  # This is an explicitly opted-in, disposable test lab, not a production
  # capability or a general-purpose ACL/file deletion tool.
  if ($env:ROOTARK_ISSUE66_W25_NATIVE_IO_LAB -ne '1') { throw 'LAB_DISABLED' }
  # Keep the disposable lab under the current user's LocalAppData, NOT a
  # public or caller-selected TEMP directory and not an arbitrary repository.
  $approvedParent = [System.IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)).TrimEnd('\')
  $directory = [System.IO.DirectoryInfo]::new($Scratch)
  if (-not $directory.Exists -or
      $directory.Name -notmatch '^rootark-w25-native-rooted-io-[A-Za-z0-9_-]{6,}$' -or
      -not [string]::Equals($directory.Parent.FullName.TrimEnd('\'), $approvedParent,
        [StringComparison]::OrdinalIgnoreCase) -or
      ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $directory.GetFileSystemInfos().Count -ne 0 -or
      (([System.IO.DirectoryInfo]::new($approvedParent)).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'UNOWNED_LAB_SCRATCH'
  }

  $original = [System.IO.Path]::Combine($directory.FullName, 'held-ancestor')
  [System.IO.Directory]::CreateDirectory($original) | Out-Null
  $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner($owner)
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $owner, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow))
  [System.IO.Directory]::SetAccessControl($original, $acl)

  Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class RootarkW25RootedIoLab {
  [StructLayout(LayoutKind.Sequential)]
  private struct UnicodeString {
    public ushort Length, MaximumLength;
    public IntPtr Buffer;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct ObjectAttributes {
    public int Length;
    public IntPtr RootDirectory, ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor, SecurityQualityOfService;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct IoStatusBlock {
    public IntPtr Status, Information;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct FileDispositionInfo {
    [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct FileAttributeTagInfo {
    public uint Attributes, ReparseTag;
  }

  [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern SafeFileHandle OpenInitialDirectory(string name, uint access, uint share,
    IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("ntdll.dll", EntryPoint="NtCreateFile", ExactSpelling=true)]
  private static extern int OpenRelative(out SafeFileHandle result, uint access,
    ref ObjectAttributes attributes, out IoStatusBlock status, IntPtr allocation,
    uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaSize);
  [DllImport("kernel32.dll", EntryPoint="SetFileInformationByHandle", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool SetInfo(SafeFileHandle file, int klass,
    ref FileDispositionInfo info, uint size);
  [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetTag(SafeFileHandle file, int klass,
    out FileAttributeTagInfo info, uint size);
  [DllImport("kernel32.dll", EntryPoint="GetVolumeInformationByHandleW", CharSet=CharSet.Unicode,
    SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetVolume(SafeFileHandle handle, StringBuilder name, uint capacity,
    IntPtr serial, IntPtr componentLength, IntPtr flags, StringBuilder fileSystem, uint fsCapacity);

  private const uint GenericRead = 0x80000000, GenericWrite = 0x40000000;
  private const uint AccessDelete = 0x00010000, AccessSync = 0x00100000;
  private const uint ShareReadWrite = 0x00000003;
  private const uint OpenExisting = 3, FileCreate = 2, FileOpen = 1;
  private const uint DirectoryFlags = 0x02200000; // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
  private const uint FileOptions = 0x00200060; // OPEN_REPARSE_POINT | SYNCHRONOUS | NON_DIRECTORY
  private const uint ObjectFlags = 0x00001040; // OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE
  private const uint ReparseAttribute = 0x00000400;

  private static void CheckNormal(SafeFileHandle file, bool expectDirectory) {
    FileAttributeTagInfo tag;
    if (!GetTag(file, 9, out tag, (uint)Marshal.SizeOf(typeof(FileAttributeTagInfo))) ||
        (tag.Attributes & ReparseAttribute) != 0 ||
        (((tag.Attributes & 0x10) != 0) != expectDirectory))
      throw new InvalidOperationException("INVALID_HANDLE_TARGET");
  }

  private static SafeFileHandle RootedFile(SafeFileHandle root, string leaf, bool create) {
    if (leaf != "original.bin" && leaf != "after-swap.bin")
      throw new InvalidOperationException("UNTRUSTED_LEAF");
    IntPtr buffer = Marshal.StringToHGlobalUni(leaf);
    IntPtr unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
    try {
      UnicodeString u = new UnicodeString {
        Length = checked((ushort)(leaf.Length * 2)),
        MaximumLength = checked((ushort)((leaf.Length + 1) * 2)),
        Buffer = buffer
      };
      Marshal.StructureToPtr(u, unicode, false);
      ObjectAttributes attr = new ObjectAttributes {
        Length = Marshal.SizeOf(typeof(ObjectAttributes)),
        RootDirectory = root.DangerousGetHandle(), ObjectName = unicode,
        Attributes = ObjectFlags
      };
      IoStatusBlock result;
      SafeFileHandle file;
      int ntStatus = OpenRelative(out file, GenericRead | GenericWrite | AccessDelete | AccessSync,
        ref attr, out result, IntPtr.Zero, 0x80, ShareReadWrite,
        create ? FileCreate : FileOpen, FileOptions, IntPtr.Zero, 0);
      if (ntStatus != 0) {
        if (file != null) file.Dispose();
        throw new InvalidOperationException("NATIVE_ROOTED_OPEN_FAILED");
      }
      try { CheckNormal(file, false); return file; }
      catch { file.Dispose(); throw; }
    } finally {
      Marshal.FreeHGlobal(unicode);
      Marshal.FreeHGlobal(buffer);
    }
  }

  private static void Write(SafeFileHandle root, string leaf, string content) {
    using (SafeFileHandle file = RootedFile(root, leaf, true))
    using (FileStream stream = new FileStream(file, FileAccess.ReadWrite, 4096, false)) {
      byte[] bytes = Encoding.UTF8.GetBytes(content);
      stream.Write(bytes, 0, bytes.Length);
      stream.Flush(true); // file bytes only; NOT a directory/name durability proof
    }
  }

  private static string Read(SafeFileHandle root, string leaf) {
    using (SafeFileHandle file = RootedFile(root, leaf, false))
    using (FileStream stream = new FileStream(file, FileAccess.ReadWrite, 4096, false)) {
      if (stream.Length > 128) throw new InvalidOperationException("OVERSIZED_FIXTURE");
      byte[] bytes = new byte[stream.Length];
      if (stream.Read(bytes, 0, bytes.Length) != bytes.Length)
        throw new InvalidOperationException("SHORT_FIXTURE_READ");
      return Encoding.UTF8.GetString(bytes);
    }
  }

  private static void Delete(SafeFileHandle root, string leaf) {
    using (SafeFileHandle file = RootedFile(root, leaf, false)) {
      FileDispositionInfo disposition = new FileDispositionInfo { DeleteFile = true };
      if (!SetInfo(file, 4, ref disposition, (uint)Marshal.SizeOf(typeof(FileDispositionInfo))))
        throw new InvalidOperationException("HANDLE_DELETE_FAILED");
    }
  }

  public static string Run(string scratch) {
    // All *protected* file IO is NtCreateFile RootDirectory-relative. The
    // following pathname operations are the explicitly adversarial actor.
    string original = Path.Combine(scratch, "held-ancestor");
    string moved = Path.Combine(scratch, "moved-ancestor");
    string foreign = original; // replacement at the former trusted pathname
    using (SafeFileHandle root = OpenInitialDirectory(original,
        0x00020080, ShareReadWrite, IntPtr.Zero, // READ_CONTROL|FILE_READ_ATTRIBUTES
        OpenExisting, DirectoryFlags, IntPtr.Zero)) {
      if (root.IsInvalid) throw new InvalidOperationException("ROOT_OPEN_FAILED");
      CheckNormal(root, true);
      StringBuilder fs = new StringBuilder(32);
      if (!GetVolume(root, null, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, fs, 32) ||
          !string.Equals(fs.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("NTFS_REQUIRED");

      Write(root, "original.bin", "TRUSTED_ORIGINAL");
      Directory.Move(original, moved); // active ancestor ABA attacker
      Directory.CreateDirectory(foreign);
      File.WriteAllText(Path.Combine(foreign, "original.bin"), "FOREIGN_CANARY");

      bool heldRootRead = Read(root, "original.bin") == "TRUSTED_ORIGINAL";
      Delete(root, "original.bin");
      bool originalDeleted = !File.Exists(Path.Combine(moved, "original.bin"));
      bool foreignUnchanged = File.ReadAllText(Path.Combine(foreign, "original.bin")) == "FOREIGN_CANARY";

      Write(root, "after-swap.bin", "TRUSTED_AFTER_SWAP");
      bool originalReceived = File.Exists(Path.Combine(moved, "after-swap.bin"));
      bool replacementNotWritten = !File.Exists(Path.Combine(foreign, "after-swap.bin"));
      bool newReadBound = Read(root, "after-swap.bin") == "TRUSTED_AFTER_SWAP";
      Delete(root, "after-swap.bin");
      bool originalClean = !File.Exists(Path.Combine(moved, "after-swap.bin"));

      if (!heldRootRead || !originalDeleted || !foreignUnchanged ||
          !originalReceived || !replacementNotWritten || !newReadBound || !originalClean)
        throw new InvalidOperationException("ROOT_ESCAPE_OR_WRONG_OBJECT");
      return "ROOTARK_W25_ROOTED_IO_V1 originalRead=1 originalDelete=1 foreignPreserved=1 postSwapCreate=1 postSwapRead=1 postSwapDelete=1";
    }
  }
}
'@ | Out-Null

  [Console]::Out.WriteLine([RootarkW25RootedIoLab]::Run($directory.FullName))
  exit 0
} catch {
  # Deliberately no paths, ACLs, SIDs, compiler diagnostics or exception data.
  [Console]::Error.WriteLine('ROOTARK_W25_ROOTED_IO_REJECTED')
  exit 41
}
