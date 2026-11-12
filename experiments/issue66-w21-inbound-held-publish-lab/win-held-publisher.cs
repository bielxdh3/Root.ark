// PR300 / Issue66 NTFS FOD PUBLICATION LAB ONLY. NOT production sync code.
// A Windows HANDLE-bound hard link can bind the originally opened FileId
// even after a real second process swaps the source name. This does NOT
// establish trusted RootSession/operator custody or mapped-writer fencing.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

class W21WinHandleLinkLab {
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_WRITE_ATTRIBUTES = 0x00000100;
    private const uint DELETE = 0x00010000;
    private const uint FILE_SHARE_ALL = 7;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const int FileIdInfo = 18;
    private const int NtFileRenameInformation = 10;
    private const int NtFileLinkInformation = 11; // FILE_INFORMATION_CLASS, NOT Win32 FILE_INFO_BY_HANDLE_CLASS.
    private const int STATUS_OBJECT_NAME_COLLISION = unchecked((int)0xC0000035);
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    // A narrowly scoped, nonauthorizing original-A enrollment experiment.
    // The Node harness verifies a separately issued *test* Ed25519 receipt;
    // this helper receives already-verified physical IDs, never a private key.
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint FILE_READ_ATTRIBUTES = 0x00000080;
    private const uint FILE_TRAVERSE = 0x00000020;
    private const uint FILE_LIST_DIRECTORY = 0x00000001;
    private const uint OBJ_CASE_INSENSITIVE = 0x40;
    private const uint OBJ_DONT_REPARSE = 0x1000;
    private const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_DIRECTORY_FILE = 0x1;
    private const uint FILE_NON_DIRECTORY_FILE = 0x40;
    private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
    private const int FileAttributeTagInfo = 9;
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
    private struct FILE_ATTRIBUTE_TAG_INFO {
        public uint Attributes, ReparseTag;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr securityAttributes, uint creation, uint flags, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(IntPtr handle, int cls,
        IntPtr buffer, uint length);
    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(IntPtr handle, ref IO_STATUS_BLOCK io,
        IntPtr buffer, uint length, int informationClass);
    [DllImport("ntdll.dll", EntryPoint = "NtCreateFile", ExactSpelling = true)]
    private static extern int NtCreateFile(out IntPtr handle, uint access,
        ref OBJECT_ATTRIBUTES attr, out IO_STATUS_BLOCK status, IntPtr allocation,
        uint attributes, uint share, uint disposition, uint options,
        IntPtr ea, uint eaLength);
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAttributeTag(IntPtr handle, int cls,
        out FILE_ATTRIBUTE_TAG_INFO data, uint length);
    [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(IntPtr handle,
        StringBuilder volumeName, uint volumeLength, IntPtr serial,
        IntPtr maxComponent, IntPtr flags, StringBuilder filesystem, uint filesystemLength);
    [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string driveRoot);

    private static void Require(bool condition, string stage) {
        if (!condition) throw new Exception("WINDOWS_NATIVE_HANDLE_LAB_FAIL " + stage
            + " win32=" + Marshal.GetLastWin32Error());
    }
    private static IntPtr OpenHeld(string file) {
        IntPtr handle = CreateFileW(file, GENERIC_READ | FILE_WRITE_ATTRIBUTES | DELETE,
            FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);
        Require(handle != new IntPtr(-1) && handle != IntPtr.Zero, "open-held");
        return handle;
    }
    private static string FileId(IntPtr handle) {
        IntPtr data = Marshal.AllocHGlobal(24);
        try {
            Require(GetFileInformationByHandleEx(handle, FileIdInfo, data, 24), "FileIdInfo");
            byte[] value = new byte[24];
            Marshal.Copy(data, value, 0, value.Length);
            return Convert.ToBase64String(value);
        } finally { Marshal.FreeHGlobal(data); }
    }
    private static IntPtr OpenHeldDirectory(string directory) {
        IntPtr handle = CreateFileW(directory, GENERIC_READ,
            FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        Require(handle != new IntPtr(-1) && handle != IntPtr.Zero, "open-parent-directory");
        return handle;
    }
    private static bool SetHeldName(IntPtr handle, IntPtr parentDirectory,
        string name, int informationClass, out int status) {
        Require(IntPtr.Size == 8, "x64-mandatory");
        Require(name.IndexOfAny(new char[] { '\\', '/', ':' }) == -1 && name.Length < 128,
            "relative-leaf-only");
        byte[] utf16 = Encoding.Unicode.GetBytes(name);
        // NT FILE_LINK_INFORMATION/FILE_RENAME_INFORMATION x64:
        // BOOLEAN ReplaceIfExists @0; HANDLE RootDirectory
        // @8; DWORD FileNameLength (BYTES) @16; WCHAR FileName[] @20.
        // Strictly NO REPLACE and held destination PARENT handle.
        byte[] payload = new byte[20 + utf16.Length + 2];
        Array.Copy(BitConverter.GetBytes(parentDirectory.ToInt64()), 0, payload, 8, 8);
        Array.Copy(BitConverter.GetBytes(utf16.Length), 0, payload, 16, 4);
        Array.Copy(utf16, 0, payload, 20, utf16.Length);
        IntPtr info = Marshal.AllocHGlobal(payload.Length);
        try {
            Marshal.Copy(payload, 0, info, payload.Length);
            IO_STATUS_BLOCK io = new IO_STATUS_BLOCK();
            status = NtSetInformationFile(handle, ref io, info,
                (uint)payload.Length, informationClass);
            return status >= 0;
        } finally { Marshal.FreeHGlobal(info); }
    }
    // Test-only PREPARE keeps both OS handles live. Only COMMIT methods may
    // mutate a namespace; neither accepts a source pathname or replaces an
    // existing destination. This is NOT a trusted RootSession or owner-A.
    private sealed class PreparedOperation : IDisposable {
        private IntPtr source;
        private IntPtr destinationParent;
        private readonly string originalSourceId;
        private readonly string originalParentId;
        public string OriginalId { get { return originalSourceId; } }
        public PreparedOperation(string sourceName, string parentName) {
            source = OpenHeld(sourceName);
            try {
                destinationParent = OpenHeldDirectory(parentName);
                originalSourceId = FileId(source);
                originalParentId = FileId(destinationParent);
            } catch { Dispose(); throw; }
        }
        private void CheckPrepared() {
            Require(source != IntPtr.Zero && destinationParent != IntPtr.Zero,
                "prepared-state-required");
            Require(FileId(source) == originalSourceId
                && FileId(destinationParent) == originalParentId,
                "prepare-physical-identity");
        }
        public bool CommitLink(string newLeaf, out int status) {
            CheckPrepared();
            return SetHeldName(source, destinationParent, newLeaf,
                NtFileLinkInformation, out status);
        }
        public bool CommitRenameNoReplace(string newLeaf, out int status) {
            CheckPrepared();
            return SetHeldName(source, destinationParent, newLeaf,
                NtFileRenameInformation, out status);
        }
        public void Dispose() {
            if (source != IntPtr.Zero) CloseHandle(source);
            if (destinationParent != IntPtr.Zero) CloseHandle(destinationParent);
            source = IntPtr.Zero;
            destinationParent = IntPtr.Zero;
        }
    }
    private static string CurrentSid() {
        return WindowsIdentity.GetCurrent().User.Value;
    }
    private static void AssertNativeType(IntPtr handle, bool directory) {
        FILE_ATTRIBUTE_TAG_INFO tag;
        Require(GetAttributeTag(handle, FileAttributeTagInfo, out tag,
            (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO)))
            && (tag.Attributes & 0x400) == 0
            && ((tag.Attributes & 0x10) != 0) == directory,
            "held-native-plain-type");
    }
    private static IntPtr OpenNativeRelative(IntPtr parent, string leaf,
        bool directory, uint share, bool commitSource = false) {
        Require(!string.IsNullOrEmpty(leaf) && leaf != "." && leaf != ".."
            && leaf.Length < 256 && leaf.IndexOfAny(new char[] { '\\', '/', ':', '\0' }) == -1,
            "native-leaf-validation");
        IntPtr unicode = Marshal.StringToHGlobalUni(leaf);
        IntPtr nameStruct = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        try {
            UNICODE_STRING name = new UNICODE_STRING {
                Length = (ushort)(leaf.Length * 2),
                MaximumLength = (ushort)((leaf.Length + 1) * 2), Buffer = unicode,
            };
            Marshal.StructureToPtr(name, nameStruct, false);
            OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = parent, ObjectName = nameStruct,
                Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            };
            IO_STATUS_BLOCK status;
            IntPtr opened;
            uint access = SYNCHRONIZE | FILE_READ_ATTRIBUTES
                | (directory ? FILE_TRAVERSE | FILE_LIST_DIRECTORY
                    : (commitSource ? GENERIC_READ | DELETE : 0U));
            int code = NtCreateFile(out opened, access, ref attributes, out status,
                IntPtr.Zero, 0x80, share, 1, FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE),
                IntPtr.Zero, 0);
            Require(code == 0 && opened != IntPtr.Zero && opened != new IntPtr(-1),
                "native-relative-open-ntstatus=" + code.ToString("X8"));
            try { AssertNativeType(opened, directory); return opened; }
            catch { CloseHandle(opened); throw; }
        } finally {
            Marshal.FreeHGlobal(nameStruct);
            Marshal.FreeHGlobal(unicode);
        }
    }
    // All path parts are lexical only. The OS object walk opens *every*
    // component via NtCreateFile(RootDirectory=the previously retained HANDLE).
    // Once pinned, native code never uses that pathname for publication.
    private sealed class EnrolledOriginal : IDisposable {
        private readonly System.Collections.Generic.List<IntPtr> held =
            new System.Collections.Generic.List<IntPtr>();
        private readonly System.Collections.Generic.List<string> names =
            new System.Collections.Generic.List<string>();
        private readonly System.Collections.Generic.List<string> ids =
            new System.Collections.Generic.List<string>();
        private readonly uint share;
        public string EnrolledIds { get { return string.Join(",", ids.ToArray()); } }
        public EnrolledOriginal(string targetDirectory, bool lockNames) {
            share = lockNames ? 3U : FILE_SHARE_ALL;
            string full = Path.GetFullPath(targetDirectory);
            string drive = Path.GetPathRoot(full);
            Require(drive != null && drive.Length == 3 && drive[1] == ':'
                && drive[2] == '\\', "absolute-local-drive-required");
            Require(GetDriveTypeW(drive) == 3U, "local-fixed-drive-required");
            // This native drive-root anchor is checked against the enrolled
            // original FileId too. Independent volume/mount trust is absent.
            IntPtr root = CreateFileW(drive, SYNCHRONIZE | FILE_READ_ATTRIBUTES
                | FILE_TRAVERSE | FILE_LIST_DIRECTORY, share, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            Require(root != IntPtr.Zero && root != new IntPtr(-1), "drive-root-open");
            held.Add(root);
            try {
                AssertNativeType(root, true);
                StringBuilder filesystem = new StringBuilder(32);
                Require(GetVolumeInformationByHandleW(root, null, 0, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, filesystem, 32)
                    && string.Equals(filesystem.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase),
                    "physical-NTFS-required");
                ids.Add(FileId(root));
                string[] parts = full.Substring(drive.Length).TrimEnd('\\')
                    .Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                Require(parts.Length > 1 && parts.Length <= 32, "bounded-directory-depth");
                foreach (string part in parts) {
                    IntPtr child = OpenNativeRelative(held[held.Count - 1], part, true, share);
                    held.Add(child);
                    names.Add(part);
                    ids.Add(FileId(child));
                }
                // Keep source DELETE-capable for the real held-HANDLE link.
                // In locked mode its own share=3 prevents hostile source
                // renames; read-only reopens below must permit original
                // DELETE access via share=7, while requesting no DELETE.
                IntPtr source = OpenNativeRelative(held[held.Count - 1], "source", false,
                    share, true);
                held.Add(source);
                ids.Add(FileId(source));
            } catch { Dispose(); throw; }
        }
        public bool Matches(string expected) {
            string[] enrolled = expected.Split(',');
            if (enrolled.Length != ids.Count) return false;
            for (int i = 0; i < enrolled.Length; i++) {
                if (!string.Equals(enrolled[i], ids[i], StringComparison.Ordinal)) return false;
            }
            return true;
        }
        public bool StillNamedOriginal() {
            for (int i = 0; i < held.Count; i++) {
                if (!string.Equals(FileId(held[i]), ids[i], StringComparison.Ordinal)) return false;
                if (i == 0) continue;
                IntPtr reopened = IntPtr.Zero;
                try {
                    reopened = OpenNativeRelative(held[i - 1],
                        i == held.Count - 1 ? "source" : names[i - 1],
                        i != held.Count - 1,
                        i == held.Count - 1 ? FILE_SHARE_ALL : share);
                    if (!string.Equals(FileId(reopened), ids[i], StringComparison.Ordinal)) return false;
                } catch { return false; }
                finally { if (reopened != IntPtr.Zero) CloseHandle(reopened); }
            }
            return true;
        }
        public bool CommitLink(out int status) {
            return SetHeldName(held[held.Count - 1], held[held.Count - 2],
                "published", NtFileLinkInformation, out status);
        }
        public void Dispose() {
            for (int i = held.Count - 1; i >= 0; i--) CloseHandle(held[i]);
            held.Clear();
        }
    }
    private static int EnrolledMode(string[] args) {
        Require(args.Length >= 3, "enrolled-args");
        bool lockNames = args[1] == "locked";
        Require(args[1] == "locked" || args[1] == "movable", "enrollment-mode");
        using (EnrolledOriginal original = new EnrolledOriginal(args[2], lockNames)) {
            if (args[0] == "enroll") {
                Console.WriteLine("ENROLLED|" + original.EnrolledIds);
                return 0;
            }
            Require(args[0] == "publish" && args.Length == 4, "publication-args");
            if (!original.Matches(args[3])) {
                Console.WriteLine("REJECTED|ENROLLED_ORIGINAL_MISMATCH");
                return 21;
            }
            Console.WriteLine("PINNED|" + CurrentSid() + "|" + Process.GetCurrentProcess().Id);
            Console.Out.Flush();
            Require(Console.ReadLine() == "COMMIT", "commit-signal");
            if (!original.StillNamedOriginal()) {
                Console.WriteLine("REJECTED|ORIGINAL_ANCESTRY_REBOUND");
                return 22;
            }
            int status;
            if (!original.CommitLink(out status)) {
                Console.WriteLine("REJECTED|NO_REPLACE_" + status.ToString("X8"));
                return 23;
            }
            Console.WriteLine("PUBLISHED|HELD_SOURCE|NO_REPLACE|" + CurrentSid());
            return 0;
        }
    }
    private static string ReadWhileNativeHandleRetained(string name) {
        // The lab's PREPARE source was opened with DELETE access. A normal
        // File.ReadAllText stream can omit FILE_SHARE_DELETE and fail despite
        // otherwise sound inode publication under NTFS share-mode rules.
        using (FileStream stream = new FileStream(name, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete))
        using (StreamReader reader = new StreamReader(stream, Encoding.UTF8)) {
            return reader.ReadToEnd();
        }
    }

    private static int Attacker(string root, string sourceLeaf) {
        Require(sourceLeaf == "source" || sourceLeaf == "rename-source", "attack-leaf");
        string source = Path.Combine(root, sourceLeaf);
        string retained = Path.Combine(root, sourceLeaf + ".retained");
        Console.WriteLine("READY|" + CurrentSid() + "|" + Process.GetCurrentProcess().Id);
        if (Console.ReadLine() != "START") return 10;
        File.Move(source, retained);
        File.WriteAllText(source, "FOREIGN SECOND-PROCESS BYTES", Encoding.UTF8);
        using (FileStream foreign = new FileStream(source, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete))
        using (FileStream late = new FileStream(Path.Combine(root, "occupied-late"),
            FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete)) {
            byte[] lateBytes = Encoding.UTF8.GetBytes("FOREIGN LATE FOD DESTINATION");
            late.Write(lateBytes, 0, lateBytes.Length);
            late.Flush(true);
            Console.WriteLine("SWAPPED");
            if (Console.ReadLine() != "RELEASE") return 11;
        }
        return 0;
    }

    private static int Parent() {
        string root = Path.Combine(Path.GetTempPath(),
            "rootark67-w21-native-handle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string source = Path.Combine(root, "source");
        string retained = Path.Combine(root, "source.retained");
        string published = Path.Combine(root, "published");
        Process child = null;
        PreparedOperation prepared = null;
        try {
            File.WriteAllText(source, "ORIGINAL VERIFIED BYTES", Encoding.UTF8);
            prepared = new PreparedOperation(source, root);
            string originalId = prepared.OriginalId;
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = System.Reflection.Assembly.GetExecutingAssembly().Location;
            start.Arguments = "attacker \"" + root.Replace("\"", "\\\"") + "\" source";
            start.UseShellExecute = false;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.CreateNoWindow = true;
            child = Process.Start(start);
            Require(child != null && child.Id != Process.GetCurrentProcess().Id,
                "different-process");
            string greeting = child.StandardOutput.ReadLine();
            Require(greeting != null && greeting.StartsWith("READY|"), "child-ready");
            string[] fields = greeting.Split('|');
            Require(fields.Length == 3 && fields[1] == CurrentSid()
                && int.Parse(fields[2]) == child.Id, "same-sid-child");
            child.StandardInput.WriteLine("START");
            child.StandardInput.Flush();
            Require(child.StandardOutput.ReadLine() == "SWAPPED", "child-swapped");
            IntPtr retainedHandle = OpenHeld(retained);
            try { Require(FileId(retainedHandle) == originalId, "retained-inode"); }
            finally { CloseHandle(retainedHandle); }
            IntPtr foreignHandle = OpenHeld(source);
            string foreignId;
            try { foreignId = FileId(foreignHandle); }
            finally { CloseHandle(foreignHandle); }
            Require(foreignId != originalId, "distinct-foreign-inode");
            string occupiedLate = Path.Combine(root, "occupied-late");
            IntPtr lateHandle = OpenHeld(occupiedLate);
            string lateId;
            try { lateId = FileId(lateHandle); }
            finally { CloseHandle(lateHandle); }
            int status;
            Require(!prepared.CommitLink("occupied-late", out status)
                && status == STATUS_OBJECT_NAME_COLLISION,
                "late-foreign-destination-no-replace");
            IntPtr lateAfter = OpenHeld(occupiedLate);
            try { Require(FileId(lateAfter) == lateId, "late-foreign-inode-preserved"); }
            finally { CloseHandle(lateAfter); }
            Require(ReadWhileNativeHandleRetained(occupiedLate) == "FOREIGN LATE FOD DESTINATION",
                "late-foreign-destination-bytes-preserved");
            Require(prepared.CommitLink("published", out status),
                "native-NtSetInformationFile-link status=" + status.ToString("X8"));
            IntPtr publishedHandle = OpenHeld(published);
            try { Require(FileId(publishedHandle) == originalId, "published-original-FileId"); }
            finally { CloseHandle(publishedHandle); }
            Require(ReadWhileNativeHandleRetained(published) == "ORIGINAL VERIFIED BYTES",
                "published-original-bytes");
            Require(ReadWhileNativeHandleRetained(source) == "FOREIGN SECOND-PROCESS BYTES",
                "foreign-preserved");
            Require(!prepared.CommitLink("published", out status)
                && status == STATUS_OBJECT_NAME_COLLISION,
                "no-replace-must-fail-EEXIST");
            child.StandardInput.WriteLine("RELEASE");
            child.StandardInput.Flush();
            Require(child.WaitForExit(10000) && child.ExitCode == 0, "child-exit");
            Console.WriteLine("WINDOWS_NATIVE_HANDLE_LINK_LAB_PASS secondProcess=true sameSid=true originalFileId=true noReplace=true foreignPreserved=true");
            Console.WriteLine("WINDOWS_FOD_LATE_DESTINATION_PROTECTED secondProcess=true sameSid=true noReplace=true lateForeignPreserved=true rootAuthority=false");
            return 0;
        } finally {
            if (prepared != null) prepared.Dispose();
            if (child != null) {
                if (!child.HasExited) child.Kill();
                child.Dispose();
            }
            // Lab-created synthetic directory only, after all handles close.
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }
    private static int ParentRename() {
        string root = Path.Combine(Path.GetTempPath(),
            "rootark67-w21-native-rename-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string source = Path.Combine(root, "rename-source");
        string retained = Path.Combine(root, "rename-source.retained");
        string renamed = Path.Combine(root, "staged-owner");
        string occupied = Path.Combine(root, "occupied");
        Process child = null;
        PreparedOperation prepared = null;
        try {
            File.WriteAllText(source, "ORIGINAL RENAME BYTES", Encoding.UTF8);
            File.WriteAllText(occupied, "OCCUPIED FOREIGN DESTINATION", Encoding.UTF8);
            prepared = new PreparedOperation(source, root);
            string originalId = prepared.OriginalId;
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = System.Reflection.Assembly.GetExecutingAssembly().Location;
            start.Arguments = "attacker \"" + root.Replace("\"", "\\\"") + "\" rename-source";
            start.UseShellExecute = false;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.CreateNoWindow = true;
            child = Process.Start(start);
            Require(child != null && child.Id != Process.GetCurrentProcess().Id,
                "rename-distinct-pid");
            string[] hello = (child.StandardOutput.ReadLine() ?? "").Split('|');
            Require(hello.Length == 3 && hello[0] == "READY"
                && hello[1] == CurrentSid() && int.Parse(hello[2]) == child.Id,
                "rename-same-SID");
            child.StandardInput.WriteLine("START");
            child.StandardInput.Flush();
            Require(child.StandardOutput.ReadLine() == "SWAPPED", "rename-foreign-swapped");
            IntPtr retainedHandle = OpenHeld(retained);
            try { Require(FileId(retainedHandle) == originalId, "rename-original-retained"); }
            finally { CloseHandle(retainedHandle); }
            IntPtr foreignHandle = OpenHeld(source);
            try { Require(FileId(foreignHandle) != originalId, "rename-foreign-distinct"); }
            finally { CloseHandle(foreignHandle); }
            int status;
            Require(!prepared.CommitRenameNoReplace("occupied", out status)
                && status == STATUS_OBJECT_NAME_COLLISION, "rename-no-replace");
            Require(!prepared.CommitRenameNoReplace("occupied-late", out status)
                && status == STATUS_OBJECT_NAME_COLLISION, "rename-late-no-replace");
            Require(ReadWhileNativeHandleRetained(Path.Combine(root, "occupied-late"))
                == "FOREIGN LATE FOD DESTINATION", "rename-late-foreign-preserved");
            Require(ReadWhileNativeHandleRetained(occupied)
                == "OCCUPIED FOREIGN DESTINATION", "collision-foreign-preserved");
            Require(prepared.CommitRenameNoReplace("staged-owner", out status),
                "rename-NtSetInformationFile status=" + status.ToString("X8"));
            IntPtr stagedHandle = OpenHeld(renamed);
            try { Require(FileId(stagedHandle) == originalId, "rename-staged-original-id"); }
            finally { CloseHandle(stagedHandle); }
            Require(!File.Exists(retained), "rename-source-alias-moved");
            Require(ReadWhileNativeHandleRetained(renamed) == "ORIGINAL RENAME BYTES",
                "rename-original-bytes");
            Require(ReadWhileNativeHandleRetained(source) == "FOREIGN SECOND-PROCESS BYTES",
                "rename-foreign-source-preserved");
            child.StandardInput.WriteLine("RELEASE");
            child.StandardInput.Flush();
            Require(child.WaitForExit(10000) && child.ExitCode == 0, "rename-child-exit");
            Console.WriteLine("WINDOWS_NATIVE_HANDLE_RENAME_LAB_PASS secondProcess=true sameSid=true originalFileId=true noReplace=true foreignPreserved=true");
            return 0;
        } finally {
            if (prepared != null) prepared.Dispose();
            if (child != null) {
                if (!child.HasExited) child.Kill();
                child.Dispose();
            }
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }
    public static int Main(string[] args) {
        try {
            if (args.Length > 0 && (args[0] == "enroll" || args[0] == "publish"))
                return EnrolledMode(args);
            if (args.Length == 3 && args[0] == "attacker") return Attacker(args[1], args[2]);
            if (args.Length == 1 && args[0] == "rename") return ParentRename();
            if (args.Length == 0) return Parent();
            throw new Exception("Invalid LAB arguments");
        } catch (Exception error) {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }
}
