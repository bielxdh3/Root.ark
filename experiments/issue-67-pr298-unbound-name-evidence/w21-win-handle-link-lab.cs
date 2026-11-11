// PR298 / Issue67 NTFS LAB ONLY. NOT production sync code.
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
            FileShare.ReadWrite | FileShare.Delete)) {
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
            int status;
            Require(prepared.CommitLink("published", out status),
                "native-NtSetInformationFile-link status=" + status.ToString("X8"));
            IntPtr publishedHandle = OpenHeld(published);
            try { Require(FileId(publishedHandle) == originalId, "published-original-FileId"); }
            finally { CloseHandle(publishedHandle); }
            Require(File.ReadAllText(published, Encoding.UTF8) == "ORIGINAL VERIFIED BYTES",
                "published-original-bytes");
            Require(File.ReadAllText(source, Encoding.UTF8) == "FOREIGN SECOND-PROCESS BYTES",
                "foreign-preserved");
            Require(!prepared.CommitLink("published", out status)
                && status == STATUS_OBJECT_NAME_COLLISION,
                "no-replace-must-fail-EEXIST");
            child.StandardInput.WriteLine("RELEASE");
            child.StandardInput.Flush();
            Require(child.WaitForExit(10000) && child.ExitCode == 0, "child-exit");
            Console.WriteLine("WINDOWS_NATIVE_HANDLE_LINK_LAB_PASS secondProcess=true sameSid=true originalFileId=true noReplace=true foreignPreserved=true");
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
