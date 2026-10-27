const { execFileSync } = require("node:child_process");

// This verifier is the final authority for protected on-disk ciphertext and
// its co-located device registry. Executing a PATH-selected powershell.exe
// lets a local attacker substitute a no-op binary returning exit status 0,
// silently approving arbitrary NTFS ACLs. Pin ALL native ACL actions to
// Windows PowerShell's canonical system executable, including create/sddl.
const TRUSTED_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

const NATIVE_ACL = String.raw`
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

public static class RootarkChunkAclNative {
  const uint OWNER_SECURITY_INFORMATION = 0x1;
  const uint DACL_SECURITY_INFORMATION = 0x4;
  const uint SE_FILE_OBJECT = 1;
  const int DELETE = 0x00010000;
  const int DELETE_CHILD = 0x00000040;
  const int WRITE_DAC = 0x00040000;
  const int WRITE_OWNER = 0x00080000;
  const int GENERIC_ALL = unchecked((int)0x10000000);
  const int FULL_CONTROL = 0x001F01FF;

  [StructLayout(LayoutKind.Sequential)] public struct SecurityAttributes {
    public int Length;
    public IntPtr SecurityDescriptor;
    [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
  }

  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, IntPtr size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  static extern uint GetNamedSecurityInfoW(string path, uint objectType, uint securityInfo, out IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr descriptor, uint revision, uint securityInfo, out IntPtr sddl, out uint length);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr LocalFree(IntPtr memory);

  static string ReadSddl(string path) {
    IntPtr owner, descriptor, sddl;
    uint status = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, out owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out descriptor);
    if (status != 0) throw new Win32Exception((int)status);
    try {
      uint length;
      if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, out sddl, out length)) throw new Win32Exception(Marshal.GetLastWin32Error());
      try { return Marshal.PtrToStringUni(sddl); }
      finally { LocalFree(sddl); }
    } finally { LocalFree(descriptor); }
  }

  static RawSecurityDescriptor ReadDescriptor(string path) {
    return new RawSecurityDescriptor(ReadSddl(path));
  }

  static void AssertDirectoryNoReparse(string path) {
    FileAttributes attributes = File.GetAttributes(path);
    if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Unsafe chunk staging directory");
  }

  static bool IsTrusted(string sid, string[] trusted) {
    foreach (string item in trusted) if (item == sid) return true;
    return false;
  }

  static void AssertTrustedOwnerAndSafeAncestors(string root, string[] trusted) {
    string[] trustedAncestors = new string[] { trusted[0], trusted[1], trusted[2], "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
    DirectoryInfo cursor = Directory.GetParent(root);
    while (cursor != null) {
      AssertDirectoryNoReparse(cursor.FullName);
      RawSecurityDescriptor descriptor = ReadDescriptor(cursor.FullName);
      if (descriptor.Owner == null || !IsTrusted(descriptor.Owner.Value, trustedAncestors)) throw new InvalidOperationException("Untrusted owner on chunk staging ancestor");
      if (descriptor.DiscretionaryAcl == null) throw new InvalidOperationException("Unverifiable chunk staging ancestor DACL");
      foreach (GenericAce entry in descriptor.DiscretionaryAcl) {
        QualifiedAce ace = entry as QualifiedAce;
        if (ace == null || ace.SecurityIdentifier == null) throw new InvalidOperationException("Unverifiable chunk staging ancestor ACE");
        if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
        if (ace.AceQualifier == AceQualifier.AccessAllowed && !IsTrusted(ace.SecurityIdentifier.Value, trustedAncestors)) {
          int unsafeRights = DELETE | DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
          if ((ace.AccessMask & unsafeRights) != 0) throw new InvalidOperationException("Untrusted principal can replace chunk staging path");
        }
      }
      cursor = cursor.Parent;
    }
  }

  static void AssertRestrictedItem(string path, bool rootItem, string[] trusted) {
    FileAttributes attributes = File.GetAttributes(path);
    if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Reparse point in chunk staging tree");
    RawSecurityDescriptor descriptor = ReadDescriptor(path);
    if (descriptor.Owner == null || !IsTrusted(descriptor.Owner.Value, trusted)) throw new InvalidOperationException("Untrusted owner in chunk staging tree");
    if (descriptor.DiscretionaryAcl == null || (rootItem && (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)) throw new InvalidOperationException("Unverifiable chunk staging DACL");
    HashSet<string> fullControl = new HashSet<string>(StringComparer.Ordinal);
    foreach (GenericAce entry in descriptor.DiscretionaryAcl) {
      QualifiedAce ace = entry as QualifiedAce;
      if (ace == null || ace.SecurityIdentifier == null || !IsTrusted(ace.SecurityIdentifier.Value, trusted) || ace.AceQualifier != AceQualifier.AccessAllowed) throw new InvalidOperationException("Untrusted principal in chunk staging DACL");
      if ((ace.AccessMask & FULL_CONTROL) == FULL_CONTROL) fullControl.Add(ace.SecurityIdentifier.Value);
    }
    foreach (string sid in trusted) if (!fullControl.Contains(sid)) throw new InvalidOperationException("Trusted principal lacks full control in chunk staging tree");
  }

  // Authority signing keys, CA bundles and the bootstrap JSON can be loaded
  // from an operator-owned inherited (but safe) DACL. Do not demand a special
  // protected staging root. Reject ANY nontrusted ALLOW ACE on the leaf:
  // reading an Ed25519 private key is already an authority compromise.
  static void AssertAuthorityFile(string file, string[] trusted) {
    AssertTrustedOwnerAndSafeAncestors(file, trusted);
    FileAttributes attributes = File.GetAttributes(file);
    if ((attributes & FileAttributes.Directory) != 0 || (attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Authority file is a reparse point");
    RawSecurityDescriptor descriptor = ReadDescriptor(file);
    if (descriptor.Owner == null || !IsTrusted(descriptor.Owner.Value, trusted)
      || descriptor.DiscretionaryAcl == null) throw new InvalidOperationException("Untrusted authority file owner or DACL");
    foreach (GenericAce entry in descriptor.DiscretionaryAcl) {
      QualifiedAce ace = entry as QualifiedAce;
      if (ace == null || ace.SecurityIdentifier == null) throw new InvalidOperationException("Unverifiable authority ACE");
      if (ace.AceQualifier == AceQualifier.AccessAllowed && !IsTrusted(ace.SecurityIdentifier.Value, trusted))
        throw new InvalidOperationException("Untrusted authority file ACE");
    }
  }

  public static string Ensure(string root, string action) {
    root = Path.GetFullPath(root);
    string currentSid = WindowsIdentity.GetCurrent().User.Value;
    string[] trusted = new string[] { currentSid, "S-1-5-18", "S-1-5-32-544" };
    if (action == "sddl") return ReadSddl(root);
    if (action == "verify-authority") {
      // No UNC/server path or alternate device namespace for signing keys.
      if (root.StartsWith(@"\\", StringComparison.Ordinal) || !Path.IsPathRooted(root))
        throw new InvalidOperationException("Authority path must be local");
      AssertAuthorityFile(root, trusted);
      return String.Empty;
    }
    AssertTrustedOwnerAndSafeAncestors(root, trusted);
    if (action == "create") {
      if (!Directory.Exists(root)) {
        string sddl = "D:P(A;OICI;FA;;;" + currentSid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        IntPtr securityDescriptor;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out securityDescriptor, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
          SecurityAttributes attributes = new SecurityAttributes();
          attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));
          attributes.SecurityDescriptor = securityDescriptor;
          if (!CreateDirectoryW(root, ref attributes)) {
            int error = Marshal.GetLastWin32Error();
            if (error != 183) throw new Win32Exception(error);
          }
        } finally { LocalFree(securityDescriptor); }
      }
      AssertDirectoryNoReparse(root);
      return String.Empty;
    }
    if (action == "verify") {
      // Concurrent trusted SQLite writers may delete transient WAL/SHM files
      // after enumeration but before the ACL query. Restart the ENTIRE scan,
      // including ancestry and root, only for positively identified absence;
      // never retry an unsafe DACL, reparse point, or access-denied result.
      for (int attempt = 0; attempt < 4; attempt++) {
        try {
          AssertTrustedOwnerAndSafeAncestors(root, trusted);
          AssertDirectoryNoReparse(root);
          AssertRestrictedItem(root, true, trusted);
          Stack<string> pending = new Stack<string>();
          pending.Push(root);
          while (pending.Count > 0) {
            string directory = pending.Pop();
            foreach (string entry in Directory.GetFileSystemEntries(directory)) {
              FileAttributes attributes = File.GetAttributes(entry);
              AssertRestrictedItem(entry, false, trusted);
              if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
            }
          }
          return ReadSddl(root);
        } catch (FileNotFoundException) {
          if (attempt == 3) throw;
        } catch (DirectoryNotFoundException) {
          if (attempt == 3) throw;
        } catch (Win32Exception error) {
          if ((error.NativeErrorCode != 2 && error.NativeErrorCode != 3) || attempt == 3) throw;
        }
        Thread.Sleep(10 * (attempt + 1));
      }
      throw new InvalidOperationException("Chunk staging tree changed during ACL verification");
    }
    throw new InvalidOperationException("Invalid chunk ACL operation");
  }
}
`;

function runAclScript(rootDir, action) {
  const escapedRoot = rootDir.replace(/'/g, "''");
  const script = `Add-Type -TypeDefinition @'\n${NATIVE_ACL}\n'@\n[RootarkChunkAclNative]::Ensure('${escapedRoot}', '${action}')`;
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  try {
    // Pin every ACL action, not only authority verification, while retaining
    // the existing bounded subprocess execution and output limits.
    return execFileSync(TRUSTED_POWERSHELL, ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", encoded], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], windowsHide: true, timeout: 12000, maxBuffer: 32 * 1024 }).trim();
  } catch (error) {
    const detail = String(error.stdout || error.stderr || "").match(/Untrusted principal can replace[^"_<\r\n]*/)?.[0];
    throw new Error(detail || "Windows chunk staging ACL validation failed");
  }
}

function ensureWindowsChunkUploadRoot(rootDir) {
  if (process.platform !== "win32") return;
  runAclScript(rootDir, "create");
}

function verifyWindowsChunkUploadTree(rootDir) {
  if (process.platform !== "win32") return;
  runAclScript(rootDir, "verify");
}

function getWindowsChunkAclDescriptor(rootDir) {
  if (process.platform !== "win32") throw new Error("Windows ACL inspection is only available on Windows");
  return runAclScript(rootDir, "sddl");
}

function verifyWindowsAuthorityFilePath(filename) {
  if (process.platform !== "win32") return;
  runAclScript(filename, "verify-authority");
}

module.exports = { ensureWindowsChunkUploadRoot, verifyWindowsChunkUploadTree, getWindowsChunkAclDescriptor,
  verifyWindowsAuthorityFilePath, NATIVE_ACL, TRUSTED_POWERSHELL };
