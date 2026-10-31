const { execFileSync, spawn } = require("node:child_process");
const crypto = require("node:crypto");

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
    if (action == "verify-bridge-directory") {
      // The full tree is verified at bridge startup. At each request, pin the
      // ACL trust boundary for the specific directory containing the target;
      // scanning every unrelated file would make GET O(total tree size).
      AssertTrustedOwnerAndSafeAncestors(root, trusted);
      AssertDirectoryNoReparse(root);
      AssertRestrictedItem(root, false, trusted);
      return String.Empty;
    }
    if (action == "verify-bridge-file") {
      // The parent must remain a trusted directory, and the leaf must not
      // acquire a writable/readable foreign ACE after the startup tree scan.
      AssertTrustedOwnerAndSafeAncestors(root, trusted);
      string parent = Path.GetDirectoryName(root);
      AssertDirectoryNoReparse(parent);
      AssertRestrictedItem(parent, false, trusted);
      if ((File.GetAttributes(root) & FileAttributes.Directory) != 0)
        throw new InvalidOperationException("Bridge leaf must be a file");
      AssertRestrictedItem(root, false, trusted);
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
    if (action == "verify" || action == "verify-bridge") {
      // Concurrent trusted SQLite writers may delete transient WAL/SHM files
      // after enumeration but before the ACL query. Restart the ENTIRE scan,
      // including ancestry and root, only for positively identified absence;
      // never retry an unsafe DACL, reparse point, or access-denied result.
      for (int attempt = 0; attempt < 4; attempt++) {
        try {
          AssertTrustedOwnerAndSafeAncestors(root, trusted);
          AssertDirectoryNoReparse(root);
          // Existing user-selected WebDAV roots can inherit a safe DACL from
          // a private parent. Require identical trusted principals/full access
          // on every item, but do not demand a protected root ACL for this
          // bridge-only mode. The original "verify" contract remains strict.
          AssertRestrictedItem(root, action == "verify", trusted);
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

// Windows CreateProcess limits the *entire* argv command line to 32,767
// characters. Base64-encoding the full C# source plus a long owner-private
// path can exceed that limit even though the ACL itself is perfectly valid.
// The bridge verifier already compiles this exact comment/blank-free source;
// reuse it for the one-shot pinned PowerShell invocations, without removing
// a single native security check or changing the fail-closed behavior.
const COMPACT_NATIVE_ACL = NATIVE_ACL.replace(/^[ \t]*\/\/[^\r\n]*\r?\n/gm, "")
  .replace(/^[ \t]*\r?\n/gm, "");

function runAclScript(rootDir, action) {
  const escapedRoot = rootDir.replace(/'/g, "''");
  const script = `Add-Type -TypeDefinition @'\n${COMPACT_NATIVE_ACL}\n'@\n[RootarkChunkAclNative]::Ensure('${escapedRoot}', '${action}')`;
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

function verifyWindowsLocalWebDavTree(rootDir) {
  if (process.platform !== "win32") return;
  runAclScript(rootDir, "verify-bridge");
}

function verifyWindowsLocalWebDavDirectory(directory) {
  if (process.platform !== "win32") return;
  runAclScript(directory, "verify-bridge-directory");
}

// A bridge owns one long-lived, isolated PowerShell subprocess. Compile the
// native ACL verifier ONCE, then perform a fresh native ACL lookup for EACH
// request. The pipe is private to the child process; no PATH lookup, shell,
// temporary script, TTL, optimistic cache, or skipped check is involved.
// A single worker and at most 16 waiting requests bound native admission.
function createWindowsLocalWebDavAclVerifier() {
  if (process.platform !== "win32") {
    return { verify: async () => {}, verifyFile: async () => {},
      verifyAuthorityFile: async () => {}, stop: () => {} };
  }
  // Windows CreateProcess has a 32K command-line limit. The native source is
  // shared with the one-shot verifier; omit comment-only/blank C# lines from
  // this EncodedCommand rather than weakening checks or spawning per request.
  const script = `$ErrorActionPreference = 'Stop'\nAdd-Type -TypeDefinition @'\n${COMPACT_NATIVE_ACL}\n'@\n` + String.raw`
[Console]::Out.WriteLine('READY')
[Console]::Out.Flush()
while ($true) {
  $line = [Console]::ReadLine()
  if ($null -eq $line) { break }
  if ($line.Length -gt 131072) { break }
  $parts = $line.Split('|')
  if ($parts.Length -ne 3 -or $parts[0] -cnotmatch '^[a-f0-9]{32}$' -or ($parts[1] -cne 'D' -and $parts[1] -cne 'F' -and $parts[1] -cne 'P' -and $parts[1] -cne 'C' -and $parts[1] -cne 'A')) { break }
  $nonce = $parts[0]
  try {
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $item = $utf8.GetString([Convert]::FromBase64String($parts[2]))
    if ($parts[1] -ceq 'C') {
      [void][RootarkChunkAclNative]::Ensure($item, 'create')
      [void][RootarkChunkAclNative]::Ensure($item, 'verify')
    } else {
      $action = if ($parts[1] -ceq 'A') { 'verify-authority' } elseif ($parts[1] -ceq 'F') { 'verify-bridge-file' } elseif ($parts[1] -ceq 'P') { 'verify' } else { 'verify-bridge-directory' }
      [void][RootarkChunkAclNative]::Ensure($item, $action)
    }
    [Console]::Out.WriteLine($nonce + '|OK')
  } catch {
    [Console]::Out.WriteLine($nonce + '|DENY')
  }
  [Console]::Out.Flush()
}
`;
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  const MAX_WAITING = 16;
  const CHECK_DEADLINE_MS = 12000;
  let closed = false;
  let worker = null;
  let ready = false;
  let output = "";
  let errorOutput = "";
  let active = null;
  const queue = [];
  const rejectCheck = () => new Error("Windows bridge ACL validation failed");

  function finish(job, error) {
    if (job.finished) return;
    job.finished = true;
    clearTimeout(job.timer);
    if (error) job.reject(rejectCheck());
    else job.resolve();
  }
  function failWorker() {
    const old = worker;
    worker = null;
    ready = false;
    output = "";
    errorOutput = "";
    if (old) {
      old.stdout.removeAllListeners("data");
      old.stderr.removeAllListeners("data");
      old.kill();
    }
    if (active) { finish(active, true); active = null; }
    while (queue.length) finish(queue.shift(), true);
  }
  function sendNext() {
    if (!ready || !worker || active || closed) return;
    let next;
    do { next = queue.shift(); } while (next?.finished);
    if (!next) return;
    active = next;
    const nonce = crypto.randomBytes(16).toString("hex");
    next.nonce = nonce;
    const bytes = Buffer.from(next.directory, "utf8").toString("base64");
    try {
      if (!worker.stdin.write(nonce + "|" + next.kind + "|" + bytes + "\n")) {
        // Pipe backpressure is bounded by one in-flight request. The response
        // cannot authorize a read without an exact matching nonce either way.
      }
    } catch (_) { failWorker(); }
  }
  function onLine(line) {
    if (!ready) {
      if (line !== "READY") return failWorker();
      ready = true;
      return sendNext();
    }
    if (!active || line !== active.nonce + "|OK" && line !== active.nonce + "|DENY") {
      return failWorker();
    }
    const job = active;
    active = null;
    finish(job, line.endsWith("|DENY"));
    sendNext();
  }
  function startWorker() {
    if (worker || closed) return;
    try {
      const child = spawn(TRUSTED_POWERSHELL, ["-NoLogo", "-NoProfile", "-NonInteractive",
        "-OutputFormat", "Text", "-EncodedCommand", encoded], {
        windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
      });
      worker = child;
      ready = false;
      output = "";
      errorOutput = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (data) => {
        if (worker !== child) return;
        output += data;
        if (output.length > 4096) return failWorker();
        let index;
        while (worker === child && (index = output.indexOf("\n")) !== -1) {
          const line = output.slice(0, index).replace(/\r$/, "");
          output = output.slice(index + 1);
          onLine(line);
        }
      });
      child.stderr.on("data", (data) => {
        if (worker !== child) return;
        errorOutput += data.toString("utf8");
        // Windows PowerShell writes only this empty CLIXML prologue to its
        // redirected error stream on successful native console startup.
        // Any actual error record or unexpected stderr content kills the
        // authority subprocess and denies all outstanding requests.
        const harmlessHeader = "#< CLIXML\r\n";
        if (!harmlessHeader.startsWith(errorOutput)
          && errorOutput !== harmlessHeader) failWorker();
      });
      child.stdin.on("error", () => { if (worker === child) failWorker(); });
      child.on("error", () => { if (worker === child) failWorker(); });
      child.on("exit", () => { if (worker === child) failWorker(); });
    } catch (_) { failWorker(); }
  }
  function enqueue(directory, kind) {
      if (closed || typeof directory !== "string" || !directory.length
        || Buffer.byteLength(directory, "utf8") > 65000
        || queue.length >= MAX_WAITING) return Promise.reject(rejectCheck());
      return new Promise((resolve, reject) => {
        const job = { directory, kind, resolve, reject, nonce: "", finished: false };
        job.timer = setTimeout(() => {
          // If the child is blocked or its output is missing/ambiguous, fail
          // ALL unfinished checks, kill it, and never accept a late response.
          failWorker();
        }, CHECK_DEADLINE_MS);
        queue.push(job);
        startWorker();
        sendNext();
      });
  }
  return {
    verify(directory) { return enqueue(directory, "D"); },
    // Same strict, protected-root and recursive ACL verifier as the one-shot
    // `verifyWindowsChunkUploadTree`, with its native C# compiled only once.
    verifyPrivateDirectory(directory) { return enqueue(directory, "P"); },
    createPrivateDirectory(directory) { return enqueue(directory, "C"); },
    verifyFile(filename) { return enqueue(filename, "F"); },
    // Exact native AssertAuthorityFile semantics, including owner, ancestor
    // DELETE_CHILD and every non-operator leaf ALLOW ACE, on EVERY request.
    verifyAuthorityFile(filename) { return enqueue(filename, "A"); },
    stop() {
      closed = true;
      failWorker();
    },
  };
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
  verifyWindowsAuthorityFilePath, verifyWindowsLocalWebDavTree, verifyWindowsLocalWebDavDirectory,
  createWindowsLocalWebDavAclVerifier, NATIVE_ACL, TRUSTED_POWERSHELL };
