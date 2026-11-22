#pragma once
// Windows native RootSession retained NTFS root and ancestry.
// Independent original root enrollment and cold-restart authority are still required.
#include <Windows.h>
#include <winternl.h>
#include <memory>
#include <string>
#include <vector>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include "rootark-sync-windows-cfapi-root-policy.hpp"
namespace {
struct HeldRoot {
  HANDLE handle = INVALID_HANDLE_VALUE;
  FILE_ID_INFO id{};
  ~HeldRoot() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
  bool open(const wchar_t* root, bool allowExclusiveChildCreate = false) {
    // A retained handle without FILE_SHARE_DELETE prevents ordinary rename
    // of this root while a disposable callback is connected. Full RootSession
    // still needs independently enrolled ancestors and anti-rollback custody.
    const DWORD access = FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL
      | (allowExclusiveChildCreate ? FILE_ADD_FILE : 0);
    handle = CreateFileW(root, access,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes,
        sizeof(attributes)) || !(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      || !GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id))) return false;
    wchar_t filesystem[64]{};
    return GetVolumeInformationByHandleW(handle, nullptr, 0, nullptr, nullptr,
      nullptr, filesystem, 64) && _wcsicmp(filesystem, L"NTFS") == 0;
  }
  bool samePath(const wchar_t* root) const {
    HANDLE reopened = CreateFileW(root, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (reopened == INVALID_HANDLE_VALUE) return false;
    FILE_ID_INFO current{};
    const bool exact = GetFileInformationByHandleEx(reopened, FileIdInfo,
      &current, sizeof(current))
      && current.VolumeSerialNumber == id.VolumeSerialNumber
      && std::memcmp(&current.FileId, &id.FileId, sizeof(id.FileId)) == 0;
    CloseHandle(reopened);
    return exact;
  }
  bool registeredPolicy() const {
    if (handle == INVALID_HANDLE_VALUE) return false;
    FILE_ATTRIBUTE_TAG_INFO tags{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
      &tags, sizeof(tags)) || !(tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      || !(tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      // Registration converts this exact native root into a Cloud Files
      // reparse point. Accept only the documented CLOUD tag family; reject
      // junctions, symlinks, mount points and arbitrary provider aliases.
      || (tags.ReparseTag & 0xFFFF0FFFUL) != IO_REPARSE_TAG_CLOUD) return false;
    wchar_t filesystem[64]{};
    if (!GetVolumeInformationByHandleW(handle, nullptr, 0, nullptr, nullptr,
      nullptr, filesystem, 64) || _wcsicmp(filesystem, L"NTFS") != 0) return false;
    std::vector<unsigned char> sid;
    if (!currentUserSid(sid)) return false;
    ScopedDescriptor descriptor;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    return GetSecurityInfo(handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, nullptr, &dacl, nullptr, &descriptor.value) == ERROR_SUCCESS
      && trustedDacl(descriptor.value, dacl, owner, sid);
  }
};

// Retain every ancestor from the physical fixed NTFS volume root through the
// independently opened parent while a callback is live. A same-SID process
// cannot perform ordinary directory rename of those retained objects without
// FILE_SHARE_DELETE. This only pins identity AFTER acquisition; it is NOT an
// operator-issued original-A enrollment or a cold-restart authority.
struct HeldAncestors {
  struct Entry {
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::wstring path;
    FILE_ID_INFO id{};
    ~Entry() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
  };
  std::vector<std::unique_ptr<Entry>> entries;
  bool captureOne(const std::wstring& segment) {
    auto next = std::make_unique<Entry>();
    next->path = segment;
    next->handle = CreateFileW(segment.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (next->handle == INVALID_HANDLE_VALUE) return false;
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(next->handle, FileAttributeTagInfo,
        &tag, sizeof(tag)) || !(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      || !GetFileInformationByHandleEx(next->handle, FileIdInfo,
        &next->id, sizeof(next->id))) return false;
    if (!entries.empty() && next->id.VolumeSerialNumber
        != entries.front()->id.VolumeSerialNumber) return false;
    entries.push_back(std::move(next));
    return true;
  }
  bool capture(const wchar_t* root) {
    const std::wstring path(root);
    const auto last = path.find_last_of(L'\\');
    if (last == std::wstring::npos || last <= 3 || path.size() > 4096
      || path[1] != L':' || path[2] != L'\\') return false;
    const std::wstring parent = path.substr(0, last);
    const std::wstring drive = path.substr(0, 3);
    if (GetDriveTypeW(drive.c_str()) != DRIVE_FIXED || !captureOne(drive)) return false;
    wchar_t filesystem[64]{};
    if (!GetVolumeInformationByHandleW(entries.front()->handle, nullptr, 0,
      nullptr, nullptr, nullptr, filesystem, 64)
      || _wcsicmp(filesystem, L"NTFS") != 0) return false;
    for (std::size_t at = 3; at < parent.size();) {
      if (entries.size() >= 64) return false;
      const auto slash = parent.find(L'\\', at);
      const auto end = slash == std::wstring::npos ? parent.size() : slash;
      const auto name = parent.substr(at, end - at);
      if (name.empty() || name == L"." || name == L".."
        || !captureOne(parent.substr(0, end))) return false;
      if (slash == std::wstring::npos) break;
      at = slash + 1;
    }
    return samePaths();
  }
  bool samePaths() const {
    if (entries.empty()) return false;
    for (const auto& entry : entries) {
      HANDLE reopened = CreateFileW(entry->path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      if (reopened == INVALID_HANDLE_VALUE) return false;
      FILE_ID_INFO current{};
      FILE_ATTRIBUTE_TAG_INFO tag{};
      const bool same = GetFileInformationByHandleEx(reopened, FileIdInfo,
        &current, sizeof(current))
        && GetFileInformationByHandleEx(reopened, FileAttributeTagInfo,
          &tag, sizeof(tag))
        && (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        && current.VolumeSerialNumber == entry->id.VolumeSerialNumber
        && std::memcmp(&current.FileId, &entry->id.FileId,
          sizeof(entry->id.FileId)) == 0;
      CloseHandle(reopened);
      if (!same) return false;
    }
    return true;
  }
  bool sameVolume(const FILE_ID_INFO& rootId) const {
    return !entries.empty()
      && entries.front()->id.VolumeSerialNumber == rootId.VolumeSerialNumber;
  }
};

// Exact physical IDs expected from an independently authenticated enrollment
// receipt. This native comparator never issues or authenticates that receipt:
// a caller must verify its signer outside the mutable root and pin the whole
// original chain BEFORE its first native open. A locally self-issued snapshot
// can be used for tests only; it provides no production authority.
struct NativeOriginalEnrollment {
  FILE_ID_INFO root{};
  std::vector<FILE_ID_INFO> ancestors;
};

bool sameEnrolledFileId(const FILE_ID_INFO& actual,
    const FILE_ID_INFO& expected) {
  return actual.VolumeSerialNumber == expected.VolumeSerialNumber
    && std::memcmp(&actual.FileId, &expected.FileId,
      sizeof(actual.FileId)) == 0;
}

bool matchesOriginalEnrollment(const NativeOriginalEnrollment& expected,
    const HeldRoot& root, const HeldAncestors& held) {
  if (root.handle == INVALID_HANDLE_VALUE || held.entries.empty()
      || expected.ancestors.size() != held.entries.size()
      || expected.ancestors.size() > 64
      || !sameEnrolledFileId(root.id, expected.root)) return false;
  for (std::size_t i = 0; i < held.entries.size(); ++i) {
    if (!sameEnrolledFileId(held.entries[i]->id, expected.ancestors[i])
        || held.entries[i]->id.VolumeSerialNumber
          != expected.root.VolumeSerialNumber) return false;
  }
  return true;
}

// Open an exact child of the retained native directory HANDLE. Never
// construct a new pathname or follow a directory alias from this operation.
// The caller retains both parent and returned child handles across its I/O.
// This is a read-only RootSession primitive: no signed object or write trust
// is inferred from a successful open alone.
bool exactHeldChildFileId(HANDLE directory, const wchar_t* expected,
    std::size_t count, ULONGLONG& id) {
  constexpr DWORD kBufferSize = 64 * 1024;
  constexpr std::size_t kMinEntry = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
  std::vector<unsigned char> bytes(kBufferSize);
  bool restart = true;
  bool found = false;
  std::uint64_t enumerated = 0;
  for (;;) {
    const auto info = restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
    restart = false;
    if (!GetFileInformationByHandleEx(directory, info, bytes.data(), kBufferSize)) {
      return GetLastError() == ERROR_NO_MORE_FILES && found;
    }
    std::size_t at = 0;
    for (;;) {
      if (at > kBufferSize || kBufferSize - at < kMinEntry) return false;
      const auto* item = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(bytes.data() + at);
      const auto next = item->NextEntryOffset;
      const std::size_t available = next ? next : kBufferSize - at;
      if (available < kMinEntry || available > kBufferSize - at
          || !item->FileNameLength || item->FileNameLength % sizeof(WCHAR) != 0
          || item->FileNameLength > available - kMinEntry) return false;
      // The ancestor/root session must not let a hostile or pathological
      // directory stall a signed-data callback for an unbounded scan.
      if (++enumerated > 2'000'000) return false;
      const int itemChars = static_cast<int>(item->FileNameLength / sizeof(WCHAR));
      const bool exact = static_cast<std::size_t>(itemChars) == count
        && std::memcmp(item->FileName, expected, item->FileNameLength) == 0;
      const int comparison = CompareStringOrdinal(item->FileName, itemChars,
        expected, static_cast<int>(count), TRUE);
      // A case-only alternate directory entry cannot alias a portable file
      // identity, and a DOS short name must not silently select another inode.
      if (comparison == 0 || (comparison == CSTR_EQUAL && !exact)) return false;
      if (exact) {
        if (found) return false;
        found = true;
        id = static_cast<ULONGLONG>(item->FileId.QuadPart);
      }
      if (!next) break;
      if (next < kMinEntry + sizeof(WCHAR) || next % sizeof(ULONG) != 0) return false;
      at += next;
    }
  }
}

bool openNativeExactChild(HANDLE parent, const wchar_t* exactName,
    bool cloudFile, HANDLE& child) {
  child = INVALID_HANDLE_VALUE;
  if (!parent || parent == INVALID_HANDLE_VALUE || !exactName) return false;
  std::size_t count = 0;
  while (count <= 255 && exactName[count] != L'\0') ++count;
  if (!count || count > 255 || exactName[0] == L'.'
    || exactName[count - 1] == L'.' || exactName[count - 1] == L' ') return false;
  for (std::size_t i = 0; i < count; ++i) {
    if (exactName[i] == L'\\' || exactName[i] == L'/' || exactName[i] == L':'
      || exactName[i] == L'*' || exactName[i] == L'?' || exactName[i] == L'"'
      || exactName[i] == L'<' || exactName[i] == L'>' || exactName[i] == L'|'
      || exactName[i] < 0x20) return false;
  }
  ULONGLONG listedId = 0;
  if (!exactHeldChildFileId(parent, exactName, count, listedId)) return false;
  FILE_ID_INFO parentId{};
  if (!GetFileInformationByHandleEx(parent, FileIdInfo, &parentId, sizeof(parentId))) return false;
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return false;
  using NtCreateFileFn = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG,
    ULONG, PVOID, ULONG);
  auto ntCreateFile = reinterpret_cast<NtCreateFileFn>(GetProcAddress(ntdll, "NtCreateFile"));
  if (!ntCreateFile) return false;
  UNICODE_STRING name{};
  name.Buffer = const_cast<PWSTR>(exactName);
  name.Length = static_cast<USHORT>(count * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  OBJECT_ATTRIBUTES attrs{};
  attrs.Length = sizeof(attrs);
  attrs.RootDirectory = parent;
  attrs.ObjectName = &name;
  attrs.Attributes = 0x00001000UL; // OBJ_DONT_REPARSE: do not traverse child aliases
  IO_STATUS_BLOCK io{};
  HANDLE opened = INVALID_HANDLE_VALUE;
  const ACCESS_MASK access = FILE_READ_ATTRIBUTES | SYNCHRONIZE
    | (cloudFile ? 0 : FILE_LIST_DIRECTORY | READ_CONTROL);
  const ULONG options = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    | (cloudFile ? FILE_NON_DIRECTORY_FILE : FILE_DIRECTORY_FILE);
  const NTSTATUS result = ntCreateFile(&opened, access,
    &attrs, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
    options, nullptr, 0);
  if (result < 0 || !opened || opened == INVALID_HANDLE_VALUE) return false;
  FILE_ID_INFO childId{};
  FILE_ATTRIBUTE_TAG_INFO tags{};
  BY_HANDLE_FILE_INFORMATION fileInfo{};
  bool trusted = GetFileInformationByHandleEx(opened, FileIdInfo,
      &childId, sizeof(childId))
    && GetFileInformationByHandleEx(opened, FileAttributeTagInfo,
      &tags, sizeof(tags))
    && GetFileInformationByHandle(opened, &fileInfo)
    && parentId.VolumeSerialNumber == childId.VolumeSerialNumber
    && (cloudFile ? !(tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        && (tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        && (tags.ReparseTag & 0xFFFF0FFFUL) == IO_REPARSE_TAG_CLOUD
        && fileInfo.nNumberOfLinks == 1
      : (tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        && !(tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    && ((static_cast<ULONGLONG>(fileInfo.nFileIndexHigh) << 32)
      | fileInfo.nFileIndexLow) == listedId;
  if (trusted && !cloudFile) {
    std::vector<unsigned char> sid;
    ScopedDescriptor descriptor;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    trusted = currentUserSid(sid)
      && GetSecurityInfo(opened, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor.value) == ERROR_SUCCESS
      && trustedDacl(descriptor.value, dacl, owner, sid);
  }
  if (!trusted) { CloseHandle(opened); return false; }
  child = opened;
  return true;
}

bool openNativeCloudChild(HANDLE parent, const wchar_t* exactName, HANDLE& child) {
  return openNativeExactChild(parent, exactName, true, child);
}

bool openNativeDirectoryChild(HANDLE parent, const wchar_t* exactName, HANDLE& child) {
  return openNativeExactChild(parent, exactName, false, child);
}

// Native no-replace building blocks for a separately authorized RootSession.
// Do not treat a successful FILE_CREATE + FlushFileBuffers + rename as a
// crash-durable transaction: the ordered namespace checkpoint and independent
// signed PREPARE/COMMIT fence must still be implemented before product writes.
bool nativeSafeLeaf(const wchar_t* leaf, std::size_t& count) {
  count = 0;
  if (!leaf) return false;
  while (count <= 255 && leaf[count]) ++count;
  if (!count || count > 255 || leaf[0] == L'.'
      || leaf[count - 1] == L'.' || leaf[count - 1] == L' ') return false;
  for (std::size_t i = 0; i < count; ++i)
    if (leaf[i] < 0x20 || wcschr(L"\\/:*?\"<>|", leaf[i])) return false;
  return true;
}

bool nativeCreateExclusiveStage(HANDLE parent, const wchar_t* leaf,
    HANDLE& stage) {
  stage = INVALID_HANDLE_VALUE;
  std::size_t count = 0;
  if (!parent || parent == INVALID_HANDLE_VALUE
      || !nativeSafeLeaf(leaf, count)) return false;
  FILE_ID_INFO parentId{};
  if (!GetFileInformationByHandleEx(parent, FileIdInfo,
      &parentId, sizeof(parentId))) return false;
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return false;
  using NtCreateFileFn = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG,
    ULONG, PVOID, ULONG);
  auto create = reinterpret_cast<NtCreateFileFn>(GetProcAddress(ntdll, "NtCreateFile"));
  if (!create) return false;
  UNICODE_STRING name{};
  name.Buffer = const_cast<PWSTR>(leaf);
  name.Length = static_cast<USHORT>(count * sizeof(WCHAR));
  name.MaximumLength = name.Length;
  OBJECT_ATTRIBUTES attributes{};
  attributes.Length = sizeof(attributes);
  attributes.RootDirectory = parent;
  attributes.ObjectName = &name;
  attributes.Attributes = 0x00001000UL; // OBJ_DONT_REPARSE
  IO_STATUS_BLOCK io{};
  HANDLE opened = INVALID_HANDLE_VALUE;
  const NTSTATUS result = create(&opened, FILE_READ_DATA | FILE_WRITE_DATA
      | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
    &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ, FILE_CREATE, FILE_NON_DIRECTORY_FILE
      | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
  if (result < 0 || !opened || opened == INVALID_HANDLE_VALUE) return false;
  FILE_ID_INFO stageId{};
  FILE_ATTRIBUTE_TAG_INFO tags{};
  BY_HANDLE_FILE_INFORMATION fileInfo{};
  const bool accepted = GetFileInformationByHandleEx(opened, FileIdInfo,
      &stageId, sizeof(stageId))
    && GetFileInformationByHandleEx(opened, FileAttributeTagInfo,
      &tags, sizeof(tags))
    && GetFileInformationByHandle(opened, &fileInfo)
    && stageId.VolumeSerialNumber == parentId.VolumeSerialNumber
    && !(tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    && !(tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    && fileInfo.nNumberOfLinks == 1;
  if (!accepted) { CloseHandle(opened); return false; }
  stage = opened;
  return true;
}

bool nativeWriteAndFlushOpenedStage(HANDLE stage,
    const unsigned char* bytes, std::size_t length) {
  if (!stage || stage == INVALID_HANDLE_VALUE || !bytes
      || !length || length > 1024 * 1024) return false;
  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(stage, zero, nullptr, FILE_BEGIN)) return false;
  std::size_t at = 0;
  while (at < length) {
    DWORD written = 0;
    const DWORD step = static_cast<DWORD>(length - at);
    if (!WriteFile(stage, bytes + at, step, &written, nullptr) || !written)
      return false;
    at += written;
  }
  if (!FlushFileBuffers(stage)) return false;
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(stage, &size)
      || size.QuadPart != static_cast<LONGLONG>(length)
      || !SetFilePointerEx(stage, zero, nullptr, FILE_BEGIN)) return false;
  std::vector<unsigned char> verified(length);
  at = 0;
  while (at < length) {
    DWORD read = 0;
    const DWORD step = static_cast<DWORD>(length - at);
    if (!ReadFile(stage, verified.data() + at, step, &read, nullptr) || !read) {
      SecureZeroMemory(verified.data(), verified.size());
      return false;
    }
    at += read;
  }
  const bool exact = std::memcmp(verified.data(), bytes, length) == 0;
  SecureZeroMemory(verified.data(), verified.size());
  return exact;
}

bool nativeRenameOpenedStageNoReplace(HANDLE stage, HANDLE heldParent,
    const wchar_t* destinationLeaf, DWORD* failedError = nullptr) {
  std::size_t count = 0;
  if (!stage || stage == INVALID_HANDLE_VALUE
      || !heldParent || heldParent == INVALID_HANDLE_VALUE
      || !nativeSafeLeaf(destinationLeaf, count)) return false;
  FILE_ID_INFO stageBefore{}, parent{};
  if (!GetFileInformationByHandleEx(stage, FileIdInfo,
      &stageBefore, sizeof(stageBefore))
      || !GetFileInformationByHandleEx(heldParent, FileIdInfo,
        &parent, sizeof(parent))
      || stageBefore.VolumeSerialNumber != parent.VolumeSerialNumber
      || !FlushFileBuffers(stage)) return false;
  const std::size_t nameBytes = count * sizeof(WCHAR);
  const std::size_t bytes = offsetof(FILE_RENAME_INFO, FileName) + nameBytes;
  std::vector<unsigned char> storage(bytes);
  auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
  rename->ReplaceIfExists = FALSE;
  rename->RootDirectory = heldParent;
  rename->FileNameLength = static_cast<DWORD>(nameBytes);
  std::memcpy(rename->FileName, destinationLeaf, nameBytes);
  // Win32 FileRenameInfo rejects relative RootDirectory on supported hosts
  // (ERROR_INVALID_PARAMETER 87). Native NtSetInformationFile accepts the
  // retained directory HANDLE and FILE_RENAME_INFORMATION (class 10).
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return false;
  using NtSetInformationFileFn = NTSTATUS (NTAPI *)(HANDLE,
    PIO_STATUS_BLOCK, PVOID, ULONG, int);
  auto nativeSet = reinterpret_cast<NtSetInformationFileFn>(
    GetProcAddress(ntdll, "NtSetInformationFile"));
  if (!nativeSet) return false;
  IO_STATUS_BLOCK io{};
  const NTSTATUS result = nativeSet(stage, &io, rename,
    static_cast<ULONG>(bytes), 10 /* FileRenameInformation */);
  if (result < 0) {
    if (failedError) *failedError = static_cast<DWORD>(result);
    return false;
  }
  FILE_ID_INFO after{};
  // This proves identity through the native rename. It does not establish
  // directory fsync or independent replay authorization after power loss.
  return GetFileInformationByHandleEx(stage, FileIdInfo, &after, sizeof(after))
    && sameEnrolledFileId(stageBefore, after);
}

} // namespace
