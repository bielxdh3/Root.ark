#pragma once
// Windows native RootSession retained NTFS root and ancestry.
// Independent original root enrollment and cold-restart authority are still required.
#include <Windows.h>
#include <winternl.h>
#include <memory>
#include <string>
#include <vector>
#include <cstring>
#include "rootark-sync-windows-cfapi-root-policy.hpp"
namespace {
struct HeldRoot {
  HANDLE handle = INVALID_HANDLE_VALUE;
  FILE_ID_INFO id{};
  ~HeldRoot() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
  bool open(const wchar_t* root) {
    // A retained handle without FILE_SHARE_DELETE prevents ordinary rename
    // of this root while a disposable callback is connected. Full RootSession
    // still needs independently enrolled ancestors and anti-rollback custody.
    handle = CreateFileW(root, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL,
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

// Open an exact child of the retained native directory HANDLE. Never
// construct a new pathname or follow a directory alias from this operation.
// The caller retains both parent and returned child handles across its I/O.
// This is a read-only RootSession primitive: no signed object or write trust
// is inferred from a successful open alone.
bool openNativeCloudChild(HANDLE parent, const wchar_t* exactName, HANDLE& child) {
  child = INVALID_HANDLE_VALUE;
  if (!parent || parent == INVALID_HANDLE_VALUE || !exactName) return false;
  const std::size_t count = std::wcslen(exactName);
  if (!count || count > 255 || exactName[0] == L'.'
    || exactName[count - 1] == L'.' || exactName[count - 1] == L' ') return false;
  for (std::size_t i = 0; i < count; ++i) {
    if (exactName[i] == L'\\' || exactName[i] == L'/' || exactName[i] == L':'
      || exactName[i] < 0x20) return false;
  }
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
  const NTSTATUS result = ntCreateFile(&opened, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
    &attrs, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
    FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    nullptr, 0);
  if (result < 0 || !opened || opened == INVALID_HANDLE_VALUE) return false;
  FILE_ID_INFO childId{};
  FILE_ATTRIBUTE_TAG_INFO tags{};
  BY_HANDLE_FILE_INFORMATION fileInfo{};
  const bool trusted = GetFileInformationByHandleEx(opened, FileIdInfo,
      &childId, sizeof(childId))
    && GetFileInformationByHandleEx(opened, FileAttributeTagInfo,
      &tags, sizeof(tags))
    && GetFileInformationByHandle(opened, &fileInfo)
    && parentId.VolumeSerialNumber == childId.VolumeSerialNumber
    && !(tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    && (tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    && (tags.ReparseTag & 0xFFFF0FFFUL) == IO_REPARSE_TAG_CLOUD
    && fileInfo.nNumberOfLinks == 1;
  if (!trusted) { CloseHandle(opened); return false; }
  child = opened;
  return true;
}

} // namespace
