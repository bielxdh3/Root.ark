// Disposable Windows CFAPI integration fixture. This is NOT a RootSession
// implementation or a production provider. Run only against a new empty test
// directory; the caller owns its lifecycle and checks it is disposable.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cfapi.h>
#include <cstddef>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <array>
#include <vector>
#include <string>
#include <memory>
#include "rootark-sync-windows-cfapi-root-policy.hpp"

namespace {
constexpr std::size_t kPayloadLength = 4097;
constexpr char kIdentity[] = "rootark-cfapi-test-v1";
std::vector<unsigned char> makePayload() {
  std::vector<unsigned char> bytes(kPayloadLength);
  for (std::size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = static_cast<unsigned char>((i * 19 + 7) % 251);
  return bytes;
}
constexpr NTSTATUS kCloudFailure = static_cast<NTSTATUS>(0xC000CF12UL);
struct Context {
  std::vector<unsigned char> payload = makePayload();
  unsigned callbacks = 0;
  unsigned successful = 0;
  unsigned rejected = 0;
  ~Context() { if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size()); }
};

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

bool readBoundedStdin(std::vector<unsigned char>& payload) {
  HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  if (!input || input == INVALID_HANDLE_VALUE) return false;
  constexpr std::size_t maximum = 1024 * 1024;
  std::vector<unsigned char> result;
  unsigned char chunk[8192]{};
  DWORD read = 0;
  for (;;) {
    if (!ReadFile(input, chunk, sizeof(chunk), &read, nullptr)) {
      if (GetLastError() == ERROR_BROKEN_PIPE) break;
      SecureZeroMemory(chunk, sizeof(chunk));
      if (!result.empty()) SecureZeroMemory(result.data(), result.size());
      return false;
    }
    if (!read) break;
    if (result.size() > maximum - read) {
      SecureZeroMemory(chunk, sizeof(chunk));
      if (!result.empty()) SecureZeroMemory(result.data(), result.size());
      return false;
    }
    result.insert(result.end(), chunk, chunk + read);
  }
  SecureZeroMemory(chunk, sizeof(chunk));
  if (result.empty()) return false;
  payload.swap(result);
  return true;
}

void CALLBACK onFetch(const CF_CALLBACK_INFO* info, const CF_CALLBACK_PARAMETERS* params) {
  if (!info || !params || !info->CallbackContext) return;
  auto& ctx = *static_cast<Context*>(info->CallbackContext);
  ++ctx.callbacks;
  CF_OPERATION_INFO op{};
  op.StructSize = sizeof(op);
  op.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
  op.ConnectionKey = info->ConnectionKey;
  op.TransferKey = info->TransferKey;
  op.RequestKey = info->RequestKey;
  CF_OPERATION_PARAMETERS transfer{};
  transfer.ParamSize = static_cast<ULONG>(offsetof(CF_OPERATION_PARAMETERS, TransferData)
      + sizeof(transfer.TransferData));
  transfer.TransferData.Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
  transfer.TransferData.CompletionStatus = kCloudFailure;
  transfer.TransferData.Buffer = nullptr;
  transfer.TransferData.Offset = params->FetchData.RequiredFileOffset;
  transfer.TransferData.Length = params->FetchData.RequiredLength;
  const auto offset = params->FetchData.RequiredFileOffset.QuadPart;
  const auto length = params->FetchData.RequiredLength.QuadPart;
  // Each request must be bound to the provider's exact identity and checked
  // against the verified immutable buffer. This fixture does not certify a
  // production owner-signed object or live revocation policy.
  const bool identityMatches = info->FileIdentity
    && info->FileIdentityLength == sizeof(kIdentity) - 1
    && std::memcmp(info->FileIdentity, kIdentity, sizeof(kIdentity) - 1) == 0
    && info->FileSize.QuadPart == static_cast<LONGLONG>(ctx.payload.size());
  const bool rangeMatches = offset >= 0 && offset % 4096 == 0 && length > 0
    && offset < static_cast<LONGLONG>(ctx.payload.size())
    && length <= static_cast<LONGLONG>(ctx.payload.size()) - offset
    && (length % 4096 == 0 || offset + length == static_cast<LONGLONG>(ctx.payload.size()));
  if (identityMatches && rangeMatches) {
    transfer.TransferData.CompletionStatus = 0;
    transfer.TransferData.Buffer = ctx.payload.data() + static_cast<std::size_t>(offset);
    if (SUCCEEDED(CfExecute(&op, &transfer))) ++ctx.successful;
    return;
  }
  ++ctx.rejected;
  (void)CfExecute(&op, &transfer);
}

void CALLBACK onCancel(const CF_CALLBACK_INFO*, const CF_CALLBACK_PARAMETERS*) {}
constexpr CF_CALLBACK_REGISTRATION kCallbacks[] = {
  {CF_CALLBACK_TYPE_FETCH_DATA, onFetch},
  {CF_CALLBACK_TYPE_CANCEL_FETCH_DATA, onCancel},
  CF_CALLBACK_REGISTRATION_END,
};
}

int wmain(int argc, wchar_t** argv) {
  if (argc != 3 || (std::wcscmp(argv[1], L"--disposable-live") != 0
      && std::wcscmp(argv[1], L"--disposable-live-stdin") != 0)) return 2;
  const bool streamed = std::wcscmp(argv[1], L"--disposable-live-stdin") == 0;
  const wchar_t* root = argv[2];
  if (!root || std::wcslen(root) < 8 || std::wcslen(root) > 4096
      || root[1] != L':' || root[2] != L'\\') return 3;
  wchar_t temp[MAX_PATH]{};
  const DWORD tempLength = GetTempPathW(MAX_PATH, temp);
  if (!tempLength || tempLength >= MAX_PATH || tempLength >= std::wcslen(root)
      || _wcsnicmp(root, temp, tempLength) != 0) return 10;
  const wchar_t* leaf = root + tempLength;
  constexpr wchar_t prefix[] = L"rootark-cfapi-live-";
  const wchar_t* separator = std::wcschr(leaf, L'\\');
  if (!separator || std::wcsncmp(leaf, prefix,
      (sizeof(prefix) / sizeof(wchar_t)) - 1) != 0
      || separator - leaf < static_cast<std::ptrdiff_t>(
        sizeof(prefix) / sizeof(wchar_t) - 1 + 6)
      || std::wcscmp(separator, L"\\owner-only") != 0
      || std::wcschr(leaf, L'/')) return 11;
  const DWORD attributes = GetFileAttributesW(root);
  if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)
      || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return 12;
  // Never reuse an existing registered root or a nonempty directory.
  WIN32_FIND_DATAW found{};
  wchar_t pattern[4096]{};
  if (swprintf_s(pattern, L"%ls\\*", root) < 0) return 4;
  HANDLE entries = FindFirstFileW(pattern, &found);
  if (entries != INVALID_HANDLE_VALUE) {
    bool nonempty = false;
    do {
      if (std::wcscmp(found.cFileName, L".") && std::wcscmp(found.cFileName, L".."))
        nonempty = true;
    } while (!nonempty && FindNextFileW(entries, &found));
    FindClose(entries);
    if (nonempty) return 5;
  } else if (GetLastError() != ERROR_FILE_NOT_FOUND) return 6;

  HeldAncestors ancestors;
  if (!ancestors.capture(root)) return 15;
  HeldRoot held;
  DWORD platform = 0;
  if (!held.open(root) || !held.samePath(root) || !ancestors.samePaths()
    || !ancestors.sameVolume(held.id) || !inspect(root, platform)) return 14;

  Context context;
  if (streamed && !readBoundedStdin(context.payload)) return 13;
  CF_SYNC_REGISTRATION registration{};
  registration.StructSize = sizeof(registration);
  registration.ProviderName = L"Rootark disposable CFAPI fixture";
  registration.ProviderVersion = L"1";
  registration.SyncRootIdentity = kIdentity;
  registration.SyncRootIdentityLength = sizeof(kIdentity) - 1;
  CF_SYNC_POLICIES policies{};
  policies.StructSize = sizeof(policies);
  policies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
  policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;
  HRESULT result = CfRegisterSyncRoot(root, &registration, &policies, CF_REGISTER_FLAG_NONE);
  if (FAILED(result)) { std::printf("register=0x%08lx\n", static_cast<unsigned long>(result)); return 7; }
  CF_CONNECTION_KEY connection{};
  bool connected = false;
  bool finalIdentity = false;
  bool finalAncestors = false;
  bool finalPolicy = false;
  bool finalCloudReparse = false;
  bool finalOwnerAcl = false;
  DWORD finalTag = 0;
  int exitCode = 8;
  do {
    if (!ancestors.samePaths() || !held.samePath(root)
        || !inspect(root, platform)) break;
    result = CfConnectSyncRoot(root, kCallbacks, &context, CF_CONNECT_FLAG_NONE, &connection);
    if (FAILED(result)) break;
    connected = true;
    CF_PLACEHOLDER_CREATE_INFO item{};
    item.RelativeFileName = L"payload.bin";
    item.FsMetadata.FileSize.QuadPart = static_cast<LONGLONG>(context.payload.size());
    item.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    item.FileIdentity = kIdentity;
    item.FileIdentityLength = sizeof(kIdentity) - 1;
    DWORD processed = 0;
    result = CfCreatePlaceholders(root, &item, 1, CF_CREATE_FLAG_NONE, &processed);
    if (FAILED(result) || processed != 1 || FAILED(item.Result)) break;
    wchar_t file[4096]{};
    if (swprintf_s(file, L"%ls\\payload.bin", root) < 0) break;
    HANDLE handle = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) break;
    std::vector<unsigned char> received(context.payload.size());
    DWORD got = 0;
    const BOOL read = ReadFile(handle, received.data(),
      static_cast<DWORD>(received.size()), &got, nullptr);
    CloseHandle(handle);
    finalIdentity = held.samePath(root);
    finalAncestors = ancestors.samePaths();
    finalPolicy = held.registeredPolicy();
    FILE_ATTRIBUTE_TAG_INFO tags{};
    finalCloudReparse = GetFileInformationByHandleEx(held.handle, FileAttributeTagInfo,
      &tags, sizeof(tags)) && (tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      && (tags.ReparseTag & 0xFFFF0FFFUL) == IO_REPARSE_TAG_CLOUD;
    finalTag = tags.ReparseTag;
    std::vector<unsigned char> sid;
    ScopedDescriptor descriptor;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    finalOwnerAcl = currentUserSid(sid)
      && GetSecurityInfo(held.handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor.value) == ERROR_SUCCESS
      && trustedDacl(descriptor.value, dacl, owner, sid);
    if (!read || !finalIdentity || !finalAncestors || !finalPolicy
        || got != context.payload.size()
        || std::memcmp(received.data(), context.payload.data(), context.payload.size()) != 0
        || context.callbacks == 0 || context.successful == 0) break;
    exitCode = 0;
  } while (false);
  if (connected) CfDisconnectSyncRoot(connection);
  // A registered root must never be left registered by this fixture.
  const HRESULT unregisterResult = CfUnregisterSyncRoot(root);
  if (FAILED(unregisterResult)) exitCode = 9;
  std::printf("{\"liveKernelCallbackCount\":%u,\"successfulTransfers\":%u,"
    "\"rejectedTransfers\":%u,\"verifiedBytes\":%zu,"
    "\"finalRootIdentity\":%s,\"finalAncestorsHeld\":%s,\"finalRootPolicy\":%s,"
    "\"finalCloudReparse\":%s,\"finalOwnerAcl\":%s,"
    "\"finalReparseTag\":%lu,"
    "\"unregistered\":%s,\"positiveReadVerified\":%s}\n",
    context.callbacks, context.successful, context.rejected, context.payload.size(),
    finalIdentity ? "true" : "false", finalAncestors ? "true" : "false",
    finalPolicy ? "true" : "false",
    finalCloudReparse ? "true" : "false", finalOwnerAcl ? "true" : "false",
    finalTag,
    SUCCEEDED(unregisterResult) ? "true" : "false",
    exitCode == 0 ? "true" : "false");
  return exitCode;
}
