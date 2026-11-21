// Read-only, real-Windows handle/ACL preflight for a future native CFAPI root.
// This is NOT an authorization to register or connect: a later path-based
// CfRegisterSyncRoot would still require race-safe root identity reconciliation.
// No persistent registration, service, callback, placeholder, file content,
// encryption key, ACL mutation or profile mutation is reachable from main.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <Aclapi.h>
#include <cfapi.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <vector>

namespace {
struct ScopedHandle {
  HANDLE value = INVALID_HANDLE_VALUE;
  explicit ScopedHandle(HANDLE handle) : value(handle) {}
  ~ScopedHandle() {
    if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value);
  }
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
};

struct ScopedDescriptor {
  PSECURITY_DESCRIPTOR value = nullptr;
  ScopedDescriptor() = default;
  ~ScopedDescriptor() { if (value) LocalFree(value); }
  ScopedDescriptor(const ScopedDescriptor&) = delete;
  ScopedDescriptor& operator=(const ScopedDescriptor&) = delete;
};

bool currentUserSid(std::vector<unsigned char>& ownerSid) {
  HANDLE rawToken = INVALID_HANDLE_VALUE;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) return false;
  ScopedHandle token(rawToken);
  DWORD required = 0;
  (void)GetTokenInformation(token.value, TokenUser, nullptr, 0, &required);
  if (required < sizeof(TOKEN_USER) || required > 65536) return false;
  std::vector<unsigned char> storage(required);
  if (!GetTokenInformation(token.value, TokenUser, storage.data(), required, &required))
    return false;
  const auto* identity = reinterpret_cast<const TOKEN_USER*>(storage.data());
  if (!IsValidSid(identity->User.Sid)) return false;
  const DWORD length = GetLengthSid(identity->User.Sid);
  ownerSid.resize(length);
  return CopySid(length, ownerSid.data(), identity->User.Sid) != FALSE;
}

bool wellKnownSid(WELL_KNOWN_SID_TYPE kind, std::vector<unsigned char>& storage) {
  DWORD length = SECURITY_MAX_SID_SIZE;
  storage.resize(length);
  if (!CreateWellKnownSid(kind, nullptr, storage.data(), &length)) return false;
  storage.resize(length);
  return true;
}

bool trustedDacl(PSECURITY_DESCRIPTOR descriptor, PACL dacl,
    PSID owner, const std::vector<unsigned char>& user) {
  if (!descriptor || !dacl || !IsValidAcl(dacl) || !IsValidSid(owner)
      || !EqualSid(owner, const_cast<unsigned char*>(user.data()))) return false;
  SECURITY_DESCRIPTOR_CONTROL control{};
  DWORD revision = 0;
  if (!GetSecurityDescriptorControl(descriptor, &control, &revision)
      || (control & SE_DACL_PROTECTED) == 0) return false;
  std::vector<unsigned char> system;
  std::vector<unsigned char> admins;
  if (!wellKnownSid(WinLocalSystemSid, system)
      || !wellKnownSid(WinBuiltinAdministratorsSid, admins)) return false;
  bool ownerHasGrant = false;
  for (DWORD i = 0; i < dacl->AceCount; ++i) {
    void* raw = nullptr;
    if (!GetAce(dacl, i, &raw) || !raw) return false;
    const auto* header = static_cast<const ACE_HEADER*>(raw);
    // An inherit-only ACE grants no access to this directory itself. Never
    // count it as an owner grant or silently ignore it on a protected root.
    if ((header->AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) != 0) return false;
    // Reject unfamiliar/callback/object ACE shapes until they have a
    // well-defined, reviewed authorization and account model.
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE
        && header->AceType != ACCESS_DENIED_ACE_TYPE) return false;
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
    // Even an ACL returned by the kernel must not let a malformed ACE's
    // SID-length field send IsValidSid outside the ACE's bounded bytes.
    constexpr std::size_t kSidOffset = offsetof(ACCESS_ALLOWED_ACE, SidStart);
    if (header->AceSize < kSidOffset + 8) return false;
    const auto* sid = reinterpret_cast<const SID*>(&ace->SidStart);
    if (sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES
        || GetSidLengthRequired(sid->SubAuthorityCount) > header->AceSize - kSidOffset)
      return false;
    PSID principal = const_cast<DWORD*>(&ace->SidStart);
    if (!IsValidSid(principal)) return false;
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    const bool matchesUser = EqualSid(principal, const_cast<unsigned char*>(user.data())) != FALSE;
    const bool trusted = matchesUser
      || EqualSid(principal, system.data()) != FALSE
      || EqualSid(principal, admins.data()) != FALSE;
    if (!trusted) return false;
    if (matchesUser && (ace->Mask & (FILE_READ_ATTRIBUTES | READ_CONTROL))
        == (FILE_READ_ATTRIBUTES | READ_CONTROL))
      ownerHasGrant = true;
  }
  return ownerHasGrant;
}

// First genuine handle-bound RootSession building block: stream the opened
// directory's native NTFS entries, not a separate pathname enumeration. This
// is strictly an informational preflight: without writer isolation, signed
// object identities, cold-reopen proof and CFAPI callbacks, it can NEVER be
// used to authorize file publication, removal or positive hydration.
bool enumerateHeldDirectory(HANDLE directory, const FILE_ID_INFO& before,
    std::uint64_t& total) {
  constexpr DWORD kBufferSize = 64 * 1024;
  constexpr std::uint64_t kMaxCount = 2'000'000;
  constexpr std::size_t kMinimumEntry = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
  std::vector<unsigned char> bytes(kBufferSize);
  bool restart = true;
  for (;;) {
    const auto information = restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
    restart = false;
    if (!GetFileInformationByHandleEx(directory, information, bytes.data(), kBufferSize)) {
      if (GetLastError() == ERROR_NO_MORE_FILES) break;
      return false;
    }
    std::size_t offset = 0;
    for (;;) {
      if (offset > kBufferSize || kBufferSize - offset < kMinimumEntry) return false;
      const auto* entry = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(bytes.data() + offset);
      const DWORD next = entry->NextEntryOffset;
      const std::size_t available = next ? static_cast<std::size_t>(next)
        : static_cast<std::size_t>(kBufferSize - offset);
      if (available < kMinimumEntry || available > kBufferSize - offset
          || entry->FileNameLength == 0 || (entry->FileNameLength % sizeof(WCHAR)) != 0
          || entry->FileNameLength > available - kMinimumEntry) return false;
      const std::size_t characters = entry->FileNameLength / sizeof(WCHAR);
      const bool dot = characters == 1 && entry->FileName[0] == L'.';
      const bool dotdot = characters == 2 && entry->FileName[0] == L'.'
        && entry->FileName[1] == L'.';
      if (!dot && !dotdot && ++total > kMaxCount) return false;
      if (!next) break;
      if (next < kMinimumEntry + sizeof(WCHAR) || (next % sizeof(ULONG)) != 0) return false;
      offset += next;
    }
  }
  // One HANDLE is retained throughout; verify its real file ID and volume
  // did not change. This DOES NOT prove a consistent snapshot against writes.
  FILE_ID_INFO after{};
  return GetFileInformationByHandleEx(directory, FileIdInfo, &after, sizeof(after))
    && after.VolumeSerialNumber == before.VolumeSerialNumber
    && std::memcmp(&after.FileId, &before.FileId, sizeof(before.FileId)) == 0;
}

bool inspect(const wchar_t* supplied, DWORD& platformBuild,
    bool enumerate = false, std::uint64_t* enumerationCount = nullptr) {
  CF_PLATFORM_INFO platform{};
  if (FAILED(CfGetPlatformInfo(&platform)) || platform.BuildNumber < 16299)
    return false;
  platformBuild = platform.BuildNumber;
  if (!supplied || !*supplied) return false;
  // OPEN_REPARSE_POINT keeps the inspected handle on the exact final object;
  // ancestors and names are NOT securely pinned by this standalone probe.
  ScopedHandle file(CreateFileW(supplied, FILE_READ_ATTRIBUTES | READ_CONTROL
      | (enumerate ? FILE_LIST_DIRECTORY : 0),
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (file.value == INVALID_HANDLE_VALUE) return false;
  FILE_ATTRIBUTE_TAG_INFO tags{};
  if (!GetFileInformationByHandleEx(file.value, FileAttributeTagInfo, &tags, sizeof(tags))
      || (tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
      || (tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;
  FILE_ID_INFO id{};
  if (!GetFileInformationByHandleEx(file.value, FileIdInfo, &id, sizeof(id)))
    return false;
  // The captured volume/file identity is scoped to this live handle only;
  // its bytes are intentionally not printed or persisted.
  wchar_t filesystem[64]{};
  if (!GetVolumeInformationByHandleW(file.value, nullptr, 0, nullptr, nullptr,
      nullptr, filesystem, 64) || _wcsicmp(filesystem, L"NTFS") != 0) return false;
  std::vector<unsigned char> user;
  if (!currentUserSid(user)) return false;
  ScopedDescriptor descriptor;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  if (GetSecurityInfo(file.value, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, nullptr, &dacl, nullptr, &descriptor.value) != ERROR_SUCCESS)
    return false;
  if (!trustedDacl(descriptor.value, dacl, owner, user)) return false;
  if (enumerate) {
    if (!enumerationCount) return false;
    if (!enumerateHeldDirectory(file.value, id, *enumerationCount)) return false;
  }
  return true;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc != 3 || (std::wcscmp(argv[1], L"--inspect") != 0
      && std::wcscmp(argv[1], L"--enumerate") != 0)) return 2;
  const bool enumerate = std::wcscmp(argv[1], L"--enumerate") == 0;
  DWORD platformBuild = 0;
  std::uint64_t count = 0;
  const bool accepted = inspect(argv[2], platformBuild, enumerate, &count);
  std::printf("{\"aclPreflightPassed\":%s,\"handleIdentityCaptured\":%s,"
    "\"platformBuild\":%lu,\"nativeEnumerationInformational\":%s,"
    "\"directoryEntriesEnumerated\":%llu,\"syncRootRegistered\":false,"
    "\"cloudDataBytesTransferred\":0}\n",
    accepted ? "true" : "false", accepted ? "true" : "false", platformBuild,
    enumerate && accepted ? "true" : "false",
    static_cast<unsigned long long>(accepted ? count : 0));
  return accepted ? 0 : 4;
}
