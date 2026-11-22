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
#include <atomic>
#include <thread>
#include "rootark-sync-windows-cfapi-provider.hpp"

namespace {
constexpr std::size_t kPayloadLength = 4097;
constexpr char kIdentity[] = "rootark-cfapi-test-v1";
std::vector<unsigned char> makePayload() {
  std::vector<unsigned char> bytes(kPayloadLength);
  for (std::size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = static_cast<unsigned char>((i * 19 + 7) % 251);
  return bytes;
}
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

// Deliberately test-only authority. A production RootSession must supply a
// distinct issuer-backed native verifier here, not this disposable callback.
bool disposableLabAuthorize(const CF_CALLBACK_INFO* info, void* opaque) noexcept {
  return info != nullptr && opaque != nullptr &&
    static_cast<const Context*>(opaque)->root != nullptr;
}


}

int wmain(int argc, wchar_t** argv) {
  if (argc != 3 || (std::wcscmp(argv[1], L"--disposable-live") != 0
      && std::wcscmp(argv[1], L"--disposable-live-stdin") != 0
      && std::wcscmp(argv[1], L"--disposable-live-alias") != 0
      && std::wcscmp(argv[1], L"--disposable-concurrent-alias") != 0
      && std::wcscmp(argv[1], L"--disposable-no-authority") != 0
      && std::wcscmp(argv[1], L"--disposable-stale-enrollment") != 0
      && std::wcscmp(argv[1], L"--disposable-stale-ancestor") != 0
      && std::wcscmp(argv[1], L"--disposable-native-publish") != 0
      && std::wcscmp(argv[1], L"--disposable-native-names") != 0)) return 2;
  const bool streamed = std::wcscmp(argv[1], L"--disposable-live-stdin") == 0;
  const bool aliasMode = std::wcscmp(argv[1], L"--disposable-live-alias") == 0;
  const bool concurrentMode = std::wcscmp(argv[1], L"--disposable-concurrent-alias") == 0;
  const bool nameMode = std::wcscmp(argv[1], L"--disposable-native-names") == 0;
  const bool denyAuthority = std::wcscmp(argv[1], L"--disposable-no-authority") == 0;
  const bool staleEnrollment = std::wcscmp(argv[1], L"--disposable-stale-enrollment") == 0;
  const bool staleAncestor = std::wcscmp(argv[1], L"--disposable-stale-ancestor") == 0;
  const bool publicationMode = std::wcscmp(argv[1], L"--disposable-native-publish") == 0;
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
  if (!held.open(root, publicationMode) || !held.samePath(root) || !ancestors.samePaths()
    || !ancestors.sameVolume(held.id) || !inspect(root, platform)) return 14;

  // Only the disposable fixture self-issues these expected IDs. In a real
  // RootSession they must originate from a distinct enrolled owner/custodian
  // before this program first opens any ancestor or root.
  NativeOriginalEnrollment fixtureEnrollment{};
  fixtureEnrollment.root = held.id;
  for (const auto& entry : ancestors.entries)
    fixtureEnrollment.ancestors.push_back(entry->id);
  if (staleEnrollment)
    fixtureEnrollment.root.FileId.Identifier[0] ^= 0x01;
  if (staleAncestor && !fixtureEnrollment.ancestors.empty())
    fixtureEnrollment.ancestors.back().FileId.Identifier[0] ^= 0x01;

  Context context;
  context.payload = makePayload();
  context.identity.assign(kIdentity, kIdentity + sizeof(kIdentity) - 1);
  if (!denyAuthority) {
    context.authorize = disposableLabAuthorize;
    context.authorityContext = &context;
  }
  context.root = &held;
  context.ancestors = &ancestors;
  context.enrollment = &fixtureEnrollment;
  context.path = root;
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
  bool alienAliasDenied = false;
  unsigned concurrentAliasDenials = 0;
  unsigned unsafeNameDenials = 0;
  bool nativeRelativeOpen = false;
  bool positiveReadVerified = false;
  bool nativeNoReplacePublished = false;
  unsigned nativePublishStage = 0;
  DWORD nativePublishError = 0;
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
    item.FileIdentity = context.identity.data();
    item.FileIdentityLength = static_cast<DWORD>(context.identity.size());
    DWORD processed = 0;
    result = CfCreatePlaceholders(root, &item, 1, CF_CREATE_FLAG_NONE, &processed);
    if (FAILED(result) || processed != 1 || FAILED(item.Result)) break;
    wchar_t file[4096]{};
    if (swprintf_s(file, L"%ls\\payload.bin", root) < 0) break;
    // Identity authority comes from the already retained native root HANDLE.
    // A new pathname open at this boundary would reintroduce parent aliasing.
    ScopedHandle original(INVALID_HANDLE_VALUE);
    if (!openNativeCloudChild(held.handle, L"payload.bin", original.value)) break;
    nativeRelativeOpen = true;
    if (nameMode) {
      // All of these names would be dangerous if a future RootSession simply
      // used Win32's default case-insensitive or DOS-short-name resolution.
      const wchar_t* invalid[] = { L"PAYLOAD.BIN", L"payload~1.bin",
        L"..\\payload.bin", L"payload.bin:stream", L"payload.bin.", L"payload.bin ",
        L"*", L"" };
      for (const auto* name : invalid) {
        HANDLE alien = INVALID_HANDLE_VALUE;
        if (openNativeCloudChild(held.handle, name, alien)) {
          if (alien != INVALID_HANDLE_VALUE) CloseHandle(alien);
          break;
        }
        ++unsafeNameDenials;
      }
      if (unsafeNameDenials != sizeof(invalid) / sizeof(invalid[0])) break;
    }
    BY_HANDLE_FILE_INFORMATION physical{};
    if (!GetFileInformationByHandle(original.value, &physical)
        || physical.nNumberOfLinks != 1
        || !(physical.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) break;
    context.placeholderFileId.store(
      (static_cast<ULONGLONG>(physical.nFileIndexHigh) << 32) | physical.nFileIndexLow,
      std::memory_order_relaxed);
    context.placeholderPinned.store(true, std::memory_order_release);
    HANDLE handle = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) break;
    std::vector<unsigned char> received(context.payload.size());
    DWORD got = 0;
    const BOOL read = ReadFile(handle, received.data(),
      static_cast<DWORD>(received.size()), &got, nullptr);
    CloseHandle(handle);
    if (denyAuthority || staleEnrollment || staleAncestor) {
      if (read || got != 0 || context.successful.load() != 0
          || context.rejected.load() == 0) break;
      exitCode = 0;
      break;
    }
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
    positiveReadVerified = true;
    if (publicationMode) {
      // Exercise future production's shared HANDLE-relative publishing
      // primitive only under the already allowlisted disposable native root.
      ScopedHandle first(INVALID_HANDLE_VALUE);
      if (!nativeCreateExclusiveStage(held.handle, L"stage-first.bin", first.value)) break;
      nativePublishStage = 1;
      if (!nativeWriteAndFlushOpenedStage(first.value,
            context.payload.data(), context.payload.size())) break;
      nativePublishStage = 2;
      if (!nativeRenameOpenedStageNoReplace(first.value, held.handle,
            L"published.bin", &nativePublishError)) break;
      nativePublishStage = 3;
      FILE_ID_INFO firstId{};
      if (!GetFileInformationByHandleEx(first.value, FileIdInfo,
            &firstId, sizeof(firstId))) break;
      // Release the original DELETE/WRITE handle so a refusal on the second
      // rename is actual no-replace protection, not a sharing violation.
      CloseHandle(first.value);
      first.value = INVALID_HANDLE_VALUE;
      ScopedHandle second(INVALID_HANDLE_VALUE);
      if (!nativeCreateExclusiveStage(held.handle, L"stage-second.bin", second.value)) break;
      nativePublishStage = 4;
      if (!nativeWriteAndFlushOpenedStage(second.value,
            context.payload.data(), context.payload.size())) break;
      nativePublishStage = 5;
      if (nativeRenameOpenedStageNoReplace(second.value, held.handle,
            L"published.bin")) break;
      nativePublishStage = 6;
      // Test-only pathname readback checks the destination content; it never
      // grants native authority or participates in the actual publication.
      wchar_t publishedPath[4096]{};
      if (swprintf_s(publishedPath, L"%ls\\published.bin", root) < 0) break;
      ScopedHandle published(CreateFileW(publishedPath,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
      FILE_ID_INFO publishedId{};
      std::vector<unsigned char> readback(context.payload.size());
      DWORD bytesRead = 0;
      if (published.value == INVALID_HANDLE_VALUE) {
        nativePublishError = GetLastError(); break;
      }
      nativePublishStage = 7;
      if (!GetFileInformationByHandleEx(published.value, FileIdInfo,
            &publishedId, sizeof(publishedId))
          || !sameEnrolledFileId(firstId, publishedId)) break;
      nativePublishStage = 8;
      if (!ReadFile(published.value, readback.data(),
            static_cast<DWORD>(readback.size()), &bytesRead, nullptr)
          || bytesRead != readback.size()
          || std::memcmp(readback.data(), context.payload.data(),
            readback.size()) != 0) break;
      nativeNoReplacePublished = true;
      nativePublishStage = 9;
    }
    if (aliasMode) {
      // Reuse the exact same caller-visible FileIdentity but plant a second
      // real NTFS placeholder. A provider relying on FileIdentity alone would
      // leak the original object's payload to this unrelated physical inode.
      CF_PLACEHOLDER_CREATE_INFO alien = item;
      alien.RelativeFileName = L"alien.bin";
      processed = 0;
      result = CfCreatePlaceholders(root, &alien, 1, CF_CREATE_FLAG_NONE, &processed);
      if (FAILED(result) || processed != 1 || FAILED(alien.Result)) break;
      wchar_t alienPath[4096]{};
      if (swprintf_s(alienPath, L"%ls\\alien.bin", root) < 0) break;
      HANDLE alienFile = CreateFileW(alienPath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
      if (alienFile == INVALID_HANDLE_VALUE) break;
      const auto previousFailures = context.rejected.load();
      const auto previousSuccesses = context.successful.load();
      DWORD alienBytes = 0;
      std::vector<unsigned char> alienBuffer(context.payload.size());
      const BOOL alienRead = ReadFile(alienFile, alienBuffer.data(),
        static_cast<DWORD>(alienBuffer.size()), &alienBytes, nullptr);
      CloseHandle(alienFile);
      alienAliasDenied = !alienRead && alienBytes == 0
        && context.rejected > previousFailures
        && context.successful == previousSuccesses;
      if (!alienAliasDenied) break;
    }
    if (concurrentMode) {
      constexpr std::size_t kRivals = 8;
      std::array<std::wstring, kRivals> names;
      std::array<CF_PLACEHOLDER_CREATE_INFO, kRivals> outsiders{};
      for (std::size_t i = 0; i < kRivals; ++i) {
        names[i] = L"alien-" + std::to_wstring(i) + L".bin";
        outsiders[i] = item;
        outsiders[i].RelativeFileName = names[i].c_str();
      }
      processed = 0;
      result = CfCreatePlaceholders(root, outsiders.data(),
        static_cast<DWORD>(outsiders.size()), CF_CREATE_FLAG_NONE, &processed);
      if (FAILED(result) || processed != kRivals) break;
      bool created = true;
      for (const auto& outside : outsiders) if (FAILED(outside.Result)) created = false;
      if (!created) break;
      const auto positiveBefore = context.successful.load();
      const auto deniedBefore = context.rejected.load();
      std::array<std::thread, kRivals> workers;
      std::array<bool, kRivals> denied{};
      for (std::size_t i = 0; i < kRivals; ++i) {
        workers[i] = std::thread([&, i] {
          wchar_t filename[4096]{};
          if (swprintf_s(filename, L"%ls\\%ls", root, names[i].c_str()) < 0)
            return;
          HANDLE foreign = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
          if (foreign == INVALID_HANDLE_VALUE) return;
          std::vector<unsigned char> destination(context.payload.size());
          DWORD got = 0;
          const BOOL fetched = ReadFile(foreign, destination.data(),
            static_cast<DWORD>(destination.size()), &got, nullptr);
          CloseHandle(foreign);
          denied[i] = !fetched && got == 0;
        });
      }
      for (auto& worker : workers) worker.join();
      for (const bool deniedEntry : denied) if (deniedEntry) ++concurrentAliasDenials;
      if (concurrentAliasDenials != kRivals
          || context.successful.load() != positiveBefore
          || context.rejected.load() < deniedBefore + kRivals) break;
    }
    exitCode = 0;
  } while (false);
  if (connected) CfDisconnectSyncRoot(connection);
  // A registered root must never be left registered by this fixture.
  const HRESULT unregisterResult = CfUnregisterSyncRoot(root);
  if (FAILED(unregisterResult)) exitCode = 9;
  std::printf("{\"liveKernelCallbackCount\":%u,\"successfulTransfers\":%u,"
    "\"rejectedTransfers\":%u,\"verifiedBytes\":%zu,"
    "\"finalRootIdentity\":%s,\"finalAncestorsHeld\":%s,\"finalRootPolicy\":%s,"
    "\"finalCloudReparse\":%s,\"finalOwnerAcl\":%s,\"alienAliasDenied\":%s,"
    "\"nativeRelativeOpen\":%s,\"unsafeNameDenials\":%u,"
    "\"concurrentAliasDenials\":%u,\"nativeNoReplacePublished\":%s,"
    "\"nativePublishStage\":%u,\"nativePublishError\":%lu,"
    "\"finalReparseTag\":%lu,"
    "\"unregistered\":%s,\"positiveReadVerified\":%s}\n",
    context.callbacks.load(), context.successful.load(), context.rejected.load(),
    context.payload.size(),
    finalIdentity ? "true" : "false", finalAncestors ? "true" : "false",
    finalPolicy ? "true" : "false",
    finalCloudReparse ? "true" : "false", finalOwnerAcl ? "true" : "false",
    alienAliasDenied ? "true" : "false",
    nativeRelativeOpen ? "true" : "false", unsafeNameDenials,
    concurrentAliasDenials, nativeNoReplacePublished ? "true" : "false",
    nativePublishStage, static_cast<unsigned long>(nativePublishError), finalTag,
    SUCCEEDED(unregisterResult) ? "true" : "false",
    positiveReadVerified && exitCode == 0 ? "true" : "false");
  return exitCode;
}
