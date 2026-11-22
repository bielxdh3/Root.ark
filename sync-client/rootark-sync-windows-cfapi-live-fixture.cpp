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
#include "rootark-sync-windows-native-root-session.hpp"

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
  const HeldRoot* root = nullptr;
  const HeldAncestors* ancestors = nullptr;
  const wchar_t* path = nullptr;
  // Bind the callback to the exact native placeholder inode, independently
  // of user-controlled FileIdentity or a reopened mutable pathname.
  std::atomic<ULONGLONG> placeholderFileId{0};
  std::atomic<bool> placeholderPinned{false};
  std::atomic<unsigned> callbacks{0};
  std::atomic<unsigned> successful{0};
  std::atomic<unsigned> rejected{0};
  ~Context() { if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size()); }
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
    && info->FileSize.QuadPart == static_cast<LONGLONG>(ctx.payload.size())
    && ctx.placeholderPinned.load(std::memory_order_acquire)
    && static_cast<ULONGLONG>(info->FileId.QuadPart)
      == ctx.placeholderFileId.load(std::memory_order_relaxed);
  const bool rangeMatches = offset >= 0 && offset % 4096 == 0 && length > 0
    && offset < static_cast<LONGLONG>(ctx.payload.size())
    && length <= static_cast<LONGLONG>(ctx.payload.size()) - offset
    && (length % 4096 == 0 || offset + length == static_cast<LONGLONG>(ctx.payload.size()));
  const bool physicalCustody = ctx.root && ctx.ancestors && ctx.path
    && ctx.ancestors->samePaths() && ctx.root->samePath(ctx.path)
    && ctx.root->registeredPolicy();
  if (identityMatches && rangeMatches && physicalCustody) {
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
      && std::wcscmp(argv[1], L"--disposable-live-stdin") != 0
      && std::wcscmp(argv[1], L"--disposable-live-alias") != 0
      && std::wcscmp(argv[1], L"--disposable-concurrent-alias") != 0
      && std::wcscmp(argv[1], L"--disposable-native-names") != 0)) return 2;
  const bool streamed = std::wcscmp(argv[1], L"--disposable-live-stdin") == 0;
  const bool aliasMode = std::wcscmp(argv[1], L"--disposable-live-alias") == 0;
  const bool concurrentMode = std::wcscmp(argv[1], L"--disposable-concurrent-alias") == 0;
  const bool nameMode = std::wcscmp(argv[1], L"--disposable-native-names") == 0;
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
  context.root = &held;
  context.ancestors = &ancestors;
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
    "\"concurrentAliasDenials\":%u,"
    "\"finalReparseTag\":%lu,"
    "\"unregistered\":%s,\"positiveReadVerified\":%s}\n",
    context.callbacks.load(), context.successful.load(), context.rejected.load(),
    context.payload.size(),
    finalIdentity ? "true" : "false", finalAncestors ? "true" : "false",
    finalPolicy ? "true" : "false",
    finalCloudReparse ? "true" : "false", finalOwnerAcl ? "true" : "false",
    alienAliasDenied ? "true" : "false",
    nativeRelativeOpen ? "true" : "false", unsafeNameDenials,
    concurrentAliasDenials, finalTag,
    SUCCEEDED(unregisterResult) ? "true" : "false",
    exitCode == 0 ? "true" : "false");
  return exitCode;
}
