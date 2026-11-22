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

namespace {
constexpr std::size_t kPayloadLength = 4097;
constexpr char kIdentity[] = "rootark-cfapi-test-v1";
std::array<unsigned char, kPayloadLength> makePayload() {
  std::array<unsigned char, kPayloadLength> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = static_cast<unsigned char>((i * 19 + 7) % 251);
  return bytes;
}
constexpr NTSTATUS kCloudFailure = static_cast<NTSTATUS>(0xC000CF12UL);
struct Context {
  std::array<unsigned char, kPayloadLength> payload = makePayload();
  unsigned callbacks = 0;
  unsigned successful = 0;
  unsigned rejected = 0;
};

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
    && info->FileSize.QuadPart == static_cast<LONGLONG>(kPayloadLength);
  const bool rangeMatches = offset >= 0 && offset % 4096 == 0 && length > 0
    && length <= static_cast<LONGLONG>(kPayloadLength) - offset
    && (length % 4096 == 0 || offset + length == static_cast<LONGLONG>(kPayloadLength));
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
  if (argc != 3 || std::wcscmp(argv[1], L"--disposable-live") != 0) return 2;
  const wchar_t* root = argv[2];
  if (!root || std::wcslen(root) < 8 || std::wcslen(root) > 4096
      || root[1] != L':' || root[2] != L'\\') return 3;
  wchar_t temp[MAX_PATH]{};
  const DWORD tempLength = GetTempPathW(MAX_PATH, temp);
  if (!tempLength || tempLength >= MAX_PATH || tempLength >= std::wcslen(root)
      || _wcsnicmp(root, temp, tempLength) != 0) return 10;
  const wchar_t* leaf = root + tempLength;
  constexpr wchar_t prefix[] = L"rootark-cfapi-live-";
  if (std::wcsncmp(leaf, prefix, (sizeof(prefix) / sizeof(wchar_t)) - 1) != 0
      || !leaf[sizeof(prefix) / sizeof(wchar_t) - 1]
      || std::wcschr(leaf, L'\\') || std::wcschr(leaf, L'/')) return 11;
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
  Context context;
  CF_CONNECTION_KEY connection{};
  bool connected = false;
  int exitCode = 8;
  do {
    result = CfConnectSyncRoot(root, kCallbacks, &context, CF_CONNECT_FLAG_NONE, &connection);
    if (FAILED(result)) break;
    connected = true;
    CF_PLACEHOLDER_CREATE_INFO item{};
    item.RelativeFileName = L"payload.bin";
    item.FsMetadata.FileSize.QuadPart = kPayloadLength;
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
    std::array<unsigned char, kPayloadLength> received{};
    DWORD got = 0;
    const BOOL read = ReadFile(handle, received.data(),
      static_cast<DWORD>(received.size()), &got, nullptr);
    CloseHandle(handle);
    if (!read || got != kPayloadLength
        || std::memcmp(received.data(), context.payload.data(), kPayloadLength) != 0
        || context.callbacks == 0 || context.successful == 0) break;
    exitCode = 0;
  } while (false);
  if (connected) CfDisconnectSyncRoot(connection);
  // A registered root must never be left registered by this fixture.
  const HRESULT unregisterResult = CfUnregisterSyncRoot(root);
  if (FAILED(unregisterResult)) exitCode = 9;
  std::printf("{\"liveKernelCallbackCount\":%u,\"successfulTransfers\":%u,"
    "\"rejectedTransfers\":%u,\"verifiedBytes\":%zu,"
    "\"unregistered\":%s,\"positiveReadVerified\":%s}\n",
    context.callbacks, context.successful, context.rejected, kPayloadLength,
    SUCCEEDED(unregisterResult) ? "true" : "false",
    exitCode == 0 ? "true" : "false");
  return exitCode;
}
