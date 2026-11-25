// Windows SDK-only, in-process CFAPI TRANSFER_DATA parameter-shape probe.
// NOT a CFAPI provider. Never registers/connects a sync root, attaches a
// callback to the kernel, opens a file, decrypts a CEK, or calls real CfExecute.
// A mocked successful operation here does NOT authorize positive hydration.
// Owner-signed custody, independent R1 CURRENT/floor and physical identity
// remain mandatory before any real positive completion can be developed.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cfapi.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {
constexpr std::uint64_t kAlignment = 4096;
constexpr std::uint64_t kMaxFileBytes = 1024 * 1024;
constexpr NTSTATUS kSuccess = static_cast<NTSTATUS>(0); // STATUS_SUCCESS

// This is ONLY the positive transfer RANGE SHAPE, not an authorization check.
// Use the conservative EOF exception: the final short range ends exactly at
// logical EOF, rather than copying padding past the source buffer.
bool validRange(std::uint64_t size, std::uint64_t offset, std::uint64_t length) {
  return size > 0 && size <= kMaxFileBytes && offset < size
    && offset % kAlignment == 0 && length > 0
    && length <= size - offset
    && (length % kAlignment == 0 || offset + length == size);
}

struct Mock {
  unsigned positive = 0;
  std::uint64_t bytes = 0;
};

bool inspectMockPositive(Mock& mock, const std::vector<unsigned char>& source,
  std::uint64_t offset, std::uint64_t length) {
  if (!validRange(source.size(), offset, length)) return false;
  // No native provider connection or real request key is constructed.
  CF_OPERATION_INFO op{};
  op.StructSize = sizeof(op);
  op.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
  CF_OPERATION_PARAMETERS params{};
  params.ParamSize = static_cast<ULONG>(
    offsetof(CF_OPERATION_PARAMETERS, TransferData) + sizeof(params.TransferData));
  params.TransferData.Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
  params.TransferData.CompletionStatus = kSuccess;
  params.TransferData.Buffer = source.data() + static_cast<std::size_t>(offset);
  params.TransferData.Offset.QuadPart = static_cast<LONGLONG>(offset);
  params.TransferData.Length.QuadPart = static_cast<LONGLONG>(length);

  // Inspect only the exact SDK structures, not an actual Cloud Files API.
  if (op.StructSize != sizeof(op) || op.Type != CF_OPERATION_TYPE_TRANSFER_DATA
    || params.ParamSize != offsetof(CF_OPERATION_PARAMETERS, TransferData)
      + sizeof(params.TransferData)
    || params.TransferData.CompletionStatus != kSuccess
    || params.TransferData.Flags != CF_OPERATION_TRANSFER_DATA_FLAG_NONE
    || params.TransferData.Buffer == nullptr
    || params.TransferData.Offset.QuadPart != static_cast<LONGLONG>(offset)
    || params.TransferData.Length.QuadPart != static_cast<LONGLONG>(length)) {
    return false;
  }
  const auto* expected = source.data() + static_cast<std::size_t>(offset);
  if (params.TransferData.Buffer != expected) return false;
  mock.positive++;
  mock.bytes += length;
  return true;
}

bool checkShape() {
  Mock mock;
  unsigned rejected = 0;
  std::vector<unsigned char> one(1, 0x5A);
  std::vector<unsigned char> odd(4097);
  for (std::size_t i = 0; i < odd.size(); ++i)
    odd[i] = static_cast<unsigned char>((i * 17u + 23u) % 251u);
  const auto accept = [&](const std::vector<unsigned char>& data,
      std::uint64_t offset, std::uint64_t length) {
    return inspectMockPositive(mock, data, offset, length);
  };
  if (!accept(one, 0, 1) || !accept(odd, 0, 4096)
    || !accept(odd, 4096, 1)) return false;
  const auto reject = [&](const std::vector<unsigned char>& data,
      std::uint64_t offset, std::uint64_t length) {
    if (validRange(data.size(), offset, length)) return false;
    if (inspectMockPositive(mock, data, offset, length)) return false;
    ++rejected;
    return true;
  };
  std::vector<unsigned char> empty;
  std::vector<unsigned char> tooLarge(kMaxFileBytes + 1, 0x00);
  if (!reject(empty, 0, 1) || !reject(one, 0, 0)
    || !reject(odd, 1, 1) || !reject(odd, 4096, 2)
    || !reject(odd, 0, 4095) || !reject(odd, 8192, 1)
    || !reject(tooLarge, 0, 4096) || !reject(odd, 0, 4098)
    || !reject(odd, 4095, 2)) return false;
  if (mock.positive != 3 || mock.bytes != 4098 || rejected != 9) return false;
  SecureZeroMemory(one.data(), one.size());
  SecureZeroMemory(odd.data(), odd.size());
  SecureZeroMemory(tooLarge.data(), tooLarge.size());
  // This result means only that copied ABI parameter shapes were inspected.
  std::printf("\"mockPositiveOperations\":%u,\"mockPositiveBytes\":%llu,"
    "\"mockRejectedRanges\":%u", mock.positive,
    static_cast<unsigned long long>(mock.bytes), rejected);
  return true;
}
} // namespace

int main(int argc, char** argv) {
  if (argc != 2 || std::strcmp(argv[1], "--self-test") != 0) return 2;
  CF_PLATFORM_INFO platform{};
  if (FAILED(CfGetPlatformInfo(&platform)) || platform.BuildNumber < 16299)
    return 3;
  const HMODULE module = GetModuleHandleW(L"CldApi.dll");
  const bool exportsPresent = module
    && GetProcAddress(module, "CfRegisterSyncRoot")
    && GetProcAddress(module, "CfConnectSyncRoot")
    && GetProcAddress(module, "CfHydratePlaceholder");
  if (!exportsPresent) return 4;
  std::printf("{\"nativeApiPresent\":true,\"platformBuild\":%lu,"
    "\"syncRootRegistered\":false,\"providerConnected\":false,"
    "\"kernelCallbackInvoked\":false,\"positiveHydrationAuthorized\":false,",
    platform.BuildNumber);
  if (!checkShape()) return 5;
  std::printf(",\"cloudDataBytesTransferred\":0}\n");
  return 0;
}
