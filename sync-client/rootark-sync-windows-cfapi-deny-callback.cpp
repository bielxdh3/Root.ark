// CFAPI callback ABI exercise. This binary can ONLY run the in-process
// --self-test: no CfRegisterSyncRoot, CfConnectSyncRoot, placeholder creation,
// CEK access, or CF_OPERATION_TYPE_TRANSFER_DATA is reachable from main.
// The FETCH_DATA callback always completes TRANSFER_DATA with a failing
// cloud-file NTSTATUS and a NULL buffer (the required CFAPI failure shape).
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cfapi.h>
#include <cstdio>
#include <cstring>
#include <cstddef>

namespace {
constexpr NTSTATUS kDenied = static_cast<NTSTATUS>(0xC000CF12UL); // STATUS_CLOUD_FILE_UNSUCCESSFUL
using Execute = HRESULT(WINAPI *)(const CF_OPERATION_INFO*, CF_OPERATION_PARAMETERS*);

struct CallbackContext {
  Execute execute;
};

void CALLBACK denyFetch(const CF_CALLBACK_INFO* info, const CF_CALLBACK_PARAMETERS* params) {
  if (!info || !params || !info->CallbackContext) return;
  const auto* context = static_cast<const CallbackContext*>(info->CallbackContext);
  if (!context->execute) return;

  CF_OPERATION_INFO op{};
  op.StructSize = sizeof(op);
  op.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
  op.ConnectionKey = info->ConnectionKey;
  op.TransferKey = info->TransferKey;
  op.RequestKey = info->RequestKey;

  CF_OPERATION_PARAMETERS failure{};
  failure.ParamSize = static_cast<ULONG>(offsetof(CF_OPERATION_PARAMETERS, TransferData)
    + sizeof(failure.TransferData));
  failure.TransferData.Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
  failure.TransferData.CompletionStatus = kDenied;
  failure.TransferData.Buffer = nullptr;
  const auto& requested = params->FetchData;
  if (requested.RequiredFileOffset.QuadPart >= 0 && requested.RequiredLength.QuadPart > 0) {
    failure.TransferData.Offset = requested.RequiredFileOffset;
    failure.TransferData.Length = requested.RequiredLength;
  }
  // No buffer is allocated or supplied, and no transfer action exists here.
  (void)context->execute(&op, &failure);
}

void CALLBACK cancelFetch(const CF_CALLBACK_INFO*, const CF_CALLBACK_PARAMETERS*) {
  // denyFetch completes synchronously. There is no pending transfer to cancel.
}

const CF_CALLBACK_REGISTRATION kCallbacks[] = {
  {CF_CALLBACK_TYPE_FETCH_DATA, denyFetch},
  {CF_CALLBACK_TYPE_CANCEL_FETCH_DATA, cancelFetch},
  CF_CALLBACK_REGISTRATION_END,
};

unsigned int gFailedCompletions = 0;
unsigned int gBytesTransferred = 0;
HRESULT WINAPI mockExecute(const CF_OPERATION_INFO* op, CF_OPERATION_PARAMETERS* params) {
  if (!op || !params || op->Type != CF_OPERATION_TYPE_TRANSFER_DATA
      || params->ParamSize != offsetof(CF_OPERATION_PARAMETERS, TransferData) + sizeof(params->TransferData)
      || params->TransferData.CompletionStatus != kDenied
      || params->TransferData.Buffer != nullptr
      || params->TransferData.Offset.QuadPart != 0
      || params->TransferData.Length.QuadPart != 16) {
    ++gBytesTransferred;
    return E_FAIL;
  }
  ++gFailedCompletions;
  return S_OK;
}
} // namespace

int main(int argc, char** argv) {
  if (argc != 2 || std::strcmp(argv[1], "--self-test") != 0) return 2;
  CF_PLATFORM_INFO platform{};
  if (FAILED(CfGetPlatformInfo(&platform)) || platform.BuildNumber < 16299) return 5;
  if (kCallbacks[0].Type != CF_CALLBACK_TYPE_FETCH_DATA
      || kCallbacks[1].Type != CF_CALLBACK_TYPE_CANCEL_FETCH_DATA
      || kCallbacks[2].Type != CF_CALLBACK_TYPE_NONE) return 3;
  CallbackContext context{mockExecute};
  CF_CALLBACK_INFO info{};
  info.StructSize = sizeof(info);
  info.CallbackContext = &context;
  CF_CALLBACK_PARAMETERS request{};
  request.ParamSize = sizeof(request);
  request.FetchData.RequiredFileOffset.QuadPart = 0;
  request.FetchData.RequiredLength.QuadPart = 16;
  kCallbacks[0].Callback(&info, &request);
  if (gFailedCompletions != 1 || gBytesTransferred != 0) return 4;
  std::printf("{\"nativeCallback\":\"FETCH_DATA\",\"platformBuild\":%lu,\"failedTransferCompletions\":%u,\"dataBytesTransferred\":%u,\"syncRootRegistered\":false}\n", platform.BuildNumber, gFailedCompletions, gBytesTransferred);
  return 0;
}
