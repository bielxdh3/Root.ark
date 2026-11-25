// Native-only adversarial CFAPI callback test: mocked CfExecute, no CFAPI
// registration, no root, no object data, no credential and no OS mutation.
// This intentionally cannot produce a successful TRANSFER_DATA.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cfapi.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {
void CALLBACK onCancel(const CF_CALLBACK_INFO*, const CF_CALLBACK_PARAMETERS*);
std::atomic<unsigned> denied{0};
std::atomic<unsigned> unsafe{0};
CF_CALLBACK_INFO* cancelDuringCfExecute = nullptr;
HRESULT WINAPI fakeCfExecute(const CF_OPERATION_INFO* operation,
    CF_OPERATION_PARAMETERS* params) {
  if (cancelDuringCfExecute) {
    CF_CALLBACK_INFO* cancelInfo = cancelDuringCfExecute;
    cancelDuringCfExecute = nullptr;
    onCancel(cancelInfo, nullptr);
  }
  if (!operation || !params ||
    operation->Type != CF_OPERATION_TYPE_TRANSFER_DATA ||
    params->TransferData.Buffer != nullptr ||
    params->TransferData.CompletionStatus != static_cast<NTSTATUS>(0xC000CF12UL)) {
    ++unsafe;
    return E_FAIL;
  }
  ++denied;
  return S_OK;
}
}

#define CfExecute fakeCfExecute
#include "rootark-sync-windows-cfapi-provider.hpp"
#undef CfExecute

namespace {
CF_CALLBACK_INFO request(Context& ctx, LONGLONG connection,
    LONGLONG transfer, LONGLONG value) {
  CF_CALLBACK_INFO info{};
  info.StructSize = sizeof(info);
  info.CallbackContext = &ctx;
  info.ConnectionKey.Internal = connection;
  info.TransferKey.QuadPart = transfer;
  info.RequestKey.QuadPart = value;
  return info;
}

bool run() {
  Context ctx;
  ctx.identity.assign({'c', 'f', 'a', 'p', 'i'});
  ctx.payload.assign(4097, 0xA5);
  ctx.publishPlaceholder(12345);
  CF_CALLBACK_INFO canceled = request(ctx, 11, 22, 33);
  canceled.FileSize.QuadPart = static_cast<LONGLONG>(ctx.payload.size());
  canceled.FileIdentity = ctx.identity.data();
  canceled.FileIdentityLength = static_cast<DWORD>(ctx.identity.size());
  canceled.FileId.QuadPart = 12345;
  if (ctx.cancellations.canceled(&canceled)) return false;
  onCancel(&canceled, nullptr);
  onCancel(&canceled, nullptr); // A duplicate must not exhaust the finite fence.
  if (!ctx.cancellations.canceled(&canceled)) return false;
  Context unrelatedContext;
  CF_CALLBACK_INFO sameKeysElsewhere = request(unrelatedContext, 11, 22, 33);
  if (unrelatedContext.cancellations.canceled(&sameKeysElsewhere)) return false;
  onCancel(nullptr, nullptr);
  CF_CALLBACK_INFO noContext = request(ctx, 1, 2, 3);
  noContext.CallbackContext = nullptr;
  onCancel(&noContext, nullptr);

  CF_CALLBACK_INFO differentTransfer = request(ctx, 11, 23, 33);
  CF_CALLBACK_INFO differentRequest = request(ctx, 11, 22, 34);
  CF_CALLBACK_INFO differentConnection = request(ctx, 12, 22, 33);
  if (ctx.cancellations.canceled(&differentTransfer)
    || ctx.cancellations.canceled(&differentRequest)
    || ctx.cancellations.canceled(&differentConnection)) return false;

  CF_CALLBACK_PARAMETERS required{};
  required.ParamSize = sizeof(required);
  required.FetchData.RequiredFileOffset.QuadPart = 0;
  required.FetchData.RequiredLength.QuadPart = 4096;
  onFetch(&canceled, &required);
  if (ctx.successful.load() != 0 || ctx.rejected.load() != 1
    || denied.load() != 1 || unsafe.load() != 0) return false;

  // Reusing the exact canceled tuple for another claimed inode, followed by
  // the original inode again, must never clear the cancellation tombstone.
  CF_CALLBACK_INFO reused = canceled;
  reused.FileId.QuadPart = 99999;
  onFetch(&reused, &required);
  reused.FileId = canceled.FileId;
  onFetch(&reused, &required);
  if (ctx.successful.load() != 0 || denied.load() != 3
    || !ctx.cancellations.canceled(&reused)) return false;

  // In the absence of a production signed/AEAD verifier, merely pinning a
  // plausible FileId and identity must never produce a positive CFAPI result.
  differentRequest.FileSize = canceled.FileSize;
  differentRequest.FileIdentity = canceled.FileIdentity;
  differentRequest.FileIdentityLength = canceled.FileIdentityLength;
  differentRequest.FileId = canceled.FileId;
  onFetch(&differentRequest, &required);
  if (ctx.successful.load() != 0 || denied.load() != 4 || unsafe.load() != 0)
    return false;

  // Concurrent CANCEL callbacks are keyed exactly and must not race. These
  // 160 keys + the first cancellation remain below the bounded capacity.
  std::vector<std::thread> threads;
  std::atomic<bool> cancelAckLost{false};
  for (int shard = 0; shard < 8; ++shard) {
    threads.emplace_back([&ctx, &cancelAckLost, shard] {
      for (int j = 0; j < 20; ++j) {
        CF_CALLBACK_INFO info = request(ctx, 90, shard + 100,
          static_cast<LONGLONG>(j + 1000));
        onCancel(&info, nullptr);
        // Check the happens-before boundary while other workers are mutating
        // the table. Once onCancel returned, the exact tombstone must exist.
        if (!ctx.cancellations.canceled(&info)) cancelAckLost.store(true);
      }
    });
  }
  for (auto& thread : threads) thread.join();
  if (cancelAckLost.load()) return false;
  for (int shard = 0; shard < 8; ++shard) {
    for (int j = 0; j < 20; ++j) {
      CF_CALLBACK_INFO info = request(ctx, 90, shard + 100,
        static_cast<LONGLONG>(j + 1000));
      if (!ctx.cancellations.canceled(&info)) return false;
    }
  }
  if (ctx.cancellations.canceled(&differentTransfer)) return false;

  // Deliberately overflow the fixed tombstone set: no eviction, allocation,
  // wraparound or success fallback is permitted for this provider Context.
  for (int index = 0; index < 95; ++index) {
    CF_CALLBACK_INFO info = request(ctx, 567, 890,
      static_cast<LONGLONG>(index + 2000));
    onCancel(&info, nullptr);
  }
  if (ctx.cancellations.canceled(&differentTransfer)) return false;
  CF_CALLBACK_INFO overflow = request(ctx, 567, 890, 2095);
  onCancel(&overflow, nullptr);
  if (!ctx.cancellations.canceled(&differentTransfer)
    || !ctx.cancellations.canceled(&differentRequest)
    || !ctx.cancellations.canceled(&differentConnection)
    || !ctx.cancellations.canceled(&canceled)
    || unrelatedContext.cancellations.canceled(&sameKeysElsewhere)) return false;
  onFetch(&differentRequest, &required);
  if (ctx.successful.load() != 0 || denied.load() != 5
    || unsafe.load() != 0) return false;

  // A CFAPI completion can reenter cancellation. Never hold the SRW fence
  // lock across CfExecute; this failure-only mock asserts no deadlock and
  // preserves per-Context cancellation isolation.
  Context reentrantContext;
  CF_CALLBACK_INFO reentrantFetch = request(reentrantContext, 16, 17, 18);
  cancelDuringCfExecute = &reentrantFetch;
  onFetch(&reentrantFetch, &required);
  if (cancelDuringCfExecute ||
    !reentrantContext.cancellations.canceled(&reentrantFetch) ||
    reentrantContext.successful.load() != 0 || denied.load() != 6)
    return false;

  // Model a pin revoked after initial identity admission but before its
  // authorizer returns. The final pure identity predicate must now reject.
  // This is a gate test ONLY; no trust signature or AEAD is being fabricated.
  Context latePin;
  latePin.identity.assign({'p', 'i', 'n'});
  latePin.payload.assign(4096, 0xAC);
  latePin.publishPlaceholder(17);
  CF_CALLBACK_INFO pinRequest = request(latePin, 41, 42, 43);
  pinRequest.FileIdentity = latePin.identity.data();
  pinRequest.FileIdentityLength = static_cast<DWORD>(latePin.identity.size());
  pinRequest.FileSize.QuadPart = static_cast<LONGLONG>(latePin.payload.size());
  pinRequest.FileId.QuadPart = 17;
  if (!matchesPinnedPlaceholder(latePin, &pinRequest)) return false;
  latePin.revokePlaceholder();
  if (matchesPinnedPlaceholder(latePin, &pinRequest)) return false;
  latePin.publishPlaceholder(18);
  if (matchesPinnedPlaceholder(latePin, &pinRequest)) return false;
  latePin.publishPlaceholder(17);
  // A callback can yield to native unpin/re-pin while a separate authority
  // check is running. Reusing the very same physical inode must not make
  // that new pin silently authorize an OLD in-flight request.
  const auto beforeAba = latePin.pinGeneration();
  latePin.revokePlaceholder();
  latePin.publishPlaceholder(17);
  if (!matchesPinnedPlaceholder(latePin, &pinRequest)
      || latePin.pinGeneration() == beforeAba) return false;
  unsigned char foreignIdentity[3] = {'b', 'a', 'd'};
  pinRequest.FileIdentity = foreignIdentity;
  if (matchesPinnedPlaceholder(latePin, &pinRequest)) return false;
  pinRequest.FileIdentity = latePin.identity.data();
  pinRequest.FileSize.QuadPart = 1;
  if (matchesPinnedPlaceholder(latePin, &pinRequest)) return false;

  return unrelatedContext.cancellations.canceled(&sameKeysElsewhere) == false
    && reentrantContext.successful.load() == 0 && unsafe.load() == 0;
}
}

int main(int argc, char** argv) {
  if (argc != 2 || std::strcmp(argv[1], "--self-test") != 0) return 2;
  if (!run()) return 3;
  std::printf("{\"cancelFence\":true,\"concurrentKeys\":160,"
    "\"overflowFailsClosed\":true,\"pinRevalidation\":true,"
    "\"reusedKeyDenied\":true,\"reentrantCancel\":true,"
    "\"deniedTransfers\":%u,"
    "\"successfulTransfers\":0,\"syncRootRegistered\":false}\n",
    denied.load());
  return 0;
}
