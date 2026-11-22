#pragma once
// Native CFAPI FETCH_DATA handler shared between RootSession runtime and tests.
// Caller must independently verify owner authorization, CURRENT floor, pinned original
// NTFS identity and durability before constructing an admitted Context.
#include <Windows.h>
#include <winternl.h>
#include <cfapi.h>
#include <vector>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "rootark-sync-windows-cfapi-cancel-fence.hpp"
#include "rootark-sync-windows-native-root-session.hpp"
namespace {
constexpr NTSTATUS kCloudFailure = static_cast<NTSTATUS>(0xC000CF12UL);
struct Context {
  // A native RootSession caller must provide a separate callback-time
  // authorization decision (enrolled device, signed CURRENT and monotonic
  // floor). There is deliberately no default successful decision.
  using Authorize = bool (*)(const CF_CALLBACK_INFO*, void*) noexcept;
  Authorize authorize = nullptr;
  void* authorityContext = nullptr;
  std::vector<unsigned char> payload;
  std::vector<unsigned char> identity;
  const HeldRoot* root = nullptr;
  const HeldAncestors* ancestors = nullptr;
  const NativeOriginalEnrollment* enrollment = nullptr;
  const wchar_t* path = nullptr;
private:
  // A revoke/reissue, even to the same physical inode, must invalidate an
  // in-flight FETCH_DATA authorization rather than lending it a new pin.
  std::atomic<ULONGLONG> placeholderFileId{0};
  std::atomic<bool> placeholderPinned{false};
  std::atomic<std::uint64_t> placeholderGeneration{0};
public:
  void publishPlaceholder(ULONGLONG fileId) noexcept {
    placeholderPinned.store(false, std::memory_order_release);
    placeholderFileId.store(fileId, std::memory_order_release);
    placeholderGeneration.fetch_add(1, std::memory_order_acq_rel);
    placeholderPinned.store(true, std::memory_order_release);
  }
  void revokePlaceholder() noexcept {
    placeholderPinned.store(false, std::memory_order_release);
    placeholderGeneration.fetch_add(1, std::memory_order_acq_rel);
  }
  std::uint64_t pinGeneration() const noexcept {
    return placeholderGeneration.load(std::memory_order_acquire);
  }
  ULONGLONG pinnedFileId() const noexcept {
    return placeholderFileId.load(std::memory_order_acquire);
  }
  bool isPlaceholderPinned() const noexcept {
    return placeholderPinned.load(std::memory_order_acquire);
  }
  std::atomic<unsigned> callbacks{0};
  std::atomic<unsigned> successful{0};
  std::atomic<unsigned> rejected{0};
  rootark_cfapi::CancelFence cancellations;
  ~Context() { if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size()); }
};

bool matchesPinnedPlaceholder(const Context& ctx, const CF_CALLBACK_INFO* info) noexcept {
  return info && info->FileIdentity
    && !ctx.identity.empty() && ctx.identity.size() <= 256
    && info->FileIdentityLength == ctx.identity.size()
    && std::memcmp(info->FileIdentity, ctx.identity.data(), ctx.identity.size()) == 0
    && info->FileSize.QuadPart == static_cast<LONGLONG>(ctx.payload.size())
    && ctx.isPlaceholderPinned()
    && static_cast<ULONGLONG>(info->FileId.QuadPart) == ctx.pinnedFileId();
}

bool retainsNativeCustody(const Context& ctx) {
  return ctx.root && ctx.ancestors && ctx.enrollment && ctx.path
    && matchesOriginalEnrollment(*ctx.enrollment, *ctx.root, *ctx.ancestors)
    && ctx.ancestors->samePaths() && ctx.root->samePath(ctx.path)
    && ctx.root->registeredPolicy();
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
  const auto admittedPinGeneration = ctx.pinGeneration();
  const bool identityMatches = matchesPinnedPlaceholder(ctx, info);
  const bool rangeMatches = offset >= 0 && offset % 4096 == 0 && length > 0
    && offset < static_cast<LONGLONG>(ctx.payload.size())
    && length <= static_cast<LONGLONG>(ctx.payload.size()) - offset
    && (length % 4096 == 0 || offset + length == static_cast<LONGLONG>(ctx.payload.size()));
  const bool independentlyAdmitted = identityMatches && rangeMatches
    && !ctx.cancellations.canceled(info) && retainsNativeCustody(ctx) && ctx.authorize
    && ctx.authorize(info, ctx.authorityContext);
  // Recheck after callback-time authorization, which may race CANCEL,
  // revocation, ABA pin reissue, or a physical root replacement.
  if (independentlyAdmitted && !ctx.cancellations.canceled(info)
      && ctx.pinGeneration() == admittedPinGeneration
      && matchesPinnedPlaceholder(ctx, info) && retainsNativeCustody(ctx)) {
    transfer.TransferData.CompletionStatus = 0;
    transfer.TransferData.Buffer = ctx.payload.data() + static_cast<std::size_t>(offset);
    if (SUCCEEDED(CfExecute(&op, &transfer))) ++ctx.successful;
    return;
  }
  ++ctx.rejected;
  (void)CfExecute(&op, &transfer);
}

void CALLBACK onCancel(const CF_CALLBACK_INFO* info, const CF_CALLBACK_PARAMETERS*) {
  if (!info || !info->CallbackContext) return;
  auto& ctx = *static_cast<Context*>(info->CallbackContext);
  ctx.cancellations.cancel(info);
}
constexpr CF_CALLBACK_REGISTRATION kCallbacks[] = {
  {CF_CALLBACK_TYPE_FETCH_DATA, onFetch},
  {CF_CALLBACK_TYPE_CANCEL_FETCH_DATA, onCancel},
  CF_CALLBACK_REGISTRATION_END,
};
} // namespace
