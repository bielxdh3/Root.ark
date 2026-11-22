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
  const wchar_t* path = nullptr;
  // Bind the callback to the exact native placeholder inode, independently
  // of user-controlled FileIdentity or a reopened mutable pathname.
  std::atomic<ULONGLONG> placeholderFileId{0};
  std::atomic<bool> placeholderPinned{false};
  std::atomic<unsigned> callbacks{0};
  std::atomic<unsigned> successful{0};
  std::atomic<unsigned> rejected{0};
  rootark_cfapi::CancelFence cancellations;
  ~Context() { if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size()); }
};

// Pure callback-time identity predicate. Payload and FileIdentity MUST remain
// immutable for the lifetime of an admitted Context; only the pin and file-ID
// atomics may change while an authorization callback is in progress.
// This check is necessary, never sufficient, for a positive kernel transfer.
bool matchesPinnedPlaceholder(const Context& ctx, const CF_CALLBACK_INFO* info) noexcept {
  return info && info->FileIdentity
    && !ctx.identity.empty() && ctx.identity.size() <= 256
    && info->FileIdentityLength == ctx.identity.size()
    && std::memcmp(info->FileIdentity, ctx.identity.data(), ctx.identity.size()) == 0
    && info->FileSize.QuadPart == static_cast<LONGLONG>(ctx.payload.size())
    && ctx.placeholderPinned.load(std::memory_order_acquire)
    && static_cast<ULONGLONG>(info->FileId.QuadPart)
      == ctx.placeholderFileId.load(std::memory_order_acquire);
}

bool retainsNativeCustody(const Context& ctx) {
  return ctx.root && ctx.ancestors && ctx.path
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
  const bool identityMatches = matchesPinnedPlaceholder(ctx, info);
  const bool rangeMatches = offset >= 0 && offset % 4096 == 0 && length > 0
    && offset < static_cast<LONGLONG>(ctx.payload.size())
    && length <= static_cast<LONGLONG>(ctx.payload.size()) - offset
    && (length % 4096 == 0 || offset + length == static_cast<LONGLONG>(ctx.payload.size()));
  const bool independentlyAdmitted = identityMatches && rangeMatches
    && !ctx.cancellations.canceled(info) && retainsNativeCustody(ctx) && ctx.authorize
    && ctx.authorize(info, ctx.authorityContext);
  // Authorization may yield to CANCEL_FETCH_DATA, pin withdrawal or physical
  // path replacement. Recheck all three predicates after the authority call,
  // before offering data to the kernel. This narrows (does not eliminate) the
  // final check -> CfExecute window: already-submitted bytes are irreversible.
  // Pin true -> false -> true ABA requires an independent custody generation;
  // neither this callback nor a mock can certify that external authority.
  if (independentlyAdmitted && !ctx.cancellations.canceled(info)
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
