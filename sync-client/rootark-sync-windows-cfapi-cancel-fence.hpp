#pragma once
// Per-provider, bounded CFAPI request cancellation tombstones. A cancellation
// is scoped to the exact connection, transfer and request keys; a different
// request (or a reconnected provider) must not inherit its denial. Never drop
// old tombstones on overflow: fail closed until this Context is retired.
// No CFAPI registration, file access, decryption or transfer lives here.
#include <Windows.h>
#include <cfapi.h>
#include <array>
#include <cstddef>
#include <cstdint>

namespace rootark_cfapi {
class CancelFence final {
  struct Key {
    std::uint64_t connection;
    std::uint64_t transfer;
    std::uint64_t request;
  };
  static Key key(const CF_CALLBACK_INFO& info) noexcept {
    return {static_cast<std::uint64_t>(info.ConnectionKey.Internal),
      static_cast<std::uint64_t>(info.TransferKey.QuadPart),
      static_cast<std::uint64_t>(info.RequestKey.QuadPart)};
  }
  static bool equal(const Key& a, const Key& b) noexcept {
    return a.connection == b.connection && a.transfer == b.transfer
      && a.request == b.request;
  }
  SRWLOCK lock_ = SRWLOCK_INIT;
  std::array<Key, 256> tombstones_{};
  std::size_t used_ = 0;
  bool saturated_ = false;
public:
  static constexpr std::size_t kMaxCanceled = 256;
  CancelFence() = default;
  CancelFence(const CancelFence&) = delete;
  CancelFence& operator=(const CancelFence&) = delete;

  void cancel(const CF_CALLBACK_INFO* info) noexcept {
    if (!info) return;
    const Key value = key(*info);
    AcquireSRWLockExclusive(&lock_);
    bool already = false;
    for (std::size_t i = 0; i < used_; ++i) {
      if (equal(tombstones_[i], value)) { already = true; break; }
    }
    if (!already && !saturated_) {
      if (used_ == tombstones_.size()) saturated_ = true;
      else tombstones_[used_++] = value;
    }
    ReleaseSRWLockExclusive(&lock_);
  }

  bool canceled(const CF_CALLBACK_INFO* info) noexcept {
    if (!info) return true;
    const Key value = key(*info);
    AcquireSRWLockShared(&lock_);
    bool isDenied = saturated_;
    for (std::size_t i = 0; !isDenied && i < used_; ++i)
      isDenied = equal(tombstones_[i], value);
    ReleaseSRWLockShared(&lock_);
    return isDenied;
  }
};
} // namespace rootark_cfapi
