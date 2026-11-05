#pragma once
#include <taucloud/core.hpp>
#include <atomic>

namespace tc::nfs_detail {
// Shared only between the probe owner and its active writer. Queued transports
// retain a weak reference, so retiring a probe also cancels an unsent frame.
class callback_delivery {
  const int64_t queued_until_;
  std::atomic<int64_t> sent_at_{0}; // zero: pending; -1: failed; positive: sent
public:
  explicit callback_delivery(int64_t created = now()) : queued_until_(created + 5000) {}
  int64_t queued_until() const { return queued_until_; }
  bool expire_send(int64_t time = now()) {
    if (time >= queued_until_) {
      int64_t pending = 0;
      sent_at_.compare_exchange_strong(pending, -1);
    }
    return sent_at_.load() < 0;
  }
  bool finish(int64_t time = now()) {
    if (expire_send(time)) return false;
    int64_t pending = 0;
    return sent_at_.compare_exchange_strong(pending, time);
  }
  int64_t deadline() const {
    auto sent = sent_at_.load();
    return sent < 0 ? 0 : sent ? sent + 5000 : queued_until_;
  }
};
} // namespace tc::nfs_detail
