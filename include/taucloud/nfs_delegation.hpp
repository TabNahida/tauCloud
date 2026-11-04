#pragma once
#include <algorithm>
#include <cstdint>

namespace tc::nfs_detail {
// Monotonic-time lifecycle for file-domain coherence retention. This is not a
// data-access capability. Each IO still needs a fresh signed identity grant.
class delegation_lifetime {
public:
  enum class state { active, recalling, returned, revoked, expired };
private:
  int64_t period_, expires_, recall_until_ = 0;
  state state_ = state::active;
public:
  delegation_lifetime(int64_t time, int64_t period, int64_t remaining)
      : period_(period), expires_(time + std::clamp<int64_t>(remaining, 0, period)) {}
  state status() const { return state_; }
  bool held() const { return state_ == state::active || state_ == state::recalling; }
  int64_t expires() const { return expires_; }
  int64_t recall_until() const { return recall_until_; }
  void expire(int64_t time) {
    if (!held()) return;
    // A client lease expiring before the recall interval revokes all of that
    // client's state. Later renewals cannot resurrect this delegation.
    if (time >= expires_ && (!recall_until_ || expires_ < recall_until_)) state_ = state::expired;
    else if (recall_until_ && time >= recall_until_) state_ = state::revoked;
    else if (time >= expires_) state_ = state::expired;
  }
  void recall(int64_t time) {
    expire(time);
    if (state_ != state::active) return;
    state_ = state::recalling;
    recall_until_ = time + period_;
  }
  bool renew(int64_t time, int64_t remaining) {
    expire(time);
    if (!held() || remaining <= 0 || remaining > period_) return false;
    expires_ = std::max(expires_, time + remaining);
    // Renewing the client lease never extends the original recall deadline.
    return true;
  }
  void returned(int64_t time) {
    expire(time);
    if (held()) state_ = state::returned;
  }
};
} // namespace tc::nfs_detail
