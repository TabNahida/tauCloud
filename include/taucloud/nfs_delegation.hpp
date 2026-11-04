#pragma once
#include <algorithm>
#include <cstdint>
#include <limits>

namespace tc::nfs_detail {
// Monotonic-time lifecycle for file-domain coherence retention. This is not a
// data-access capability. Each IO still needs a fresh signed identity grant.
class delegation_lifetime {
public:
  enum class state { active, recalling, returned, revoked, expired };
private:
  int64_t period_, expires_, recall_until_ = 0;
  state state_ = state::active;
  uint32_t reservations_ = 0;
  bool external_authority_ = false;
public:
  delegation_lifetime(int64_t time, int64_t period, int64_t remaining, bool external_authority = false)
      : period_(period), expires_(time + std::clamp<int64_t>(remaining, 0, period)),
        external_authority_(external_authority) {}
  state status() const { return state_; }
  bool held() const { return state_ == state::active || state_ == state::recalling; }
  int64_t expires() const { return expires_; }
  int64_t recall_until() const { return recall_until_; }
  uint32_t reservations() const { return reservations_; }
  // Acknowledged in-flight work prevents lease expiry, but never recall expiry.
  // The owner binds each use to a unique token and releases it on completion.
  bool reserve(int64_t time) {
    expire(time);
    // Existing in-flight work is not authority for unrelated late arrivals.
    // A validated renewal may advance expires_ before reserving more work.
    if (!held() || time >= expires_ || reservations_ == 32) return false;
    ++reservations_;
    return true;
  }
  bool complete(int64_t time, bool renew_lease) {
    if (!reservations_) return false;
    expire(time);
    if (held() && renew_lease) expires_ = std::max(expires_, time + period_);
    --reservations_;
    expire(time);
    return held();
  }
  int64_t protected_until() const {
    auto expiry = reservations_ ? std::numeric_limits<int64_t>::max() : expires_;
    return held() ? (recall_until_ ? std::min(expiry, recall_until_) : expiry) : 0;
  }
  // Import a native authority's absolute monotonic deadlines. Observation may
  // shorten protection, never extend it or restart a recall after IPC delay.
  void constrain(int64_t expires, int64_t recall_until) {
    if (!held()) return;
    expires_ = std::min(expires_, expires);
    if (recall_until) {
      state_ = state::recalling;
      recall_until_ = recall_until_ ? std::min(recall_until_, recall_until) : recall_until;
    }
  }
  // An independent controller may reserve or complete work after our last
  // observation. Import its ACKs and never infer native expiry from a stale
  // local lease/count. Only confirmed owner termination or explicit return
  // can retire this mirror while its authority remains reachable.
  void synchronize_owner(int64_t expires, int64_t recall_until, uint32_t reservations) {
    if (!external_authority_ || !held()) return;
    expires_ = expires;
    reservations_ = reservations;
    constrain(expires, recall_until);
  }
  void owner_lost(int64_t time) {
    if (!external_authority_) return;
    if (held()) {
      // The owner conservatively retains unknown independent work at EOF.
      // Bound our unavailable local fence without extending existing recall.
      expires_ = std::max(expires_, time + period_);
      recall(time);
    }
    external_authority_ = false;
    expire(time);
  }
  // A remote native authority may observe expiry/revocation first. Such an
  // observation can retire local state, never revive or renew it.
  void observe_terminal(state value) {
    if (held() && (value == state::returned || value == state::revoked || value == state::expired))
      state_ = value;
  }
  void expire(int64_t time) {
    if (!held() || external_authority_) return;
    // A client lease expiring before the recall interval revokes all of that
    // client's state. Later renewals cannot resurrect this delegation.
    if (!reservations_ && time >= expires_ && (!recall_until_ || expires_ < recall_until_)) state_ = state::expired;
    else if (recall_until_ && time >= recall_until_) state_ = state::revoked;
    else if (!reservations_ && time >= expires_) state_ = state::expired;
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
