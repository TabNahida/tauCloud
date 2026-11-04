#pragma once
#include <taucloud/smb.hpp>
#include <optional>
#include <map>
#include <memory>
#include <set>

namespace tc::smb_detail {
inline constexpr int64_t lease_handle_ack_ms = 35000;
// Protocol state shared by every open carrying one (ClientGuid, LeaseKey).
// This class grants no file authority: the caller must first obtain native
// exclusion, and keep it until a break is delivered/acknowledged or fenced.
struct lease_request {
  bytes key, parent;
  unsigned state = 0, version = 1;
  uint16_t epoch = 0;
  static lease_request decode(std::string_view data);
};
struct lease_break {
  uint64_t serial;
  unsigned current, target;
  uint16_t epoch;
  bool acknowledgment;
  bytes encode(std::string_view key) const;
};
class lease_state {
public:
  explicit lease_state(const lease_request &request);
  unsigned state() const { return state_; }
  uint16_t epoch() const { return epoch_; }
  unsigned version() const { return version_; }
  const bytes &key() const { return key_; }
  const bytes &parent() const { return parent_; }
  bool breaking() const { return breaking_; }
  bool unsettled() const { return breaking_ || pending_.has_value(); }
  // RH has no dirty write cache. Once its NONE notification is delivered,
  // data operations may proceed while HANDLE invalidation still awaits ACK.
  bool data_invalidated() const {
    return state_ == 3 && breaking_ && notified_target_ == 0 && !pending_;
  }
  const std::optional<lease_break> &pending() const { return pending_; }
  int64_t deadline() const { return deadline_; }
  // A subsequent CREATE cannot downgrade a lease, promote during a break, or
  // grant capabilities not confirmed by the underlying object store.
  bool promote(unsigned requested, unsigned available);
  void recall(unsigned target);
  // Called only after the exact notification was successfully transmitted.
  // Times and durations use monotonic milliseconds, not wall-clock expiry.
  // A stale completion cannot consume a later notification.
  void sent(uint64_t serial, int64_t time, int64_t timeout);
  // Returns an NTSTATUS; invalid ACKs do not modify state or the deadline.
  // An ACK can overtake the asynchronous send completion on another transport.
  uint32_t acknowledge(unsigned state);
  bool timed_out(int64_t time) const;
  // A delivered RH -> NONE notification already invalidated all data. Its
  // HANDLE ACK timeout can complete to NONE without fencing usable opens.
  bool expire_read_invalidation(int64_t time);
  // Call only after the associated opens/transports have been fenced/closed.
  void fence();
  bytes response() const;
  bytes acknowledgment_response() const;
private:
  bytes key_, parent_;
  unsigned version_, state_ = 0, target_ = 0, notified_target_ = 0;
  uint16_t epoch_;
  bool breaking_ = false;
  uint64_t serial_ = 0;
  int64_t deadline_ = 0;
  std::optional<lease_break> pending_;
  void start_break(unsigned next);
};
// The integrating service must serialize all registry/state access. Names are canonical,
// namespace-qualified identities, never just the basename of a wire path.
// Attach only after a successful open, detach only after closing/fencing it.
class lease_registry {
public:
  using identity = std::pair<bytes, bytes>; // ClientGuid, LeaseKey
  struct entry {
    std::string filename;
    bool delete_on_close = false;
    std::shared_ptr<lease_state> state;
    std::set<std::string> opens;
  };
  explicit lease_registry(size_t limit = 4096) : limit_(limit) {}
  const entry *find(std::string_view client, std::string_view key) const;
  void validate(std::string_view client, const lease_request &, const std::string &filename) const;
  std::shared_ptr<lease_state> attach(const bytes &client, const lease_request &,
      const std::string &filename, const std::string &open, bool delete_on_close = false);
  void detach(const std::string &open);
  void rename(const bytes &client, const bytes &key, const std::string &filename);
  size_t size() const { return entries_.size(); }
private:
  size_t limit_;
  std::map<identity, entry> entries_;
  std::map<std::string, identity> opens_;
};
} // namespace tc::smb_detail
