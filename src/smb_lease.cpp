#include <taucloud/smb_lease.hpp>
#include <limits>

namespace tc::smb_detail {
namespace {
bool valid_state(unsigned state) {
  return state == 0 || state == 1 || state == 3 || state == 5 || state == 7;
}
}
lease_request lease_request::decode(std::string_view data) {
  require(data.size() == 32 || data.size() == 52, "invalid_packet");
  lease_request result;
  result.key = bytes(data.substr(0, 16));
  result.state = unsigned(get(data, 16, 4));
  require((result.state & ~7u) == 0, "invalid_packet");
  // Reserved flags, duration and v2 Reserved are ignored on receipt.
  if (data.size() == 52) {
    result.version = 2;
    if (get(data, 20, 4) & 4) result.parent = bytes(data.substr(32, 16));
    result.epoch = uint16_t(get(data, 48, 2));
  }
  return result;
}
lease_state::lease_state(const lease_request &r)
    : key_(r.key), parent_(r.parent), version_(r.version), epoch_(r.version == 2 ? r.epoch : 0) {
  require(key_.size() == 16 && (version_ == 1 || version_ == 2) &&
              (parent_.empty() || (version_ == 2 && parent_.size() == 16)), "invalid_packet");
}
bool lease_state::promote(unsigned requested, unsigned available) {
  require((requested & ~7u) == 0 && valid_state(available), "invalid_request");
  if (unsettled() || (requested & state_) != state_) return false;
  auto next = requested & available;
  // Existing leases are promoted only when the complete requested state is
  // available. Partial initial grants must not become partial upgrades.
  if (state_ && next != requested) return false;
  if (!valid_state(next) || (next & state_) != state_ || next == state_) return false;
  state_ = next;
  target_ = next;
  if (version_ == 2) ++epoch_;
  return true;
}
void lease_state::start_break() {
  require(!pending_ && !breaking_ && target_ != state_, "invalid_device_state");
  auto current = state_;
  breaking_ = current != 1;
  notified_target_ = target_;
  if (version_ == 2) ++epoch_;
  pending_ = lease_break{++serial_, current, target_, epoch_, breaking_};
  // R -> NONE needs no ACK. Retain the old state/exclusion until sent().
}
void lease_state::recall(unsigned target) {
  require(valid_state(target) && target != 7, "invalid_request");
  target_ &= target;
  if (unsettled() || state_ == target_) return;
  start_break();
}
void lease_state::sent(uint64_t serial, int64_t time, int64_t timeout) {
  require(time >= 0 && timeout > 0 && time <= std::numeric_limits<int64_t>::max() - timeout,
          "invalid_request");
  if (!pending_ || pending_->serial != serial) return;
  if (!breaking_) state_ = pending_->target;
  pending_.reset();
  if (breaking_) deadline_ = time + timeout;
}
uint32_t lease_state::acknowledge(unsigned state) {
  if (!breaking_) return 0xc0000001; // STATUS_UNSUCCESSFUL
  if ((state & ~notified_target_) != 0) return 0xc00000d0; // REQUEST_NOT_ACCEPTED
  state_ = state;
  breaking_ = false;
  pending_.reset();
  deadline_ = 0;
  target_ &= state;
  // A second conflict may tighten the target while the first ACK is in
  // flight. Complete that ACK and send another break; never silently revoke.
  if (state_ != target_) start_break();
  return 0;
}
bool lease_state::timed_out(int64_t time) const {
  return breaking_ && deadline_ && time >= deadline_;
}
void lease_state::fence() {
  state_ = target_ = notified_target_ = 0;
  breaking_ = false;
  deadline_ = 0;
  pending_.reset();
}
bytes lease_state::response() const {
  bytes result(version_ == 2 ? 52 : 32, '\0');
  result.replace(0, 16, key_);
  // The no-ACK notification already invalidates the client's read lease.
  // Native exclusion is retained until delivery, but a racing CREATE must
  // not re-advertise R at this new epoch after the NONE notification.
  put(result, 16, pending_ && !pending_->acknowledgment ? pending_->target : state_, 4);
  put(result, 20, (breaking_ ? 2u : 0u) | (parent_.empty() ? 0u : 4u), 4);
  if (version_ == 2) {
    if (!parent_.empty()) result.replace(32, 16, parent_);
    put(result, 48, epoch_, 2);
  }
  return result;
}
bytes lease_state::acknowledgment_response() const {
  bytes result(36, '\0');
  put(result, 0, 36, 2);
  result.replace(8, 16, key_);
  put(result, 24, state_, 4);
  return result;
}
bytes lease_break::encode(std::string_view key) const {
  require(key.size() == 16, "invalid_request");
  bytes result(44, '\0');
  put(result, 0, 44, 2);
  put(result, 2, epoch, 2);
  put(result, 4, acknowledgment ? 1 : 0, 4);
  result.replace(8, 16, key);
  put(result, 24, current, 4);
  put(result, 28, target, 4);
  return result;
}
const lease_registry::entry *lease_registry::find(std::string_view client, std::string_view key) const {
  auto it = entries_.find({bytes(client), bytes(key)});
  return it == entries_.end() ? nullptr : &it->second;
}
void lease_registry::validate(std::string_view client, const lease_request &r,
                              const std::string &filename) const {
  require(client.size() == 16 && r.key.size() == 16 && !filename.empty(), "invalid_request");
  auto found = find(client, r.key);
  require(!found || found->delete_on_close || found->filename == filename, "invalid_request");
}
std::shared_ptr<lease_state> lease_registry::attach(const bytes &client, const lease_request &r,
    const std::string &filename, const std::string &open, bool delete_on_close) {
  validate(client, r, filename);
  require(!open.empty() && !opens_.contains(open), "invalid_request");
  require(opens_.size() < limit_, "resource_limit");
  identity id{client, r.key};
  auto it = entries_.find(id);
  bool created = it == entries_.end();
  if (created)
    it = entries_.emplace(id, entry{filename, false, std::make_shared<lease_state>(r), {}}).first;
  auto &e = it->second;
  try {
    e.opens.insert(open);
    opens_.emplace(open, id);
  } catch (...) {
    e.opens.erase(open);
    if (created) entries_.erase(it);
    throw;
  }
  e.delete_on_close |= delete_on_close;
  return e.state;
}
void lease_registry::detach(const std::string &open) {
  auto it = opens_.find(open);
  if (it == opens_.end()) return;
  auto found = entries_.find(it->second);
  auto &e = found->second;
  e.opens.erase(open);
  opens_.erase(it);
  if (e.opens.empty()) {
    e.state->fence();
    entries_.erase(found);
  }
}
void lease_registry::rename(const bytes &client, const bytes &key, const std::string &filename) {
  require(!filename.empty(), "invalid_request");
  auto it = entries_.find({client, key});
  require(it != entries_.end(), "not_found");
  it->second.filename = filename;
}
} // namespace tc::smb_detail
