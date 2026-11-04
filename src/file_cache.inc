// File-domain cache authority. Protocol workers receive a cookie, never a
// native handle. Native exclusion ends only after ACK, close or fencing.
static int64_t cache_clock() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}
static bool cache_native_deadline_safe() {
#ifdef __linux__
  // Leave a margin beyond the five-second recall deadline. Never change the
  // host's global setting or infer unlimited time from an unknown value.
  int64_t seconds = 0;
  std::ifstream input("/proc/sys/fs/lease-break-time");
  return bool(input >> seconds) && seconds >= 10;
#else
  return true; // Windows RW waits for an explicit native acknowledgement.
#endif
}
void sync_lease_cache(const std::shared_ptr<lease_cache> &group) {
  auto state = group->state.state();
  if (!group->state.unsettled()) group->break_until = 0;
  if (!state && !group->state.unsettled()) group->guard.reset();
  for (auto &[id, member] : handles) {
    if (member.lease_cache_state != group) continue;
    member.cache = group->guard;
    member.cache_cookie = group->cookie;
    member.cache_level = state & 4 ? 8 : state & 2 ? 9 : state ? 1 : 0;
    member.cache_break_until = group->break_until;
  }
}
void cache_break(opened &h, unsigned level = 0, unsigned lease_target = 0) {
  if (h.lease_cache_state) {
    auto group = h.lease_cache_state;
    group->state.recall(lease_target);
    if (group->state.unsettled() && !group->break_until) group->break_until = cache_clock() + 5000;
    sync_lease_cache(group);
    return;
  }
  if (!h.cache || (level == 1 && h.cache_level == 1)) return;
  if (!h.cache_break_until) {
    h.cache_break_until = cache_clock() + 5000;
    h.cache_break_level = level;
    h.cache_downgrade_pending = level == 1;
  } else if (level == 0) {
    // A write/native conflict can tighten a pending downgrade, never extend it.
    h.cache_break_level = 0;
  }
}
bool native_cache_breaks() {
  bool pending = false;
  for (auto &[id, h] : handles) {
    if (!h.cache) continue;
    if (h.cache->breaking()) { cache_break(h); pending = true; }
  }
  return pending;
}
void cache_conflict(const std::string &space, const std::string &path,
                    const std::string &owner = "", unsigned level = 0,
                    const std::shared_ptr<lease_cache> &lease_owner = {}, unsigned lease_target = 0) {
  bool pending = false;
  for (auto &[id, h] : handles) {
    if (h.cache && id != owner && (!lease_owner || h.lease_cache_state != lease_owner) && h.space == space &&
        (beneath(h.path, path) || beneath(path, h.path))) {
      auto target = level;
      if (target == 1 && (h.cache_level == 8 || h.cache_level == 9) && !locks.empty()) {
        auto native = h.file.info().at("object").get<std::string>();
        if (std::any_of(locks.begin(), locks.end(),
            [&](const auto &held) { return held.object == native; })) target = 0;
      }
      cache_break(h, target, lease_target);
      pending |= h.cache_break_until != 0;
    }
  }
  require(!pending, "cache_break_pending");
}
void maintain_caches() {
  bool any = std::any_of(handles.begin(), handles.end(),
      [](const auto &entry) { return bool(entry.second.cache); });
  if (!any) return;
  auto time = cache_clock();
  bool native_safe = cache_native_deadline_safe();
  for (auto it = handles.begin(); it != handles.end();) {
    auto &h = it->second;
    if (!h.cache) { ++it; continue; }
    bool lost = !native_safe || h.cache_authority_until <= time ||
                (h.cache_break_until && h.cache_break_until <= time);
    if (!lost) {
      try { if (h.cache->breaking()) cache_break(h); }
      catch (...) { lost = true; }
    }
    if (!lost) { ++it; continue; }
    // Fence the complete open before admitting another writer. Merely dropping
    // the native guard would let the old client flush stale cached data later.
    auto id = it->first;
    it = handles.erase(it);
    std::erase_if(locks, [&](const auto &l) { return l.handle == id; });
    std::erase_if(smb_waiters, [&](const auto &w) { return w.range.handle == id; });
    // Existing durable close/deferred-metadata records are reaped by the next
    // ordinary SMB operation or service recovery, using their native identity.
  }
}
json cache_snapshot(const opened &h) const {
  if (h.lease_cache_state) {
    const auto &g = *h.lease_cache_state;
    json value = {{"granted", g.state.state() != 0}, {"cookie", g.cookie},
        {"lease", true}, {"state", g.state.state()}, {"epoch", g.state.epoch()},
        {"context", encode_bytes(g.state.response())},
        {"breaking", g.state.unsettled()}, {"ack_required", g.state.breaking()},
        {"remaining_ms", g.break_until ? std::max<int64_t>(0, g.break_until - cache_clock()) : 0}};
    if (auto &pending = g.state.pending(); pending)
      value["notification"] = {{"serial", pending->serial},
          {"body", encode_bytes(pending->encode(g.state.key()))}};
    return value;
  }
  return {{"granted", bool(h.cache)}, {"cookie", h.cache_cookie},
          {"level", h.cache ? h.cache_level : 0}, {"break_level", h.cache_break_level},
          {"breaking", bool(h.cache_break_until)},
          {"remaining_ms", h.cache_break_until
              ? std::max<int64_t>(0, h.cache_break_until - cache_clock()) : 0}};
}
void cache_renew(opened &h, const json &grant) {
  auto remaining = grant.at("expires").get<int64_t>() - now();
  require(remaining > 0 && remaining <= 2500, "lease_expired");
  h.cache_authority_until = cache_clock() + remaining;
}
json lease_cache_dispatch(const std::string &op, const json &body, const json &grant, opened &h) {
  auto group = h.lease_cache_state;
  require(bool(group) && !h.directory && h.access != 0, "forbidden");
  if (group->guard && group->guard->breaking()) cache_break(h);
  if (op == "smb_cache_acquire") {
    auto requested = body.at("state").get<unsigned>();
    require((requested & ~7u) == 0, "invalid_request");
    auto available = requested;
    if (!(h.access & 1)) available = 0;
    if (!h.writable || !grant.at("write").get<bool>()) available &= ~4u;
    std::shared_ptr<native_cache_guard> guard = group->guard;
    for (const auto &[id, other] : handles) {
      if (other.space != h.space || other.path != h.path || other.lease_cache_state == group) continue;
      if (other.protocol != "smb" || (other.access & 0x27)) available &= ~4u;
      if (!other.cache) continue;
      bool compatible = other.lease_cache_state
          ? !(other.lease_cache_state->state.state() & 4) && !other.lease_cache_state->state.unsettled()
          : other.cache_level == 1 && !other.cache_break_until;
      if (!compatible) return cache_snapshot(h);
      require(other.file.info().at("object") == group->native, "object_replaced");
      guard = other.cache;
    }
    for (const auto &l : locks) {
      auto holder = handles.find(l.handle);
      if (l.object == group->native &&
          (holder == handles.end() || holder->second.lease_cache_state != group)) available = 0;
    }
    // The protocol state may only be promoted after proving native exclusion.
    // Keep all existing capabilities when a later CREATE requests fewer bits.
    if (available && !group->state.unsettled() && cache_native_deadline_safe()) {
      if (!guard) guard = h.file.cache_guard(true);
      if (guard) {
        cache_renew(h, grant);
        if (group->state.promote(requested, available)) group->guard = std::move(guard);
      }
    }
    cache_renew(h, grant);
    sync_lease_cache(group);
    return cache_snapshot(h);
  }
  require(body.at("cookie") == group->cookie, "invalid_request");
  cache_renew(h, grant);
  if (op == "smb_cache_poll") return cache_snapshot(h);
  if (op == "smb_cache_sent") {
    group->state.sent(body.at("serial"), cache_clock(), 5000);
    sync_lease_cache(group);
    return cache_snapshot(h);
  }
  require(op == "smb_cache_ack", "not_supported");
  // An ACK can arrive on a read-only open while another member has flushed
  // dirty data. Flush every writable native member before releasing exclusion.
  auto before = group->state;
  auto status = before.acknowledge(body.at("state"));
  if (status) { auto result = cache_snapshot(h); result["status"] = status; return result; }
  if (group->state.state() & 4)
    for (auto &[id, member] : handles)
      if (member.lease_cache_state == group && member.file.writable()) member.file.flush();
  group->state = std::move(before);
  sync_lease_cache(group);
  auto result = cache_snapshot(h);
  result["status"] = 0;
  result["response"] = encode_bytes(group->state.acknowledgment_response());
  return result;
}
json cache_dispatch(const std::string &op, const json &body, const json &grant, opened &h) {
  if (h.lease_cache_state) return lease_cache_dispatch(op, body, grant, h);
  require(!h.directory && h.access != 0, "forbidden");
  if (op == "smb_cache_acquire") {
    auto level = body.value("level", 8u);
    require(level == 1 || level == 8 || level == 9, "invalid_request");
    if (level == 8)
      require(h.writable && (h.access & 3) == 3 && grant.at("write").get<bool>(), "forbidden");
    if (level == 9 && h.writable) require(grant.at("write").get<bool>(), "forbidden");
    if (!h.cache && cache_native_deadline_safe()) {
      auto cookie = random_hex(16);
      std::shared_ptr<native_cache_guard> guard;
      for (const auto &[id, held] : handles) {
        if (&held == &h || held.space != h.space || held.path != h.path) continue;
        // Retained descriptors can represent several protocol opens without
        // adding a kernel open. They still rule out exclusive network caching.
        if (held.protocol != "smb" || (held.access & 0x27)) level = 1;
        if (!held.cache) continue;
        // Joining read caching never upgrades another holder's authority and
        // cannot join a group whose invalidation is already in progress.
        bool shared = held.lease_cache_state
            ? !(held.lease_cache_state->state.state() & 4) && !held.lease_cache_state->state.unsettled()
            : held.cache_level == 1 && !held.cache_break_until;
        if (!shared) return cache_snapshot(h);
        require(held.file.info().at("object") == h.file.info().at("object"), "object_replaced");
        guard = held.cache;
        level = 1;
      }
      if (level == 1 && !locks.empty()) {
        auto native = h.file.info().at("object").get<std::string>();
        if (std::any_of(locks.begin(), locks.end(),
            [&](const auto &held) { return held.object == native; })) return cache_snapshot(h);
      }
      if (!guard) guard = h.file.cache_guard(true);
      if (guard) {
        cache_renew(h, grant);
        h.cache_cookie = std::move(cookie);
        h.cache = std::move(guard);
        h.cache_level = level;
        h.cache_break_level = 0;
        h.cache_downgrade_pending = false;
        h.cache_break_until = 0;
      }
    }
    if (h.cache) cache_renew(h, grant);
    return cache_snapshot(h);
  }
  require(h.cache != nullptr, "invalid_device_state");
  if (h.cache_level == 8)
    require(h.writable && (h.access & 3) == 3 && grant.at("write").get<bool>(), "forbidden");
  if (h.cache_level == 9 && h.writable) require(grant.at("write").get<bool>(), "forbidden");
  require(body.at("cookie") == h.cache_cookie, "invalid_request");
  if (h.cache->breaking()) cache_break(h);
  if (op == "smb_cache_poll") {
    cache_renew(h, grant);
    return cache_snapshot(h);
  }
  require(op == "smb_cache_ack" || op == "smb_cache_release", "not_supported");
  require(op != "smb_cache_ack" || h.cache_break_until, "invalid_device_state");
  auto level = op == "smb_cache_ack" ? body.value("level", 0u) : 0u;
  require(level == 0 || (level == 1 && (h.cache_level == 8 || h.cache_level == 9) && h.cache_downgrade_pending),
          "invalid_request");
  // Writable EXCLUSIVE/BATCH holders can have dirty client writes. Level II
  // and read-only BATCH opens cannot; FlushFileBuffers would require write
  // access on their physical Windows handles.
  if ((h.cache_level == 8 || h.cache_level == 9) && h.writable) h.file.flush();
  if (level == 1) {
    h.cache_level = 1;
    h.cache_downgrade_pending = false;
    // A native writer or mutation may have tightened the recall after an II
    // notification was sent. Accept that valid ACK, but keep the NONE recall
    // and its original deadline until the subsequent no-ACK break is sent.
    if (h.cache_break_level == 1) {
      h.cache_break_until = 0;
      h.cache_break_level = 0;
    }
    cache_renew(h, grant);
    return cache_snapshot(h);
  }
  // Each holder has an independent authority/deadline. Closing or expiring
  // one holder must not release native exclusion protecting other readers.
  if (h.cache.use_count() == 1) h.cache->release();
  h.cache.reset(); h.cache_cookie.clear();
  h.cache_level = h.cache_break_level = 0;
  h.cache_downgrade_pending = false;
  h.cache_authority_until = h.cache_break_until = 0;
  return cache_snapshot(h);
}
