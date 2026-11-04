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
void cache_break(opened &h, unsigned level = 0) {
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
                    const std::string &owner = "", unsigned level = 0) {
  bool pending = false;
  for (auto &[id, h] : handles) {
    if (h.cache && id != owner && h.space == space &&
        (beneath(h.path, path) || beneath(path, h.path))) {
      auto target = level;
      if (target == 1 && h.cache_level == 8 && !locks.empty()) {
        auto native = h.file.info().at("object").get<std::string>();
        if (std::any_of(locks.begin(), locks.end(),
            [&](const auto &held) { return held.object == native; })) target = 0;
      }
      cache_break(h, target);
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
json cache_dispatch(const std::string &op, const json &body, const json &grant, opened &h) {
  require(!h.directory && (h.access & 1), "forbidden");
  if (op == "smb_cache_acquire") {
    auto level = body.value("level", 8u);
    require(level == 1 || level == 8, "invalid_request");
    if (level == 8)
      require(h.writable && (h.access & 3) == 3 && grant.at("write").get<bool>(), "forbidden");
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
        if (held.cache_level != 1 || held.cache_break_until) return cache_snapshot(h);
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
  require(body.at("cookie") == h.cache_cookie, "invalid_request");
  if (h.cache->breaking()) cache_break(h);
  if (op == "smb_cache_poll") {
    cache_renew(h, grant);
    return cache_snapshot(h);
  }
  require(op == "smb_cache_ack" || op == "smb_cache_release", "not_supported");
  require(op != "smb_cache_ack" || h.cache_break_until, "invalid_device_state");
  auto level = op == "smb_cache_ack" ? body.value("level", 0u) : 0u;
  require(level == 0 || (level == 1 && h.cache_level == 8 && h.cache_downgrade_pending),
          "invalid_request");
  // Only EXCLUSIVE can hold dirty client writes. A Level II participant may
  // have a physically read-only handle (FlushFileBuffers requires write access
  // on Windows), and cannot write until all read caches have been invalidated.
  if (h.cache_level == 8) h.file.flush();
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
