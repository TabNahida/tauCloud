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
void cache_break(opened &h) {
  if (h.cache && !h.cache_break_until) h.cache_break_until = cache_clock() + 5000;
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
                    const std::string &owner = "") {
  bool pending = false;
  for (auto &[id, h] : handles) {
    if (h.cache && id != owner && h.space == space &&
        (beneath(h.path, path) || beneath(path, h.path))) {
      cache_break(h);
      pending = true;
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
  require(!h.directory && h.writable && (h.access & 3) == 3 && grant.at("write").get<bool>(),
          "forbidden");
  if (op == "smb_cache_acquire") {
    if (!h.cache && cache_native_deadline_safe()) {
      auto cookie = random_hex(16);
      auto guard = h.file.cache_guard(true);
      if (guard) {
        cache_renew(h, grant);
        h.cache_cookie = std::move(cookie);
        h.cache = std::move(guard);
        h.cache_break_until = 0;
      }
    }
    if (h.cache) cache_renew(h, grant);
    return cache_snapshot(h);
  }
  require(h.cache != nullptr, "invalid_device_state");
  require(body.at("cookie") == h.cache_cookie, "invalid_request");
  if (h.cache->breaking()) cache_break(h);
  if (op == "smb_cache_poll") {
    cache_renew(h, grant);
    return cache_snapshot(h);
  }
  require(op == "smb_cache_ack" || op == "smb_cache_release", "not_supported");
  require(op != "smb_cache_ack" || h.cache_break_until, "invalid_device_state");
  h.file.flush();
  h.cache->release();
  h.cache.reset(); h.cache_cookie.clear();
  h.cache_authority_until = h.cache_break_until = 0;
  return cache_snapshot(h);
}
