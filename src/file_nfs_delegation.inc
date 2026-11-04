// Private file-domain primitive, not yet advertised as a wire delegation.
// Network stateids/callbacks and crash-safe recovery must precede handout.
bool nfs_delegation_native_safe() const {
#ifdef __linux__
  int64_t seconds = 0;
  std::ifstream input("/proc/sys/fs/lease-break-time");
  // Reserve time for detection/maintenance before kernel-forced release.
  return bool(input >> seconds) && seconds >= int64_t(cfg.nfs_lease_seconds) + 5;
#elif defined(_WIN32)
  return true; // Native RW waits for explicit acknowledgment.
#else
  return false;
#endif
}
void maintain_nfs_delegations() {
  auto time = cache_clock();
  for (auto &[cookie, d] : nfs_delegations) {
    if (!d.guard) continue;
    try { if (d.guard->breaking()) d.lifetime.recall(time); }
    catch (...) { d.lifetime.recall(time); }
    d.lifetime.expire(time);
    if (!d.lifetime.held()) {
      d.guard.reset();
      d.file = native_file();
    }
  }
}
void nfs_delegation_conflict(const std::string &space, const std::string &path) {
  bool pending = false;
  for (auto &[cookie, d] : nfs_delegations) {
    if (!d.lifetime.held() || d.space != space ||
        !(beneath(d.path, path) || beneath(path, d.path))) continue;
    d.lifetime.recall(cache_clock());
    pending |= d.lifetime.held();
  }
  require(!pending, "cache_break_pending");
}
json nfs_delegation_snapshot(const std::string &cookie, const nfs_delegation_guard &d) const {
  using state = nfs_detail::delegation_lifetime::state;
  const char *status = "active";
  switch (d.lifetime.status()) {
  case state::active: break;
  case state::recalling: status = "recalling"; break;
  case state::returned: status = "returned"; break;
  case state::revoked: status = "revoked"; break;
  case state::expired: status = "expired"; break;
  }
  auto time = cache_clock();
  return {{"cookie", cookie}, {"granted", d.lifetime.held()}, {"state", status},
      {"lease_remaining_ms", std::max<int64_t>(0, d.lifetime.expires() - time)},
      {"recall_remaining_ms", d.lifetime.recall_until()
          ? std::max<int64_t>(0, d.lifetime.recall_until() - time) : 0}};
}
json nfs_delegation_dispatch(const json &body, const call_context &ctx) {
  require(ctx.caller == "nfs", "forbidden");
  auto op = body.at("op").get<std::string>();
  require(op == "acquire" || op == "renew" || op == "poll" || op == "recall" ||
              op == "return" || op == "forget", "not_supported");
  // Poll/return/forget carry a signed original grant and an unguessable cookie.
  // They cannot read file data, create state or renew the client lease. Cleanup
  // remains possible after policy revocation and short-lived grant expiry.
  auto g = verify(body.at("grant"), false, op != "acquire" && op != "renew");
  require(g.at("protocol") == "nfs" && g.contains("export"), "forbidden");
  auto space = g.at("space").at("id").get<std::string>();
  auto client = body.at("client").get<std::string>();
  require(!client.empty() && client.size() <= 128, "invalid_request");
  auto remaining = [&] {
    require(body.at("remaining_ms").is_number_integer(), "invalid_request");
    auto value = body.at("remaining_ms").get<int64_t>();
    require(value > 0 && value <= int64_t(cfg.nfs_lease_seconds) * 1000, "invalid_request");
    return value;
  };
  if (op == "acquire") {
    auto interval = remaining();
    // F_SETLEASE does not interpose every host metadata/namespace mutation;
    // this worker also cannot retain its native guard after process death.
    // The wire coordinator must not publish state until the file authority
    // can guarantee those properties. Direct component tests exercise the
    // primitive separately; no configuration switch bypasses this gate.
    if (body.value("wire", false)) return {{"granted", false}};
    auto &s = attach(g, ctx);
    nfs_init();
    auto handle = body.at("handle").get<std::string>();
    auto o = nfs_resolve(s, g, handle, false, ctx);
    auto info = o.file.info();
    require(!info.at("directory").get<bool>() && !o.unlinked, "not_supported");
    security_check(s, g, info, 1);
    lease(g, ctx);
    auto token = o.file.stable_identity();
    for (const auto &[cookie, d] : nfs_delegations) {
      if (!d.lifetime.held() || d.token != token) continue;
      // Retrying an acquisition after a lost IPC reply must recover the same
      // cookie, without creating another guard or extending its lease.
      if (d.actor == g.at("actor").get<std::string>() && d.client == client && d.handle == handle &&
          d.export_id == g.at("export").at("uuid").get<std::string>())
        return nfs_delegation_snapshot(cookie, d);
      return {{"granted", false}};
    }
    if (nfs_delegations.size() >= 256 || !nfs_delegation_native_safe()) return {{"granted", false}};
    // Refuse existing opens/locks, including read-only ones: the primitive
    // currently obtains exclusive native data protection on both platforms.
    for (const auto &[id, h] : handles)
      if (h.file.info().at("object") == info.at("object")) return {{"granted", false}};
    range_unlocked("", info.at("object"), 0, UINT64_MAX);
    auto guard = o.file.cache_guard(true);
    if (!guard) return {{"granted", false}};
    lease(g, ctx);
    auto cookie = random_hex(16);
    auto [it, inserted] = nfs_delegations.emplace(cookie, nfs_delegation_guard{
        g.at("actor"), space, o.path, g.at("root").dump(), token, handle,
        g.at("export").at("uuid"), client, std::move(o.file), std::move(guard),
        nfs_detail::delegation_lifetime(cache_clock(), int64_t(cfg.nfs_lease_seconds) * 1000, interval)});
    require(inserted, "operation_limit");
    return nfs_delegation_snapshot(cookie, it->second);
  }
  auto cookie = body.at("cookie").get<std::string>();
  auto it = nfs_delegations.find(cookie);
  require(it != nfs_delegations.end(), "stale_handle");
  auto &d = it->second;
  require(d.actor == g.at("actor").get<std::string>() && d.space == space && d.root == g.at("root").dump() &&
              d.client == client && d.export_id == g.at("export").at("uuid").get<std::string>() &&
              d.handle == body.at("handle").get<std::string>() &&
              beneath(d.path, g.at("path").get<std::string>()), "forbidden");
  auto time = cache_clock();
  if (op == "renew") {
    auto interval = remaining();
    require(d.lifetime.held(), "stale_handle");
    auto &s = attach(g, ctx);
    security_check(s, g, d.file.info(), 1);
    lease(g, ctx);
    require(d.lifetime.renew(cache_clock(), interval), "stale_handle");
  } else if (op == "recall") d.lifetime.recall(time);
  else if (op == "return") d.lifetime.returned(time);
  else if (op == "forget") require(!d.lifetime.held(), "locked");
  maintain_nfs_delegations();
  auto result = nfs_delegation_snapshot(cookie, d);
  if (op == "forget") nfs_delegations.erase(it);
  return result;
}
