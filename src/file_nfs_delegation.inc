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
    if (d.owner_id) {
      bool observed_terminal = false;
      try {
        if (!d.owner_failed) {
          auto observed = nfs_owner->inspect(d.owner_id);
          auto state = observed.at("state").get<std::string>();
          using status = nfs_detail::delegation_lifetime::state;
          if (state == "recalling") d.lifetime.recall(time);
          else if (state == "expired" || state == "revoked") {
            d.lifetime.observe_terminal(state == "expired" ? status::expired : status::revoked);
            observed_terminal = true;
          }
          if (d.lifetime.status() == status::recalling && !d.owner_recalled) {
            nfs_owner->recall(d.owner_id); d.owner_recalled = true;
          }
        }
      } catch (const error &) { d.owner_failed = true; d.lifetime.recall(time); }
      d.lifetime.expire(cache_clock());
      if (!d.lifetime.held()) {
        bool released = observed_terminal;
        try { nfs_owner->release(d.owner_id); released = true; }
        catch (const error &) { d.owner_failed = true; }
        if (released) { d.owner_id = 0; d.file = native_file(); }
      }
      continue;
    }
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
  return {{"cookie", cookie}, {"granted", d.lifetime.held() && !d.owner_failed}, {"state", status},
      {"provider", d.owner_backed ? "independent-owner" : "local-primitive"},
      {"owner_available", d.owner_backed && !d.owner_failed},
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
    // The independent owner protects supported Linux native incarnations
    // across file-worker death. Worker replacement, acknowledged network
    // renewal, durable reclaim and whole-server recovery still need proof.
    // No configuration switch bypasses those production wire requirements.
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
    // Conservatively refuse existing domain opens/locks. Retained writable
    // pins and the legacy fallback require exclusive native protection.
    for (const auto &[id, h] : handles)
      if (h.file.info().at("object") == info.at("object")) return {{"granted", false}};
    range_unlocked("", info.at("object"), 0, UINT64_MAX);
    uint64_t owner_id = 0;
    auto accepted = cache_clock();
#ifdef __linux__
    if (!nfs_owner) nfs_owner = std::make_unique<native_delegation_owner>();
    owner_id = nfs_owner->acquire(o.file, int64_t(cfg.nfs_lease_seconds) * 1000, interval, o.file.writable());
#endif
    // Legacy primitives remain private component fallbacks only. An uncertain
    // owner call throws above: it must never trigger a second acquisition.
    auto guard = owner_id ? nullptr : o.file.cache_guard(true);
    if (!owner_id && !guard) return {{"granted", false}};
    std::string cookie;
    bool registered = false;
    try {
      lease(g, ctx);
      cookie = random_hex(16);
      auto [it, inserted] = nfs_delegations.emplace(cookie, nfs_delegation_guard{
          g.at("actor"), space, o.path, g.at("root").dump(), token, handle,
          g.at("export").at("uuid"), client, std::move(o.file), std::move(guard),
          nfs_detail::delegation_lifetime(accepted, int64_t(cfg.nfs_lease_seconds) * 1000, interval),
          owner_id, owner_id != 0});
      require(inserted, "operation_limit");
      registered = true;
      maintain_nfs_delegations();
      return nfs_delegation_snapshot(cookie, it->second);
    } catch (...) {
      if (registered) nfs_delegations.erase(cookie);
      if (owner_id) { try { nfs_owner->release(owner_id); } catch (...) {} }
      throw;
    }
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
    auto accepted = cache_clock();
    if (d.owner_id) {
      require(!d.owner_failed, "delegation_owner_lost");
      try {
        nfs_owner->renew(d.owner_id, interval);
        lease(g, ctx);
      } catch (const error &e) {
        d.owner_failed |= std::string_view(e.what()) == "delegation_owner_lost";
        d.lifetime.recall(accepted);
        throw;
      }
    }
    require(d.lifetime.renew(accepted, interval), "stale_handle");
  } else if (op == "recall") d.lifetime.recall(time);
  else if (op == "return") d.lifetime.returned(time);
  else if (op == "forget") require(!d.lifetime.held(), "locked");
  maintain_nfs_delegations();
  auto result = nfs_delegation_snapshot(cookie, d);
  if (op == "forget") {
    require(!d.owner_id, "delegation_owner_lost");
    nfs_delegations.erase(it);
  }
  return result;
}
