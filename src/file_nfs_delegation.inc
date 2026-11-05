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
bool nfs_delegation_owner_snapshot(nfs_delegation_guard &d, const json &observed) {
  auto state = observed.at("state").get<std::string>();
  using status = nfs_detail::delegation_lifetime::state;
  d.lifetime.synchronize_owner(observed.at("lease_expires_ms"), observed.at("recall_deadline_ms"),
      observed.at("reservations"));
  bool terminal = state == "expired" || state == "revoked" || state == "returned";
  if (terminal) d.lifetime.observe_terminal(state == "expired" ? status::expired :
      state == "returned" ? status::returned : status::revoked);
  return terminal;
}
void maintain_nfs_delegations() {
  require(!nfs_recovery_failed, "delegation_recovery_failed");
  auto time = cache_clock();
  for (auto &[cookie, d] : nfs_delegations) {
    if (d.owner_id) {
      bool observed_terminal = false;
      try {
        if (!d.owner_failed) {
          auto observed = nfs_owner->inspect(d.owner_id);
          observed_terminal = nfs_delegation_owner_snapshot(d, observed);
          using status = nfs_detail::delegation_lifetime::state;
          if (d.lifetime.status() == status::recalling && !d.owner_recalled) {
            nfs_checkpoint_delegations();
            auto confirmed = nfs_owner->recall(d.owner_id, d.lifetime.recall_until());
            observed_terminal = nfs_delegation_owner_snapshot(d, confirmed);
            d.owner_recalled = true;
          }
        }
      } catch (const error &) {
        if (nfs_recovery_failed) throw;
        d.owner_failed = true; d.lifetime.recall(time);
        nfs_checkpoint_delegations();
      }
      if (d.owner_failed) d.lifetime.owner_lost(cache_clock());
      d.lifetime.expire(cache_clock());
      if (!d.lifetime.held()) {
        nfs_checkpoint_delegations(); // Return/revocation intent before release.
        bool released = observed_terminal;
        try { nfs_owner->release(d.owner_id); released = true; }
        catch (const error &) { d.owner_failed = true; }
        if (released) {
          d.owner_id = 0; d.file = native_file(); d.reservations.clear();
          d.recovered = false;
          while (d.lifetime.reservations()) d.lifetime.complete(cache_clock(), false);
        }
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
  if (pending) nfs_checkpoint_delegations();
  require(!pending, "cache_break_pending");
}
json nfs_delegation_snapshot(const std::string &cookie, const nfs_delegation_guard &d) const {
  using state = nfs_detail::delegation_lifetime::state;
  auto time = cache_clock();
  auto lifetime = d.lifetime;
  lifetime.expire(time);
  const char *status = "active";
  switch (lifetime.status()) {
  case state::active: break;
  case state::recalling: status = "recalling"; break;
  case state::returned: status = "returned"; break;
  case state::revoked: status = "revoked"; break;
  case state::expired: status = "expired"; break;
  }
  return {{"cookie", cookie}, {"granted", lifetime.held() && !d.owner_failed && !d.recovered}, {"state", status},
      {"requires_revalidation", d.recovered},
      {"provider", d.owner_backed ? "independent-owner" : "local-primitive"},
      {"owner_available", d.owner_backed && !d.owner_failed},
      {"reservations", lifetime.reservations()},
      {"lease_expires_ms", lifetime.expires()}, {"recall_deadline_ms", lifetime.recall_until()},
      {"protected_until_ms", d.owner_failed ? 0 : lifetime.protected_until()},
      {"lease_remaining_ms", std::max<int64_t>(0, lifetime.expires() - time)},
      {"recall_remaining_ms", lifetime.recall_until()
          ? std::max<int64_t>(0, lifetime.recall_until() - time) : 0}};
}
json nfs_delegation_dispatch(const json &body, const call_context &ctx) {
  require(ctx.caller == "nfs", "forbidden");
  auto op = body.at("op").get<std::string>();
  require(op == "acquire" || op == "renew" || op == "retain" || op == "poll" || op == "recall" ||
              op == "return" || op == "forget" || op == "reserve" || op == "complete" ||
              op == "cancel" || op == "channel", "not_supported");
  // Cleanup operations carry a signed original grant and unguessable cookie.
  // Reservations retain an existing guard; they never grant file-data access.
  // Retain extends coherence protection while starting a fixed recall interval.
  // Cleanup remains possible after policy revocation and short-lived grant expiry.
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
    auto cookie = random_hex(16);
    auto accepted = cache_clock();
#ifdef __linux__
    nfs_prepare_owner();
    require(!nfs_recovery.at("records").contains(cookie), "operation_limit");
    nfs_recovery["records"][cookie] = {{"actor", g.at("actor")}, {"space", space}, {"path", o.path},
        {"root", g.at("root").dump()}, {"token", token}, {"handle", handle}, {"export_id", g.at("export").at("uuid")},
        {"client", client}, {"space_object", g.at("space").at("object")},
        {"owner_id", 0}, {"intent", true}, {"status", 0}, {"recall_deadline_ms", 0},
        {"period_ms", int64_t(cfg.nfs_lease_seconds) * 1000}, {"last_reservation", 0}};
    nfs_checkpoint_delegations();
    delegation_recovery_boundary(1);
    try { owner_id = nfs_owner->acquire(o.file, int64_t(cfg.nfs_lease_seconds) * 1000, interval, o.file.writable()); }
    catch (...) { nfs_recovery_failed = true; throw; }
    delegation_recovery_boundary(2);
    if (!owner_id) { nfs_recovery["records"].erase(cookie); nfs_checkpoint_delegations(); }
#endif
    // Legacy primitives remain private component fallbacks only. An uncertain
    // owner call throws above: it must never trigger a second acquisition.
    auto guard = owner_id ? nullptr : o.file.cache_guard(true);
    if (!owner_id && !guard) return {{"granted", false}};
    bool registered = false;
    try {
      lease(g, ctx);
      auto [it, inserted] = nfs_delegations.emplace(cookie, nfs_delegation_guard{
          g.at("actor"), space, o.path, g.at("root").dump(), token, handle,
          g.at("export").at("uuid"), client, std::move(o.file), std::move(guard),
          nfs_detail::delegation_lifetime(accepted, int64_t(cfg.nfs_lease_seconds) * 1000, interval, owner_id != 0),
          owner_id, owner_id != 0});
      require(inserted, "operation_limit");
      it->second.space_object = g.at("space").at("object");
      registered = true;
      if (owner_id) {
        nfs_recovery["records"][cookie]["intent"] = false;
        nfs_checkpoint_delegations();
      }
      maintain_nfs_delegations();
      delegation_recovery_boundary(3);
      return nfs_delegation_snapshot(cookie, it->second);
    } catch (...) {
      if (registered) nfs_delegations.erase(cookie);
      if (owner_id) {
        try {
          nfs_owner->release(owner_id);
          nfs_recovery["records"].erase(cookie); nfs_checkpoint_delegations();
        } catch (...) { nfs_recovery_failed = true; }
      }
      throw;
    }
  }
  auto cookie = body.at("cookie").get<std::string>();
  auto it = nfs_delegations.find(cookie);
  require(it != nfs_delegations.end(), "stale_handle");
  auto &d = it->second;
  require(d.actor == g.at("actor").get<std::string>() && d.space == space && d.root == g.at("root").dump() &&
              d.space_object == g.at("space").at("object").get<std::string>() &&
              d.client == client && d.export_id == g.at("export").at("uuid").get<std::string>() &&
              d.handle == body.at("handle").get<std::string>() &&
              beneath(d.path, g.at("path").get<std::string>()), "forbidden");
  auto time = cache_clock();
  uint64_t reservation = 0;
  json channel;
  if (op == "channel") {
    require(d.owner_backed, "not_supported");
    require(d.lifetime.held(), "stale_handle");
    require(!d.recovered, "delegation_revalidation_required");
    require(!d.owner_failed && d.owner_id && nfs_owner, "delegation_owner_lost");
    try { channel = nfs_owner->reservation_capability(d.owner_id); }
    catch (const error &e) {
      d.owner_failed |= std::string_view(e.what()) == "delegation_owner_lost";
      if (d.owner_failed) d.lifetime.owner_lost(cache_clock());
      throw;
    }
  } else if (op == "reserve" || op == "complete" || op == "cancel") {
    require(!d.recovered, "delegation_revalidation_required");
    auto value = body.at("reservation");
    require(value.is_number_unsigned() || (value.is_number_integer() && value.get<int64_t>() > 0),
            "invalid_request");
    reservation = value.get<uint64_t>();
    require(reservation != 0, "invalid_request");
    require(d.owner_backed, "not_supported");
    require(d.lifetime.held(), "stale_handle");
    require(!d.owner_failed && d.owner_id && nfs_owner, "delegation_owner_lost");
    auto found = d.reservations.find(reservation);
    if (op == "reserve" && found != d.reservations.end()) {
      // Retrying a lost file-domain reply recovers the same native token.
      // Neither the lease nor reservation count changes.
    } else if (op == "reserve") {
      require(reservation > d.last_reservation, "stale_handle");
      require(d.reservations.size() < 32, "operation_limit");
      // Allocate bookkeeping before asking the owner. The owner alone decides
      // expiry and shared capacity; independent channels may change both.
      auto [entry, inserted] = d.reservations.emplace(reservation, 0);
      require(inserted, "stale_handle");
      d.last_reservation = reservation;
      nfs_checkpoint_delegations();
      try {
        auto confirmed = nfs_owner->reserve(d.owner_id);
        entry->second = confirmed.at("reservation").get<uint64_t>();
        nfs_delegation_owner_snapshot(d, confirmed);
      } catch (const error &e) {
        d.reservations.erase(entry);
        d.owner_failed |= std::string_view(e.what()) == "delegation_owner_lost";
        if (d.owner_failed) d.lifetime.recall(time);
        throw;
      }
    } else {
      require(found != d.reservations.end(), "stale_handle");
      try {
        auto confirmed = nfs_owner->complete(d.owner_id, found->second, op == "complete");
        d.reservations.erase(found);
        nfs_delegation_owner_snapshot(d, confirmed);
      } catch (const error &e) {
        d.owner_failed |= std::string_view(e.what()) == "delegation_owner_lost";
        if (d.owner_failed) d.lifetime.recall(time);
        throw;
      }
    }
  } else if (op == "renew" || op == "retain") {
    auto interval = remaining();
    require(d.lifetime.held(), "stale_handle");
    if (op == "renew") {
      auto &s = attach(g, ctx);
      security_check(s, g, d.file.info(), 1);
      lease(g, ctx);
    }
    auto accepted = cache_clock();
    if (op == "retain") { d.lifetime.recall(accepted); nfs_checkpoint_delegations(); }
    if (d.owner_id) {
      require(!d.owner_failed, "delegation_owner_lost");
      try {
        if (op == "retain" && !d.owner_recalled) {
          nfs_delegation_owner_snapshot(d, nfs_owner->recall(d.owner_id, d.lifetime.recall_until()));
          d.owner_recalled = true;
        }
        auto confirmed = nfs_owner->renew(d.owner_id, interval);
        // Preserve the acknowledged coherence extension even when the short
        // data grant expires during IPC. That failure cannot authorize IO, but
        // must not discard retention the native owner has already accepted.
        nfs_delegation_owner_snapshot(d, confirmed);
        if (op == "renew") { lease(g, ctx); d.recovered = false; }
      } catch (const error &e) {
        d.owner_failed |= std::string_view(e.what()) == "delegation_owner_lost";
        d.lifetime.recall(accepted);
        nfs_checkpoint_delegations();
        throw;
      }
    } else require(d.lifetime.renew(accepted, interval), "stale_handle");
  } else if (op == "recall") { d.lifetime.recall(time); nfs_checkpoint_delegations(); }
  else if (op == "return") {
    d.lifetime.returned(time); nfs_checkpoint_delegations(); delegation_recovery_boundary(4);
  }
  else if (op == "forget") require(!d.lifetime.held(), "locked");
  maintain_nfs_delegations();
  auto result = nfs_delegation_snapshot(cookie, d);
  if (reservation) result["reservation"] = reservation;
  if (!channel.is_null()) {
    require(d.lifetime.held() && !d.owner_failed, "stale_handle");
    result["reservation_capability"] = std::move(channel);
  }
  if (op == "forget") {
    require(!d.owner_id, "delegation_owner_lost");
    nfs_delegations.erase(it);
    if (!nfs_recovery.is_null()) { nfs_recovery["records"].erase(cookie); nfs_checkpoint_delegations(); }
  }
  return result;
}
