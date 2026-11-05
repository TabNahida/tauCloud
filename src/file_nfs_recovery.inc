// The journal contains control capabilities, never client credentials. It is
// private, authenticated, fsynced and excluded from metadata backups.
fs::path nfs_recovery_path() const { return cfg.state / (role + ".nfs-delegations.json"); }
void nfs_checkpoint_delegations() {
#ifdef __linux__
  if (nfs_recovery.is_null()) return;
  require(!nfs_recovery_failed, "delegation_recovery_failed");
  try {
    nfs_recovery["minimum_epoch"] = minimum_epoch;
    for (const auto &[cookie, d] : nfs_delegations) {
      if (!d.owner_backed || !nfs_recovery.at("records").contains(cookie)) continue;
      auto &record = nfs_recovery["records"][cookie];
      record["owner_id"] = d.owner_id;
      record["status"] = static_cast<unsigned>(d.lifetime.status());
      record["recall_deadline_ms"] = d.lifetime.recall_until();
      record["last_reservation"] = d.last_reservation;
    }
    json value = {{"body", nfs_recovery}, {"signature", mac(key, nfs_recovery.dump())}};
    require(value.dump(2).size() < 1024 * 1024 - 1, "operation_limit");
    write_json(nfs_recovery_path(), value);
  } catch (...) {
    nfs_recovery_failed = true;
    throw error("delegation_recovery_failed");
  }
#endif
}
#ifdef __linux__
static std::string nfs_boot_identity() {
  std::ifstream input("/proc/sys/kernel/random/boot_id");
  std::string value; input >> value;
  require(value.size() == 36, "delegation_recovery_failed");
  return value;
}
// Unlike verified_alive(), an observation/permission error is not death proof.
// Never signal this PID; compare birth within the recorded boot or observe a
// terminal/missing task. Capability authentication still controls reconnection.
static bool nfs_owner_gone(const json &saved) {
  auto pid = saved.at("pid").get<int64_t>();
  auto birth = saved.at("birth").get<uint64_t>();
  require(pid > 0 && birth > 0, "delegation_recovery_failed");
  auto path = fs::path("/proc") / std::to_string(pid);
  std::error_code ec;
  auto exists = fs::exists(path, ec);
  require(!ec, "delegation_recovery_failed");
  if (!exists) return true;
  std::ifstream input(path / "stat"); std::string line;
  std::getline(input, line);
  auto end = line.rfind(')');
  if (end == std::string::npos) {
    exists = fs::exists(path, ec);
    require(!ec && !exists, "delegation_recovery_failed");
    return true;
  }
  std::istringstream fields(line.substr(end + 2));
  std::string field, state;
  uint64_t actual = 0;
  for (int i = 3; i <= 22; ++i) {
    require(bool(fields >> field), "delegation_recovery_failed");
    if (i == 3) state = field;
    if (i == 22) actual = std::stoull(field);
  }
  return state == "Z" || state == "X" || actual != birth;
}
void nfs_prepare_owner() {
  require(!nfs_recovery_failed, "delegation_recovery_failed");
  if (!nfs_recovery_lock)
    nfs_recovery_lock = std::make_unique<file_lock>(cfg.state / (role + ".nfs-delegations.lock"));
  if (nfs_recovery.is_null()) {
    require(!fs::exists(nfs_recovery_path()), "delegation_recovery_failed");
    nfs_recovery = {{"version", 1}, {"role", role}, {"boot", nfs_boot_identity()},
        {"minimum_epoch", minimum_epoch}, {"records", json::object()}};
  }
  if (!nfs_owner) {
    nfs_owner = std::make_unique<native_delegation_owner>();
    nfs_recovery["capability"] = nfs_owner->recovery_capability();
    nfs_recovery["process"] = process_info(nfs_owner->process_id());
    nfs_recovery["boot"] = nfs_boot_identity();
    nfs_checkpoint_delegations(); // Durable endpoint before any acquisition.
  }
}
#endif
void nfs_restore_delegations() {
  if (!fs::exists(nfs_recovery_path())) return;
#ifdef __linux__
  nfs_recovery_lock = std::make_unique<file_lock>(cfg.state / (role + ".nfs-delegations.lock"));
  auto status = fs::symlink_status(nfs_recovery_path());
  require(fs::is_regular_file(status) &&
      (status.permissions() & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none,
      "delegation_recovery_failed");
  auto envelope = read_json(nfs_recovery_path());
  auto saved = envelope.at("body");
  require(equal(envelope.at("signature").get<std::string>(), mac(key, saved.dump())) &&
      saved.at("version") == 1 && saved.at("role") == role &&
      saved.at("records").is_object() && saved.at("records").size() <= 256, "delegation_recovery_failed");
  minimum_epoch = std::max(minimum_epoch, saved.at("minimum_epoch").get<int64_t>());
  bool pending = false;
  for (const auto &[cookie, record] : saved.at("records").items()) {
    require(cookie.size() == 32 && record.at("period_ms").get<int64_t>() >= 5000 &&
        record.at("period_ms").get<int64_t>() <= 3600000 && record.at("status").get<unsigned>() <= 4,
        "delegation_recovery_failed");
    pending |= record.at("owner_id").get<uint64_t>() != 0 || record.at("intent").get<bool>();
  }
  std::unique_ptr<native_delegation_owner> owner;
  json inventory = json::array();
  bool gone = saved.at("boot") != nfs_boot_identity();
  if (pending && !gone) {
    gone = nfs_owner_gone(saved.at("process"));
    if (!gone) {
      auto until = cache_clock() + 1500;
      for (;;) {
        try { owner = std::make_unique<native_delegation_owner>(saved.at("capability")); break; }
        catch (const error &e) {
          if ((gone = nfs_owner_gone(saved.at("process")))) break;
          auto code = std::string_view(e.what());
          require(cache_clock() < until && (code == "forbidden" || code == "delegation_owner_unavailable" ||
              code == "delegation_owner_lost" || code == "stale_handle"), "delegation_recovery_failed");
          std::this_thread::sleep_for(10ms);
        }
      }
      if (owner) inventory = owner->inventory();
    }
  }
  std::map<std::string, nfs_delegation_guard> restored;
  std::set<uint64_t> matched;
  std::vector<std::string> abandoned;
  for (auto &[cookie, record] : saved["records"].items()) {
    auto id = record.at("owner_id").get<uint64_t>();
    auto token = record.at("token").get<std::string>();
    json observed;
    for (const auto &candidate : inventory) {
      if (id ? candidate.at("id") != id : !record.at("intent").get<bool>() ||
          candidate.at("identity_sha256") != digest(token)) continue;
      require(observed.is_null() && candidate.at("identity_sha256") == digest(token) &&
          !matched.contains(candidate.at("id").get<uint64_t>()), "delegation_recovery_failed");
      observed = candidate;
    }
    if (observed.is_null() && record.at("intent").get<bool>()) { abandoned.push_back(cookie); continue; }
    using state = nfs_detail::delegation_lifetime::state;
    auto prior = static_cast<state>(record.at("status").get<unsigned>());
    nfs_detail::delegation_lifetime lifetime(0, record.at("period_ms"), 0, true);
    native_file file;
    bool recalling = false;
    if (!observed.is_null()) {
      id = observed.at("id"); matched.insert(id);
      if (prior == state::returned || prior == state::revoked || prior == state::expired) {
        owner->release(id); observed = nullptr;
      } else {
        auto cutoff = record.at("recall_deadline_ms").get<int64_t>();
        if (cutoff) observed = owner->recall(id, cutoff);
        if (observed.at("held").get<bool>()) {
          try { file = owner->restore(id, token); }
          catch (const error &e) {
            if (std::string_view(e.what()) != "stale_handle") throw;
            observed = owner->inspect(id);
            require(!observed.at("held").get<bool>(), "delegation_recovery_failed");
          }
        }
      }
    }
    bool live = !observed.is_null() && observed.at("held").get<bool>();
    if (live) {
      lifetime.synchronize_owner(observed.at("lease_expires_ms"), observed.at("recall_deadline_ms"), observed.at("reservations"));
      recalling = observed.at("recall_deadline_ms").get<int64_t>() != 0;
    } else {
      id = 0;
      lifetime.observe_terminal(prior >= state::returned ? prior : gone ? state::revoked : state::expired);
    }
    restored.emplace(cookie, nfs_delegation_guard{record.at("actor"), record.at("space"), record.at("path"),
        record.at("root"), token, record.at("handle"), record.at("export_id"), record.at("client"),
        std::move(file), nullptr, std::move(lifetime), id, true, gone, recalling,
        record.at("last_reservation"), {}, live, record.at("space_object")});
    record["intent"] = false;
  }
  require(matched.size() == inventory.size(), "delegation_recovery_failed");
  for (const auto &cookie : abandoned) saved["records"].erase(cookie);
  nfs_recovery = std::move(saved);
  nfs_owner = std::move(owner);
  nfs_delegations = std::move(restored);
  nfs_checkpoint_delegations();
#else
  throw error("delegation_recovery_unavailable");
#endif
}
