// NFSv4 delegation protocol state is independent of OPEN and of callback slots.
// The file domain has the final decision on whether native protection is safe
// for wire handout; the current provider declines that request.
auto find_delegation(const std::string &id) {
  return std::find_if(delegations.begin(), delegations.end(), [&](const auto &d) {
    return id.size() == 32 && d.first.substr(8) == id.substr(8);
  });
}
auto delegation_key(const std::string &id, const std::string &sid, const identity &who,
                    const std::string &fh = "", bool allow_revoked = false, uint32_t cleanup = 0) {
  auto it = find_delegation(id);
  check(it != delegations.end(), 10025);
  auto &d = it->second;
  check(d.client == sessions.at(sid).client && (fh.empty() || d.fh == fh), 10025);
  check(d.principal == who.key || machine_cleanup(sid, who, cleanup),
        client_ids.at(d.client).protection ? 10082 : 10025);
  auto seq = uint32_t(std::stoul(id.substr(0, 8), nullptr, 16));
  check(!seq || seq == 1, 10025);
  if (!allow_revoked) check(!d.revoked, d.revoked);
  return it;
}
json delegation_control(delegation_state &d, const std::string &op, int64_t remaining = 0) {
  json body = {{"op", op}, {"grant", d.grant}, {"cookie", d.cookie},
      {"handle", d.fh}, {"client", std::to_string(d.client)}};
  if (remaining) body["remaining_ms"] = remaining;
  return call(d.worker, "nfs_delegation", body);
}
void delegation_snapshot(delegation_state &d, const json &snapshot) {
  auto state = snapshot.at("state").get<std::string>();
  d.recalling |= state == "recalling";
  if (state == "revoked" || state == "expired" || state == "returned") {
    d.revoked = state == "expired" ? 10011 : 10087;
    remove_recovery(d.recovery);
  }
}
bool delegation_revoked(uint64_t client) const {
  return std::any_of(delegations.begin(), delegations.end(), [&](const auto &d) {
    return d.second.client == client && d.second.revoked != 0;
  });
}
void recall_delegation(delegation_state &d) {
  if (d.revoked) return;
  d.recalling = true;
  try { delegation_snapshot(d, delegation_control(d, "recall")); }
  catch (const error &e) {
    if (std::string_view(e.what()) == "stale_handle") {
      d.revoked = 10087; remove_recovery(d.recovery);
    }
    // Unreachable authority is not proof of release. Keep the state recalled.
  }
}
void retire_delegations(uint64_t client) {
  for (auto it = delegations.begin(); it != delegations.end();) {
    if (it->second.client != client) { ++it; continue; }
    auto &d = it->second;
    try { delegation_control(d, "return"); delegation_control(d, "forget"); }
    catch (const error &) {} // The authority still owns its bounded lease.
    remove_recovery(d.recovery);
    it = delegations.erase(it);
  }
}
void expire_delegations() {
  std::set<uint64_t> expired;
  for (const auto &[id, d] : delegations) {
    auto c = client_ids.find(d.client);
    if (c == client_ids.end() || c->second.expires <= now()) expired.insert(d.client);
  }
  for (auto client : expired) retire_delegations(client);
}
void renew_delegations(uint64_t client) {
  for (auto &[id, d] : delegations) {
    if (d.client != client || d.revoked) continue;
    try {
      auto fresh = authorize({{"peer", "127.0.0.1"}, {"credential", d.credential},
          {"uuid", encode_bytes(decode_bytes(d.fh).substr(2, 16))}, {"write", false}});
      check(grant_scope(fresh) == grant_scope(d.grant), 13);
      d.grant = std::move(fresh);
      auto remaining = client_ids.at(client).expires - now();
      if (remaining <= 0) continue;
      delegation_snapshot(d, delegation_control(d, "renew", remaining));
    } catch (const error &) { recall_delegation(d); }
      catch (const failure &) { recall_delegation(d); }
  }
}
void delegation_callback_completed(const std::string &operation, uint32_t status) {
  if (operation.empty()) return;
  reader r(operation);
  if (r.u32() != 4) return;
  auto state = encode_bytes(r.fixed(16));
  auto it = delegations.find(state);
  if (it == delegations.end()) return;
  // Receipt is never a DELEGRETURN. A definitive DELAY is retried with a new
  // callback sequence; uncertain execution is retried by the session slot.
  it->second.callback_done = status != 10008;
  it->second.retry_after = status == 10008 ? now() + 250 : 0;
}
void maintain_delegations() {
  for (auto &[id, d] : delegations) {
    if (d.revoked) continue;
    try { delegation_snapshot(d, delegation_control(d, "poll")); }
    catch (const error &) { recall_delegation(d); }
    if (!d.recalling || d.revoked || d.callback_done || d.retry_after > now()) continue;
    writer operation;
    operation.u32(4).fixed(decode_bytes(id)).boolean(false).opaque(decode_bytes(d.fh));
    bool queued = std::any_of(sessions.begin(), sessions.end(), [&](const auto &s) {
      return s.second.client == d.client && s.second.callback_extra == operation.data;
    });
    if (queued) continue;
    auto target = std::find_if(sessions.begin(), sessions.end(), [&](const auto &entry) {
      const auto &s = entry.second;
      return s.client == d.client && s.expires > now() && callback_available(s) &&
          !s.callback_up.empty() && !s.callback_unresolved && s.callback_extra.empty() &&
          s.callback_operations >= 2 && callback_fits(s, operation.data.size(), 8);
    });
    if (target == sessions.end() || callback_probes.size() >= 128) continue;
    target->second.callback_extra = operation.data;
    target->second.callback_references.clear();
    sequence_callback(target->first);
  }
}
bool delegation4(writer &body, const identity &who, const std::string &sid,
                 const std::string &fh, const json &metadata, uint32_t access) {
  auto want = access & 0xff00u;
  if (want == 0x400 || want == 0x500 || metadata.at("directory").get<bool>()) return false;
  auto client = sessions.at(sid).client;
  if (!callback_path_up(client) || delegations.size() >= 32) return false;
  const auto object = metadata.at("object").get<std::string>();
  for (const auto &[id, o] : opens)
    if (o.object == object && ((o.access & 2) || (o.deny & 1))) return false;
  for (const auto &[id, lock] : byte_locks)
    if (lock.object == object && !lock.ranges.empty()) return false;
  for (const auto &[id, lock] : nlm_held)
    if (lock.object == object && !lock.ranges.empty()) return false;
  auto emit = [&](const std::string &id, bool recall) {
    body.u32(1).fixed(decode_bytes(id)).boolean(recall)
        .u32(1).u32(0).u32(0x1f01ff).opaque("EVERYONE@");
    // Deny-all delegation ACE requires ACCESS checks for each user; it does
    // not replace the file ACL or confer cached authorization to other users.
  };
  for (auto &[id, d] : delegations) if (d.object == object && !d.revoked) {
    if (d.client != client || d.principal != who.key || d.fh != fh) return false;
    if (want == 0x200) { body.u32(3).u32(5); return true; } // WND4_NOT_SUPP_UPGRADE.
    emit(id, d.recalling); return true;
  }
  if (want == 0x200) return false;
  auto grant = authorize({{"peer", "127.0.0.1"}, {"credential", who.credential},
      {"uuid", encode_bytes(decode_bytes(fh).substr(2, 16))}, {"write", false}});
  auto remaining = client_ids.at(client).expires - now();
  if (remaining <= 0) return false;
  const auto worker = grant.at("root").at("worker").get<std::string>();
  json acquired;
  try {
    acquired = call(worker, "nfs_delegation", {{"op", "acquire"}, {"wire", true},
        {"handle", fh}, {"client", std::to_string(client)}, {"grant", grant}, {"remaining_ms", remaining}});
  } catch (const error &) { return false; }
  if (!acquired.at("granted").get<bool>()) return false;
  auto stateid = encode_bytes(writer().u32(1).fixed(decode_bytes(random_hex(12))).data);
  json recovery = {{"kind", "delegation"}, {"client", client_ids.at(client).owner},
      {"principal", who.key}, {"handle", fh}, {"type", 1}};
  auto rid = digest(recovery.dump());
  delegation_state d{client, fh, object, who.key, acquired.at("cookie"), worker, rid, who.credential, grant};
  try {
    statement q(db, "INSERT OR REPLACE INTO recovery VALUES(?,?)");
    q.bind(1, rid); q.bind(2, recovery.dump()); q.row();
    delegations.emplace(stateid, d);
  } catch (...) {
    try { delegation_control(d, "return"); delegation_control(d, "forget"); } catch (...) {}
    throw;
  }
  emit(stateid, acquired.at("state") == "recalling");
  return true;
}
void delegation_open_conflict(const std::string &object, uint32_t access, uint32_t deny) {
  if (!(access & 2) && !(deny & 1)) return;
  bool conflict = false;
  for (auto &[id, d] : delegations) if (d.object == object && !d.revoked) {
    recall_delegation(d); conflict |= !d.revoked;
  }
  check(!conflict, 10008);
}
