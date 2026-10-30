// NLMv4 is advisory: it coordinates lock requests (including NFSv4 locks),
// never mistakes owner-less NFSv3 READ/WRITE requests for a different owner.
struct nlm_lock {
  identity who;
  std::string caller, handle, owner, object;
  uint32_t svid = 0, state = 0;
  std::vector<lock_range> ranges;
};
struct nlm_waiter {
  nlm_lock lock;
  lock_range range;
  std::string cookie;
  bool reserved = false;
  std::vector<lock_range> previous;
};
std::map<std::string, nlm_lock> nlm_held, nlm_reclaim;
std::map<std::string, nlm_waiter> nlm_waiting;
std::map<std::string, uint32_t> nlm_peers;
uint32_t nsm_state = 1;
int64_t nlm_grace_end = 0;
bool nsm_notify_pending = false;
int64_t nsm_notify_after = 0;
unsigned nsm_notify_attempts = 0;
std::map<std::string, json> nsm_monitors;
std::string nlm_owner(const nlm_lock &l) {
  return digest(json::array({l.who.key, l.caller, l.owner, l.svid}).dump());
}
std::string nlm_key(const nlm_lock &l) { return digest(nlm_owner(l) + l.object); }
std::vector<lock_range> nlm_merge(std::vector<lock_range> ranges) {
  std::sort(ranges.begin(), ranges.end(), [](auto a, auto b) { return a.start < b.start; });
  std::vector<lock_range> result;
  for (auto r : ranges) {
    if (!result.empty() && result.back().type == r.type &&
        (result.back().end == UINT64_MAX || r.start <= result.back().end + 1))
      result.back().end = std::max(result.back().end, r.end);
    else result.push_back(r);
  }
  return result;
}
json nlm_json(const nlm_lock &l) {
  json ranges = json::array();
  for (auto r : l.ranges) ranges.push_back(json::array({r.start, r.end, r.type}));
  return {{"credential", l.who.credential}, {"principal", l.who.key},
      {"caller", l.caller}, {"handle", l.handle}, {"owner", l.owner},
      {"object", l.object}, {"svid", l.svid}, {"state", l.state}, {"ranges", ranges}};
}
nlm_lock nlm_from_json(const json &j) {
  nlm_lock l;
  l.who = {j.at("credential"), j.at("principal")};
  l.caller = j.at("caller"); l.handle = j.at("handle"); l.owner = j.at("owner");
  l.object = j.at("object"); l.svid = j.at("svid"); l.state = j.at("state");
  require(j.at("ranges").size() <= 1024, "invalid_state");
  for (auto r : j.at("ranges")) l.ranges.push_back({r.at(0), r.at(1), r.at(2)});
  return l;
}
void persist_nlm(const std::string &key, const nlm_lock &l) {
  auto snapshot = l;
  if (nlm_reclaim.contains(key))
    for (auto remaining : nlm_reclaim.at(key).ranges) {
      snapshot.ranges = without_range(snapshot.ranges, remaining);
      snapshot.ranges.push_back(remaining);
    }
  snapshot.ranges = nlm_merge(std::move(snapshot.ranges));
  if (snapshot.ranges.empty()) {
    statement q(db, "DELETE FROM nlm_locks WHERE id=?"); q.bind(1, key); q.row();
  } else {
    statement q(db, "INSERT OR REPLACE INTO nlm_locks VALUES(?,?)");
    q.bind(1, key); q.bind(2, nlm_json(snapshot).dump()); q.row();
  }
}
void start_nlm() {
  sql(db, "CREATE TABLE IF NOT EXISTS nlm_locks(id TEXT PRIMARY KEY,body TEXT NOT NULL);"
      "CREATE TABLE IF NOT EXISTS nlm_peers(name TEXT PRIMARY KEY,state INTEGER NOT NULL);"
      "CREATE TABLE IF NOT EXISTS nsm_monitors(id TEXT PRIMARY KEY,body TEXT NOT NULL);"
      "CREATE TABLE IF NOT EXISTS nsm_state(id INTEGER PRIMARY KEY,state INTEGER NOT NULL);");
  {
    statement q(db, "SELECT id,body FROM nlm_locks");
    while (q.row()) {
      require(nlm_reclaim.size() < 128, "invalid_state");
      nlm_reclaim.emplace(q.text(0), nlm_from_json(json::parse(q.text(1))));
    }
  }
  {
    statement q(db, "SELECT name,state FROM nlm_peers");
    while (q.row()) {
      require(nlm_peers.size() < 64, "invalid_state");
      nlm_peers.emplace(q.text(0), uint32_t(q.integer(1)));
    }
  }
  if (!nlm_reclaim.empty()) {
    nlm_grace_end = now() + 60000;
    grace_end = std::max(grace_end, nlm_grace_end);
  }
  {
    statement q(db, "SELECT id,body FROM nsm_monitors");
    while (q.row()) {
      require(nsm_monitors.size() < 64, "invalid_state");
      nsm_monitors[q.text(0)] = json::parse(q.text(1));
    }
  }
  {
    statement q(db, "SELECT state FROM nsm_state WHERE id=1");
    if (q.row()) nsm_state = (uint32_t(q.integer(0)) + 2u) & 0x7fffffffu;
    nsm_state |= 1u;
  }
  statement q(db, "INSERT OR REPLACE INTO nsm_state VALUES(1,?)");
  q.bind(1, int64_t(nsm_state)); q.row();
  nsm_notify_pending = !nlm_peers.empty();
}
bool nlm_overlap(lock_range a, lock_range b) {
  return a.start <= b.end && a.end >= b.start && (a.type == 2 || b.type == 2);
}
std::optional<std::pair<nlm_lock, lock_range>> nlm_conflict(const nlm_lock &l, lock_range range) {
  nlm_prune(l.object);
  for (const auto &[key, held] : nlm_held)
    if (held.object == l.object && nlm_owner(l) != nlm_owner(held))
      for (auto r : held.ranges)
        if (nlm_overlap(r, range)) return std::pair{held, r};
  for (const auto &[key, held] : byte_locks)
    if (held.object == l.object)
      for (auto r : held.ranges)
        if (nlm_overlap(r, range)) {
          nlm_lock other;
          other.owner = held.owner; // Opaque diagnostic only; cannot unlock v4 state.
          return std::pair{other, r};
        }
  return {};
}
void nlm_peer_state(const std::string &caller, uint32_t state) {
  auto peer = nlm_peers.find(caller);
  if (peer != nlm_peers.end() && peer->second != state) {
    // Ignore stale reboot announcements / old retransmissions.
    check(uint32_t(state - peer->second) < 0x80000000u, 9);
    std::vector<std::pair<std::string, nlm_lock>> retired;
    for (auto it = nlm_reclaim.begin(); it != nlm_reclaim.end();)
      if (it->second.caller == caller) {
        retired.emplace_back(it->first, it->second);
        it = nlm_reclaim.erase(it);
      } else ++it;
    for (auto it = nlm_held.begin(); it != nlm_held.end();)
      if (it->second.caller == caller) {
        auto empty = it->second; empty.ranges.clear(); persist_nlm(it->first, empty);
        it = nlm_held.erase(it);
      } else ++it;
    for (auto &[key, empty] : retired) { empty.ranges.clear(); persist_nlm(key, empty); }
    std::erase_if(nlm_waiting, [&](const auto &w) { return w.second.lock.caller == caller; });
  }
  check(nlm_peers.contains(caller) || nlm_peers.size() < 64, 2);
  statement q(db, "INSERT OR REPLACE INTO nlm_peers VALUES(?,?)");
  q.bind(1, caller); q.bind(2, int64_t(state)); q.row();
  nlm_peers[caller] = state;
}
uint32_t nlm_error(std::string_view code) {
  auto s = status(code);
  if (s == 70) return 7;
  if (s == 13) return 6;
  if (s == 10018 || s == 10008) return 2;
  return 9;
}
void nlm_authorize(nlm_lock &l, bool exclusive) {
  auto m = file(l.who, l.handle, "stat");
  check(!m.at("directory").get<bool>(), 9);
  if (exclusive) {
    auto raw = decode_bytes(l.handle);
    authorize({{"peer", "127.0.0.1"}, {"credential", l.who.credential},
        {"uuid", encode_bytes(raw.substr(2, 16))}, {"write", true}});
  }
  auto object = m.at("object").get<std::string>();
  check(l.object.empty() || l.object == object, 7);
  l.object = object;
}
void nlm_grant(nlm_lock l, lock_range range) {
  auto key = nlm_key(l);
  check(nlm_held.contains(key) || nlm_held.size() < 128, 2);
  if (nlm_held.contains(key)) l.ranges = nlm_held.at(key).ranges;
  auto ranges = without_range(l.ranges, range);
  check(ranges.size() < 1024, 2);
  ranges.push_back(range); l.ranges = nlm_merge(std::move(ranges));
  persist_nlm(key, l);
  nlm_held.insert_or_assign(key, std::move(l));
}
void nlm_prune(const std::string &object) {
  for (auto it = nlm_held.begin(); it != nlm_held.end();)
    if (it->second.object == object) {
      try {
        nlm_authorize(it->second, std::any_of(it->second.ranges.begin(), it->second.ranges.end(),
            [](auto r) { return r.type == 2; }));
        ++it;
      } catch (const error &e) {
        auto code = std::string_view(e.what());
        if (code != "forbidden" && code != "permission_denied" && code != "policy_revoked" &&
            code != "stale_handle" && code != "object_replaced") throw;
        auto key = it->first;
        auto empty = it->second; empty.ranges.clear();
        nlm_reclaim.erase(key); persist_nlm(key, empty);
        for (auto &[id, waiting] : nlm_waiting)
          if (nlm_key(waiting.lock) == key) { waiting.reserved = false; waiting.previous.clear(); }
        it = nlm_held.erase(it);
      }
    } else ++it;
}
void nlm_unlock(const nlm_lock &l, lock_range range) {
  auto key = nlm_key(l);
  auto it = nlm_held.find(key);
  if (it == nlm_held.end()) return;
  auto updated = it->second;
  updated.ranges = without_range(updated.ranges, range);
  persist_nlm(key, updated);
  if (updated.ranges.empty()) nlm_held.erase(it);
  else it->second = std::move(updated);
}
void nlm_cancel_grant(const nlm_waiter &waiter) {
  if (!waiter.reserved) return;
  nlm_unlock(waiter.lock, waiter.range);
  for (auto previous : waiter.previous) nlm_grant(waiter.lock, previous);
}
std::pair<nlm_lock, lock_range> parse_nlm_lock(const identity &who, reader &r, bool exclusive) {
  nlm_lock l;
  l.who = who;
  l.caller = r.opaque(255);
  check(!l.caller.empty(), 9);
  l.handle = encode_bytes(r.opaque(64));
  l.owner = encode_bytes(r.opaque(1024));
  l.svid = r.u32();
  auto start = r.u64(), length = r.u64();
  // A wrapped end is rejected after the entire argument has been decoded.
  return {l, {start, length ? start + length - 1 : UINT64_MAX, exclusive ? 2u : 1u}};
}
void write_nlm_lock(writer &w, const nlm_lock &l, lock_range range) {
  w.opaque(l.caller).opaque(decode_bytes(l.handle)).opaque(decode_bytes(l.owner))
      .u32(l.svid).u64(range.start).u64(range.end == UINT64_MAX ? 0 : range.end - range.start + 1);
}
bool nlm_deadlock(const nlm_lock &candidate, lock_range range) {
  auto owner = nlm_owner(candidate);
  std::set<std::string> visiting;
  std::function<bool(const nlm_lock &, lock_range)> reaches = [&](const nlm_lock &l, lock_range r) {
    for (const auto &[key, held] : nlm_held) {
      if (held.object != l.object || nlm_owner(held) == nlm_owner(l)) continue;
      if (!std::any_of(held.ranges.begin(), held.ranges.end(), [&](auto x) { return nlm_overlap(x, r); })) continue;
      auto blocking = nlm_owner(held);
      if (blocking == owner) return true;
      if (!visiting.insert(blocking).second) continue;
      for (const auto &[id, waiting] : nlm_waiting)
        if (nlm_owner(waiting.lock) == blocking && reaches(waiting.lock, waiting.range)) return true;
    }
    return false;
  };
  return reaches(candidate, range);
}
std::string nlm(const identity &who, uint32_t proc, reader &r) {
  if (proc == 0) { r.end(); return {}; }
  auto cookie = r.opaque(64);
  bool block = false, exclusive = false, recovering = false;
  if (proc == 2 || proc == 3) block = r.boolean();
  if (proc != 4) exclusive = r.boolean();
  auto [l, range] = parse_nlm_lock(who, r, exclusive);
  if (proc == 2) { recovering = r.boolean(); l.state = r.u32(); }
  r.end();
  writer out;
  out.opaque(cookie);
  try {
    expire();
    check(range.end >= range.start, 8);
    // Cleanup remains available to the original owner after export revocation
    // or unlink; it cannot acquire rights or change somebody else's locks.
    if (proc == 3 || proc == 4) {
      for (const auto &[key, held] : nlm_held)
        if (held.handle == l.handle && nlm_owner(held) == nlm_owner(l)) l.object = held.object;
      for (const auto &[key, waiting] : nlm_waiting)
        if (waiting.lock.handle == l.handle && nlm_owner(waiting.lock) == nlm_owner(l)) l.object = waiting.lock.object;
    }
    if (l.object.empty()) nlm_authorize(l, exclusive);
    auto key = nlm_key(l);
    auto wait_key = digest(key + cookie + std::to_string(range.start) + ":" + std::to_string(range.end));
    if (proc == 4) {
      for (const auto &[id, waiting] : nlm_waiting)
        if (nlm_key(waiting.lock) == key && range.start <= waiting.range.end && range.end >= waiting.range.start)
          nlm_cancel_grant(waiting);
      nlm_unlock(l, range);
      std::erase_if(nlm_waiting, [&](const auto &w) {
        return nlm_key(w.second.lock) == key && range.start <= w.second.range.end && range.end >= w.second.range.start;
      });
      return out.u32(0).data;
    }
    if (proc == 3) {
      for (auto it = nlm_waiting.begin(); it != nlm_waiting.end(); ++it)
        if (nlm_key(it->second.lock) == key && it->second.range.start == range.start &&
            it->second.range.end == range.end && it->second.range.type == range.type) {
          nlm_cancel_grant(it->second);
          nlm_waiting.erase(it);
          return out.u32(0).data;
        }
      return out.u32(1).data;
    }
    check(!grace_end || recovering, 4);
    check(!recovering || nlm_grace_end, 4);
    if (proc == 2) {
      nlm_peer_state(l.caller, l.state);
      if (recovering) {
        auto it = nlm_reclaim.find(key);
        check(it != nlm_reclaim.end() && it->second.handle == l.handle &&
            std::any_of(it->second.ranges.begin(), it->second.ranges.end(), [&](auto held) {
              return range.start >= held.start && range.end <= held.end && range.type == held.type;
            }), 9);
      }
    }
    if (auto conflict = nlm_conflict(l, range)) {
      if (proc == 2 && block) {
        check(bool(callback) && (nlm_waiting.contains(wait_key) || nlm_waiting.size() < 128), 2);
        check(!nlm_deadlock(l, range), 5);
        nlm_waiting.insert_or_assign(wait_key, nlm_waiter{l, range, cookie});
        return out.u32(3).data;
      }
      out.u32(1);
      if (proc == 1) {
        auto &[holder, held] = *conflict;
        out.boolean(held.type == 2).u32(holder.svid).opaque(decode_bytes(holder.owner))
            .u64(held.start).u64(held.end == UINT64_MAX ? 0 : held.end - held.start + 1);
      }
      return out.data;
    }
    if (proc == 2) {
      nlm_grant(l, range);
      if (recovering) {
        auto &old = nlm_reclaim.at(key);
        old.ranges = without_range(old.ranges, range);
        if (old.ranges.empty()) nlm_reclaim.erase(key);
      }
      nlm_waiting.erase(wait_key);
    }
    return out.u32(proc == 5 ? 1 : 0).data;
  } catch (const failure &e) { return out.u32(e.status <= 9 ? e.status : e.status == 70 ? 7 : 9).data; }
    catch (const error &e) { return out.u32(nlm_error(e.what())).data; }
}
void nlm_expire() {
  if (nlm_grace_end && now() >= nlm_grace_end) {
    auto expired = std::move(nlm_reclaim); nlm_reclaim.clear();
    for (const auto &[key, l] : expired) {
      if (nlm_held.contains(key)) persist_nlm(key, nlm_held.at(key));
      else { auto empty = l; empty.ranges.clear(); persist_nlm(key, empty); }
    }
    nlm_grace_end = 0;
  }
}
void nlm_maintenance() {
  nlm_expire();
  if (!callback) return;
  for (auto &[id, monitor] : nsm_monitors)
    if (monitor.contains("pending") && monitor.value("retry_after", int64_t(0)) <= now()) {
      writer body;
      body.opaque(monitor.at("name").get<std::string>()).u32(monitor.at("pending"))
          .fixed(decode_bytes(monitor.at("private").get<std::string>()));
      try {
        callback(100021, 4, monitor.at("procedure"), body.data);
        monitor.erase("pending");
        monitor.erase("retry_after");
        statement q(db, "UPDATE nsm_monitors SET body=? WHERE id=?");
        q.bind(1, monitor.dump()); q.bind(2, id); q.row();
      } catch (...) { monitor["retry_after"] = now() + 5000; }
      return;
    }
  if (nsm_notify_pending && now() >= nsm_notify_after) {
    writer body;
    body.opaque(cfg.nfs_address).u32(nsm_state);
    try { callback(100024, 1, 6, body.data); nsm_notify_pending = false; }
    catch (...) {
      nsm_notify_after = now() + 5000;
      if (++nsm_notify_attempts >= 12) nsm_notify_pending = false;
    }
    return;
  }
  for (auto it = nlm_waiting.begin(); it != nlm_waiting.end(); ++it) {
    auto &waiter = it->second;
    try { nlm_authorize(waiter.lock, waiter.range.type == 2); }
    catch (...) {
      nlm_cancel_grant(waiter);
      nlm_waiting.erase(it); return;
    }
    if (!waiter.reserved) {
      if (grace_end || nlm_conflict(waiter.lock, waiter.range)) continue;
      auto key = nlm_key(waiter.lock);
      if (nlm_held.contains(key))
        for (auto held : nlm_held.at(key).ranges)
          if (held.start <= waiter.range.end && held.end >= waiter.range.start)
            waiter.previous.push_back({std::max(held.start, waiter.range.start),
                std::min(held.end, waiter.range.end), held.type});
      nlm_grant(waiter.lock, waiter.range);
      waiter.reserved = true;
    }
    writer body;
    body.opaque(waiter.cookie).boolean(waiter.range.type == 2);
    write_nlm_lock(body, waiter.lock, waiter.range);
    try {
      auto bytes = callback(100021, 4, 5, body.data);
      reader reply(bytes);
      require(reply.opaque(64) == waiter.cookie, "callback_rejected");
      auto status = reply.u32(); reply.end();
      if (status != 0) nlm_cancel_grant(waiter);
      nlm_waiting.erase(it);
    } catch (...) { /* The reserved grant is retried; CANCEL/UNLOCK can release it. */ }
    return; // At most one bounded callback per maintenance tick.
  }
}
json nsm_identity(reader &r) {
  auto name = r.opaque(255);
  auto program = r.u32(), version = r.u32(), procedure = r.u32();
  return {{"callback_name", name}, {"program", program}, {"version", version}, {"procedure", procedure}};
}
std::string nsm(uint32_t proc, reader &r) {
  writer out;
  if (proc == 0) { r.end(); return {}; }
  if (proc == 1) {
    auto name = r.opaque(255); r.end();
    bool local = name == "localhost" || name == "127.0.0.1" || name == cfg.nfs_address || nlm_peers.contains(name);
    return out.u32(local ? 0 : 1).u32(nsm_state).data;
  }
  if (proc == 2 || proc == 3) {
    auto name = r.opaque(255);
    auto monitor = nsm_identity(r);
    monitor["name"] = name;
    auto id = digest(monitor.dump());
    if (proc == 2) monitor["private"] = encode_bytes(r.fixed(16));
    r.end();
    if (proc == 2) {
      bool valid = !name.empty() && monitor.at("program") == 100021 &&
          monitor.at("version") == 4 && (monitor.at("procedure") == 16 || monitor.at("procedure") == 24);
      if (!valid || (nsm_monitors.size() >= 64 && !nsm_monitors.contains(id)))
        return out.u32(1).u32(nsm_state).data;
      statement q(db, "INSERT OR REPLACE INTO nsm_monitors VALUES(?,?)");
      q.bind(1, id); q.bind(2, monitor.dump()); q.row();
      nsm_monitors[id] = monitor;
      out.u32(0);
    } else {
      statement q(db, "DELETE FROM nsm_monitors WHERE id=?");
      q.bind(1, id); q.row(); nsm_monitors.erase(id);
    }
    return out.u32(nsm_state).data;
  }
  if (proc == 4) {
    auto target = nsm_identity(r); r.end();
    for (auto it = nsm_monitors.begin(); it != nsm_monitors.end();)
      if (it->second.at("callback_name") == target.at("callback_name") &&
          it->second.at("program") == target.at("program") &&
          it->second.at("version") == target.at("version") &&
          it->second.at("procedure") == target.at("procedure")) {
        statement q(db, "DELETE FROM nsm_monitors WHERE id=?");
        q.bind(1, it->first); q.row(); it = nsm_monitors.erase(it);
      } else ++it;
    return out.u32(nsm_state).data;
  }
  auto name = r.opaque(255); auto state = r.u32(); r.end();
  if (nlm_peers.contains(name)) {
    try { nlm_peer_state(name, state); } catch (const failure &) { return {}; }
  }
  for (auto &[id, monitor] : nsm_monitors)
    if (monitor.at("name") == name) {
      monitor["pending"] = state;
      statement q(db, "UPDATE nsm_monitors SET body=? WHERE id=?");
      q.bind(1, monitor.dump()); q.bind(2, id); q.row();
    }
  return {};
}
