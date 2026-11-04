// NFS byte locks use client/open ownership, inclusive bounded ranges and the
// same durable reclaim journal as OPEN. They do not grant any file authority.
lock_range lock_interval(const json &a) {
  auto start = a.at("offset").get<uint64_t>(), length = a.at("length").get<uint64_t>();
  auto type = a.at("type").get<uint32_t>();
  check(type >= 1 && type <= 4);
  check(length != 0, 10042);
  check(length == UINT64_MAX || start <= UINT64_MAX - (length - 1), 10042);
  return {start, length == UINT64_MAX ? UINT64_MAX : start + length - 1, (type - 1) % 2 + 1};
}
json durable_lock(const lock_state &l, const lock_range &range) {
  const auto &c = client_ids.at(l.client);
  return {{"kind", "lock"}, {"client", c.owner}, {"principal", l.principal},
          {"owner", l.owner}, {"handle", l.fh}, {"start", range.start},
          {"end", range.end}, {"type", range.type}};
}
void persist_locks(const lock_state &old, const std::vector<lock_range> &ranges) {
  transaction tx(db);
  for (const auto &r : old.ranges)
    remove_recovery(digest(durable_lock(old, r).dump()));
  for (const auto &r : ranges) {
    auto body = durable_lock(old, r);
    statement q(db, "INSERT OR REPLACE INTO recovery VALUES(?,?)");
    q.bind(1, digest(body.dump())); q.bind(2, body.dump()); q.row();
  }
  tx.commit();
}
std::string lock_key(const std::string &id, const std::string &sid) {
  check(id.size() == 32, 10025);
  for (const auto &[key, l] : byte_locks)
    if (key.substr(8) == id.substr(8)) {
      check(l.client == sessions.at(sid).client, 10025);
      auto seq = uint32_t(std::stoul(id.substr(0, 8), nullptr, 16));
      auto current_seq = uint32_t(std::stoul(key.substr(0, 8), nullptr, 16));
      check(!seq || seq == current_seq, seq < current_seq ? 10024 : 10025);
      return key;
    }
  check(false, 10025);
  return {};
}
std::string io_state(const std::string &id, const std::string &sid) {
  for (const auto &[key, l] : byte_locks)
    if (key.substr(8) == id.substr(8)) {
      lock_key(id, sid);
      for (const auto &[o, state] : opens)
        if (o.substr(8) == l.open_other)
          return o;
      check(false, 10025);
    }
  return open_key(id, sid);
}
std::vector<lock_range> without_range(const std::vector<lock_range> &ranges, lock_range cut) {
  std::vector<lock_range> result;
  for (auto r : ranges) {
    if (r.end < cut.start || r.start > cut.end)
      result.push_back(r);
    else {
      if (r.start < cut.start) result.push_back({r.start, cut.start - 1, r.type});
      if (r.end > cut.end) result.push_back({cut.end + 1, r.end, r.type});
    }
  }
  return result;
}
void lock_conflict(const lock_state &candidate, lock_range range, writer &body) {
  nlm_prune(candidate.object);
  for (const auto &[key, held] : nlm_held)
    if (held.object == candidate.object)
      for (auto r : held.ranges)
        if (nlm_overlap(r, range)) {
          body.u64(r.start).u64(r.end == UINT64_MAX ? UINT64_MAX : r.end - r.start + 1)
              .u32(r.type).u64(0).opaque(decode_bytes(held.owner));
          check(false, 10010);
        }
  for (const auto &[key, other] : byte_locks) {
    if (candidate.object != other.object ||
        (candidate.client == other.client && candidate.owner == other.owner && candidate.principal == other.principal))
      continue;
    for (auto held : other.ranges)
      if (range.start <= held.end && range.end >= held.start && (range.type == 2 || held.type == 2)) {
        body.u64(held.start).u64(held.end == UINT64_MAX ? UINT64_MAX : held.end - held.start + 1)
            .u32(held.type).u64(other.client).opaque(decode_bytes(other.owner));
        check(false, 10010);
      }
  }
}
std::string lock_wait_key(const lock_state &state) {
  return digest(json::array({state.client, state.principal, state.object, state.owner}).dump());
}
void notify_lock_waiters() {
  // Maintenance runs outside a foreground COMPOUND's replay-authority recorder.
  // Bound both memory and fresh-authority work; notification is only a hint.
  unsigned budget = 8;
  for (auto it = lock_waiters.begin(); it != lock_waiters.end();) {
    auto &waiter = it->second;
    auto &candidate = waiter.state;
    auto client = client_ids.find(candidate.client);
    auto opened = std::find_if(opens.begin(), opens.end(), [&](const auto &o) {
      return o.first.substr(8) == candidate.open_other && o.second.client == candidate.client &&
             o.second.principal == candidate.principal;
    });
    if (client == client_ids.end() || !client_live(waiter.state.client) || opened == opens.end()) {
      it = lock_waiters.erase(it); continue;
    }
    try {
      writer ignored;
      lock_conflict(candidate, waiter.range, ignored);
    } catch (const failure &e) {
      if (e.status == 10010) { ++it; continue; }
      it = lock_waiters.erase(it); continue;
    }
    writer operation;
    operation.u32(13).opaque(decode_bytes(candidate.fh)).u64(candidate.client).opaque(decode_bytes(candidate.owner));
    auto target = std::find_if(sessions.begin(), sessions.end(), [&](const auto &entry) {
      const auto &s = entry.second;
      return s.client == candidate.client && client_live(s.client) && callback_available(s) &&
             !s.callback_up.empty() && !s.callback_unresolved && s.callback_extra.empty() &&
             s.callback_operations >= 2 &&
             callback_fits(s, operation.data.size() + waiter.references.size() - 4, 8);
    });
    if (target == sessions.end() || callback_probes.size() >= 128) { ++it; continue; }
    if (!budget) return;
    --budget;
    try {
      const auto &o = opened->second;
      check((o.access & waiter.range.type) != 0, 13);
      auto metadata = meta4(identity{o.credential, o.principal}, candidate.fh);
      check(metadata.at("object") == candidate.object &&
            (metadata.at("security_access").get<uint32_t>() & waiter.range.type) != 0, 13);
      if (waiter.range.type == 2) {
        auto handle = decode_bytes(candidate.fh);
        authorize({{"peer", "127.0.0.1"}, {"credential", o.credential},
                   {"uuid", encode_bytes(handle.substr(2, 16))}, {"write", true}});
      }
    } catch (const error &) { it = lock_waiters.erase(it); continue; }
      catch (const failure &) { it = lock_waiters.erase(it); continue; }
    auto &s = target->second;
    s.callback_extra = std::move(operation.data);
    s.callback_references = waiter.references;
    sequence_callback(target->first);
    // Once sent, the session owns the immutable callback until completion.
    it = lock_waiters.erase(it);
  }
}
void lock_operation(const identity &who, const json &a, const std::string &sid,
                    const std::string &current, std::string &current_state, writer &body,
                    const json &sequence) {
  auto op = a.at("op").get<uint32_t>();
  auto client = sessions.at(sid).client;
  if (op == 45) {
    auto id = a.at("state").get<std::string>();
    for (const auto &[key, o] : opens)
      if (key.substr(8) == id.substr(8)) {
        open_key(id, sid);
        check(o.principal == who.key || machine_cleanup(sid, who, op),
              client_ids.at(client).protection ? 10082 : 10025);
        check(false, 10037);
      }
    auto key = lock_key(id, sid);
    check(byte_locks.at(key).principal == who.key || machine_cleanup(sid, who, op),
          client_ids.at(client).protection ? 10082 : 10025);
    check(byte_locks.at(key).ranges.empty(), 10037);
    byte_locks.erase(key);
    return;
  }
  json m;
  if (op == 14 && machine_cleanup(sid, who, op)) {
    const auto &open = state4(io_state(a.at("state"), sid), sid, current, 0, who, op);
    m = {{"directory", false}, {"object", open.object}};
  } else m = meta4(who, current);
  check(!m.at("directory").get<bool>(), 21);
  auto range = lock_interval(a);
  if (op == 13) {
    check(!grace_end, 10013);
    lock_state candidate{client, "", current, m.at("object"), a.at("owner"), who.key, {}};
    lock_conflict(candidate, range, body);
    return;
  }
  std::string key;
  lock_state state;
  if (op == 12 && a.at("new").get<bool>()) {
    auto openid = open_key(a.at("state"), sid);
    auto &o = state4(openid, sid, current, range.type == 1 ? 1 : 2, who);
    state = {client, openid.substr(8), current, o.object, a.at("owner"), who.key, {}};
    for (const auto &[id, old] : byte_locks)
      if (old.client == client && old.owner == state.owner && old.object == state.object && old.principal == who.key) {
        key = id; state = old; break;
      }
  } else {
    key = lock_key(a.at("state"), sid);
    state = byte_locks.at(key);
    check(state.fh == current, 10025);
    // Unlocking releases existing authority, including after OPEN_DOWNGRADE.
    state4(io_state(key, sid), sid, current, op == 14 ? 0 : range.type == 1 ? 1 : 2,
           who, op == 14 ? op : 0);
  }
  bool recovering = op == 12 && a.at("reclaim").get<bool>();
  if (op == 12) {
    check(recovering || client_ids.at(client).reclaim_complete, 10013);
    check(!recovering || !client_ids.at(client).reclaim_complete, 10033);
    check(!grace_end || recovering, 10013);
    check(!recovering || grace_end, 10033);
    auto durable = durable_lock(state, range);
    auto rid = digest(durable.dump());
    if (recovering) check(reclaim.contains(rid) && reclaim.at(rid) == durable, 10034);
    auto wait_key = lock_wait_key(state);
    lock_waiters.erase(wait_key);
    try { lock_conflict(state, range, body); }
    catch (const failure &e) {
      if (e.status == 10010 && a.at("type").get<uint32_t>() >= 3 && !recovering &&
          send_backchannel && lock_waiters.size() < 128 &&
          std::count_if(lock_waiters.begin(), lock_waiters.end(), [&](const auto &entry) {
            return entry.second.state.client == client;
          }) < 16) {
        writer referring;
        referring.u32(1).fixed(decode_bytes(sid)).u32(1).u32(sequence.at("seq")).u32(sequence.at("slot"));
        auto waiting = state;
        waiting.ranges.clear();
        lock_waiters.emplace(wait_key, lock_waiter{std::move(waiting), range, std::move(referring.data)});
      }
      throw;
    }
    auto ranges = without_range(state.ranges, range);
    check(ranges.size() < 1024 && byte_locks.size() < 1024, 10018);
    ranges.push_back(range);
    persist_locks(state, ranges);
    state.ranges = std::move(ranges);
    if (recovering) reclaim.erase(rid);
  } else {
    auto ranges = without_range(state.ranges, range);
    persist_locks(state, ranges);
    state.ranges = std::move(ranges);
  }
  if (key.empty()) {
    writer st; st.u32(1).fixed(decode_bytes(random_hex(12)));
    current_state = encode_bytes(st.data);
  } else {
    current_state = next_state(key);
    byte_locks.erase(key);
  }
  byte_locks.emplace(current_state, std::move(state));
  body.fixed(decode_bytes(current_state));
}
