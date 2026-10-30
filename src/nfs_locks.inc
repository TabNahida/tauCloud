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
  return {{"kind", "lock"}, {"client", c.owner}, {"principal", c.principal},
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
  for (const auto &[key, other] : byte_locks) {
    if (candidate.object != other.object ||
        (candidate.client == other.client && candidate.owner == other.owner))
      continue;
    for (auto held : other.ranges)
      if (range.start <= held.end && range.end >= held.start && (range.type == 2 || held.type == 2)) {
        body.u64(held.start).u64(held.end == UINT64_MAX ? UINT64_MAX : held.end - held.start + 1)
            .u32(held.type).u64(other.client).opaque(decode_bytes(other.owner));
        check(false, 10010);
      }
  }
}
void lock_operation(const identity &who, const json &a, const std::string &sid,
                    const std::string &current, std::string &current_state, writer &body) {
  auto op = a.at("op").get<uint32_t>();
  auto client = sessions.at(sid).client;
  if (op == 39) {
    auto owner = a.at("owner").get<std::string>();
    for (const auto &[key, l] : byte_locks)
      check(l.client != client || l.owner != owner || l.ranges.empty(), 10037);
    std::erase_if(byte_locks, [&](const auto &l) { return l.second.client == client && l.second.owner == owner; });
    return;
  }
  if (op == 45) {
    auto id = a.at("state").get<std::string>();
    for (const auto &[key, o] : opens)
      if (key.substr(8) == id.substr(8)) {
        open_key(id, sid);
        check(false, 10037);
      }
    auto key = lock_key(id, sid);
    check(byte_locks.at(key).ranges.empty(), 10037);
    byte_locks.erase(key);
    return;
  }
  auto m = meta4(who, current);
  check(!m.at("directory").get<bool>(), 21);
  auto range = lock_interval(a);
  if (op == 13) {
    check(!grace_end, 10013);
    lock_state candidate{client, "", current, m.at("object"), a.at("owner"), {}};
    lock_conflict(candidate, range, body);
    return;
  }
  std::string key;
  lock_state state;
  if (op == 12 && a.at("new").get<bool>()) {
    auto openid = open_key(a.at("state"), sid);
    auto &o = state4(openid, sid, current, range.type == 1 ? 1 : 2);
    state = {client, openid.substr(8), current, o.object, a.at("owner"), {}};
    for (const auto &[id, old] : byte_locks)
      if (old.client == client && old.owner == state.owner && old.object == state.object) {
        key = id; state = old; break;
      }
  } else {
    key = lock_key(a.at("state"), sid);
    state = byte_locks.at(key);
    check(state.fh == current, 10025);
    state4(io_state(key, sid), sid, current, range.type == 1 ? 1 : 2);
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
    lock_conflict(state, range, body);
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
