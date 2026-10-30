struct client_id {
  std::string owner, principal, verifier;
  uint32_t sequence = 1;
  std::string create_hash, create_reply;
};
struct slot {
  uint32_t seq = 0;
  std::string hash, reply;
  bool pending = false;
};
struct session {
  uint64_t client;
  std::string principal;
  int64_t expires;
  std::vector<slot> slots;
};
struct open_state {
  std::string session, fh, owner, recovery;
  uint32_t access, deny;
};
std::map<uint64_t, client_id> client_ids;
std::map<std::string, session> sessions;
std::map<std::string, open_state> opens;
std::map<std::string, json> reclaim;
int64_t grace_end = 0;
const std::string pseudo = encode_bytes("tauCloud:nfs:root");
void start_recovery() {
  statement q(db, "SELECT id,body FROM recovery");
  while (q.row())
    reclaim[q.text(0)] = json::parse(q.text(1));
  if (!reclaim.empty())
    grace_end = now() + 60000;
}
void remove_recovery(const std::string &id) {
  statement q(db, "DELETE FROM recovery WHERE id=?");
  q.bind(1, id);
  q.row();
}
void expire() {
  if (grace_end && now() >= grace_end) {
    for (auto &[id, b] : reclaim)
      remove_recovery(id);
    reclaim.clear();
    grace_end = 0;
  }
  for (auto it = opens.begin(); it != opens.end();) {
    auto s = sessions.find(it->second.session);
    if (s == sessions.end() || s->second.expires <= now()) {
      remove_recovery(it->second.recovery);
      it = opens.erase(it);
    } else
      ++it;
  }
  std::erase_if(sessions, [](const auto &s) { return s.second.expires <= now(); });
}
std::vector<uint32_t> bitmap(reader &r) {
  auto n = r.u32();
  if (n > 3)
    throw xdr_error();
  std::vector<uint32_t> bits(n);
  for (auto &b : bits)
    b = r.u32();
  return bits;
}
void put_bitmap(writer &w, const std::vector<uint32_t> &bits) {
  w.u32(uint32_t(bits.size()));
  for (auto b : bits)
    w.u32(b);
}
bool has(const std::vector<uint32_t> &bits, unsigned i) {
  return i / 32 < bits.size() && (bits[i / 32] & (1u << (i % 32)));
}
std::vector<uint32_t> supported_attrs() {
  std::vector<uint32_t> b(2);
  for (unsigned n : {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 19, 20, 27, 28,
                     29, 30, 31, 33, 35, 36, 37, 42, 43, 44, 45, 47, 51, 52, 53, 55})
    b[n / 32] |= 1u << (n % 32);
  return b;
}
json meta4(const identity &who, const std::string &h) {
  check(!h.empty(), 10020);
  if (h == pseudo)
    return {{"directory", true},
            {"size", 0},
            {"fileid", "0000000000000001"},
            {"fsid", "0000000000000000"},
            {"modified_ns", 0},
            {"quota", 0},
            {"used", 0},
            {"handle", pseudo}};
  return file(who, h, "stat");
}
void attributes4(writer &out, const std::vector<uint32_t> &requested, const json &m) {
  auto supported = supported_attrs();
  std::vector<uint32_t> returned(2);
  writer values;
  for (unsigned i = 0; i < 64; ++i)
    if (has(requested, i) && has(supported, i)) {
      returned[i / 32] |= 1u << (i % 32);
      bool dir = m.at("directory");
      auto size = m.at("size").get<uint64_t>();
      auto total = m.at("quota").get<uint64_t>(), used = m.at("used").get<uint64_t>();
      auto ns = m.at("modified_ns").get<uint64_t>();
      switch (i) {
      case 0:
        put_bitmap(values, supported);
        break;
      case 1:
        values.u32(dir ? 2 : 1);
        break;
      case 2:
        values.u32(0);
        break;
      case 3:
        values.u64(ns);
        break;
      case 4:
        values.u64(size);
        break;
      case 5:
      case 6:
      case 7:
        values.boolean(false);
        break;
      case 8:
        values.u64(hex64(m.at("fsid"))).u64(0);
        break;
      case 9:
        values.boolean(true);
        break;
      case 10:
        values.u32(60);
        break;
      case 11:
        values.u32(0);
        break;
      case 19:
        values.opaque(decode_bytes(m.at("handle").get<std::string>()));
        break;
      case 20:
      case 55:
        values.u64(hex64(m.at("fileid")));
        break;
      case 27:
        values.u64(INT64_MAX);
        break;
      case 28:
        values.u32(1);
        break;
      case 29:
        values.u32(255);
        break;
      case 30:
      case 31:
        values.u64(65536);
        break;
      case 33:
        values.u32(dir ? 0700 : 0600);
        break;
      case 35:
        values.u32(dir ? 2 : 1);
        break;
      case 36:
      case 37:
        values.opaque("65534");
        break;
      case 42:
      case 43:
        values.u64(total > used ? total - used : 0);
        break;
      case 44:
        values.u64(total);
        break;
      case 45:
        values.u64(size);
        break;
      case 47:
      case 52:
      case 53:
        values.u64(ns / 1000000000).u32(uint32_t(ns % 1000000000));
        break;
      case 51:
        values.u64(0).u32(1);
        break;
      }
    }
  while (!returned.empty() && !returned.back())
    returned.pop_back();
  put_bitmap(out, returned);
  out.opaque(values.data);
}
json parse_attrs4(reader &r) {
  auto bits = bitmap(r);
  auto bytes = r.opaque(4096);
  return {{"bits", bits}, {"bytes", encode_bytes(bytes)}};
}
void create_attrs4(const json &a, bool dir) {
  auto bits = a.at("bits").get<std::vector<uint32_t>>();
  auto bytes = decode_bytes(a.at("bytes").get<std::string>());
  reader r(bytes);
  for (unsigned i = 0; i < bits.size() * 32; ++i)
    if (has(bits, i)) {
      if (i == 33)
        check((r.u32() & 07777) == (dir ? 0700u : 0600u), 10032);
      else if (i == 4)
        check(r.u64() == 0, 10032);
      else
        check(false, 10032);
    }
  r.end();
}
std::vector<uint32_t> channel(reader &r) {
  std::vector<uint32_t> a;
  for (int i = 0; i < 6; ++i)
    a.push_back(r.u32());
  auto n = r.u32();
  if (n > 1)
    throw xdr_error();
  if (n)
    r.u32();
  return a;
}
void put_channel(writer &w, const std::vector<uint32_t> &a) {
  for (auto v : a)
    w.u32(v);
  w.u32(0);
}
json parse4(reader &r) {
  auto op = r.u32();
  json a = {{"op", op}};
  switch (op) {
  case 42: {
    a["verifier"] = encode_bytes(r.fixed(8));
    a["owner"] = encode_bytes(r.opaque(1024));
    a["flags"] = r.u32();
    a["protect"] = r.u32();
    check(a["protect"] == 0, 10006);
    auto n = r.u32();
    if (n > 1)
      throw xdr_error();
    if (n) {
      r.opaque(1024);
      r.opaque(1024);
      r.u64();
      r.u32();
    }
    break;
  }
  case 43: {
    a["client"] = r.u64();
    a["seq"] = r.u32();
    a["flags"] = r.u32();
    a["fore"] = channel(r);
    a["back"] = channel(r);
    r.u32();
    auto n = r.u32();
    if (n > 16)
      throw xdr_error();
    for (uint32_t i = 0; i < n; ++i) {
      auto auth = r.u32();
      if (auth == 1) {
        r.u32();
        r.opaque(255);
        r.u32();
        r.u32();
        auto groups = r.u32();
        if (groups > 16)
          throw xdr_error();
        for (uint32_t j = 0; j < groups; ++j)
          r.u32();
      } else if (auth != 0)
        throw xdr_error();
    }
    break;
  }
  case 41:
    a["session"] = encode_bytes(r.fixed(16));
    a["dir"] = r.u32();
    a["rdma"] = r.boolean();
    break;
  case 44:
    a["session"] = encode_bytes(r.fixed(16));
    break;
  case 53:
    a["session"] = encode_bytes(r.fixed(16));
    a["seq"] = r.u32();
    a["slot"] = r.u32();
    a["highest"] = r.u32();
    a["cache"] = r.boolean();
    break;
  case 57:
    a["client"] = r.u64();
    break;
  case 58:
    a["one_fs"] = r.boolean();
    break;
  case 22:
    a["handle"] = encode_bytes(r.opaque(128));
    break;
  case 24:
  case 23:
  case 10:
  case 31:
  case 32:
  case 16:
    break;
  case 15:
  case 28:
  case 33:
    a["name"] = component(r);
    break;
  case 52:
    a["style"] = r.u32();
    break;
  case 9:
    a["bits"] = bitmap(r);
    break;
  case 3:
    a["access"] = r.u32();
    break;
  case 25:
    a["state"] = encode_bytes(r.fixed(16));
    a["offset"] = r.u64();
    a["count"] = r.u32();
    break;
  case 38:
    a["state"] = encode_bytes(r.fixed(16));
    a["offset"] = r.u64();
    a["stable"] = r.u32();
    a["data"] = encode_bytes(r.opaque(65536));
    break;
  case 5:
    a["offset"] = r.u64();
    a["count"] = r.u32();
    break;
  case 26:
    a["cookie"] = r.u64();
    a["verifier"] = encode_bytes(r.fixed(8));
    a["dircount"] = r.u32();
    a["count"] = r.u32();
    a["bits"] = bitmap(r);
    break;
  case 18: {
    a["seq"] = r.u32();
    a["access"] = r.u32();
    a["deny"] = r.u32();
    a["client"] = r.u64();
    a["owner"] = encode_bytes(r.opaque(1024));
    a["create"] = r.u32();
    if (a["create"] == 1) {
      auto mode = r.u32();
      a["mode"] = mode;
      if (mode == 2 || mode == 3)
        a["verifier"] = encode_bytes(r.fixed(8));
      if (mode == 0 || mode == 1 || mode == 3)
        a["attrs"] = parse_attrs4(r);
      check(mode <= 3);
    } else
      check(a["create"] == 0);
    auto claim = r.u32();
    a["claim"] = claim;
    if (claim == 0)
      a["name"] = component(r);
    else if (claim == 1)
      a["delegation"] = r.u32();
    else
      check(claim == 4, 10004);
    break;
  }
  case 4:
    a["seq"] = r.u32();
    a["state"] = encode_bytes(r.fixed(16));
    break;
  case 34:
    a["state"] = encode_bytes(r.fixed(16));
    a["attrs"] = parse_attrs4(r);
    break;
  case 6:
    a["type"] = r.u32();
    check(a["type"] == 2, 10007);
    a["name"] = component(r);
    a["attrs"] = parse_attrs4(r);
    break;
  case 29:
    a["name"] = component(r);
    a["to"] = component(r);
    break;
  case 45:
    a["state"] = encode_bytes(r.fixed(16));
    break;
  case 55: {
    auto n = r.u32();
    if (n > 64)
      throw xdr_error();
    a["states"] = json::array();
    for (uint32_t i = 0; i < n; ++i)
      a["states"].push_back(encode_bytes(r.fixed(16)));
    break;
  }
  default:
    a["unknown"] = true;
    break;
  }
  return a;
}
open_state &state4(const std::string &id, const std::string &sid, const std::string &h,
                   uint32_t access) {
  auto it = opens.find(id);
  check(it != opens.end() && it->second.session == sid && it->second.fh == h, 10025);
  check((it->second.access & access) == access, 10038);
  return it->second;
}
void change4(writer &w) { w.boolean(false).u64(0).u64(0); } // No atomic change_info claim.
std::string v4(const identity &who, reader &r) {
  auto start = r.pos;
  auto tag = r.opaque(1024);
  auto minor = r.u32(), count = r.u32();
  writer out;
  if (minor != 1)
    return out.u32(10021).opaque(tag).u32(0).data;
  if (count > 16)
    return out.u32(10018).opaque(tag).u32(0).data;
  std::vector<json> ops;
  try {
    for (uint32_t i = 0; i < count; ++i) {
      ops.push_back(parse4(r));
      if (ops.back().value("unknown", false))
        break;
    }
    if (ops.empty() || !ops.back().value("unknown", false))
      r.end();
  } catch (const failure &e) {
    return out.u32(e.status).opaque(tag).u32(0).data;
  }
  auto hash = digest(std::string(r.data.substr(start)));
  expire();
  std::string sid, current, saved;
  slot *active = nullptr;
  uint32_t final_status = 0, done = 0;
  writer results;
  auto session_check = [&](const std::string &id) -> session & {
    auto i = sessions.find(id);
    check(i != sessions.end() && i->second.principal == who.key, 10052);
    return i->second;
  };
  // Reserve sufficient cached response space before any compound side effects.
  size_t bound = tag.size() + 64;
  for (const auto &a : ops) {
    unsigned op = a.at("op");
    bound += (op == 25 || op == 26) ? std::min(a.value("count", 0u), 65536u) + 512 : 4096;
  }
  if (bound > 120 * 1024) {
    if (!ops.empty())
      results.u32(ops[0].at("op")).u32(10067);
    return out.u32(10067).opaque(tag).u32(ops.empty() ? 0 : 1).fixed(results.data).data;
  }
  for (size_t index = 0; index < ops.size(); ++index) {
    auto &a = ops[index];
    unsigned op = a.at("op");
    writer body;
    uint32_t code = 0;
    try {
      if (index == 0 && op != 53)
        check(ops.size() == 1 && (op == 42 || op == 43 || op == 44 || op == 41 || op == 57), 10071);
      if (index > 0)
        check(op != 53, 10064);
      if (op == 42) {
        check(a.at("protect") == 0, 10006);
        check(client_ids.size() < 128, 10018);
        uint64_t id = 0;
        bool confirmed = false;
        for (auto &[n, c] : client_ids)
          if (c.owner == a.at("owner").get<std::string>() && c.principal == who.key &&
              c.verifier == a.at("verifier").get<std::string>()) {
            id = n;
            confirmed = !c.create_reply.empty();
            break;
          }
        if (!id) {
          id = hex64(random_hex(8)) & INT64_MAX;
          client_ids[id] = {a.at("owner"), who.key, a.at("verifier"), 1, "", ""};
        }
        body.u64(id)
            .u32(client_ids.at(id).sequence)
            .u32(0x10000 | (confirmed ? 0x80000000u : 0))
            .u32(0)
            .u64(1)
            .opaque("tauCloud")
            .opaque("tauCloud-loopback")
            .u32(0);
      } else if (op == 43) {
        auto id = a.at("client").get<uint64_t>();
        auto it = client_ids.find(id);
        check(it != client_ids.end() && it->second.principal == who.key, 10022);
        auto &c = it->second;
        auto seq = a.at("seq").get<uint32_t>();
        if (seq + 1 == c.sequence && !c.create_reply.empty()) {
          check(c.create_hash == hash, 10076);
          body.fixed(c.create_reply);
        } else {
          check(seq == c.sequence, 10063);
          check(sessions.size() < 32, 10018);
          auto fore = a.at("fore").get<std::vector<uint32_t>>();
          check(fore[1] >= 4096 && fore[2] >= 4096 && fore[3] >= 4096 && fore[4] > 0 && fore[5] > 0,
                10005);
          // Use fixed limits only when the client offered at least those limits.
          check(fore[1] >= 128 * 1024 && fore[2] >= 128 * 1024 && fore[3] >= 128 * 1024 &&
                    fore[4] >= 16,
                10005);
          fore = {0, 128 * 1024, 128 * 1024, 128 * 1024, 16, std::min(fore[5], 8u)};
          std::vector<uint32_t> back = {0, 4096, 4096, 0, 1, 1};
          auto idstr = random_hex(16);
          sessions.emplace(idstr, session{id, who.key, now() + 60000, std::vector<slot>(fore[5])});
          body.fixed(decode_bytes(idstr)).u32(seq).u32(0);
          put_channel(body, fore);
          put_channel(body, back);
          c.create_hash = hash;
          c.create_reply = body.data;
          ++c.sequence;
        }
      } else if (op == 53) {
        sid = a.at("session");
        auto &s = session_check(sid);
        auto n = a.at("slot").get<uint32_t>();
        check(n < s.slots.size(), 10053);
        check(a.at("highest").get<uint32_t>() >= n, 10077);
        auto &sl = s.slots[n];
        auto seq = a.at("seq").get<uint32_t>();
        for (const auto &[id, o] : opens)
          if (o.session == sid) {
            try {
              file(who, o.fh, "stat");
            } catch (...) {
              check(false, 10008);
            }
            break;
          }
        if (seq == sl.seq && sl.seq) {
          check(hash == sl.hash, 10076);
          check(!sl.pending && !sl.reply.empty(), 10008);
          s.expires = now() + 60000;
          return sl.reply;
        }
        check(seq == sl.seq + 1 && !sl.pending, 10063);
        sl.seq = seq;
        sl.hash = hash;
        sl.reply.clear();
        sl.pending = true;
        active = &sl;
        s.expires = now() + 60000;
        body.fixed(decode_bytes(sid))
            .u32(seq)
            .u32(n)
            .u32(uint32_t(s.slots.size() - 1))
            .u32(uint32_t(s.slots.size() - 1))
            .u32(0);
      } else if (op == 41) {
        auto &s = session_check(a.at("session"));
        (void)s;
        check(!a.at("rdma").get<bool>() && a.at("dir").get<uint32_t>() != 2, 10004);
        body.fixed(decode_bytes(a.at("session").get<std::string>())).u32(1).boolean(false);
      } else if (op == 44) {
        auto target = a.at("session").get<std::string>();
        session_check(target);
        check(target != sid, 10016);
        for (const auto &[id, o] : opens)
          check(o.session != target, 10074);
        sessions.erase(target);
      } else if (op == 57) {
        auto id = a.at("client").get<uint64_t>();
        auto i = client_ids.find(id);
        check(i != client_ids.end() && i->second.principal == who.key, 10022);
        for (const auto &[n, s] : sessions)
          check(s.client != id, 10074);
        client_ids.erase(i);
      } else {
        check(!sid.empty(), 10071);
        auto &session = session_check(sid);
        auto &client = client_ids.at(session.client);
        auto request =
            digest(sid + std::to_string(a.at("op").get<unsigned>()) + hash + std::to_string(index));
        if (op == 24 || op == 23)
          current = pseudo;
        else if (op == 22) {
          current = a.at("handle");
          meta4(who, current);
        } else if (op == 10) {
          meta4(who, current);
          body.opaque(decode_bytes(current));
        } else if (op == 32) {
          meta4(who, current);
          saved = current;
        } else if (op == 31) {
          check(!saved.empty(), 10030);
          current = saved;
        } else if (op == 15) {
          check(!current.empty(), 10020);
          auto m = current == pseudo ? file(who, "", "root", json::object(), "", a.at("name"))
                                     : file(who, current, "lookup", {{"name", a.at("name")}});
          current = m.at("handle");
        } else if (op == 9) {
          auto m = meta4(who, current);
          attributes4(body, a.at("bits").get<std::vector<uint32_t>>(), m);
        } else if (op == 3) {
          meta4(who, current);
          auto asked = a.at("access").get<uint32_t>();
          uint32_t allowed = asked & 0x23;
          if (current != pseudo) {
            try {
              auto raw = decode_bytes(current);
              json b = {{"peer", "127.0.0.1"},
                        {"credential", who.credential},
                        {"uuid", encode_bytes(raw.substr(2, 16))},
                        {"write", true}};
              call("identity", "nfs_authorize", b);
              allowed = asked & 0x3f;
            } catch (...) {
            }
          }
          body.u32(asked & 0x3f).u32(allowed);
        } else if (op == 33 || op == 52) {
          meta4(who, current);
          if (op == 52)
            check(a.at("style") == 0, 10004);
          else
            file(who, current, "lookup", {{"name", a.at("name")}});
          body.u32(1).u32(1);
          current.clear();
        } else if (op == 18) {
          auto access = a.at("access").get<uint32_t>(), deny = a.at("deny").get<uint32_t>();
          check((access & 3) > 0 && (access & ~0x303u) == 0 && deny <= 3);
          check(deny == 0, 10004);
          access &= 3;
          check(a.at("client").get<uint64_t>() == session.client, 10022);
          check(opens.size() < 1024, 10018);
          auto claim = a.at("claim").get<unsigned>();
          bool recovering = claim == 1;
          check(!grace_end || recovering, 10013);
          check(!recovering || grace_end, 10033);
          check(current != pseudo && !current.empty(), 10020);
          if (a.at("create") == 1) {
            check(claim == 0, 22);
            check(a.at("mode") == 1, 10004);
            create_attrs4(a.at("attrs"), false);
          }
          auto target = current;
          if (claim == 0) {
            try {
              target = file(who, current, "lookup", {{"name", a.at("name")}}).at("handle");
              check(a.at("create") == 0, 17);
            } catch (const error &e) {
              if (std::string_view(e.what()) != "not_found" || a.at("create") != 1)
                throw;
              target = file(who, current, "create", {{"name", a.at("name")}}, request).at("handle");
            }
          }
          auto m = meta4(who, target);
          check(!m.at("directory").get<bool>(), 21);
          // Authorization is checked for read and for the requested write access.
          if (access & 2) {
            auto raw = decode_bytes(target);
            json b = {{"peer", "127.0.0.1"},
                      {"credential", who.credential},
                      {"uuid", encode_bytes(raw.substr(2, 16))},
                      {"write", true}};
            call("identity", "nfs_authorize", b);
          }
          auto owner = a.at("owner").get<std::string>();
          for (const auto &[id, o] : opens) {
            check(!(o.session == sid && o.owner == owner && o.fh == target), 10008);
            // One export per session bounds policy renewal work and keeps isolation explicit.
            if (o.session == sid)
              check(o.fh.substr(4, 32) == target.substr(4, 32), 10018);
          }
          auto rid = digest(client.owner + who.key + owner + target);
          json durable = {{"client", client.owner}, {"principal", who.key}, {"owner", owner},
                          {"handle", target},       {"access", access},     {"deny", deny}};
          if (recovering) {
            check(a.at("delegation") == 0 && reclaim.contains(rid) && reclaim.at(rid) == durable,
                  10034);
          }
          for (const auto &[id, o] : opens)
            if (o.fh == target)
              check(!(o.deny & access) && !(deny & o.access), 10015);
          writer state;
          state.u32(1).fixed(decode_bytes(random_hex(12)));
          auto stateid = encode_bytes(state.data);
          statement persist(db, "INSERT OR REPLACE INTO recovery VALUES(?,?)");
          persist.bind(1, rid);
          persist.bind(2, durable.dump());
          persist.row();
          opens.emplace(stateid, open_state{sid, target, owner, rid, access, deny});
          reclaim.erase(rid);
          current = target;
          body.fixed(state.data);
          change4(body);
          body.u32(0).u32(0).u32(0);
        } else if (op == 4) {
          auto id = a.at("state").get<std::string>();
          auto &o = state4(id, sid, current, 0);
          remove_recovery(o.recovery);
          opens.erase(id);
          writer st;
          st.u32(2).fixed(decode_bytes(id).substr(4));
          body.fixed(st.data);
        } else if (op == 25 || op == 38 || op == 34) {
          check(current != pseudo, 21);
          auto id = a.at("state").get<std::string>();
          state4(id, sid, current, op == 25 ? 1 : 2);
          if (op == 25) {
            auto m = file(who, current, "read",
                          {{"offset", a.at("offset")},
                           {"count", std::min(a.at("count").get<uint32_t>(), 65536u)}});
            body.boolean(m.at("eof")).opaque(decode_bytes(m.at("data").get<std::string>()));
          } else if (op == 38) {
            check(a.at("stable").get<uint32_t>() <= 2);
            auto m = file(who, current, "write",
                          {{"offset", a.at("offset")}, {"data", a.at("data")}}, request);
            body.u32(m.at("count")).u32(2).fixed(verifier);
          } else {
            auto bits = a.at("attrs").at("bits").get<std::vector<uint32_t>>();
            check(bits == std::vector<uint32_t>{16}, 10032);
            auto data = decode_bytes(a.at("attrs").at("bytes").get<std::string>());
            reader values(data);
            auto size = values.u64();
            values.end();
            file(who, current, "resize", {{"size", size}}, request);
            put_bitmap(body, bits);
          }
        } else if (op == 5) {
          file(who, current, "commit");
          body.fixed(verifier);
        } else if (op == 6) {
          create_attrs4(a.at("attrs"), true);
          auto m = file(who, current, "mkdir", {{"name", a.at("name")}}, request);
          current = m.at("handle");
          change4(body);
          body.u32(0);
        } else if (op == 28) {
          for (const auto &[id, o] : opens) {
            auto m = file(who, current, "lookup", {{"name", a.at("name")}});
            check(o.fh != m.at("handle").get<std::string>(), 10008);
          }
          file(who, current, "remove", {{"name", a.at("name")}}, request);
          change4(body);
        } else if (op == 29) {
          check(!saved.empty(), 10030);
          file(who, saved, "rename",
               {{"name", a.at("name")}, {"target", current}, {"to", a.at("to")}}, request);
          change4(body);
          change4(body);
        } else if (op == 26) {
          check(current != pseudo, 10004);
          auto m = file(who, current, "list");
          auto cookie = a.at("cookie").get<uint64_t>();
          auto &entries = m.at("entries");
          check(!cookie || a.at("verifier") == m.at("verifier"), 10003);
          check(cookie <= entries.size(), 10003);
          auto budget = std::min(a.at("count").get<uint32_t>(), 65536u);
          check(budget >= 512, 10005);
          body.fixed(decode_bytes(m.at("verifier").get<std::string>()));
          size_t i = size_t(cookie);
          for (; i < entries.size(); ++i) {
            auto &e = entries[i];
            writer item;
            item.boolean(true).u64(i + 1).opaque(e.at("name").get<std::string>());
            attributes4(item, a.at("bits").get<std::vector<uint32_t>>(), e);
            if (body.data.size() + item.data.size() + 8 > budget)
              break;
            body.fixed(item.data);
          }
          body.boolean(false).boolean(i == entries.size());
        } else if (op == 55) {
          body.u32(uint32_t(a.at("states").size()));
          for (auto &id : a.at("states")) {
            auto i = opens.find(id);
            body.u32(i != opens.end() && i->second.session == sid ? 0 : 10025);
          }
        } else if (op == 58) {
          check(!a.at("one_fs").get<bool>(), 10004);
          for (auto it = reclaim.begin(); it != reclaim.end();)
            if (it->second.at("client") == client.owner && it->second.at("principal") == who.key) {
              remove_recovery(it->first);
              it = reclaim.erase(it);
            } else
              ++it;
        } else if (op == 45)
          check(false, 10037);
        else
          check(false, a.value("unknown", false) ? 10044 : 10004);
      }
    } catch (const failure &e) {
      code = e.status;
    } catch (const error &e) {
      code = status(e.what());
    } catch (const xdr_error &) {
      code = 10036;
    }
    if (code) {
      body.data.clear();
      if (op == 34)
        body.u32(0);
    }
    results.u32(a.value("unknown", false) ? 10044 : op).u32(code).fixed(body.data);
    ++done;
    if (code) {
      final_status = code;
      break;
    }
  }
  out.u32(final_status).opaque(tag).u32(done).fixed(results.data);
  if (active) {
    active->reply = out.data;
    active->pending = false;
  }
  return out.data;
}
