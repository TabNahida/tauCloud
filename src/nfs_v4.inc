struct client_id {
  std::string owner, principal, verifier;
  uint32_t sequence = 1;
  std::string create_hash, create_reply;
  int64_t expires = now() + 60000;
  bool reclaim_complete = false;
  std::set<std::string> reclaimed_filesystems;
  uint64_t replaces = 0;
  uint32_t protection = 0;
  std::vector<uint32_t> enforce, allow;
  std::shared_ptr<ssv_context> ssv;
  std::shared_ptr<uint32_t> ssv_callback_sequence;
};
struct slot {
  uint32_t seq = 0;
  std::string hash, reply;
  bool pending = false;
  replay_authority authority;
};
struct callback_gss {
  std::string server_handle, client_handle;
  uint32_t service;
  bool operator==(const callback_gss &) const = default;
};
struct session {
  uint64_t client;
  std::string principal;
  int64_t expires;
  std::vector<slot> slots;
  std::vector<uint32_t> channel;
  std::set<std::string> connections;
  uint32_t callback_program = 0;
  std::vector<uint32_t> callback_flavors;
  uint32_t callback_flavor = UINT32_MAX;
  std::string callback_credential;
  std::vector<callback_gss> callback_contexts;
  bool callback_gss_configured = false;
  std::set<std::string> back_connections, callback_up, callback_ready;
  uint32_t callback_request_limit = 0, callback_response_limit = 0;
  uint32_t callback_slots = 0, callback_sequence = 1;
  bool callback_unresolved = false;
  bool callback_session_seen = false, callback_fault = false;
  int64_t callback_retry_after = 0;
  uint64_t callback_generation = 0;
  uint32_t callback_operations = 0;
  std::string callback_extra, callback_references;

};
struct open_state {
  std::string session, fh, owner, recovery;
  uint32_t access, deny;
  uint64_t client;
  std::string object;
  std::string principal;
  json credential;
};
struct lock_range {
  uint64_t start, end;
  uint32_t type;
};
struct lock_state {
  uint64_t client;
  std::string open_other, fh, object, owner;
  std::string principal;
  std::vector<lock_range> ranges;
};
struct lock_waiter {
  lock_state state;
  lock_range range;
  std::string references;
};
std::map<uint64_t, client_id> client_ids;
std::map<std::string, session> sessions;
std::map<std::string, open_state> opens;
std::map<std::string, lock_state> byte_locks;
std::map<std::string, lock_waiter> lock_waiters;
std::map<std::string, json> reclaim;
int64_t grace_end = 0;
#include "nfs_backchannel.inc"
std::map<std::string, std::string> retained_sets;
void reap_retained() {
  std::set<std::string> live;
  for (const auto &[id, o] : opens) live.insert(o.fh);
  for (const auto &[id, r] : reclaim)
    if (r.contains("handle")) live.insert(r.at("handle"));
  for (size_t i = 0; i < file_roles().size(); ++i) {
    auto role = file_roles()[i];
    json handles = json::array();
    for (const auto &h : live) {
      auto raw = decode_bytes(h);
      if (raw.size() == 50 && static_cast<unsigned char>(raw[1]) == i)
        handles.push_back(h);
    }
    auto signature = digest(handles.dump());
    if (retained_sets[role] == signature) continue;
    try {
      call(role, "nfs_reap", {{"handles", handles}});
      retained_sets[role] = signature;
    } catch (const error &) {
      // A failed cleanup is retried, never converted into successful release.
      // Retained bytes remain charged until the file domain drops the handle.
    }
  }
}
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
void retire_client(uint64_t client) {
  for (auto it = byte_locks.begin(); it != byte_locks.end();)
    if (it->second.client == client) {
      persist_locks(it->second, {}); it = byte_locks.erase(it);
    } else ++it;
  for (auto it = opens.begin(); it != opens.end();)
    if (it->second.client == client) {
      remove_recovery(it->second.recovery); it = opens.erase(it);
    } else ++it;
  std::erase_if(sessions, [&](const auto &s) { return s.second.client == client; });
  client_ids.erase(client);
}
void expire() {
  expire_callback_probes();
  nlm_expire();
  if (grace_end && now() >= grace_end) {
    for (auto &[id, b] : reclaim)
      remove_recovery(id);
    reclaim.clear();
    grace_end = 0;
  }
  for (auto it = byte_locks.begin(); it != byte_locks.end();) {
    auto c = client_ids.find(it->second.client);
    if (c == client_ids.end() || c->second.expires <= now()) {
      persist_locks(it->second, {});
      it = byte_locks.erase(it);
    } else
      ++it;
  }
  for (auto it = opens.begin(); it != opens.end();) {
    auto s = client_ids.find(it->second.client);
    if (s == client_ids.end() || s->second.expires <= now()) {
      remove_recovery(it->second.recovery);
      it = opens.erase(it);
    } else
      ++it;
  }
  std::erase_if(sessions, [](const auto &s) { return s.second.expires <= now(); });
  std::erase_if(client_ids, [](const auto &c) { return c.second.expires <= now(); });
  reap_retained();
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
bool protected_gss(const identity &who) {
  auto service = who.credential.value("service", 0u);
  auto auth = who.credential.value("auth", "");
  return (auth == "rpcsec-gss" || auth == "rpcsec-ssv") && (service == 2 || service == 3);
}
bool machine_credential(const client_id &client, const identity &who) {
  // The RPCSEC_GSS acceptor currently accepts only Kerberos; who.key includes
  // both that mechanism and the authenticated principal, never the local UID.
  return client.protection && protected_gss(who) && client.principal == who.key;
}
bool state_credential(const client_id &client, const identity &who) {
  if (client.protection == 1) return machine_credential(client, who);
  return client.protection == 2 && protected_gss(who) && client.ssv &&
      who.credential.value("auth", "") == "rpcsec-ssv" &&
      who.credential.value("ssv_client", uint64_t(0)) != 0 &&
      client_ids.contains(who.credential.at("ssv_client").get<uint64_t>()) &&
      client_ids.at(who.credential.at("ssv_client").get<uint64_t>()).ssv == client.ssv;
}
void enforce_machine(const client_id &client, const identity &who, uint32_t op) {
  if (client.protection && has(client.enforce, op))
    check(state_credential(client, who), 10082);
}
bool machine_cleanup(const std::string &sid, const identity &who, uint32_t op) {
  const auto &client = client_ids.at(sessions.at(sid).client);
  return has(client.allow, op) && state_credential(client, who);
}
struct ssv_selection { uint32_t hash, cipher, hash_index, cipher_index; };
ssv_selection select_ssv(const json &a, const ssv_context *existing = nullptr) {
  static const std::map<std::string, uint32_t> hashes = {
      {"06052b0e03021a", 1}, {"0609608648016503040204", 224},
      {"0609608648016503040201", 256}, {"0609608648016503040202", 384},
      {"0609608648016503040203", 512}};
  static const std::map<std::string, uint32_t> ciphers = {
      {"0609608648016503040102", 128}, {"0609608648016503040116", 192},
      {"060960864801650304012a", 256}};
  check(!a.at("hashes").empty() && !a.at("ciphers").empty() && a.at("ssv_window") != 0);
  std::vector<std::pair<uint32_t, uint32_t>> offered_hashes, offered_ciphers;
  for (uint32_t i = 0; i < a.at("hashes").size(); ++i) {
    auto found = hashes.find(a.at("hashes")[i].get<std::string>());
    if (found != hashes.end()) offered_hashes.emplace_back(found->second, i);
  }
  for (uint32_t i = 0; i < a.at("ciphers").size(); ++i) {
    auto found = ciphers.find(a.at("ciphers")[i].get<std::string>());
    if (found != ciphers.end()) offered_ciphers.emplace_back(found->second, i);
  }
  check(!offered_hashes.empty(), 10072);
  check(!offered_ciphers.empty(), 10079);
  // Prefer the strongest compatible pair, avoiding SHA-1 whenever possible.
  std::sort(offered_hashes.rbegin(), offered_hashes.rend());
  std::sort(offered_ciphers.rbegin(), offered_ciphers.rend());
  for (auto [hash, hi] : offered_hashes) for (auto [cipher, ci] : offered_ciphers) {
    if (cipher > (hash == 1 ? 160 : hash)) continue;
    if (existing && (hash != existing->hash_bits() || cipher != existing->cipher_bits())) continue;
    if (existing) check(a.at("ssv_window").get<uint32_t>() >= existing->window());
    return {hash, cipher, hi, ci};
  }
  check(false, existing ? 10027 : 10079);
  return {};
}
std::vector<uint32_t> supported_attrs() {
  std::vector<uint32_t> b(3);
  for (unsigned n : {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 19, 20, 27, 28, 29,
                     30, 31, 33, 35, 36, 37, 42, 43, 44, 45, 47, 48, 51, 52, 53, 54, 55, 74, 75})
    b[n / 32] |= 1u << (n % 32);
  return b;
}
std::vector<uint32_t> writable_attrs() {
  // Verifiers live in the database, so timestamps need not be reserved.
  return {(1u << 4) | (1u << 12), (1u << 1) | (1u << 4) | (1u << 5) | (1u << 16) | (1u << 22)};
}
json meta4(const identity &who, const std::string &h, bool acl = false) {
  check(!h.empty(), 10020);
  if (h == pseudo) {
    auto view = export_view(who);
    return {{"directory", true},
            {"size", 0},
            {"fileid", "0000000000000001"},
            {"fsid", "0000000000000000"},
            {"modified_ns", 0},
            {"change", view.at("epoch")},
            {"mode", 0555},
            {"acl",
             json::array({{{"type", 0}, {"flags", 0}, {"mask", 0x1200a9}, {"who", "EVERYONE@"}}})},
            {"quota", 0},
            {"used", 0},
            {"handle", pseudo}};
  }
  auto result = file(who, h, "stat");
  if (acl)
    result["acl"] = file(who, h, "acl").at("acl");
  return result;
}
void attributes4(writer &out, const std::vector<uint32_t> &requested, const json &m) {
  check(!has(requested, 48) && !has(requested, 54) &&
        !has(requested, 74)); // Write-only attributes.
  auto supported = supported_attrs();
  std::vector<uint32_t> returned(supported.size());
  writer values;
  for (unsigned i = 0; i < supported.size() * 32; ++i)
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
        values.u64(m.value("change", uint64_t(0)));
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
      case 12:
        values.u32(uint32_t(m.at("acl").size()));
        for (const auto &ace : m.at("acl"))
          values.u32(ace.at("type"))
              .u32(ace.at("flags"))
              .u32(ace.at("mask"))
              .opaque(ace.at("who").get<std::string>());
        break;
      case 13:
        values.u32(3); // ACL4_SUPPORT_ALLOW_ACL | ACL4_SUPPORT_DENY_ACL
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
        values.u32(m.value("mode", dir ? 0700u : 0600u));
        break;
      case 35:
        values.u32(dir ? 2 : 1);
        break;
      case 36:
        values.opaque(std::to_string(m.value("uid", 65534u)));
        break;
      case 37:
        values.opaque(std::to_string(m.value("gid", 65534u)));
        break;
      case 42:
      case 43:
        values.u64(total > used ? total - used : 0);
        break;
      case 44:
        values.u64(total);
        break;
      case 45:
        values.u64(m.value("allocated", size));
        break;
      case 47:
        values.u64(m.value("accessed_ns", ns) / 1000000000)
            .u32(uint32_t(m.value("accessed_ns", ns) % 1000000000));
        break;
      case 52:
        values.u64(m.value("changed_ns", ns) / 1000000000)
            .u32(uint32_t(m.value("changed_ns", ns) % 1000000000));
        break;
      case 53:
        values.u64(ns / 1000000000).u32(uint32_t(ns % 1000000000));
        break;
      case 51:
#ifdef _WIN32
        values.u64(0).u32(100); // NTFS FILETIME precision.
#else
        values.u64(0).u32(1);
#endif
        break;
      case 75:
        put_bitmap(values, writable_attrs());
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
  auto bytes = r.opaque(65536);
  return {{"bits", bits}, {"bytes", encode_bytes(bytes)}};
}
void validate_verify4(const json &a) {
  auto bits = a.at("bits").get<std::vector<uint32_t>>();
  auto bytes = decode_bytes(a.at("bytes").get<std::string>());
  reader r(bytes);
  for (unsigned i = 0; i < bits.size() * 32; ++i) {
    if (!has(bits, i))
      continue;
    switch (i) {
    case 0:
    case 75:
      bitmap(r);
      break;
    case 5:
    case 6:
    case 7:
    case 9:
      r.boolean();
      break;
    case 1:
    case 2:
    case 10:
    case 13:
    case 28:
    case 29:
    case 35:
      r.u32();
      break;
    case 3:
    case 4:
    case 20:
    case 27:
    case 30:
    case 31:
    case 42:
    case 43:
    case 44:
    case 45:
    case 55:
      r.u64();
      break;
    case 8:
      r.u64();
      r.u64();
      break;
    case 19:
    case 36:
    case 37:
      r.opaque(1024);
      break;
    case 33:
      check(r.u32() <= 07777);
      break;
    case 47:
    case 51:
    case 52:
    case 53:
      r.u64();
      check(r.u32() < 1000000000);
      break;
    case 12: {
      auto n = r.u32();
      check(n <= 1024);
      while (n--) {
        r.u32();
        r.u32();
        r.u32();
        r.opaque(1024);
      }
      break;
    }
    // RDATTR_ERROR and write-only attributes cannot participate in VERIFY.
    case 11:
    case 48:
    case 54:
    case 74:
      check(false);
      break;
    default:
      check(false, 10032);
    }
  }
  r.end();
}
json create_attrs4(const json &a, bool dir, bool create = true) {
  auto bits = a.at("bits").get<std::vector<uint32_t>>();
  auto bytes = decode_bytes(a.at("bytes").get<std::string>());
  reader r(bytes);
  json attrs = json::object();
  check(!has(bits, 74) || (!create && !has(bits, 33)));
  for (unsigned i = 0; i < bits.size() * 32; ++i)
    if (has(bits, i)) {
      if (i == 12) {
        auto count = r.u32();
        check(count <= 1024);
        attrs["acl"] = json::array();
        for (uint32_t n = 0; n < count; ++n) {
          auto type = r.u32(), flags = r.u32(), mask = r.u32();
          auto who = r.opaque(1024);
          check(type <= 1, 10032);
          check(!(flags & ~0xcfu) && !(mask & ~0x1f01ffu));
          check(dir || !(flags & 15), 10032);
          check(!(flags & 12) || (flags & 3), 10032);
          check(!who.empty());
          attrs["acl"].push_back({{"type", type}, {"flags", flags}, {"mask", mask}, {"who", who}});
        }
      } else if (i == 33) {
        auto mode = r.u32();
        check(mode <= 07777);
        attrs["mode"] = mode;
      } else if (i == 74) {
        auto value = r.u32(), mask = r.u32();
        check(value <= 07777 && mask <= 07777);
        attrs["mode_mask"] = {{"value", value}, {"mask", mask}};
      } else if (i == 4) {
        auto size = r.u64();
        check(size <= uint64_t(INT64_MAX), 27);
        check(!dir, 21);
        attrs["size"] = size;
      } else if (i == 36 || i == 37) {
        auto owner = r.opaque(1024);
        check(!owner.empty() && owner.size() <= 10 &&
                  owner.find_first_not_of("0123456789") == std::string::npos, 10039);
        auto id = std::stoull(owner);
        check(id <= UINT32_MAX, 10039);
        attrs[i == 36 ? "uid" : "gid"] = id;
      } else if (i == 48 || i == 54) {
        auto how = r.u32();
        check(how <= 1);
        uint64_t ns = uint64_t(now()) * 1000000;
        if (how == 1) {
          auto sec = r.u64(); auto nano = r.u32();
          check(nano < 1000000000 && sec <= (uint64_t(INT64_MAX) - nano) / 1000000000, 22);
          ns = sec * 1000000000 + nano;
        }
        attrs[i == 48 ? "atime_ns" : "mtime_ns"] = ns;
      } else
        check(false, has(supported_attrs(), i) ? 22 : 10032);
    }
  r.end();
  (void)dir;
  (void)create;
  return attrs;
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
std::vector<uint32_t> callback_security(reader &r, json &a) {
  auto n = r.u32();
  if (n > 16) throw xdr_error();
  std::vector<uint32_t> flavors;
  for (uint32_t i = 0; i < n; ++i) {
    auto auth = r.u32();
    flavors.push_back(auth);
    auto start = r.pos;
    if (auth == 1) {
      r.u32(); r.opaque(255); r.u32(); r.u32();
      auto groups = r.u32();
      if (groups > 16) throw xdr_error();
      for (uint32_t j = 0; j < groups; ++j) r.u32();
    } else if (auth == 6) {
      auto service = r.u32();
      auto server = r.opaque(1024), client = r.opaque(1024);
      a["callback_gss"].push_back({{"service", service}, {"server", encode_bytes(server)},
                                   {"client", encode_bytes(client)}});
    } else if (auth != 0) throw xdr_error();
    if (auth <= 1 && !a.contains("callback_auth"))
      a["callback_auth"] = {{"flavor", auth}, {"credential", encode_bytes(r.data.substr(start, r.pos - start))}};
  }
  return flavors;
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
    check(a["protect"].get<uint32_t>() <= 2, 10006);
    if (a["protect"] != 0) {
      a["enforce"] = bitmap(r);
      a["allow"] = bitmap(r);
    }
    if (a["protect"] == 2) {
      for (auto field : {"hashes", "ciphers"}) {
        auto count = r.u32();
        if (count > 32) throw xdr_error();
        a[field] = json::array();
        for (uint32_t i = 0; i < count; ++i) a[field].push_back(encode_bytes(r.opaque(128)));
      }
      a["ssv_window"] = r.u32();
      a["ssv_handles"] = r.u32();
    }
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
    a["callback_program"] = r.u32();
    a["callback_flavors"] = callback_security(r, a);
    break;
  }
  case 40:
    a["callback_program"] = r.u32();
    a["callback_flavors"] = callback_security(r, a);
    break;
  case 54:
    a["ssv"] = encode_bytes(r.opaque(1024));
    a["digest"] = encode_bytes(r.opaque(1024));
    break;
  case 7: // Optional delegation purge, no delegations are issued.
  case 30: // NFSv4.0 RENEW is obsolete in v4.1.
    r.u64();
    break;
  case 8:
    r.fixed(16);
    break;
  case 19:
    r.boolean();
    break;
  case 20:
    r.fixed(16); r.u32();
    break;
  case 35:
    r.fixed(8); r.opaque(1024); r.u32();
    r.opaque(256); r.opaque(1024); r.u32();
    break;
  case 36:
    r.u64(); r.fixed(8);
    break;
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
  case 27: // READLINK is recognized; this filesystem profile has no symlinks.
    break;
  case 15:
  case 28:
  case 33:
  case 11: // LINK is recognized even though hardlinks are not advertised.
    a["name"] = r.opaque(128 * 1024);
    break;
  case 52:
    a["style"] = r.u32();
    break;
  case 46:
    r.boolean(); bitmap(r);
    r.u64(); r.u32(); r.u64(); r.u32();
    bitmap(r); bitmap(r);
    break;
  case 47:
    r.fixed(16); r.u32(); r.u32(); bitmap(r);
    break;
  case 48:
    r.u32(); r.u32(); r.u64(); r.fixed(8);
    break;
  case 49:
    r.u64(); r.u64(); r.boolean(); r.fixed(16);
    if (r.boolean()) r.u64();
    if (r.boolean()) { r.u64(); r.u32(); }
    r.u32(); r.opaque(65536);
    break;
  case 50:
    r.boolean(); r.u32(); r.u32(); r.u64(); r.u64(); r.u64(); r.fixed(16); r.u32();
    break;
  case 51:
    r.boolean(); r.u32(); r.u32();
    if (r.u32() == 1) { r.u64(); r.u64(); r.fixed(16); r.opaque(65536); }
    break;
  case 56: {
    r.u32();
    auto claim = r.u32();
    if (claim == 1) r.u32();
    else if (claim != 4 && claim != 6) throw xdr_error();
    break;
  }
  case 9:
    a["bits"] = bitmap(r);
    break;
  case 17:
  case 37:
    a["attrs"] = parse_attrs4(r);
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
      a["name"] = r.opaque(128 * 1024);
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
  case 21:
    a["state"] = encode_bytes(r.fixed(16));
    a["seq"] = r.u32();
    a["access"] = r.u32();
    a["deny"] = r.u32();
    break;
  case 12:
    a["type"] = r.u32();
    a["reclaim"] = r.boolean();
    a["offset"] = r.u64();
    a["length"] = r.u64();
    a["new"] = r.boolean();
    if (a.at("new").get<bool>()) {
      r.u32();
      a["state"] = encode_bytes(r.fixed(16));
      r.u32();
      a["client"] = r.u64();
      a["owner"] = encode_bytes(r.opaque(1024));
    } else {
      a["state"] = encode_bytes(r.fixed(16));
      r.u32();
    }
    break;
  case 13:
    a["type"] = r.u32();
    a["offset"] = r.u64();
    a["length"] = r.u64();
    a["client"] = r.u64();
    a["owner"] = encode_bytes(r.opaque(1024));
    break;
  case 14:
    a["type"] = r.u32();
    r.u32();
    a["state"] = encode_bytes(r.fixed(16));
    a["offset"] = r.u64();
    a["length"] = r.u64();
    break;
  case 39:
    a["client"] = r.u64();
    a["owner"] = encode_bytes(r.opaque(1024));
    break;
  case 34:
    a["state"] = encode_bytes(r.fixed(16));
    a["attrs"] = parse_attrs4(r);
    break;
  case 6:
    a["type"] = r.u32();
    if (a["type"] == 3 || a["type"] == 4) {
      r.u32(); r.u32();
    } else if (a["type"] == 5)
      r.opaque(128 * 1024);
    a["name"] = r.opaque(128 * 1024);
    a["attrs"] = parse_attrs4(r);
    break;
  case 29:
    a["name"] = r.opaque(128 * 1024);
    a["to"] = r.opaque(128 * 1024);
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
std::string open_key(const std::string &id, const std::string &sid) {
  check(id.size() == 32, 10025);
  for (const auto &[key, o] : opens)
    if (key.substr(8) == id.substr(8)) {
      check(o.client == sessions.at(sid).client, 10025);
      auto seq = uint32_t(std::stoul(id.substr(0, 8), nullptr, 16));
      auto current_seq = uint32_t(std::stoul(key.substr(0, 8), nullptr, 16));
      check(!seq || seq == current_seq, seq < current_seq ? 10024 : 10025);
      return key;
    }
  check(false, 10025);
  return {};
}
std::string next_state(const std::string &id) {
  writer st;
  auto seq = uint32_t(std::stoul(id.substr(0, 8), nullptr, 16));
  st.u32(seq == UINT32_MAX ? 1 : seq + 1).fixed(decode_bytes(id).substr(4));
  return encode_bytes(st.data);
}
open_state &state4(const std::string &id, const std::string &sid, const std::string &h,
                   uint32_t access, const identity &who, uint32_t cleanup_op = 0) {
  auto it = opens.find(open_key(id, sid));
  check(it->second.fh == h, 10025);
  check(it->second.principal == who.key || machine_cleanup(sid, who, cleanup_op),
        client_ids.at(sessions.at(sid).client).protection ? 10082 : 10025);
  check((it->second.access & access) == access, 10038);
  return it->second;
}
#include "nfs_locks.inc"
void change4(writer &w, uint64_t before, uint64_t after) {
  // External host mutations cannot be serialized with the server's operation.
  w.boolean(false).u64(before).u64(after);
}
std::string v4(const identity &who, reader &r) {
  struct clear_authority {
    impl &self;
    ~clear_authority() { self.recording_authority = nullptr; }
  } cleanup{*this};
  auto tag = r.opaque(1024);
  auto minor = r.u32(), count = r.u32();
  auto start = r.pos; // The diagnostic tag is not part of replay identity.
  writer out;
  if (minor != 1)
    return out.u32(10021).opaque(tag).u32(0).data;
  for (size_t offset = 0; offset < tag.size();) {
    utf8proc_int32_t codepoint;
    auto n = utf8proc_iterate(reinterpret_cast<const utf8proc_uint8_t *>(tag.data() + offset),
                              tag.size() - offset, &codepoint);
    if (n < 0 || (codepoint >= 0xfdd0 && codepoint <= 0xfdef) ||
        (codepoint & 0xffff) == 0xfffe || (codepoint & 0xffff) == 0xffff)
      return out.u32(22).opaque(tag).u32(0).data;
    offset += size_t(n);
  }
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
  // A shared AUTH_SYS session must never replay another user's cached data.
  auto hash = digest(who.key + std::string(r.data.substr(start)));
  expire();
  std::string sid, current, saved, current_state, saved_state, sequence_args, sequence_result;
  slot *active = nullptr;
  uint32_t final_status = 0, done = 0;
  writer results;
  auto session_check = [&](const std::string &id) -> session & {
    auto i = sessions.find(id);
    // AUTH_SYS sessions belong to the loopback client host. A kernel client
    // multiplexes different users on one session; each file operation still
    // obtains fresh authority and each open state is bound to its principal.
    check(i != sessions.end(), 10052);
    return i->second;
  };
  // Reserve sufficient cached response space before any compound side effects.
  size_t bound = tag.size() + 64;
  for (const auto &a : ops) {
    unsigned op = a.at("op");
    bound += (op == 25 || op == 26) ? std::min(a.value("count", 0u), 65536u) + 64
                                  : (op == 9 || op == 42 ? 1024 : 256);
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
      if (index == 0 && op != 53 && !a.value("unknown", false)) {
        bool standalone = op == 42 || op == 43 || op == 44 || op == 41 || op == 57;
        check(standalone, 10071);
        check(ops.size() == 1, 10081);
      }
      if (a.value("unknown", false)) check(false, 10044);
      if (index > 0)
        check(op != 53, 10064);
      if (!sid.empty()) enforce_machine(client_ids.at(sessions.at(sid).client), who, op);
      if (op == 42) {
        auto protection = a.at("protect").get<uint32_t>();
        check(!protection || protected_gss(who), 1);
        auto flags = a.at("flags").get<uint32_t>();
        check((flags & ~0x40070103u) == 0);
        uint64_t id = 0;
        bool confirmed = false;
        uint64_t existing = 0;
        std::vector<uint64_t> unconfirmed;
        for (const auto &[n, c] : client_ids)
          if (c.owner == a.at("owner").get<std::string>()) {
            if (c.create_reply.empty()) unconfirmed.push_back(n);
            else existing = n;
          }
        uint64_t replaces = 0;
        if (existing && client_ids.at(existing).protection == 1) {
          // A downgrade or another principal cannot replace even an idle,
          // confirmed machine-protected client during its lease.
          check(machine_credential(client_ids.at(existing), who), flags & 0x40000000 ? 1 : 10017);
        }
        bool ssv_owner = false;
        if (existing && client_ids.at(existing).protection == 2) {
          const auto &c = client_ids.at(existing);
          enforce_machine(c, who, op);
          ssv_owner = state_credential(c, who) && (has(c.enforce, op) || has(c.allow, op));
          check(ssv_owner || machine_credential(c, who), flags & 0x40000000 ? 1 : 10017);
        }
        ssv_selection algorithms{};
        uint32_t handle_count = 0;
        if (protection == 2) {
          const ssv_context *old = existing && client_ids.at(existing).verifier == a.at("verifier").get<std::string>()
              ? client_ids.at(existing).ssv.get() : nullptr;
          algorithms = select_ssv(a, old);
          handle_count = std::min(a.at("ssv_handles").get<uint32_t>(), 8u);
          check(gss_sessions.size() + handle_count <= 128, 10018);
        }
        if (flags & 0x40000000) {
          check(existing != 0, 2);
          auto &c = client_ids.at(existing);
          check(c.principal == who.key || ssv_owner, 1);
          check(c.verifier == a.at("verifier").get<std::string>(), 10027);
          id = existing; confirmed = true;
        } else if (existing) {
          auto &c = client_ids.at(existing);
          if ((c.principal == who.key || ssv_owner) && c.verifier == a.at("verifier").get<std::string>()) {
            id = existing; confirmed = true;
          } else if (c.principal == who.key || ssv_owner) replaces = existing;
          else {
            for (const auto &[key, o] : opens) check(o.client != existing, 10017);
            for (const auto &[key, s] : sessions) check(s.client != existing, 10017);
            retire_client(existing);
          }
        }
        if (!id) {
          for (auto old : unconfirmed) retire_client(old);
          check(client_ids.size() < 128, 10018);
          id = hex64(random_hex(8)) & INT64_MAX;
          client_ids[id] = {a.at("owner"), who.key, a.at("verifier"), 1, "", ""};
          client_ids.at(id).replaces = replaces;
        }
        auto &client = client_ids.at(id);
        if (confirmed) check(client.protection == protection, 10027);
        // RFC 8881 18.35.3: the protection method and both operation lists
        // become immutable at confirmation, including explicit UPDATE calls.
        if (!confirmed) {
          client.protection = protection;
          if (protection) {
            client.enforce = a.at("enforce").get<std::vector<uint32_t>>();
            auto requested = a.at("allow").get<std::vector<uint32_t>>();
            // These operations only release state; they cannot grant machine
            // credentials the user's data or namespace access.
            client.allow = {0, 0};
            for (auto cleanup : {4u, 14u, 21u, 45u})
              if (has(requested, cleanup)) client.allow[cleanup / 32] |= 1u << (cleanup % 32);
            if (protection == 2) {
              if (has(requested, 42)) client.allow[1] |= 1u << (42 - 32);
              client.ssv = std::make_shared<ssv_context>(algorithms.hash, algorithms.cipher,
                  std::min(a.at("ssv_window").get<uint32_t>(), 16u));
              client.ssv_callback_sequence = std::make_shared<uint32_t>(0);
            }
          }
        }
        body.u64(id)
            .u32(client_ids.at(id).sequence)
            .u32(0x10000 | (client.protection ? 0x100u : 0) | (confirmed ? 0x80000000u : 0))
            .u32(client.protection);
        if (client.protection) {
          put_bitmap(body, client.enforce);
          put_bitmap(body, client.allow);
        }
        if (client.ssv) {
          body.u32(algorithms.hash_index).u32(algorithms.cipher_index).u32(client.ssv->length())
              .u32(client.ssv->window()).u32(handle_count);
          for (uint32_t n = 0; n < handle_count; ++n) {
            auto handle = decode_bytes(random_hex(32));
            gss_session entry;
            entry.ssv = client.ssv; entry.ssv_client = id;
            entry.ssv_callback_sequence = client.ssv_callback_sequence;
            entry.principal = "ssv:" + std::to_string(id);
            entry.program = 100003; entry.version = 4;
            entry.mic_size = client.ssv->mic_size();
            entry.expires = std::chrono::steady_clock::time_point::max();
            gss_sessions.emplace(handle, std::move(entry));
            body.opaque(handle);
          }
        }
        body.u64(1)
            .opaque("tauCloud")
            .opaque("tauCloud-loopback")
            .u32(0);
      } else if (op == 43) {
        auto id = a.at("client").get<uint64_t>();
        auto it = client_ids.find(id);
        check(it != client_ids.end(), 10022);
        auto &c = it->second;
        auto seq = a.at("seq").get<uint32_t>();
        bool confirmation = c.create_reply.empty() || (seq == 1 && c.sequence == 2);
        if (c.protection && confirmation) check(machine_credential(c, who), 10082);
        else enforce_machine(c, who, op);
        check(!c.create_reply.empty() || c.principal == who.key, 10017);
        if (seq + 1 == c.sequence && !c.create_reply.empty()) {
          // CREATE_SESSION has its own replay slot, independent of the enclosing
          // COMPOUND/session/tag. The sequence ID identifies the cached result.
          body.fixed(c.create_reply);
        } else {
          check(seq == c.sequence, 10063);
          check((a.at("flags").get<uint32_t>() & ~7u) == 0);
          check(sessions.size() < 32, 10018);
          auto fore = a.at("fore").get<std::vector<uint32_t>>();
          check(fore[1] >= 256 && fore[2] >= 256 && fore[4] > 0 && fore[5] > 0,
                10005);
          auto back_offer = a.at("back").get<std::vector<uint32_t>>();
          check(back_offer[1] >= 128 && back_offer[2] >= 128 && back_offer[4] && back_offer[5], 10005);
          fore = {0, std::min(fore[1], 128 * 1024u), std::min(fore[2], 128 * 1024u),
                  std::min({fore[3], fore[2], 128 * 1024u}), std::min(fore[4], 16u),
                  std::min(fore[5], 8u)};
          // RFC 8881 18.36.3: both channels may reduce buffer sizes, but the
          // backchannel must preserve the client's operation and slot counts.
          // These bounds alone do not grant a backchannel; binding is negotiated below.
          std::vector<uint32_t> back = {0, std::min(back_offer[1], 4096u),
              std::min(back_offer[2], 4096u), 0, back_offer[4], back_offer[5]};
          session prepared{id, who.key, now() + 60000, std::vector<slot>(fore[5]), fore, {connection}};
          configure_callback(prepared, a); // Validate every handle before replacing client state.
          auto idstr = random_hex(16);
          if (c.replaces) {
            if (!sid.empty() && sessions.at(sid).client == c.replaces) {
              active = nullptr;
              recording_authority = nullptr;
            }
            retire_client(c.replaces);
            c.replaces = 0;
          }
          sessions.emplace(idstr, std::move(prepared));
          sessions.at(idstr).callback_program = a.at("callback_program");
          sessions.at(idstr).callback_flavors = a.at("callback_flavors").get<std::vector<uint32_t>>();
          auto &created = sessions.at(idstr);
          created.callback_request_limit = back[1];
          created.callback_response_limit = back[2];
          created.callback_slots = back[5];
          created.callback_operations = back[4];
          bool backchannel = (a.at("flags").get<uint32_t>() & 2) && callback_available(created);
          if (backchannel) created.back_connections.insert(connection);
          body.fixed(decode_bytes(idstr)).u32(seq).u32(backchannel ? 2 : 0);
          put_channel(body, fore);
          put_channel(body, back);
          c.create_hash = hash;
          c.create_reply = body.data;
          ++c.sequence;
          if (backchannel) probe_callback(idstr, connection);
        }
      } else if (op == 53) {
        sid = a.at("session");
        auto &s = session_check(sid);
        auto &client = client_ids.at(s.client);
        enforce_machine(client, who, op);
        if (client.protection && has(client.enforce, 41))
          check(s.connections.contains(connection), 10055);
        check(s.connections.contains(connection) || s.connections.size() < 64, 10018);
        s.connections.insert(connection);
        // Do not replay a protected result using authentication-only GSS.
        // Integrity and privacy are interchangeable for this protection rule.
        if (client.protection) hash = digest(hash + (protected_gss(who) ? ":protected" : ":unprotected"));
        check(r.data.size() <= s.channel[1], 10065);
        check(count <= s.channel[4], 10070);
        check(bound <= s.channel[2], 10066);
        check(!a.at("cache").get<bool>() || bound <= s.channel[3], 10067);
        auto n = a.at("slot").get<uint32_t>();
        check(n < s.slots.size(), 10053);
        check(a.at("highest").get<uint32_t>() >= n, 10077);
        auto &sl = s.slots[n];
        auto seq = a.at("seq").get<uint32_t>();
        if (seq == sl.seq && sl.seq) {
          check(hash == sl.hash, 10076);
          check(!sl.pending && !sl.reply.empty(), 10008);
          replay_authorized(who, sl.authority);
          s.callback_session_seen = true;
          sequence_callback(sid);
          s.expires = now() + 60000;
          client_ids.at(s.client).expires = s.expires;
          return sl.reply;
        }
        check(seq == sl.seq + 1 && !sl.pending, 10063);
        s.callback_session_seen = true;
        sequence_callback(sid);
        sl.seq = seq;
        sl.hash = hash;
        sl.reply.clear();
        sl.authority = {};
        sl.pending = true;
        active = &sl;
        recording_authority = &sl.authority;
        s.expires = now() + 60000;
        client_ids.at(s.client).expires = s.expires;
        body.fixed(decode_bytes(sid))
            .u32(seq)
            .u32(n)
            .u32(uint32_t(s.slots.size() - 1))
            .u32(uint32_t(s.slots.size() - 1))
            .u32((callback_path_up(s.client) ? 0 : 1) | callback_gss_flags(s) |
                 (s.callback_fault ? 0x400 : 0) |
                 (s.callback_unresolved && s.back_connections.empty() ? 0x200 : 0));
        sequence_args = writer().fixed(decode_bytes(sid)).u32(seq).u32(n)
            .u32(a.at("highest")).boolean(a.at("cache")).data;
        sequence_result = writer().u32(0).fixed(body.data).data;
      } else if (op == 41) {
        auto id = a.at("session").get<std::string>();
        auto &s = session_check(id);
        enforce_machine(client_ids.at(s.client), who, op);
        auto requested = a.at("dir").get<uint32_t>();
        check(requested == 1 || requested == 2 || requested == 3 || requested == 7);
        check(!a.at("rdma").get<bool>(), 10004);
        unsigned bound = (s.connections.contains(connection) ? 1 : 0) |
                         (s.back_connections.contains(connection) ? 2 : 0);
        if (bound) {
          // Rebinding is idempotent; it cannot change existing channel roles.
          check(requested == 3 ? (bound == 1 || bound == 3) :
                requested == 7 ? (bound == 2 || bound == 3) : bound == requested);
        } else {
          bool back = requested != 1 && callback_available(s);
          check(back || requested == 1 || requested == 3, 10004);
          bound = requested == 2 ? 2 : back ? 3 : 1;
          check(s.connections.size() + s.back_connections.size() < 64, 10018);
          if (bound & 1) s.connections.insert(connection);
          if (bound & 2) s.back_connections.insert(connection);
        }
        s.callback_session_seen = true;
        if ((bound & 2) && !s.callback_up.contains(connection)) probe_callback(id, connection);
        body.fixed(decode_bytes(id)).u32(bound).boolean(false);
      } else if (op == 44) {
        auto target = a.at("session").get<std::string>();
        auto &s = session_check(target);
        enforce_machine(client_ids.at(s.client), who, op);
        check(s.connections.contains(connection), 10055);
        check(target != sid || index + 1 == ops.size(), 10081);
        if (target == sid) { active = nullptr; recording_authority = nullptr; }
        sessions.erase(target);
      } else if (op == 57) {
        auto id = a.at("client").get<uint64_t>();
        auto i = client_ids.find(id);
        if (i != client_ids.end()) enforce_machine(i->second, who, op);
        check(i != client_ids.end() && (i->second.principal == who.key ||
              state_credential(i->second, who)), 10022);
        for (const auto &[n, s] : sessions)
          check(s.client != id, 10074);
        for (const auto &[n, o] : opens)
          check(o.client != id, 10074);
        client_ids.erase(i);
      } else {
        check(!sid.empty(), 10071);
        auto &session = session_check(sid);
        auto &client = client_ids.at(session.client);
        for (const char *field : {"name", "to"})
          if (a.contains(field)) {
            auto name = a.at(field).get<std::string>();
            check(name.size() <= 255, 63);
            check(name != "." && name != "..", 10041);
            for (size_t offset = 0; offset < name.size();) {
              utf8proc_int32_t cp;
              auto n = utf8proc_iterate(reinterpret_cast<const utf8proc_uint8_t *>(name.data()+offset),
                                        name.size()-offset, &cp);
              check(n > 0 && !(cp >= 0xfdd0 && cp <= 0xfdef) &&
                        (cp & 0xffff) != 0xfffe && (cp & 0xffff) != 0xffff);
              offset += size_t(n);
            }
            portable_path(name);
            check(name.find('/') == std::string::npos);
          }
        auto request =
            digest(sid + std::to_string(a.at("op").get<unsigned>()) + hash + std::to_string(index));
        if (a.contains("state") && a.at("state") == "00000001000000000000000000000000") {
          check(!current_state.empty(), 10025);
          a["state"] = current_state;
        }
        auto put_handle = [&](const std::string &handle) {
          check(handle == pseudo || decode_bytes(handle).size() == 50, 10001);
          size_t next = index + 1;
          while (next < ops.size() && ops[next].at("op") == 32) ++next; // SAVEFH is transparent.
          auto following = next == ops.size() ? 0u : ops[next].at("op").get<unsigned>();
          bool discovery = !following || following == 22 || following == 23 || following == 24 ||
              following == 31 || following == 15 || following == 16 || following == 33 || following == 52 ||
              (following == 18 && ops[next].value("claim", 0u) == 0);
          if (handle != pseudo) {
            bool cleanup_handle = false;
            if (next < ops.size() && ops[next].contains("state") && machine_cleanup(sid, who, following)) {
              // Permit PUTFH for releasing this client's known state even if
              // the user's mapping/ticket is gone. Never use this for data I/O.
              try {
                auto state = ops[next].at("state").get<std::string>();
                auto key = following == 14 ? io_state(state, sid) : open_key(state, sid);
                cleanup_handle = opens.at(key).fh == handle;
              } catch (const failure &) {}
            }
            if (!cleanup_handle) {
              if (discovery) file(who, handle, "stat", json::object(), "", "", true);
              else meta4(who, handle);
            }
          }
          current = handle;
          current_state.clear();
        };
        if (op == 40) {
          auto flavors = a.at("callback_flavors").get<std::vector<uint32_t>>();
          auto &s = sessions.at(sid);
          configure_callback(s, a); // Atomic: invalid additions preserve the old channel.
          s.callback_program = a.at("callback_program");
          s.callback_flavors = std::move(flavors);
          ++s.callback_generation;
          s.callback_up.clear();
          s.callback_ready.clear();
          for (const auto &bound : s.back_connections) probe_callback(sid, bound);
        } else if (op == 54) {
          check(client.protection == 2 && client.ssv);
          try {
            body.opaque(client.ssv->update(decode_bytes(a.at("ssv").get<std::string>()), sequence_args,
                decode_bytes(a.at("digest").get<std::string>()), sequence_result));
          } catch (const error &e) {
            std::string_view reason(e.what());
            check(false, reason == "ssv_digest" ? 10051 : reason == "ssv_length" ? 22 : 10018);
          }
        } else if (op == 24 || op == 23) {
          put_handle(pseudo);
        } else if (op == 22) {
          put_handle(a.at("handle"));
        } else if (op == 10) {
          meta4(who, current);
          body.opaque(decode_bytes(current));
        } else if (op == 32) {
          check(!current.empty(), 10020);
          if (current != pseudo) file(who, current, "stat", json::object(), "", "", true);
          saved = current;
          saved_state = current_state;
        } else if (op == 31) {
          check(!saved.empty(), 10030);
          put_handle(saved);
          current_state = saved_state;
        } else if (op == 15) {
          check(!current.empty(), 10020);
          auto m = current == pseudo ? file(who, "", "root", json::object(), "", a.at("name"))
                                     : file(who, current, "lookup", {{"name", a.at("name")}});
          current = m.at("handle");
          current_state.clear();
        } else if (op == 9) {
          auto m = meta4(who, current, has(a.at("bits").get<std::vector<uint32_t>>(), 12));
          attributes4(body, a.at("bits").get<std::vector<uint32_t>>(), m);
        } else if (op == 16) {
          check(!current.empty(), 10020);
          check(current != pseudo, 2);
          auto m = file(who, current, "parent", json::object(), "", "", true);
          current = m.value("export_root", false) ? pseudo : m.at("handle").get<std::string>();
          if (current != pseudo) meta4(who, current);
          current_state.clear();
        } else if (op == 17 || op == 37) {
          auto bits = a.at("attrs").at("bits").get<std::vector<uint32_t>>();
          auto supported = supported_attrs();
          for (size_t i = 0; i < bits.size(); ++i)
            check((bits[i] & ~(i < supported.size() ? supported[i] : 0u)) == 0, 10032);
          validate_verify4(a.at("attrs"));
          writer attrs;
          attributes4(attrs, bits, meta4(who, current, has(bits, 12)));
          reader actual(attrs.data);
          bitmap(actual);
          bool same = encode_bytes(actual.opaque()) == a.at("attrs").at("bytes").get<std::string>();
          check(op == 37 ? same : !same, op == 37 ? 10027 : 10009);
        } else if (op == 3) {
          auto access_meta = meta4(who, current);
          auto asked = a.at("access").get<uint32_t>();
          uint32_t allowed = asked & 0x23;
          if (current != pseudo) {
            try {
              auto raw = decode_bytes(current);
              json b = {{"peer", "127.0.0.1"},
                        {"credential", who.credential},
                        {"uuid", encode_bytes(raw.substr(2, 16))},
                        {"write", true}};
              authorize(b);
              allowed = asked & 0x3f;
            } catch (...) {
            }
          }
          if (current != pseudo) {
            auto rights = access_meta.at("security_access").get<uint32_t>();
            uint32_t acl =
                ((rights & 1) ? 1u : 0u) | ((rights & 0x20) ? 0x22u : 0u) |
                ((rights & 2) ? 4u : 0u) | ((rights & 4) ? 8u : 0u) |
                ((rights & (access_meta.at("directory").get<bool>() ? 0x40u : 0x10000u)) ? 16u
                                                                                         : 0u);
            allowed &= acl;
          }
          body.u32(asked & 0x3f).u32(allowed);
        } else if (op == 46) {
          check(meta4(who, current).at("directory"), 20);
          // Directory delegation is optional: decline without granting state
          // or promising a callback. Modern clients can then use READDIR.
          body.u32(1).boolean(false); // GDD4_UNAVAIL, will_signal=false.
        } else if (op == 33 || op == 52) {
          check(!current.empty(), 10020);
          auto target = current;
          if (op == 52) {
            check(a.at("style").get<uint32_t>() <= 1);
            if (a.at("style") == 1) {
              check(current != pseudo, 2);
              auto m = file(who, current, "parent", json::object(), "", "", true);
              target = m.value("export_root", false) ? pseudo : m.at("handle").get<std::string>();
            }
            else if (current != pseudo) file(who, current, "stat", json::object(), "", "", true);
          }
          else if (current == pseudo)
            target = file(who, "", "root", json::object(), "", a.at("name"), true).at("handle");
          else
            target = file(who, current, "lookup", {{"name", a.at("name")}}, "", "", true).at("handle");
          auto flavors = target == pseudo ?
              (cfg.nfs_gss_service.empty() ? json::array({"sys"}) : json::array({"sys", "krb5", "krb5i", "krb5p"})) :
              security_flavors(who, target, "", true);
          body.u32(uint32_t(flavors.size()));
          for (const auto &flavor : flavors) {
            if (flavor == "sys") body.u32(1);
            else body.u32(6).opaque(decode_bytes("2a864886f712010202")).u32(0)
                .u32(flavor == "krb5" ? 1 : flavor == "krb5i" ? 2 : 3);
          }
          current.clear();
        } else if (op == 18) {
          auto access = a.at("access").get<uint32_t>(), deny = a.at("deny").get<uint32_t>();
          check((access & 3) > 0 && (access & ~0x3ff03u) == 0 &&
                    (access & 0xff00u) <= 0x500 && deny <= 3);
          access &= 3;
          // NFSv4.1 takes the client identity from SEQUENCE, not open_owner4.clientid.
          check(opens.size() < 1024, 10018);
          auto claim = a.at("claim").get<unsigned>();
          bool recovering = claim == 1;
          check(recovering || client.reclaim_complete, 10013);
          check(!recovering || !client.reclaim_complete, 10033);
          check(!grace_end || recovering, 10013);
          check(!recovering || grace_end, 10033);
          check(current != pseudo && !current.empty(), 10020);
          if (a.at("create") == 1) {
            check(claim == 0, 22);
            if (a.at("mode") == 3) {
              auto bits = a.at("attrs").at("bits").get<std::vector<uint32_t>>();
              auto allowed = writable_attrs();
              for (size_t i = 0; i < bits.size(); ++i)
                check((bits[i] & ~(i < allowed.size() ? allowed[i] : 0u)) == 0, 22);
            }
            if (a.contains("attrs")) create_attrs4(a.at("attrs"), false);
          }
          auto target = current;
          bool created = false;
          std::vector<uint32_t> attrset;
          uint64_t parent_before = claim == 0 ? meta4(who, current).at("change").get<uint64_t>() : 0;
          if (claim == 0) {
            try {
              target = file(who, current, "lookup", {{"name", a.at("name")}}).at("handle");
              check(a.at("create") == 0 || a.at("mode") != 1, 17);
              if (a.at("create") == 1) {
                auto attrs = a.contains("attrs") ? create_attrs4(a.at("attrs"), false) : json::object();
                attrs["name"] = a.at("name"); attrs["create_mode"] = a.at("mode");
                if (a.contains("verifier")) attrs["verifier"] = a.at("verifier");
                auto result = file(who, current, "create", attrs, request);
                target = result.at("handle"); created = result.value("created", false);
              }
            } catch (const error &e) {
              if (std::string_view(e.what()) != "not_found" || a.at("create") != 1)
                throw;
              auto attrs = a.contains("attrs") ? create_attrs4(a.at("attrs"), false) : json::object();
              attrs["name"] = a.at("name");
              attrs["create_mode"] = a.at("mode");
              if (a.contains("verifier")) attrs["verifier"] = a.at("verifier");
              auto result = file(who, current, "create", attrs, request);
              target = result.at("handle"); created = result.value("created", false);
            }
          }
          uint64_t parent_after = claim == 0 ? meta4(who, current).at("change").get<uint64_t>() : 0;
          auto m = meta4(who, target);
          check(!m.at("directory").get<bool>(), 21);
          check((access & ~m.at("security_access").get<uint32_t>()) == 0, 13);
          // Authorization is checked for read and for the requested write access.
          if (access & 2) {
            auto raw = decode_bytes(target);
            json b = {{"peer", "127.0.0.1"},
                      {"credential", who.credential},
                      {"uuid", encode_bytes(raw.substr(2, 16))},
                      {"write", true}};
            authorize(b);
          }
          auto owner = a.at("owner").get<std::string>();
          std::string previous;
          for (const auto &[id, o] : opens) {
            if (o.client == session.client && o.owner == owner && o.fh == target && o.principal == who.key)
              previous = id;
          }
          if (!previous.empty()) {
            access |= opens.at(previous).access;
            deny |= opens.at(previous).deny;
          }
          auto rid = digest(client.owner + who.key + owner + target);
          json durable = {{"client", client.owner}, {"principal", who.key}, {"owner", owner},
                          {"handle", target},       {"access", access},     {"deny", deny}};
          if (recovering) {
            check(a.at("delegation") == 0 && reclaim.contains(rid) && reclaim.at(rid) == durable,
                  10034);
          }
          for (const auto &[id, o] : opens)
            if (o.object == m.at("object").get<std::string>() && id != previous)
              check(!(o.deny & access) && !(deny & o.access), 10015);
          if (created && a.contains("attrs"))
            attrset = a.at("attrs").at("bits").get<std::vector<uint32_t>>();
          if (!created && a.at("create") == 1 && a.at("mode") == 0) {
            auto attrs = create_attrs4(a.at("attrs"), false);
            if (attrs.contains("size") && attrs.at("size") == 0) {
              // A failed share reservation must never truncate someone else's file.
              // Other UNCHECKED attributes are ignored for an existing object.
              file(who, target, "resize", {{"size", 0},
                   {"state_owner", previous.empty() ? std::string() : previous.substr(8)}}, digest(request + ":truncate"));
              attrset = {1u << 4};
            }
          }
          writer state;
          state.u32(1).fixed(decode_bytes(random_hex(12)));
          auto stateid = encode_bytes(state.data);
          if (!previous.empty()) {
            stateid = next_state(previous);
            state.data = decode_bytes(stateid);
          }
          statement persist(db, "INSERT OR REPLACE INTO recovery VALUES(?,?)");
          persist.bind(1, rid);
          persist.bind(2, durable.dump());
          persist.row();
          if (!previous.empty()) opens.erase(previous);
          opens.emplace(stateid, open_state{sid, target, owner, rid, access, deny, session.client,
                                           m.at("object"), who.key, who.credential});
          reclaim.erase(rid);
          current = target;
          current_state = stateid;
          body.fixed(state.data);
          change4(body, parent_before, parent_after);
          body.u32(send_backchannel ? 0x20 : 0); // OPEN4_RESULT_MAY_NOTIFY_LOCK
          put_bitmap(body, attrset); body.u32(0);
        } else if (op == 4) {
          auto id = open_key(a.at("state"), sid);
          auto &o = state4(id, sid, current, 0, who, op);
          for (const auto &[key, l] : byte_locks)
            check(l.open_other != id.substr(8) || l.ranges.empty(), 10037);
          std::erase_if(byte_locks, [&](const auto &l) { return l.second.open_other == id.substr(8); });
          remove_recovery(o.recovery);
          opens.erase(id);
          reap_retained();
          current_state = next_state(id);
          body.fixed(decode_bytes(current_state));
        } else if (op == 21) {
          auto id = open_key(a.at("state"), sid);
          auto &o = state4(id, sid, current, 0, who, op);
          auto access = a.at("access").get<uint32_t>(), deny = a.at("deny").get<uint32_t>();
          check(access > 0 && access <= 3 && deny <= 3);
          check((access & o.access) == access && (deny & o.deny) == deny);
          o.access = access;
          o.deny = deny;
          statement q(db, "UPDATE recovery SET body=json_set(body,'$.access',?,'$.deny',?) WHERE id=?");
          q.bind(1, int64_t(access)); q.bind(2, int64_t(deny)); q.bind(3, o.recovery); q.row();
          auto node = opens.extract(id);
          current_state = next_state(id);
          node.key() = current_state;
          opens.insert(std::move(node));
          body.fixed(decode_bytes(current_state));
        } else if (op == 12 || op == 13 || op == 14 || op == 45) {
          lock_operation(who, a, sid, current, current_state, body, ops.front());
        } else if (op == 25 || op == 38 || op == 34) {
          check(current != pseudo, 21);
          auto id = a.at("state").get<std::string>();
          auto io_args = json::object();
          if (id != std::string(32, '0') && !(op == 25 && id == std::string(32, 'f'))) {
            auto openid = io_state(id, sid);
            state4(openid, sid, current, op == 25 ? 1 : 2, who);
            io_args["state_owner"] = openid.substr(8);
          }
          if (op == 25) {
            io_args["offset"] = a.at("offset");
            io_args["count"] = std::min(a.at("count").get<uint32_t>(), 65536u);
            auto m = file(who, current, "read",
                          io_args);
            body.boolean(m.at("eof")).opaque(decode_bytes(m.at("data").get<std::string>()));
          } else if (op == 38) {
            check(a.at("stable").get<uint32_t>() <= 2);
            io_args["offset"] = a.at("offset");
            io_args["data"] = a.at("data");
            auto m = file(who, current, "write",
                          io_args, request);
            body.u32(m.at("count")).u32(2).fixed(verifier);
          } else {
            auto bits = a.at("attrs").at("bits").get<std::vector<uint32_t>>();
            auto attrs = create_attrs4(a.at("attrs"), meta4(who, current).at("directory"), false);
            io_args.update(attrs);
            file(who, current, "setattr", io_args, request);
            put_bitmap(body, bits);
          }
        } else if (op == 5) {
          file(who, current, "commit");
          body.fixed(verifier);
        } else if (op == 6) {
          check(a.at("type") == 2, 10007);
          auto attrs = create_attrs4(a.at("attrs"), true);
          attrs["name"] = a.at("name");
          auto m = file(who, current, "mkdir", attrs, request);
          current = m.at("handle");
          change4(body, m.at("change_before"), m.at("change_after"));
          put_bitmap(body, a.at("attrs").at("bits").get<std::vector<uint32_t>>());
        } else if (op == 11 || op == 27) {
          check(!current.empty(), 10020);
          check(false, 10004);
        } else if (op == 28) {
          auto m = file(who, current, "remove", {{"name", a.at("name")}}, request);
          change4(body, m.at("change_before"), m.at("change_after"));
        } else if (op == 29) {
          check(!saved.empty() && !current.empty(), 10020);
          auto m = file(who, saved, "rename",
               {{"name", a.at("name")}, {"target", current}, {"to", a.at("to")}}, request);
          change4(body, m.at("change_before"), m.at("change_after"));
          change4(body, m.at("target_before"), m.at("target_after"));
        } else if (op == 26) {
          check(!current.empty(), 10020);
          auto bits = a.at("bits").get<std::vector<uint32_t>>();
          check(!has(bits, 48) && !has(bits, 54) && !has(bits, 74));
          auto m = current == pseudo ? export_view(who) : file(who, current, "list");
          if (current == pseudo) {
            m["verifier"] = digest(who.key + m.dump()).substr(0, 16);
            m["entries"] = m.at("exports");
          }
          auto cookie = a.at("cookie").get<uint64_t>();
          auto &entries = m.at("entries");
          check(!cookie || cookie >= 3, 10003);
          check(!cookie || a.at("verifier") == m.at("verifier"), 10027);
          check(!cookie || cookie - 2 <= entries.size(), 10003);
          auto budget = std::min(a.at("count").get<uint32_t>(), 65536u);
          check(budget >= 20, 10005); // Status, verifier, list terminator and eof.
          body.fixed(decode_bytes(m.at("verifier").get<std::string>()));
          size_t i = cookie ? size_t(cookie - 2) : 0;
          auto first = i;
          for (; i < entries.size(); ++i) {
            if (current == pseudo && i - first == 32) break;
            auto e = entries[i];
            if (current == pseudo) {
              // Resolve only this page, using fresh authority for each export.
              auto name = e.at("id").get<std::string>();
              e = file(who, "", "root", json::object(), "", name);
              e["name"] = name;
            }
            writer item;
            // Cookies 1 and 2 are reserved by NFSv4 for client-side dot entries.
            item.boolean(true).u64(i + 3).opaque(e.at("name").get<std::string>());
            uint32_t attr_error = 0;
            if (has(bits, 12)) {
              try {
                e["acl"] = file(who, e.at("handle"), "acl").at("acl");
              } catch (const error &error) {
                attr_error = status(error.what());
              }
            }
            if (attr_error) {
              check(has(bits, 11), attr_error);
              put_bitmap(item, {1u << 11});
              writer error;
              error.u32(attr_error);
              item.opaque(error.data);
            } else
              attributes4(item, bits, e);
            if (body.data.size() + item.data.size() + 12 > budget) {
              check(i != first, 10005); // Never return an empty non-final page.
              break;
            }
            body.fixed(item.data);
          }
          body.boolean(false).boolean(i == entries.size());
        } else if (op == 55) {
          body.u32(uint32_t(a.at("states").size()));
          for (auto &id : a.at("states")) {
            try {
              auto key = io_state(id, sid);
              check(opens.at(key).principal == who.key, 10025);
              body.u32(0);
            } catch (const failure &e) { body.u32(e.status); }
          }
        } else if (op == 58) {
          std::string filesystem;
          if (a.at("one_fs").get<bool>()) {
            auto m = meta4(who, current);
            filesystem = m.at("fsid");
            check(!client.reclaim_complete && !client.reclaimed_filesystems.contains(filesystem), 10054);
            client.reclaimed_filesystems.insert(filesystem);
          } else {
            check(!client.reclaim_complete, 10054);
            client.reclaim_complete = true;
          }
          for (auto it = reclaim.begin(); it != reclaim.end();)
            if (it->second.at("client") == client.owner && it->second.at("principal") == who.key &&
                (filesystem.empty() || it->second.at("handle").get<std::string>().substr(4, 16) == filesystem)) {
              remove_recovery(it->first);
              it = reclaim.erase(it);
            } else
              ++it;
        } else
          check(false, a.value("unknown", false) ? 10044 : 10004);
      }
    } catch (const failure &e) {
      code = e.status;
    } catch (const error &e) {
      // Preserve the domain failure before translation to an NFS status. This
      // distinguishes malformed requests from transient IPC/storage failures.
      log("nfs", "operation_" + std::to_string(op) + "_domain_error", e.what());
      code = status(e.what());
    } catch (const xdr_error &) {
      code = 10036;
    }
    if (code) {
      log("nfs", "operation_" + std::to_string(op), std::to_string(code));
      if (!((op == 12 || op == 13) && code == 10010))
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
  reap_retained();
  if (active) {
    active->reply = out.data;
    active->pending = false;
  }
  return out.data;
}
