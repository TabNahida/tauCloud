#include <taucloud/smb.hpp>
#include <taucloud/files.hpp>
#include <taucloud/runtime/bounded_executor.hpp>
#include <pace/tcp.hpp>
#include <map>
#include <set>
#include <algorithm>
namespace tc {
namespace {
using namespace smb_detail;
struct client;
struct smb_state {
  config cfg;
  std::shared_ptr<pace::io_context> io = std::make_shared<pace::io_context>();
  taucloud::bounded_executor pool{4, 32, 32 * ipc_frame_size};
  std::atomic<int> connections = 0;
  std::set<client *> clients;
  bytes guid = decode_bytes(random_hex(16));
};
pace::task<json> smb_rpc(smb_state &s, std::string target, std::string op,
                         json body = json::object()) {
  struct result {
    json value;
    std::exception_ptr failure;
    bool done = false;
  };
  auto pending = std::make_shared<result>();
  taucloud::bounded_executor::ticket ticket;
  bool accepted = s.pool.submit(
      s.io, ipc_frame_size, std::chrono::steady_clock::now() + 5s,
      [pending, c = s.cfg, target, op, body](std::stop_token stop) {
        pending->value = rpc(c, "smb", target, op, body, "", stop);
      },
      [pending](taucloud::bounded_executor::result r) {
        pending->failure = r.error;
        if (r.state != taucloud::bounded_executor::status::completed && !pending->failure)
          pending->failure = std::make_exception_ptr(error("cancelled"));
        pending->done = true;
      },
      ticket);
  require(accepted, "overloaded");
  try {
    while (!pending->done)
      co_await s.io->sleep_for(1ms);
  } catch (...) {
    ticket.cancel();
    throw;
  }
  if (pending->failure)
    std::rethrow_exception(pending->failure);
  co_return pending->value;
}
struct status_error : std::exception {
  uint32_t status;
  explicit status_error(uint32_t s) : status(s) {}
};
void check(bool value, uint32_t status = 0xc000000d) {
  if (!value)
    throw status_error(status);
}
uint32_t status(std::string_view code) {
  if (code == "preauth_hash_overlap")
    return 0xc05d0000;
  if (code == "not_found")
    return 0xc0000034;
  if (code == "already_exists" || code == "case_collision")
    return 0xc0000035;
  if (code == "sharing_violation")
    return 0xc0000043;
  if (code == "locked")
    return 0xc0000054;
  if (code == "range_not_locked")
    return 0xc000007e;
  if (code == "delete_pending")
    return 0xc0000056;
  if (code == "directory_not_empty")
    return 0xc0000101;
  if (code == "not_directory")
    return 0xc0000103;
  if (code == "is_directory")
    return 0xc00000ba;
  if (code == "stale_handle" || code == "object_replaced")
    return 0xc0000128;
  if (code == "quota_exceeded" || code == "no_space" || code == "disk_full")
    return 0xc000007f;
  if (code == "not_supported" || code == "directory_limit")
    return 0xc00000bb;
  if (code == "unauthorized" || code == "rate_limited" || code == "ntlm_mic_required")
    return 0xc000006d;
  if (code == "forbidden" || code == "permission_denied" || code == "policy_revoked" ||
      code == "lease_expired" || code == "mixed_writers_disabled")
    return 0xc0000022;
  if (code == "overloaded" || code == "handle_limit" || code == "lock_limit")
    return 0xc000009a;
  if (code == "io_error" || code == "internal_error" || code == "uncertain_write" ||
      code == "database_error")
    return 0xc0000185;
  return 0xc000000d;
}
bytes sized(size_t n, int structure) {
  bytes b(n, '\0');
  put(b, 0, structure, 2);
  return b;
}
std::string slice(std::string_view b, size_t off, size_t len, size_t minimum) {
  check(off <= b.size() && len <= b.size() - off && (!len || off >= minimum));
  return bytes(b.substr(off, len));
}
std::string path(std::string_view encoded) {
  auto value = utf8(encoded);
  std::replace(value.begin(), value.end(), '\\', '/');
  if (!value.empty() && value.back() == '/')
    value.pop_back();
  if (!value.empty())
    portable_path(value);
  return value;
}
uint64_t filetime(const json &meta) {
  auto n = meta.value("modified_ns", int64_t(0));
  return uint64_t(n / 100) + 116444736000000000ull;
}
uint32_t attributes(const json &meta) { return meta.at("directory").get<bool>() ? 0x10 : 0x20; }
void times(bytes &b, size_t off, const json &meta) {
  for (size_t i = 0; i < 4; ++i)
    put(b, off + 8 * i, filetime(meta), 8);
}
bytes basic(const json &m) {
  bytes b(40, '\0');
  times(b, 0, m);
  put(b, 32, attributes(m), 4);
  return b;
}
bytes standard(const json &m) {
  bytes b(24, '\0');
  auto size = m.at("size").get<uint64_t>();
  put(b, 0, (size + 4095) / 4096 * 4096, 8);
  put(b, 8, size, 8);
  put(b, 16, 1, 4);
  b[20] = m.value("delete_pending", false);
  b[21] = m.at("directory").get<bool>();
  return b;
}
bytes file_info(unsigned klass, const json &m, const std::string &name, uint32_t access) {
  // NormalizedNameInformation is relative to the share (MS-SMB2 3.3.5.20.1).
  // NameInformation includes the leading separator; they are not interchangeable.
  auto native_name = (klass == 48 ? "" : "\\") + name;
  std::replace(native_name.begin(), native_name.end(), '/', '\\');
  auto encoded = utf16(native_name);
  bytes b;
  if (klass == 4)
    return basic(m);
  if (klass == 5)
    return standard(m);
  if (klass == 6) {
    b.assign(8, '\0');
    auto value = decode_bytes(digest(m.at("object").get<std::string>()).substr(0, 16));
    return value;
  }
  if (klass == 7 || klass == 16 || klass == 17) {
    return bytes(4, '\0');
  }
  if (klass == 8) {
    b.assign(4, '\0');
    put(b, 0, access, 4);
    return b;
  }
  if (klass == 9 || klass == 48) {
    b.assign(4, '\0');
    put(b, 0, encoded.size(), 4);
    return b + encoded;
  }
  if (klass == 14) {
    return bytes(8, '\0');
  }
  if (klass == 18) {
    b = basic(m) + standard(m) + file_info(6, m, name, access) + bytes(4, '\0') +
        file_info(8, m, name, access) + bytes(16, '\0') + file_info(9, m, name, access);
    return b;
  }
  if (klass == 34) {
    b = basic(m).substr(0, 32) + standard(m).substr(0, 16);
    b.resize(56);
    put(b, 48, attributes(m), 4);
    return b;
  }
  if (klass == 35) {
    b.assign(8, '\0');
    put(b, 0, attributes(m), 4);
    return b;
  }
  if (klass == 22) {
    if (m.at("directory").get<bool>())
      return {};
    auto stream_name = utf16("::$DATA");
    auto size = m.at("size").get<uint64_t>();
    b.assign(24, '\0');
    put(b, 4, stream_name.size(), 4);
    put(b, 8, size, 8);
    put(b, 16, (size + 4095) / 4096 * 4096, 8);
    return b + stream_name;
  } // Only the unnamed data stream exists.
  throw status_error(0xc00000bb);
}
bool wildcard(std::string input_pattern, std::string input_name) {
  check(input_pattern.find_first_of("<>\"") == std::string::npos, 0xc00000bb);
  auto units = [](const std::string &v) {
    auto encoded = utf16(path_fold(v));
    std::u16string result;
    for (size_t i = 0; i < encoded.size(); i += 2)
      result += static_cast<char16_t>(get(encoded, i, 2));
    return result;
  };
  auto pattern = units(input_pattern), name = units(input_name);
  if (pattern == u"*.*")
    pattern = u"*";
  size_t p = 0, n = 0, star = std::string::npos, mark = 0;
  while (n < name.size()) {
    if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == name[n])) {
      ++p;
      ++n;
    } else if (p < pattern.size() && pattern[p] == '*') {
      star = p++;
      mark = n;
    } else if (star != std::string::npos) {
      p = star + 1;
      n = ++mark;
    } else
      return false;
  }
  while (p < pattern.size() && pattern[p] == '*')
    ++p;
  return p == pattern.size();
}
bytes directory_entry(unsigned klass, const json &m) {
  auto name = utf16(m.at("name").get<std::string>());
  size_t fixed = 0;
  if (klass == 1)
    fixed = 64;
  else if (klass == 2)
    fixed = 68;
  else if (klass == 3)
    fixed = 94;
  else if (klass == 12)
    fixed = 12;
  else if (klass == 37)
    fixed = 104;
  else if (klass == 38)
    fixed = 80;
  else
    throw status_error(0xc00000bb);
  bytes b(fixed, '\0');
  if (klass == 12)
    put(b, 8, name.size(), 4);
  else {
    times(b, 8, m);
    auto size = m.at("size").get<uint64_t>();
    put(b, 40, size, 8);
    put(b, 48, (size + 4095) / 4096 * 4096, 8);
    put(b, 56, attributes(m), 4);
    put(b, 60, name.size(), 4);
    if (klass == 37 || klass == 38)
      b.replace(klass == 37 ? 96 : 72, 8,
                decode_bytes(digest(m.at("object").get<std::string>()).substr(0, 16)));
  }
  b += name;
  return b;
}
struct tree {
  std::string share, prefix, space;
  bool writable = false;
};
struct opened {
  uint32_t tree_id;
  std::string handle, path;
  json grant;
  uint32_t access;
  json entries = json::array();
  size_t cursor = 0;
  std::string pattern;
  bool pipe = false;
  bytes pending;
  std::set<uint16_t> contexts;
};
struct client {
  smb_state &s;
  pace::tcp::stream socket;
  bool negotiated = false, authenticated = false, ending = false, raw_ntlm = false;
  bool multiprotocol = false;
  bool logged_off = false;
  uint64_t session = 0, low = 0, high = 1;
  uint64_t previous_session = 0;
  std::set<uint64_t> consumed;
  std::string exchange, token, username;
  bytes key, encryption_key, decryption_key;
  negotiation selected;
  bytes transcript = bytes(64, '\0');
  bytes negotiate_transcript = bytes(64, '\0');
  bytes nonce_prefix = decode_bytes(random_hex(4));
  uint64_t nonce_counter = 0;
  std::set<bytes> received_nonces;
  std::map<uint32_t, tree> trees;
  std::map<bytes, opened> files;
  uint32_t next_tree = 1;
  bytes related_file;
  client(smb_state &state, pace::tcp::stream tcp) : s(state), socket(std::move(tcp)) {
    socket.set_no_delay();
  }
  void close() { socket.close(); }
  json auth() { return {{"token", token}, {"kind", "smb"}}; }
  pace::task<json> authorize(uint32_t tid, std::string relative, bool writing) {
    check(trees.contains(tid), 0xc00000c9);
    json request = {{"auth", auth()},
                    {"share", trees.at(tid).share},
                    {"protocol", "smb"},
                    {"path", relative},
                    {"write", writing}};
    co_return co_await smb_rpc(s, "identity", "authorize", request);
  }
  pace::task<json> operation(opened &h, std::string op, bool writing, json body = json::object()) {
    check(!h.pipe, 0xc00000bb);
    h.grant = co_await authorize(h.tree_id, h.path, writing);
    body["grant"] = h.grant;
    body["handle"] = h.handle;
    co_return co_await smb_rpc(s, h.grant.at("root").at("worker"), "smb_" + op, body);
  }
  pace::task<void> release(bytes fid) {
    auto it = files.find(fid);
    if (it == files.end())
      co_return;
    auto h = std::move(it->second);
    files.erase(it);
    if (h.pipe)
      co_return;
    try {
      json body = {{"grant", h.grant}, {"handle", h.handle}};
      co_await smb_rpc(s, h.grant.at("root").at("worker"), "smb_close", body);
    } catch (...) {
      log("smb", "close_failed", "recovery_required");
    }
  }
  pace::task<void> cleanup(uint32_t tid = 0) {
    std::vector<bytes> ids;
    for (auto &[id, h] : files)
      if (!tid || tid == h.tree_id)
        ids.push_back(id);
    for (auto id : ids)
      co_await release(id);
    if (tid)
      trees.erase(tid);
    else
      trees.clear();
  }
  opened &handle(std::string_view p, size_t offset, uint32_t tid) {
    auto fid = slice(p, offset, 16, 64);
    if (fid == bytes(16, char(0xff)))
      fid = related_file;
    auto it = files.find(fid);
    check(it != files.end() && it->second.tree_id == tid, 0xc0000128);
    return it->second;
  }
  bytes fid_for(const opened &h) {
    for (auto &[id, item] : files)
      if (&item == &h)
        return id;
    throw status_error(0xc0000128);
  }
  void renamed(const json &result) {
    std::string from = result.at("from"), to = result.at("path"), space = result.at("space");
    for (auto *connection : s.clients)
      for (auto &[id, h] : connection->files) {
        if (h.pipe)
          continue;
        auto &t = connection->trees.at(h.tree_id);
        if (t.space != space)
          continue;
        auto full = t.prefix + (t.prefix.empty() || h.path.empty() ? "" : "/") + h.path;
        if (full == from || full.starts_with(from + "/")) {
          full = to + full.substr(from.size());
          if (t.prefix.empty())
            h.path = full;
          else if (full.starts_with(t.prefix + "/"))
            h.path = full.substr(t.prefix.size() + 1);
          else
            h.path = ".tc-inaccessible";
          // Refresh the signed cleanup grant on the next operation. The file authority
          // accepts the previous path only via a fresh grant, never by unauthenticated ID.
        }
      }
  }
#include "smb_rpc.inc"
  pace::task<bytes> command(std::string_view p, uint32_t &tid, uint32_t &code) {
    check(!logged_off, 0xc0000203);
    auto cmd = get(p, 12, 2);
    auto structure = get(p, 64, 2);
    if (cmd == 0) {
      check(!negotiated && get(p, 40, 8) == 0);
      auto response = selected.accept(p, s.guid);
      check(!(get(p, 16, 4) & ~(selected.dialect == 0x311 ? 0x70ull : 0ull)));
      negotiated = true;
      co_return response;
    }
    check(negotiated, 0xc00000bb);
    if (cmd == 1) {
      check(!authenticated && structure == 25 && p.size() >= 88 && get(p, 66, 1) == 0);
      auto security = slice(p, get(p, 76, 2), get(p, 78, 2), 88);
      json request = {{"token", encode_bytes(security)}};
      bytes response;
      if (exchange.empty()) {
        check(get(p, 40, 8) == 0);
        previous_session = get(p, 80, 8);
        raw_ntlm = security.starts_with(std::string_view("NTLMSSP\0", 8));
        auto r = co_await smb_rpc(s, "identity", "smb_negotiate", request);
        exchange = r.at("exchange");
        session = get(decode_bytes(random_hex(8)), 0, 8) | 1;
        response = decode_bytes(r.at("token").get<std::string>());
        if (!raw_ntlm)
          response = spnego(response);
        code = 0xc0000016;
      } else {
        check(get(p, 40, 8) == session);
        request["exchange"] = exchange;
        exchange.clear();
        auto r = co_await smb_rpc(s, "identity", "smb_authenticate", request);
        token = r.at("token");
        username = r.at("username");
        // A reconnect still proves credentials. Only then may it replace an
        // older session belonging to that same canonical identity.
        for (auto *other : s.clients)
          if (other != this && previous_session && other->session == previous_session &&
              other->username == username)
            other->close();
        key = decode_bytes(r.at("session_key").get<std::string>());
        if (selected.dialect >= 0x300) {
          auto session_key = key;
          if (selected.dialect == 0x311) {
            key = kdf(session_key, "SMBSigningKey", transcript);
            decryption_key = kdf(session_key, "SMBC2SCipherKey", transcript);
            encryption_key = kdf(session_key, "SMBS2CCipherKey", transcript);
          } else {
            key = kdf(session_key, "SMB2AESCMAC", bytes("SmbSign\0", 8));
            decryption_key = kdf(session_key, "SMB2AESCCM", bytes("ServerIn \0", 10));
            encryption_key = kdf(session_key, "SMB2AESCCM", bytes("ServerOut\0", 10));
          }
          std::fill(session_key.begin(), session_key.end(), 0);
        }
        authenticated = true;
        response = raw_ntlm ? bytes() : spnego({}, true);
      }
      auto b = sized(8, 9);
      put(b, 4, 72, 2);
      put(b, 6, response.size(), 2);
      co_return b + response;
    }
    check(authenticated, 0xc0000022);
    if (cmd == 13) {
      check(structure == 4);
      co_return sized(4, 4);
    }
    if (cmd == 2) {
      check(structure == 4);
      co_await cleanup();
      json a = auth();
      try {
        co_await smb_rpc(s, "identity", "logout", a);
      } catch (...) {
      }
      logged_off = true;
      co_return sized(4, 4);
    }
    if (cmd == 3) {
      check(structure == 9 && p.size() >= 72 && trees.size() < 16);
      auto unc = utf8(slice(p, get(p, 68, 2), get(p, 70, 2), 72));
      check(unc.starts_with("\\\\"));
      auto split = unc.find('\\', 2);
      check(split != std::string::npos && split > 2 && split + 1 < unc.size());
      auto share = unc.substr(split + 1);
      check(share.find('\\') == std::string::npos && share.find('/') == std::string::npos,
            0xc00000cc);
      if (path_fold(share) == "ipc$") {
        json q = {{"auth", auth()}, {"resource", "shares"}};
        co_await smb_rpc(s, "identity", "policy_list", q);
        tid = next_tree++;
        trees.emplace(tid, tree{"IPC$", "", "", false});
        auto b = sized(16, 16);
        b[2] = 2;
        put(b, 12, 0x12019f, 4);
        co_return b;
      }
      json request = {
          {"auth", auth()}, {"protocol", "smb"}, {"share", share}, {"path", ""}, {"write", false}};
      auto grant = co_await smb_rpc(s, "identity", "authorize", request);
      bool writable = false;
      request["write"] = true;
      try {
        co_await smb_rpc(s, "identity", "authorize", request);
        writable = true;
      } catch (...) {
      }
      tid = next_tree++;
      trees.emplace(tid, tree{share, grant.at("path"), grant.at("space").at("id"), writable});
      auto b = sized(16, 16);
      b[2] = 1;
      put(b, 4, 0x30, 4);
      put(b, 12, writable ? 0x1301bf : 0x1200a9, 4);
      co_return b;
    }
    check(trees.contains(tid), 0xc00000c9);
    if (cmd == 4) {
      check(structure == 4);
      co_await cleanup(tid);
      co_return sized(4, 4);
    }
    if (cmd == 5) {
      check(structure == 57 && p.size() >= 120 && files.size() < 64);
      auto name = path(slice(p, get(p, 108, 2), get(p, 110, 2), 120));
      if (trees.at(tid).share == "IPC$") {
        check(path_fold(name) == "srvsvc" && get(p, 100, 4) == 1, 0xc0000034);
        auto fid = decode_bytes(random_hex(16));
        opened h{tid, "",   name, {}, static_cast<uint32_t>(get(p, 88, 4)), json::array(), 0,
                 {},  true, {},   {}};
        files.emplace(fid, std::move(h));
        related_file = fid;
        auto b = sized(88, 89);
        put(b, 4, 1, 4);
        put(b, 56, 0x80, 4);
        b.replace(64, 16, fid);
        co_return b;
      }
      auto context_len = get(p, 116, 4);
      if (context_len) {
        auto contexts = slice(p, get(p, 112, 4), context_len, 120);
        size_t pos = 0;
        int count = 0;
        while (pos < contexts.size()) {
          check(++count <= 16 && contexts.size() - pos >= 16);
          auto next = get(contexts, pos, 4);
          auto limit = next ? next : contexts.size() - pos;
          check(limit >= 16 && limit <= contexts.size() - pos && (!next || next % 8 == 0));
          auto item = std::string_view(contexts).substr(pos, limit);
          auto tag = slice(item, get(item, 4, 2), get(item, 6, 2), 16);
          slice(item, get(item, 10, 2), get(item, 12, 4), 16);
          if (tag == "DHnC" || tag == "DH2C" || tag == "TWrp" || tag == "SecD" || tag == "ExtA") {
            log("smb", "unsupported_create_context", std::string(tag));
            throw status_error(0xc00000bb);
          }
          if (!next)
            break;
          pos += next;
        }
      }
      uint32_t access = static_cast<uint32_t>(get(p, 88, 4));
      bool maximum = access & 0x02000000;
      if (access & 0x80000000)
        access |= 0x120089;
      if (access & 0x40000000)
        access |= 0x120116;
      if (access & 0x20000000)
        access |= 0x1200a0;
      if (access & 0x10000000)
        access |= 0x1301bf;
      access &= 0x0fffffff;
      if (maximum)
        access = (access & ~0x02000000) | (trees.at(tid).writable ? 0x1301bf : 0x1200a9);
      auto disposition = get(p, 100, 4), options = get(p, 104, 4);
      // MUST-ignore compatibility flags; NO_RECALL is a hint for HSM, which
      // this confined local-file profile does not implement.
      if (options & ~uint64_t(0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x800 | 0x1000 |
                              0x400 | 0x2000 | 0x4000 | 0x10000 | 0x20000 | 0x200000 |
                              0x400000 | 0x800000)) {
        log("smb", "unsupported_create_options", std::to_string(options));
        throw status_error(0xc00000bb);
      }
      if (get(p, 92, 4) & ~uint64_t(0x10 | 0x20 | 0x80)) {
        log("smb", "unsupported_create_attributes", std::to_string(get(p, 92, 4)));
        throw status_error(0xc00000bb);
      }
      bool writing = (access & (0x10000 | 0x116)) || disposition != 1;
      auto grant = co_await authorize(tid, name, writing);
      json request = {
          {"grant", grant},           {"write", writing},           {"access", access},
          {"sharing", get(p, 96, 4)}, {"disposition", disposition}, {"options", options}};
      auto meta = co_await smb_rpc(s, grant.at("root").at("worker"), "smb_open", request);
      auto fid = decode_bytes(random_hex(16));
      files.emplace(
          fid,
          opened{tid, meta.at("handle"), name, grant, access, json::array(), 0, {}, false, {}, {}});
      related_file = fid;
      auto b = sized(88, 89);
      put(b, 4, meta.at("action").get<uint32_t>(), 4);
      times(b, 8, meta);
      auto size = meta.at("size").get<uint64_t>();
      put(b, 40, (size + 4095) / 4096 * 4096, 8);
      put(b, 48, size, 8);
      put(b, 56, attributes(meta), 4);
      b.replace(64, 16, fid);
      co_return b;
    }
    if (cmd == 6 || cmd == 7) {
      check(structure == 24 && p.size() >= 88);
      auto &h = handle(p, 72, tid);
      if (h.pipe) {
        auto fid = fid_for(h);
        if (cmd == 6)
          co_await release(fid);
        co_return cmd == 6 ? sized(60, 60) : sized(4, 4);
      }
      if (cmd == 7) {
        co_await operation(h, "flush", false);
        co_return sized(4, 4);
      }
      auto meta = co_await operation(h, "stat", false);
      auto fid = fid_for(h);
      co_await release(fid);
      auto b = sized(60, 60);
      put(b, 2, 1, 2);
      times(b, 8, meta);
      auto size = meta.at("size").get<uint64_t>();
      put(b, 40, (size + 4095) / 4096 * 4096, 8);
      put(b, 48, size, 8);
      put(b, 56, attributes(meta), 4);
      co_return b;
    }
    if (cmd == 8 || cmd == 9) {
      check(structure == 49 && p.size() >= 112);
      auto &h = handle(p, 80, tid);
      auto length = get(p, 68, 4);
      check(length <= 65536);
      json request = {{"offset", get(p, 72, 8)}};
      if (h.pipe) {
        check(get(p, 72, 8) == 0);
        if (cmd == 9) {
          check(h.pending.empty(), 0xc00000ae);
          auto data = slice(p, get(p, 66, 2), length, 112);
          h.pending = co_await pipe_request(h, data);
          auto b = sized(16, 17);
          put(b, 4, length, 4);
          co_return b;
        }
        check(!h.pending.empty(), 0xc00000b0);
        auto data = h.pending.substr(0, length);
        h.pending.erase(0, data.size());
        auto b = sized(16, 17);
        b[2] = 80;
        put(b, 4, data.size(), 4);
        put(b, 8, h.pending.size(), 4);
        co_return b + data;
      }
      if (cmd == 8) {
        check(get(p, 100, 4) == 0 && get(p, 110, 2) == 0);
        request["count"] = length;
        auto r = co_await operation(h, "read", false, request);
        auto data = decode_bytes(r.at("data").get<std::string>());
        check(!data.empty() || length == 0, 0xc0000011);
        check(data.size() >= get(p, 96, 4), 0xc0000011);
        auto b = sized(16, 17);
        b[2] = 80;
        put(b, 4, data.size(), 4);
        co_return b + data;
      }
      check(get(p, 96, 4) == 0 && get(p, 106, 2) == 0 && (get(p, 108, 4) & ~1ull) == 0);
      auto data = slice(p, get(p, 66, 2), length, 112);
      request["data"] = encode_bytes(data);
      request["flush"] = bool(get(p, 108, 4) & 1);
      request["request_id"] = random_hex(16);
      auto r = co_await operation(h, "write", true, request);
      auto b = sized(16, 17);
      put(b, 4, r.at("written").get<uint32_t>(), 4);
      co_return b;
    }
    if (cmd == 11) {
      check(structure == 57 && p.size() >= 120);
      if (get(p, 68, 4) == 0x140204 && selected.dialect >= 0x300) {
        // A mismatch is a security failure, not a recoverable IOCTL error.
        try {
          require(get(p, 112, 4) == 1 && get(p, 108, 4) >= 24 && get(p, 104, 4) == 0 &&
                      p.substr(72, 16) == bytes(16, char(0xff)),
                  "invalid_packet");
          auto input = slice(p, get(p, 88, 4), get(p, 92, 4), 120);
          auto result = selected.validate(input, s.guid);
          auto b = sized(48, 49);
          put(b, 4, 0x140204, 4);
          b.replace(8, 16, 16, char(0xff));
          put(b, 24, 112, 4);
          put(b, 32, 112, 4);
          put(b, 36, result.size(), 4);
          co_return b + result;
        } catch (...) {
          close();
          throw;
        }
      }
      check(get(p, 68, 4) == 0x11c017 && get(p, 112, 4) == 1, 0xc00000bb);
      auto &h = handle(p, 72, tid);
      check(h.pipe && h.pending.empty());
      auto data = slice(p, get(p, 88, 4), get(p, 92, 4), 120);
      check(get(p, 104, 4) == 0);
      auto limit = get(p, 108, 4);
      check(limit <= 65536);
      auto result = co_await pipe_request(h, data);
      check(result.size() <= limit, 0xc0000023);
      auto b = sized(48, 49);
      put(b, 4, 0x11c017, 4);
      b.replace(8, 16, fid_for(h));
      put(b, 32, 112, 4);
      put(b, 36, result.size(), 4);
      co_return b + result;
    }
    if (cmd == 10) {
      check(structure == 48 && p.size() >= 88);
      auto &h = handle(p, 72, tid);
      auto count = get(p, 66, 2);
      check(count > 0 && count <= 64 && p.size() >= 88 + 24 * count);
      json locks = json::array();
      for (size_t i = 0; i < count; ++i) {
        auto o = 88 + 24 * i;
        locks.push_back(
            {{"offset", get(p, o, 8)}, {"length", get(p, o + 8, 8)}, {"flags", get(p, o + 16, 4)}});
      }
      json request = {{"locks", locks}};
      co_await operation(h, "lock", false, request);
      co_return sized(4, 4);
    }
    if (cmd == 14) {
      check(structure == 33 && p.size() >= 96);
      auto &h = handle(p, 72, tid);
      auto klass = get(p, 66, 1), flags = get(p, 67, 1);
      check(!(flags & ~0x13ull));
      auto limit = get(p, 92, 4);
      check(limit > 0 && limit <= 65536);
      auto pattern = utf8(slice(p, get(p, 88, 2), get(p, 90, 2), 96));
      if (h.pattern.empty() || (flags & 0x11)) {
        if (!pattern.empty())
          h.pattern = pattern;
        else if (h.pattern.empty())
          h.pattern = "*";
        h.entries = co_await operation(h, "list", false);
        h.cursor = 0;
      } else
        co_await operation(h, "stat", false);
      bytes output;
      size_t previous = 0;
      while (h.cursor < h.entries.size()) {
        auto item = h.entries[h.cursor];
        if (!wildcard(h.pattern, item.at("name"))) {
          ++h.cursor;
          continue;
        }
        auto entry = directory_entry(static_cast<unsigned>(klass), item);
        auto pad = output.empty() ? 0 : (8 - output.size() % 8) % 8;
        if (output.size() + pad + entry.size() > limit) {
          check(!output.empty(), 0xc0000023);
          break;
        }
        if (!output.empty()) {
          output.resize(output.size() + pad, '\0');
          put(output, previous, output.size() - previous, 4);
        }
        previous = output.size();
        output += entry;
        ++h.cursor;
        if (flags & 2)
          break;
      }
      check(!output.empty(), 0x80000006);
      auto b = sized(8, 9);
      put(b, 2, 72, 2);
      put(b, 4, output.size(), 4);
      co_return b + output;
    }
    if (cmd == 16) {
      check(structure == 41 && p.size() >= 104);
      auto &h = handle(p, 88, tid);
      auto type = get(p, 66, 1), klass = get(p, 67, 1), limit = get(p, 68, 4);
      check(limit <= 65536 && get(p, 76, 4) == 0);
      auto meta = co_await operation(h, "stat", false);
      bytes data;
      if (type == 1)
        data = file_info(static_cast<unsigned>(klass), meta, h.path, h.access);
      else if (type == 2) {
        if (klass == 5) {
          auto fsname = utf16("tauCloud");
          data.assign(12, '\0');
          put(data, 0, 0x00000002 | 0x00000004, 4);
          put(data, 4, 120, 4);
          put(data, 8, fsname.size(), 4);
          data += fsname;
        } else if (klass == 4) {
          data.assign(8, '\0');
          put(data, 0, 7, 4);
          put(data, 4, 0x20, 4);
        } else if (klass == 1) {
          auto label = utf16(trees.at(tid).share);
          data.assign(18, '\0');
          put(data, 8, get(s.guid, 0, 4), 4);
          put(data, 12, label.size(), 4);
          data += label;
        } else if (klass == 3 || klass == 7) {
          auto grant = co_await authorize(tid, "", false);
          json request = {{"grant", grant}};
          auto q = co_await smb_rpc(s, grant.at("root").at("worker"), "smb_quota", request);
          auto total = q.at("limit").get<uint64_t>(),
               used = q.at("used").get<uint64_t>() + q.at("reserved").get<uint64_t>();
          auto free = total > used ? total - used : 0;
          data.assign(klass == 3 ? 24 : 32, '\0');
          put(data, 0, total / 4096, 8);
          put(data, 8, free / 4096, 8);
          if (klass == 7)
            put(data, 16, free / 4096, 8);
          put(data, data.size() - 8, 8, 4);
          put(data, data.size() - 4, 512, 4);
        } else
          throw status_error(0xc00000bb);
      } else
        throw status_error(0xc00000bb); // No synthetic DACL presented as persistent security.
      if (data.size() > limit) {
        // Variable-length names must return the fixed prefix and the required
        // name length, allowing native clients to retry with a larger buffer.
        size_t fixed = type == 1 && (klass == 9 || klass == 48) ? 4 :
                       type == 1 && klass == 18 ? 100 :
                       type == 1 && klass == 22 ? 24 :
                       type == 2 && klass == 1 ? 18 :
                       type == 2 && klass == 5 ? 12 : 0;
        check(fixed && limit >= fixed, 0xc0000004);
        data.resize(limit);
        code = 0x80000005; // STATUS_BUFFER_OVERFLOW carries a QUERY_INFO response.
      }
      auto b = sized(8, 9);
      put(b, 2, 72, 2);
      put(b, 4, data.size(), 4);
      co_return b + data;
    }
    if (cmd == 17) {
      check(structure == 33 && p.size() >= 96 && get(p, 66, 1) == 1, 0xc00000bb);
      auto &h = handle(p, 80, tid);
      auto klass = get(p, 67, 1);
      auto input = slice(p, get(p, 72, 2), get(p, 68, 4), 96);
      json request;
      if (klass == 20) {
        check(input.size() == 8);
        request = {{"size", get(input, 0, 8)}};
        co_await operation(h, "resize", true, request);
      } else if (klass == 13) {
        check(input.size() == 1 && get(input, 0, 1) <= 1);
        request = {{"delete", bool(get(input, 0, 1))}};
        co_await operation(h, "disposition", true, request);
      } else if (klass == 10) {
        check(input.size() >= 20 && get(input, 8, 8) == 0 && get(input, 0, 1) <= 1);
        auto name = path(slice(input, 20, get(input, 16, 4), 20));
        auto target = co_await authorize(tid, name, true);
        request = {{"target", target}, {"replace", bool(get(input, 0, 1))}};
        auto r = co_await operation(h, "rename", true, request);
        renamed(r);
        h.grant = co_await authorize(tid, h.path, true);
      } else
        throw status_error(0xc00000bb);
      co_return sized(2, 2);
    }
    throw status_error(0xc00000bb);
  }
  pace::task<void> run() {
    s.clients.insert(this);
    try {
      while (socket.is_open() && !ending) {
        bytes prefix;
        {
          auto timer = s.io->call_after(authenticated ? 60s : 10s, [this] { close(); });
          prefix = co_await socket.read_exact(4, 4);
        }
        check(prefix[0] == 0);
        size_t length = (get(prefix, 1, 1) << 16) | (get(prefix, 2, 1) << 8) | get(prefix, 3, 1);
        check(length >= 35 && length <= 1024 * 1024 + 52);
        bytes packet;
        {
          auto timer = s.io->call_after(5s, [this] { close(); });
          packet = co_await socket.read_exact(length, 1024 * 1024 + 52);
        }
        if (packet.starts_with(std::string_view("\xffSMB", 4))) {
          // MS-SMB2 3.3.5.3: this is only the bootstrap into SMB2 negotiation,
          // never an SMB1 session or an SMB1 file operation.
          check(!negotiated && !multiprotocol && low == 0 && packet.size() <= 4096 &&
                get(packet, 4, 1) == 0x72 && !(get(packet, 9, 1) & 0x80) &&
                get(packet, 32, 1) == 0 && get(packet, 33, 2) == packet.size() - 35);
          bool wildcard = false;
          size_t at = 35, count = 0;
          while (at < packet.size()) {
            check(++count <= 64 && get(packet, at++, 1) == 2);
            auto end = packet.find('\0', at);
            check(end != bytes::npos && end - at <= 255);
            wildcard |= std::string_view(packet).substr(at, end - at) == "SMB 2.???";
            at = end + 1;
          }
          check(wildcard, 0xc00000bb);
          multiprotocol = true;
          low = 1;
          high = 2;
          bytes response(128, '\0');
          response.replace(0, 4, "\xfeSMB", 4);
          put(response, 4, 64, 2);
          put(response, 14, 1, 2);
          put(response, 16, 1, 4);
          put(response, 64, 65, 2);
          put(response, 66, 3, 2);
          put(response, 68, 0x2ff, 2);
          response.replace(72, 16, s.guid);
          for (size_t off : {92, 96, 100})
            put(response, off, 65536, 4);
          put(response, 104, (now() + 11644473600000ll) * 10000ull, 8);
          auto security = mechanisms();
          put(response, 120, 128, 2);
          put(response, 122, security.size(), 2);
          response += security;
          bytes frame(4, '\0');
          frame[2] = char(response.size() >> 8);
          frame[3] = char(response.size());
          auto timer = s.io->call_after(5s, [this] { close(); });
          co_await socket.write_all(frame + response);
          continue;
        }
        bool encrypted = packet.starts_with(std::string_view("\xfdSMB", 4));
        if (encrypted) {
          check(authenticated && selected.cipher != 0 && received_nonces.size() < 65536);
          auto plain = decrypt(decryption_key, selected.cipher, session, packet);
          check(received_nonces.insert(packet.substr(20, 16)).second);
          packet = std::move(plain);
        }
        check(packet.size() <= 1024 * 1024);
        std::vector<bytes> requests;
        size_t offset = 0;
        // Validate every segment and signature before any side effects in the compound.
        for (;;) {
          check(requests.size() < 16 && packet.size() - offset >= 64);
          auto remaining = std::string_view(packet).substr(offset);
          check(remaining.substr(0, 4) == std::string_view("\xfeSMB", 4) &&
                get(remaining, 4, 2) == 64);
          auto next = get(remaining, 20, 4);
          check(!next || (next >= 64 && next % 8 == 0 && next < remaining.size()));
          auto p = bytes(remaining.substr(0, next ? next : remaining.size()));
          auto flags = get(p, 16, 4), cmd = get(p, 12, 2);
          // SMB 3.1.1 clients (including Samba) set priority bits on SESSION_SETUP.
          // Priority affects scheduling, not authorization or signing.
          auto allowed_flags = selected.dialect == 0x311 || cmd == 0 ? 0x1000007cull : 0x1000000cull;
          check(!(flags & ~allowed_flags) && get(p, 6, 2) <= 1 && cmd <= 18);
          check(!(flags & 4) || !requests.empty());
          check(authenticated || (requests.empty() && !next));
          if (authenticated) {
            check(cmd != 0 && cmd != 1 && ((flags & 4) || get(p, 40, 8) == session), 0xc000035c);
            if (!encrypted)
              check((flags & 8) &&
                        equal(p.substr(48, 16), signature(key, p, selected.dialect >= 0x300)),
                    0xc0000022);
          }
          auto id = get(p, 24, 8);
          check(id >= low && id < high && !consumed.contains(id));
          consumed.insert(id);
          while (consumed.contains(low)) {
            consumed.erase(low);
            ++low;
          }
          requests.push_back(std::move(p));
          if (!next)
            break;
          offset += next;
        }
        related_file.clear();
        uint32_t inherited_tree = 0, previous_status = 0;
        bytes output;
        for (size_t i = 0; i < requests.size(); ++i) {
          auto &p = requests[i];
          auto cmd = get(p, 12, 2);
          uint32_t tid = static_cast<uint32_t>(get(p, 36, 4)), code = 0;
          bool related = get(p, 16, 4) & 4;
          if (related)
            tid = inherited_tree;
          bytes body;
          if (cmd == 0 || (cmd == 1 && selected.dialect == 0x311))
            transcript = preauth(transcript, p);
          try {
            if (related && previous_status)
              throw status_error(0xc000000d);
            body = co_await command(p, tid, code);
          } catch (const status_error &e) {
            code = e.status;
            log("smb", "command_" + std::to_string(cmd), std::to_string(code));
          } catch (const error &e) {
            code = status(e.what());
            log("smb", "command_" + std::to_string(cmd), e.what());
          } catch (const json::exception &) {
            code = 0xc000000d;
            log("smb", "command_" + std::to_string(cmd), "invalid_json");
          }
          // A fatal secure-negotiation failure must stop even unrelated commands
          // later in this compound, not just suppress its response.
          if (!socket.is_open())
            break;
          if (code && code != 0xc0000016 && code != 0x80000005) {
            body = sized(9, 9);
            if (code == 0xc0000004 && selected.dialect == 0x311) {
              body = sized(16, 9);
              put(body, 2, 1, 1);
              put(body, 4, 8, 4);
            }
            if (cmd == 0 || cmd == 1)
              ending = true;
          }
          auto response = sized(64, 0);
          response.replace(0, 4, "\xfeSMB", 4);
          put(response, 4, 64, 2);
          put(response, 6, 1, 2);
          put(response, 8, code, 4);
          put(response, 12, cmd, 2);
          auto credits = std::min<uint64_t>(cmd == 0 ? 32 : 1, 64 - (high - low));
          high += credits;
          put(response, 14, credits, 2);
          bool sign = authenticated && !encrypted;
          put(response, 16, 1 | (sign ? 8 : 0) | (related ? 4 : 0), 4);
          put(response, 24, get(p, 24, 8), 8);
          put(response, 36, tid, 4);
          put(response, 40, session, 8);
          response += body;
          if (i + 1 < requests.size()) {
            response.resize((response.size() + 7) / 8 * 8, '\0');
            put(response, 20, response.size(), 4);
          }
          if (sign)
            response.replace(48, 16, signature(key, response, selected.dialect >= 0x300));
          if ((cmd == 0 || (cmd == 1 && code == 0xc0000016)) && selected.dialect == 0x311)
            transcript = preauth(transcript, response);
          if (cmd == 0 && !code)
            negotiate_transcript = transcript;
          output += response;
          inherited_tree = tid;
          previous_status = code;
        }
        if (!socket.is_open())
          break;
        if (encrypted) {
          check(nonce_counter < 65536);
          bytes nonce = nonce_prefix.substr(0, selected.cipher == 1 ? 3 : 4) + bytes(8, '\0');
          put(nonce, nonce.size() - 8, ++nonce_counter, 8);
          output = encrypt(encryption_key, selected.cipher, session, nonce, output);
        }
        bytes header(4, '\0');
        header[1] = char(output.size() >> 16);
        header[2] = char(output.size() >> 8);
        header[3] = char(output.size());
        auto timer = s.io->call_after(5s, [this] { close(); });
        co_await socket.write_all(header + output);
        if (logged_off) {
          // LOGOFF ends the session, not the transport. Keeping the connection
          // alive also prevents EOF racing the client's receipt of this reply.
          logged_off = authenticated = raw_ntlm = false;
          session = 0;
          token.clear();
          username.clear();previous_session = 0;
          exchange.clear();
          std::fill(key.begin(), key.end(), 0);
          std::fill(encryption_key.begin(), encryption_key.end(), 0);
          std::fill(decryption_key.begin(), decryption_key.end(), 0);
          key.clear();encryption_key.clear();decryption_key.clear();
          received_nonces.clear();nonce_counter = 0;
          transcript = negotiate_transcript;
        }
      }
    } catch (const status_error &e) {
      log("smb", "connection_rejected", std::to_string(e.status));
    } catch (const error &e) {
      log("smb", "connection_rejected", e.what());
    } catch (...) {
    }
    close();
    co_await cleanup();
    if (!token.empty()) {
      try {
        json a = auth();
        co_await smb_rpc(s, "identity", "logout", a);
      } catch (...) {
      }
    }
    std::fill(key.begin(), key.end(), 0);
    std::fill(encryption_key.begin(), encryption_key.end(), 0);
    std::fill(decryption_key.begin(), decryption_key.end(), 0);
    s.clients.erase(this);
    --s.connections;
  }
};
pace::task<void> serve(std::shared_ptr<client> c) { co_await c->run(); }
pace::task<void> accept(smb_state &s, pace::tcp::listener &listener, std::atomic_bool &stop) {
  try {
    while (!stop) {
      auto socket = co_await listener.accept();
      if (s.connections >= std::min(s.cfg.connections, 32)) {
        socket.close();
        continue;
      }
      ++s.connections;
      s.io->spawn(serve(std::make_shared<client>(s, std::move(socket))));
    }
  } catch (...) {
    if (!stop)
      stop = true;
  }
}
} // namespace
int smb(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  if (!c.smb_port)
    return worker("smb", c, generation, stopping);
  file_lock lock(c.state / "smb.lock");
  apply_resource_budget(c);
  for (const auto &role : file_roles()) {
    bool ready = false;
    for (int n = 0; n < 20 && !stopping; ++n) {
      try {
        rpc(c, "smb", role, "smb_recover");
        ready = true;
        break;
      } catch (...) {
        std::this_thread::sleep_for(100ms);
      }
    }
    require(ready, "storage_unavailable");
  }
  smb_state s;
  s.cfg = c;
  pace::tcp::listener listener(*s.io, {"127.0.0.1", c.smb_port}, {false, 32});
  auto info = [&] {
    auto p = process_info(own_pid());
    p["role"] = "smb";
    p["generation"] = generation;
    p["business_ready"] = true;
    p["connections"] = s.connections.load();
    return p;
  };
  rpc_server server(c, "smb", generation,
                    [&](const std::string &op, const json &, const call_context &) {
                      if (op == "ping")
                        return info();
                      if (op == "stop") {
                        stopping = true;
                        return json{{"stopping", true}};
                      }
                      throw error("not_supported");
                    });
  write_json(c.state / "smb.instance.json", info());
  s.io->spawn(accept(s, listener, stopping));
  std::jthread loop([&] {
    try {
      s.io->run();
    } catch (...) {
      log("smb", "runtime_failed", "internal_error");
    }
    stopping = true;
  });
  log("smb", "started");
  while (!stopping)
    std::this_thread::sleep_for(20ms);
  s.io->post([&] {
    listener.close();
    for (auto *c : s.clients)
      c->close();
  });
  server.stop();
  auto deadline = now() + 6000;
  while (s.connections > 0 && now() < deadline)
    std::this_thread::sleep_for(20ms);
  s.pool.shutdown();
  while (s.pool.outstanding() > 0 && now() < deadline + 1000)
    std::this_thread::sleep_for(10ms);
  s.io->stop();
  loop.join();
  log("smb", "stopped");
  return 0;
}
} // namespace tc
