#include <taucloud/nfs.hpp>
#include <taucloud/files.hpp>
#include <taucloud/database.hpp>
#include <algorithm>
#include <map>
#include <set>
namespace tc::nfs_detail {
namespace {
struct failure {
  uint32_t status;
};
void check(bool b, uint32_t status = 22) {
  if (!b)
    throw failure{status};
}
uint32_t status(std::string_view code) {
  if (code == "not_found")
    return 2;
  if (code == "forbidden" || code == "permission_denied" || code == "policy_revoked" ||
      code == "lease_expired" || code == "mixed_writers_disabled")
    return 13;
  if (code == "already_exists" || code == "case_collision")
    return 17;
  if (code == "not_directory")
    return 20;
  if (code == "is_directory")
    return 21;
  if (code == "disk_full" || code == "no_space")
    return 28;
  if (code == "directory_not_empty")
    return 66;
  if (code == "quota_exceeded")
    return 69;
  if (code == "stale_handle" || code == "object_replaced")
    return 70;
  if (code == "not_supported" || code == "stable_handles_unavailable")
    return 10004;
  if (code == "overloaded" || code == "directory_limit" || code == "operation_limit" ||
      code == "uncertain_write" || code == "locked" || code == "sharing_violation")
    return 10008;
  if (code == "io_error" || code == "internal_error" || code == "database_error")
    return 5;
  return 22;
}
uint64_t hex64(const std::string &hex) { return std::stoull(hex.substr(0, 16), nullptr, 16); }
void time3(writer &w, const json &m) {
  auto ns = m.at("modified_ns").get<uint64_t>();
  w.u32(uint32_t(ns / 1000000000)).u32(uint32_t(ns % 1000000000));
}
void attr3(writer &w, const json &m) {
  bool d = m.at("directory");
  auto size = m.at("size").get<uint64_t>();
  w.u32(d ? 2 : 1)
      .u32(d ? 0700 : 0600)
      .u32(d ? 2 : 1)
      .u32(65534)
      .u32(65534)
      .u64(size)
      .u64(size)
      .u32(0)
      .u32(0)
      .u64(hex64(m.at("fsid")))
      .u64(hex64(m.at("fileid")));
  time3(w, m);
  time3(w, m);
  time3(w, m);
}
void post3(writer &w, const json &m) {
  w.boolean(!m.is_null());
  if (!m.is_null())
    attr3(w, m);
}
void wcc3(writer &w, const json &m) {
  w.boolean(false);
  post3(w, m);
}
std::string fh(reader &r) {
  auto h = r.opaque(64);
  check(h.size() == 50, 10001);
  return encode_bytes(h);
}
std::string component(reader &r) {
  auto n = r.opaque(255);
  portable_path(n);
  check(n.find('/') == std::string::npos);
  return n;
}
json attrs3(reader &r) {
  // POSIX ownership/mode mutation is deliberately unavailable in this application-ACL profile.
  json a = json::object();
  if (r.boolean())
    a["mode"] = r.u32();
  if (r.boolean())
    a["uid"] = r.u32();
  if (r.boolean())
    a["gid"] = r.u32();
  if (r.boolean())
    a["size"] = r.u64();
  for (const auto *key : {"atime", "mtime"}) {
    auto t = r.u32();
    check(t <= 2);
    if (t) {
      a[key] = t;
      if (t == 2) {
        r.u32();
        check(r.u32() < 1000000000);
      }
    }
  }
  return a;
}
} // namespace
struct server::impl {
  config cfg;
  domain_call call;
  database db;
  std::mutex mutex;
  std::string verifier = decode_bytes(random_hex(8));
  struct identity {
    json credential;
    std::string key;
  };
  impl(const config &c, domain_call f) : cfg(c), call(std::move(f)), db(c.state / "nfs.db") {
    sql(db, "CREATE TABLE IF NOT EXISTS replay(id TEXT PRIMARY KEY,hash TEXT NOT NULL,result TEXT "
            "NOT NULL);"
            "CREATE TABLE IF NOT EXISTS recovery(id TEXT PRIMARY KEY,body TEXT NOT NULL);");
    start_recovery();
  }
  json file(const identity &who, const std::string &handle, std::string op,
            json args = json::object(), std::string request = "", std::string export_name = "") {
    json b = {{"peer", "127.0.0.1"},
              {"credential", who.credential},
              {"write", op == "write" || op == "resize" || op == "create" || op == "mkdir" ||
                            op == "remove" || op == "rename"}};
    if (export_name.empty()) {
      auto raw = decode_bytes(handle);
      check(raw.size() == 50 && raw[0] == 1, 70);
      b["uuid"] = encode_bytes(raw.substr(2, 16));
    } else
      b["export"] = export_name;
    auto grant = call("identity", "nfs_authorize", b);
    args["grant"] = grant;
    args["op"] = op;
    args["handle"] = handle;
    if (!request.empty())
      args["request_id"] = request;
    return call(grant.at("root").at("worker"), "nfs_file", args);
  }
  std::string v3(const identity &who, uint32_t proc, reader &r, const std::string &request) {
    check(proc <= 21, 10004);
    if (proc == 0) {
      r.end();
      return {};
    }
    auto handle = fh(r);
    json args = json::object();
    std::string op;
    uint32_t mask = 0, count = 0;
    uint64_t cookie = 0;
    std::string cookieverf;
    json attrs = json::object();
    switch (proc) {
    case 1:
      op = "stat";
      break;
    case 2:
      attrs = attrs3(r);
      if (r.boolean()) {
        r.u32();
        r.u32();
        check(false, 10004);
      }
      op = "resize";
      break;
    case 3:
      op = "lookup";
      args["name"] = component(r);
      break;
    case 4:
      op = "stat";
      mask = r.u32();
      break;
    case 6:
      op = "read";
      args["offset"] = r.u64();
      args["count"] = std::min(r.u32(), 65536u);
      break;
    case 7: {
      op = "write";
      args["offset"] = r.u64();
      count = r.u32();
      check(r.u32() <= 2);
      auto data = r.opaque(65536);
      check(data.size() == count);
      args["data"] = encode_bytes(data);
      break;
    }
    case 8:
    case 9:
      args["name"] = component(r);
      op = proc == 8 ? "create" : "mkdir";
      if (proc == 8) {
        auto mode = r.u32();
        check(mode <= 1, 10004);
      }
      attrs = attrs3(r);
      break;
    case 12:
    case 13:
      op = "remove";
      args["directory"] = proc == 13;
      args["name"] = component(r);
      break;
    case 14:
      op = "rename";
      args["name"] = component(r);
      args["target"] = fh(r);
      args["to"] = component(r);
      break;
    case 16:
    case 17:
      op = "list";
      cookie = r.u64();
      cookieverf = r.fixed(8);
      if (proc == 17)
        r.u32();
      count = std::min(r.u32(), 65536u);
      check(count >= 512, 10005);
      break;
    case 18:
    case 19:
    case 20:
      op = "stat";
      break;
    case 21:
      op = "commit";
      args["offset"] = r.u64();
      args["count"] = r.u32();
      break;
    default:
      check(false, 10004);
    }
    r.end(); // Never mutate before the complete procedure arguments have been decoded.
    writer w;
    json meta;
    try {
      if (proc == 2) {
        check(attrs.size() == 1 && attrs.contains("size"), 10004);
        args["size"] = attrs.at("size");
      }
      if (proc == 8 || proc == 9) {
        check(!attrs.contains("uid") && !attrs.contains("gid") && !attrs.contains("atime") &&
                  !attrs.contains("mtime") && attrs.value("size", uint64_t(0)) == 0,
              10004);
        if (attrs.contains("mode"))
          check((attrs.at("mode").get<uint32_t>() & 0777) == (proc == 9 ? 0700u : 0600u), 10004);
      }
      meta = file(who, handle, op, args, request);
      w.u32(0);
      switch (proc) {
      case 1:
        attr3(w, meta);
        break;
      case 2:
        wcc3(w, meta);
        break;
      case 3:
        w.opaque(decode_bytes(meta.at("handle").get<std::string>()));
        post3(w, meta);
        post3(w, json());
        break;
      case 4: {
        uint32_t allowed = mask & 0x23;
        try {
          json a = {{"size", meta.at("size")}};
          auto raw = decode_bytes(handle);
          json b = {{"peer", "127.0.0.1"},
                    {"credential", who.credential},
                    {"uuid", encode_bytes(raw.substr(2, 16))},
                    {"write", true}};
          call("identity", "nfs_authorize", b);
          allowed = mask & 0x3f;
        } catch (...) {
        }
        post3(w, meta);
        w.u32(allowed);
        break;
      }
      case 6:
        post3(w, meta);
        {
          auto data = decode_bytes(meta.at("data").get<std::string>());
          w.u32(uint32_t(data.size())).boolean(meta.at("eof")).opaque(data);
        }
        break;
      case 7:
        wcc3(w, meta);
        w.u32(count).u32(2).fixed(verifier);
        break;
      case 8:
      case 9:
        w.boolean(true).opaque(decode_bytes(meta.at("handle").get<std::string>()));
        post3(w, meta);
        wcc3(w, json());
        break;
      case 12:
      case 13:
        wcc3(w, json());
        break;
      case 14:
        wcc3(w, json());
        wcc3(w, json());
        break;
      case 16:
      case 17: {
        auto v = decode_bytes(meta.at("verifier").get<std::string>());
        check(!cookie || cookieverf == v, 10003);
        auto &entries = meta.at("entries");
        check(cookie <= entries.size(), 10003);
        post3(w, json());
        w.fixed(v);
        size_t i = size_t(cookie);
        for (; i < entries.size(); ++i) {
          auto &e = entries[i];
          writer item;
          item.boolean(true)
              .u64(hex64(e.at("fileid")))
              .opaque(e.at("name").get<std::string>())
              .u64(i + 1);
          if (proc == 17) {
            post3(item, e);
            item.boolean(true).opaque(decode_bytes(e.at("handle").get<std::string>()));
          }
          if (w.data.size() + item.data.size() + 8 > count)
            break;
          w.fixed(item.data);
        }
        w.boolean(false).boolean(i == entries.size());
        break;
      }
      case 18: {
        post3(w, meta);
        auto total = meta.at("quota").get<uint64_t>(), used = meta.at("used").get<uint64_t>();
        auto free = total > used ? total - used : 0;
        w.u64(total).u64(free).u64(free).u64(100000).u64(0).u64(0).u32(0);
        break;
      }
      case 19:
        post3(w, meta);
        w.u32(65536)
            .u32(65536)
            .u32(1)
            .u32(65536)
            .u32(65536)
            .u32(1)
            .u32(16384)
            .u64(INT64_MAX)
            .u32(0)
            .u32(1)
            .u32(0x10);
        break;
      case 20:
        post3(w, meta);
        w.u32(1).u32(255).boolean(true).boolean(true).boolean(false).boolean(true);
        break;
      case 21:
        wcc3(w, meta);
        w.fixed(verifier);
        break;
      }
      return w.data;
    } catch (const error &e) {
      return v3_error(proc, status(e.what()));
    } catch (const failure &e) {
      return v3_error(proc, e.status);
    }
  }
  std::string v3_error(uint32_t proc, uint32_t code) {
    writer w;
    w.u32(code);
    if (proc == 2 || proc == 7 || proc == 8 || proc == 9 || proc == 12 || proc == 13 || proc == 21)
      wcc3(w, json());
    else if (proc == 14) {
      wcc3(w, json());
      wcc3(w, json());
    } else if (proc != 1)
      post3(w, json());
    return w.data;
  }
#include "nfs_v4.inc"
  std::string dispatch(std::string_view packet) {
    std::lock_guard guard(mutex);
    reader r(packet);
    uint32_t xid = r.u32();
    writer reply;
    reply.u32(xid).u32(1);
    try {
      if (r.u32() != 0)
        throw xdr_error();
      if (r.u32() != 2)
        return reply.u32(1).u32(0).u32(2).u32(2).data;
      auto prog = r.u32(), vers = r.u32(), proc = r.u32(), flavor = r.u32();
      auto credential = r.opaque(400);
      auto vf = r.u32();
      auto vb = r.opaque(400);
      if (vf != 0 || !vb.empty() ||
          (flavor != 1 && !(flavor == 0 && (proc == 0 || prog == 100000))))
        return reply.u32(1).u32(1).u32(5).data;
      identity who;
      if (flavor == 1) {
        reader a(credential);
        a.u32();
        a.opaque(255);
        auto uid = a.u32(), gid = a.u32(), n = a.u32();
        if (n > 16)
          throw xdr_error();
        json groups = json::array();
        for (uint32_t i = 0; i < n; ++i)
          groups.push_back(a.u32());
        a.end();
        who.credential = {{"uid", uid}, {"gid", gid}, {"groups", groups}};
        who.key = digest(who.credential.dump());
      } else {
        if (!credential.empty())
          throw xdr_error();
        who.credential = json::object();
      }
      reply.u32(0).u32(0).u32(0); // accepted, AUTH_NONE verifier
      auto request =
          digest(who.key + std::to_string(xid) + std::to_string(prog) + std::to_string(vers));
      if (prog == 100003) {
        if (vers != 3 && vers != 4)
          return reply.u32(2).u32(3).u32(4).data;
        if ((vers == 4 && proc > 1) || (vers == 3 && proc > 21))
          return reply.u32(3).data;
        if (proc == 0) {
          r.end();
          return reply.u32(0).data;
        }
        if (vers == 4)
          return reply.u32(0).fixed(v4(who, r)).data;
        // V3 duplicate requests have a bounded durable cache. A hash conflict is
        // never interpreted as a replay and a pending mutation is never reissued.
        auto hash = digest(std::string(packet.substr(4)));
        bool mut = proc == 2 || proc == 7 || proc == 8 || proc == 9 || proc == 12 || proc == 13 ||
                   proc == 14;
        if (mut) {
          statement q(db, "SELECT hash,result FROM replay WHERE id=?");
          q.bind(1, request);
          if (q.row()) {
            check(q.text(0) == hash, 10008);
            auto out = q.text(1);
            return reply.u32(0).fixed(out.empty() ? v3_error(proc, 10008) : decode_bytes(out)).data;
          }
          statement count(db, "SELECT count(*) FROM replay");
          count.row();
          check(count.integer(0) < 10000, 10008);
          // Domain pending/complete journal supplies crash protection; reserve the
          // network cache before dispatch, even for an eventual protocol error.
          statement add(db, "INSERT INTO replay VALUES(?,?,'')");
          add.bind(1, request);
          add.bind(2, hash);
          add.row();
        }
        std::string result;
        try {
          result = v3(who, proc, r, request);
        } catch (const failure &e) {
          result = v3_error(proc, e.status);
        } catch (const error &e) {
          result = v3_error(proc, status(e.what()));
        }
        if (mut) {
          statement q(db, "UPDATE replay SET result=? WHERE id=?");
          q.bind(1, encode_bytes(result));
          q.bind(2, request);
          q.row();
        }
        return reply.u32(0).fixed(result).data;
      }
      if (prog == 100005) { // MOUNT v3, TCP on the configured service port.
        if (vers != 3)
          return reply.u32(2).u32(3).u32(3).data;
        writer out;
        if (proc == 0) {
          r.end();
          return reply.u32(0).data;
        }
        if (proc == 1) {
          auto path = r.opaque(1024);
          r.end();
          check(path.size() > 1 && path[0] == '/' && path.find('/', 1) == std::string::npos, 13);
          try {
            auto m = file(who, "", "root", json::object(), "", path.substr(1));
            out.u32(0).opaque(decode_bytes(m.at("handle").get<std::string>())).u32(1).u32(1);
          } catch (const error &e) {
            out.u32(status(e.what()));
          }
          return reply.u32(0).fixed(out.data).data;
        }
        if (proc == 3) {
          r.opaque(1024);
          r.end();
          return reply.u32(0).data;
        }
        if (proc == 4) {
          r.end();
          return reply.u32(0).data;
        }
        return reply.u32(3).data;
      }
      if (prog == 100000) { // Read-only rpcbind/portmapper. No arbitrary SET, UNSET or CALLIT.
        if (vers != 2 && vers != 3 && vers != 4)
          return reply.u32(2).u32(2).u32(4).data;
        if (proc == 0) {
          r.end();
          return reply.u32(0).data;
        }
        if (proc != 3)
          return reply.u32(3).data;
        auto p = r.u32(), v = r.u32();
        bool tcp;
        if (vers == 2) {
          tcp = r.u32() == 6;
          r.u32();
        } else {
          tcp = r.opaque(32) == "tcp";
          r.opaque(256);
          r.opaque(256);
        }
        r.end();
        bool supported = tcp && ((p == 100003 && (v == 3 || v == 4)) || (p == 100005 && v == 3) ||
                                 (p == 100000 && (v >= 2 && v <= 4)));
        if (vers == 2)
          return reply.u32(0).u32(supported ? cfg.nfs_port : 0).data;
        return reply.u32(0)
            .opaque(supported ? "127.0.0.1." + std::to_string(cfg.nfs_port >> 8) + "." +
                                    std::to_string(cfg.nfs_port & 255)
                              : "")
            .data;
      }
      return reply.u32(1).data; // PROG_UNAVAIL, including NLM and NSM.
    } catch (const xdr_error &) {
      writer w;
      return w.u32(xid).u32(1).u32(0).u32(0).u32(0).u32(4).data;
    } catch (...) {
      writer w;
      return w.u32(xid).u32(1).u32(0).u32(0).u32(0).u32(5).data;
    }
  }
};
server::server(const config &c, domain_call f) : impl_(std::make_unique<impl>(c, std::move(f))) {}
server::~server() = default;
std::string server::dispatch(std::string_view record) { return impl_->dispatch(record); }
} // namespace tc::nfs_detail
