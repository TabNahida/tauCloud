#include <taucloud/dav.hpp>
#include <taucloud/files.hpp>
#include <taucloud/runtime/bounded_executor.hpp>
#include <openssl/evp.h>
#include <set>
namespace tc {
namespace {
struct dav_state {
  config cfg;
  std::shared_ptr<pace::io_context> io = std::make_shared<pace::io_context>();
  taucloud::bounded_executor pool{4, 32, 32 * ipc_frame_size};
  std::atomic<int> connections = 0;
  std::map<std::string, json> sessions;
  std::set<pace::tls::stream *> sockets;
};
pace::task<json> dav_rpc(dav_state &s, std::string target, std::string op,
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
        pending->value = rpc(c, "webdav", target, op, body, "", stop);
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
unsigned dav_error(std::string_view e) {
  if (e == "unauthorized")
    return 401;
  if (e == "forbidden" || e == "protected_property" || e == "unsupported_name" ||
      e == "reserved_name" || e == "unsafe_path" || e == "hardlink_denied" ||
      e == "mixed_writers_disabled")
    return 403;
  if (e == "not_found")
    return 404;
  if (e == "already_exists")
    return 405;
  if (e == "dav_locked" || e == "locked")
    return 423;
  if (e == "precondition_failed")
    return 412;
  if (e == "lock_mismatch" || e == "destination_type_conflict" || e == "parent_missing" ||
      e == "cross_volume_move_requires_copy")
    return 409;
  if (e == "quota_exceeded" || e == "disk_full" || e == "copy_limit" || e == "tree_limit" ||
      e == "property_limit")
    return 507;
  if (e == "body_too_large" || e == "headers_too_large")
    return 413;
  if (e == "unsupported_media")
    return 415;
  if (e == "expectation_failed")
    return 417;
  if (e == "invalid_xml" || e == "bad_http" || e == "invalid_path" || e == "invalid_destination" ||
      e == "invalid_if" || e == "invalid_request")
    return 400;
  if (e == "rate_limited" || e == "overloaded")
    return 429;
  return 503;
}
std::string basic(std::string text) {
  require(text.size() <= 2048 && text.size() % 4 == 0 && !text.empty(), "unauthorized");
  for (char c : text)
    require((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '+' || c == '/' || c == '=',
            "unauthorized");
  std::string out(text.size(), '\0');
  auto n = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                           reinterpret_cast<const unsigned char *>(text.data()),
                           static_cast<int>(text.size()));
  require(n >= 0, "unauthorized");
  if (text.ends_with("=="))
    n -= 2;
  else if (text.ends_with('='))
    --n;
  out.resize(static_cast<size_t>(n));
  require(out.find('\0') == std::string::npos, "unauthorized");
  return out;
}
pace::task<json> authenticate(dav_state &s, const http_stream::head &head) {
  require(head.get("cookie").empty() && head.get("origin").empty(), "forbidden");
  auto authorization = head.get("authorization");
  json auth;
  if (authorization.starts_with("Bearer "))
    auth = {{"token", authorization.substr(7)}, {"kind", "cli"}};
  else {
    require(authorization.starts_with("Basic "), "unauthorized");
    auto key = digest(authorization);
    auto it = s.sessions.find(key);
    if (it != s.sessions.end() && it->second.at("expires").get<int64_t>() > now())
      auth = {{"token", it->second.at("token")}, {"kind", "cli"}};
    else {
      auto value = basic(authorization.substr(6));
      auto colon = value.find(':');
      require(colon != std::string::npos, "unauthorized");
      json login_body = {{"username", value.substr(0, colon)},
                         {"password", value.substr(colon + 1)},
                         {"kind", "cli"},
                         {"scope", "files"}};
      auto session = co_await dav_rpc(s, "identity", "login", login_body);
      if (s.sessions.size() >= 256)
        s.sessions.erase(s.sessions.begin());
      s.sessions[key] = session;
      auth = {{"token", session.at("token")}, {"kind", "cli"}};
    }
  }
  co_await dav_rpc(s, "identity", "validate", auth);
  co_return auth;
}
struct request_files {
  dav_state &state;
  json auth;
  std::string share;
  std::map<std::string, json> cache;
  pace::task<json> grant(const std::string &path, bool writing) {
    auto key = path + (writing ? ":w" : ":r");
    auto it = cache.find(key);
    if (it != cache.end() && it->second.at("expires").get<int64_t>() > now() + 500)
      co_return it->second;
    json grant_body = {{"auth", auth},
                       {"share", share},
                       {"path", path},
                       {"write", writing},
                       {"protocol", "webdav"}};
    auto g = co_await dav_rpc(state, "identity", "authorize", grant_body);
    cache[key] = g;
    co_return g;
  }
  pace::task<json> call(const std::string &op, const std::string &path, json body = json::object(),
                        bool writing = false) {
    auto g = co_await grant(path, writing);
    body["grant"] = g;
    co_return co_await dav_rpc(state, g.at("root").at("worker"), op, body);
  }
};
std::map<std::string, std::string> dav_headers() {
  return {{"DAV", "1, 2"},
          {"Allow",
           "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK"},
          {"Cache-Control", "no-store"}};
}
pace::task<void> serve_dav(dav_state &s, pace::tls::stream &socket) {
  http_stream::stream wire(socket);
  unsigned failure = 0;
  std::string code;
  bool started = false;
  std::string cleanup_path, cleanup_job, cleanup_handle;
  json last_grant;
  std::unique_ptr<request_files> files;
  try {
    auto head = co_await wire.read_head();
    auto expected = "127.0.0.1:" + std::to_string(s.cfg.dav_port),
         localhost = "localhost:" + std::to_string(s.cfg.dav_port);
    require(head.get("host") == expected || head.get("host") == localhost, "invalid_request");
    auto origin = "https://" + head.get("host");
    auto loc = dav::decode_path(head.target);
    auto auth = co_await authenticate(s, head);
    files = std::make_unique<request_files>(request_files{s, auth, loc.share, {}});
    bool write = head.method == "PUT" || head.method == "MKCOL" || head.method == "DELETE" ||
                 head.method == "MOVE" || head.method == "PROPPATCH" || head.method == "LOCK" ||
                 head.method == "UNLOCK";
    auto grant = co_await files->grant(loc.path, write);
    last_grant = grant;
    auto base = grant.at("path").get<std::string>();
    auto prefix = base.substr(0, base.size() - loc.path.size());
    if (prefix.ends_with('/'))
      prefix.pop_back();
    auto cond = dav::conditions(head, loc, origin);
    if (cond.contains("dav_if"))
      for (auto &group : cond["dav_if"]) {
        auto p = group.at("path").get<std::string>();
        group["path"] = prefix.empty() ? p : prefix + (p.empty() ? "" : "/" + p);
      }
    require(head.get("expect").empty() || http_stream::lower(head.get("expect")) == "100-continue",
            "expectation_failed");
    std::map<std::string, std::string> headers = dav_headers();
    if (head.method == "OPTIONS") {
      started = true;
      co_await wire.respond(200, headers);
      co_return;
    }
    if (head.method == "PUT") {
      require(!loc.trailing && !loc.path.empty(), "invalid_path");
      require(head.length || head.chunked, "bad_http");
      uint64_t maximum = 1024ull * 1024 * 1024;
      auto quota = co_await files->call("quota", loc.path);
      auto occupied = quota.at("used").get<uint64_t>() + quota.at("reserved").get<uint64_t>();
      auto limit = quota.at("limit").get<uint64_t>();
      require(occupied <= limit, "quota_exceeded");
      maximum = std::min(maximum, limit - occupied);
      if (head.length)
        require(*head.length <= maximum, "quota_exceeded");
      uint64_t total = head.length.value_or(maximum);
      auto request = cond;
      request["conditions"] = cond;
      request["size"] = total;
      request["request_id"] = random_hex(16);
      bool existed = false;
      try {
        co_await files->call("dav_stat", loc.path);
        existed = true;
      } catch (const error &e) {
        if (std::string_view(e.what()) != "not_found")
          throw;
      }
      if (loc.path.find('/') != std::string::npos) {
        try {
          auto parent = co_await files->call("dav_stat", loc.path.substr(0, loc.path.rfind('/')));
          require(parent.at("directory"), "parent_missing");
        } catch (const error &) {
          throw error("parent_missing");
        }
      }
      auto job = co_await files->call("begin", loc.path, request, true);
      cleanup_job = job.at("id");
      cleanup_path = loc.path;
      wire.admit(head, total);
      if (!head.get("expect").empty())
        co_await wire.write("HTTP/1.1 100 Continue\r\n\r\n");
      uint64_t offset = 0;
      for (;;) {
        auto data = co_await wire.read();
        if (data.empty())
          break;
        size_t sent = 0;
        while (sent < data.size()) {
          json chunk_body = {{"job", cleanup_job},
                             {"offset", offset},
                             {"data", encode_bytes(std::string_view(data).substr(sent))}};
          auto result = co_await files->call("chunk", loc.path, chunk_body, true);
          auto n = result.at("written").get<size_t>();
          require(n > 0, "io_error");
          sent += n;
          offset += n;
        }
      }
      json job_body = {{"job", cleanup_job}};
      if (head.chunked)
        co_await files->call("seal", loc.path, job_body, true);
      co_await files->call("commit", loc.path, job_body, true);
      cleanup_job.clear();
      auto meta = co_await files->call("dav_stat", loc.path);
      headers["ETag"] = meta.at("etag");
      headers["Location"] = dav::href(loc.share, loc.path);
      started = true;
      co_await wire.respond(existed ? 204 : 201, headers);
      co_return;
    }
    if (head.length.value_or(0) > 65536)
      throw error("body_too_large");
    wire.admit(head, 65536);
    if (!head.get("expect").empty())
      co_await wire.write("HTTP/1.1 100 Continue\r\n\r\n");
    std::string body;
    for (;;) {
      auto part = co_await wire.read();
      if (part.empty())
        break;
      body += part;
    }
    if (head.method == "GET" || head.method == "HEAD") {
      auto meta = co_await files->call("dav_stat", loc.path);
      auto etag = meta.at("etag").get<std::string>();
      headers["ETag"] = etag;
      headers["Last-Modified"] = dav::date(meta.at("modified_ns"));
      headers["Accept-Ranges"] = "bytes";
      headers["Content-Type"] = "application/octet-stream";
      if (!head.get("if-match").empty())
        require(http_stream::etag_matches(head.get("if-match"), etag, true), "precondition_failed");
      auto since = dav::parse_date(head.get("if-modified-since"));
      auto unmodified = dav::parse_date(head.get("if-unmodified-since"));
      if (unmodified && head.get("if-match").empty())
        require(meta.at("modified_ns").get<int64_t>() / 1000000000 <= *unmodified / 1000000000,
                "precondition_failed");
      if (http_stream::etag_matches(head.get("if-none-match"), etag, true, true) ||
          (!head.headers.contains("if-none-match") && since &&
           meta.at("modified_ns").get<int64_t>() / 1000000000 <= *since / 1000000000)) {
        started = true;
        co_await wire.respond(304, headers);
        co_return;
      }
      uint64_t size = meta.at("size"), start = 0, count = size;
      unsigned status = 200;
      auto range = head.method == "GET" ? head.get("range") : "";
      if (!range.starts_with("bytes="))
        range.clear();
      if (!head.get("if-range").empty() && head.get("if-range") != etag &&
          head.get("if-range") != headers["Last-Modified"])
        range.clear();
      if (!range.empty() && range.find(',') == std::string::npos) {
        bool invalid = false;
        try {
          require(range.starts_with("bytes="), "bad_http");
          auto dash = range.find('-', 6);
          require(dash != std::string::npos, "bad_http");
          auto left = range.substr(6, dash - 6), right = range.substr(dash + 1);
          if (left.empty()) {
            auto suffix = http_stream::decimal(right);
            count = std::min(suffix, size);
            start = size - count;
          } else {
            start = http_stream::decimal(left);
            auto end = right.empty() ? size - 1 : http_stream::decimal(right);
            require(start < size && end >= start, "bad_http");
            count = std::min(end, size - 1) - start + 1;
          }
          require(count > 0, "bad_http");
        } catch (...) {
          invalid = true;
        }
        if (invalid) {
          headers["Content-Range"] = "bytes */" + std::to_string(size);
          started = true;
          co_await wire.respond(416, headers);
          co_return;
        }
        status = 206;
        headers["Content-Range"] = "bytes " + std::to_string(start) + "-" +
                                   std::to_string(start + count - 1) + "/" + std::to_string(size);
      }
      headers["Content-Length"] = std::to_string(count);
      if (head.method == "HEAD" || meta.at("directory").get<bool>()) {
        started = true;
        co_await wire.write_head(status, headers);
        co_return;
      }
      auto opened = co_await files->call("open", loc.path);
      cleanup_handle = opened.at("handle");
      cleanup_path = loc.path;
      started = true;
      co_await wire.write_head(status, headers);
      while (count) {
        json read_body = {{"handle", cleanup_handle},
                          {"offset", start},
                          {"count", std::min<uint64_t>(http_stream::chunk_size, count)}};
        auto value = co_await files->call("read", loc.path, read_body);
        auto bytes = decode_bytes(value.at("data").get<std::string>());
        require(!bytes.empty(), "object_replaced");
        co_await wire.write(bytes);
        count -= bytes.size();
        start += bytes.size();
      }
      json close_body = {{"handle", cleanup_handle}};
      co_await files->call("close", loc.path, close_body);
      cleanup_handle.clear();
      co_return;
    }
    if (head.method == "PROPFIND") {
      auto depth = head.get("depth");
      if (depth.empty() || depth == "infinity") {
        headers["Content-Type"] = "application/xml; charset=utf-8";
        started = true;
        co_await wire.respond(403, headers,
                              "<D:error xmlns:D=\"DAV:\"><D:propfind-finite-depth/></D:error>");
        co_return;
      }
      require(depth == "0" || depth == "1", "invalid_request");
      json list_body = {{"depth", depth == "0" ? 0 : 1}};
      auto items = co_await files->call("dav_list", loc.path, list_body);
      auto response = dav::propfind(body, items, loc.share, prefix);
      headers["Content-Type"] = "application/xml; charset=utf-8";
      started = true;
      co_await wire.respond(207, headers, response);
      co_return;
    }
    if (head.method == "PROPPATCH") {
      auto doc = dav::xml(body);
      require(dav::name(doc.document_element()) ==
                  std::pair<std::string, std::string>{"DAV:", "propertyupdate"},
              "invalid_xml");
      json edits = json::array();
      bool protected_value = false;
      for (auto action : doc.document_element().children())
        if (action.type() == pugi::node_element) {
          auto [ns, name] = dav::name(action);
          require(ns == "DAV:" && (name == "set" || name == "remove"), "invalid_xml");
          for (auto props : action.children())
            if (props.type() == pugi::node_element) {
              require(dav::name(props) == std::pair<std::string, std::string>{"DAV:", "prop"},
                      "invalid_xml");
              for (auto prop : props.children())
                if (prop.type() == pugi::node_element) {
                  auto p = dav::property(prop);
                  p["remove"] = name == "remove";
                  p["protected"] =
                      p.at("namespace") == "DAV:" &&
                      (p.at("name") == "getetag" || p.at("name") == "getlastmodified" ||
                       p.at("name") == "getcontentlength" || p.at("name") == "resourcetype" ||
                       p.at("name") == "supportedlock" || p.at("name") == "lockdiscovery");
                  protected_value = protected_value || p.at("protected").get<bool>();
                  edits.push_back(p);
                }
            }
        }
      require(!edits.empty(), "invalid_xml");
      auto request = cond;
      request["properties"] = edits;
      if (!protected_value)
        co_await files->call("dav_props", loc.path, request, true);
      std::string response = "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>" +
                             dav::href(loc.share, loc.path) + "</D:href>";
      for (auto p : edits) {
        unsigned status = protected_value ? (p.at("protected").get<bool>() ? 403 : 424) : 200;
        response += "<D:propstat><D:prop>" + p.at("xml").get<std::string>() +
                    "</D:prop><D:status>HTTP/1.1 " + std::to_string(status) + " " +
                    http_stream::reason(status) + "</D:status></D:propstat>";
      }
      response += "</D:response></D:multistatus>";
      headers["Content-Type"] = "application/xml; charset=utf-8";
      started = true;
      co_await wire.respond(207, headers, response);
      co_return;
    }
    if (head.method == "MKCOL") {
      require(body.empty(), "unsupported_media");
      try {
        co_await files->call("mkdir", loc.path, cond, true);
      } catch (const error &e) {
        if (std::string_view(e.what()) == "not_found")
          throw error("parent_missing");
        throw;
      }
      started = true;
      co_await wire.respond(201, headers);
      co_return;
    }
    if (head.method == "DELETE" || head.method == "COPY" || head.method == "MOVE") {
      require(head.method != "DELETE" || head.get("depth").empty() ||
                  head.get("depth") == "infinity",
              "invalid_request");
      auto request = cond;
      request["request_id"] = random_hex(16);
      std::string op = head.method == "DELETE" ? "dav_delete"
                       : head.method == "COPY" ? "dav_copy"
                                               : "dav_move";
      if (head.method != "DELETE") {
        auto destination = head.get("destination");
        require(destination.starts_with(origin + "/") || destination.starts_with("/dav/"),
                "invalid_destination");
        auto to = dav::decode_path(
            destination.starts_with("/") ? destination : destination.substr(origin.size()));
        require(to.share == loc.share, "invalid_destination");
        request["target_grant"] = co_await files->grant(to.path, true);
        auto overwrite = head.get("overwrite");
        require(overwrite.empty() || overwrite == "T" || overwrite == "F", "invalid_request");
        request["overwrite"] = overwrite != "F";
        auto depth = head.get("depth");
        require(depth.empty() || depth == "infinity" || (head.method == "COPY" && depth == "0"),
                "invalid_request");
        request["depth"] = depth.empty() ? "infinity" : depth;
      }
      auto done = co_await files->call(op, loc.path, request, head.method != "COPY");
      started = true;
      co_await wire.respond(
          head.method == "DELETE" ? 204 : (done.at("created").get<bool>() ? 201 : 204), headers);
      co_return;
    }
    if (head.method == "LOCK") {
      auto request = cond;
      auto timeout = head.get("timeout");
      int64_t seconds = 3600;
      if (timeout.starts_with("Second-"))
        seconds = std::min<uint64_t>(3600, http_stream::decimal(timeout.substr(7)));
      request["timeout"] = seconds;
      if (body.empty()) {
        require(cond.contains("dav_if"), "invalid_if");
        std::string token;
        for (auto group : cond.at("dav_if"))
          for (auto list : group.at("lists"))
            for (auto c : list)
              if (c.at("kind") == "token" && !c.at("not").get<bool>())
                token = c.at("value");
        require(!token.empty(), "invalid_if");
        request["token"] = token;
      } else {
        auto doc = dav::xml(body);
        require(dav::name(doc.document_element()) ==
                    std::pair<std::string, std::string>{"DAV:", "lockinfo"},
                "invalid_xml");
        std::string scope, owner;
        bool type = false;
        for (auto child : doc.document_element().children())
          if (child.type() == pugi::node_element) {
            auto [ns, name] = dav::name(child);
            require(ns == "DAV:", "invalid_xml");
            if (name == "lockscope") {
              for (auto node : child.children())
                if (node.type() == pugi::node_element) {
                  auto pair = dav::name(node);
                  require(pair.first == "DAV:" &&
                              (pair.second == "exclusive" || pair.second == "shared"),
                          "invalid_xml");
                  scope = pair.second;
                }
            } else if (name == "locktype") {
              for (auto node : child.children())
                if (node.type() == pugi::node_element)
                  type = dav::name(node) == std::pair<std::string, std::string>{"DAV:", "write"};
            } else if (name == "owner")
              owner = dav::property(child).at("xml");
          }
        require(type && !scope.empty(), "invalid_xml");
        request["scope"] = scope;
        request["owner"] = owner;
        auto depth = head.get("depth");
        request["depth"] = depth.empty() ? "infinity" : depth;
      }
      auto lock = co_await files->call("dav_lock", loc.path, request, true);
      headers["Lock-Token"] = "<" + lock.at("token").get<std::string>() + ">";
      headers["Content-Type"] = "application/xml; charset=utf-8";
      started = true;
      co_await wire.respond(lock.value("created", false) && !body.empty() ? 201 : 200, headers,
                            "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>" +
                                dav::lock_xml(lock, loc.share, prefix) +
                                "</D:lockdiscovery></D:prop>");
      co_return;
    }
    if (head.method == "UNLOCK") {
      auto token = head.get("lock-token");
      require(token.starts_with('<') && token.ends_with('>'), "invalid_request");
      json unlock_body = {{"token", token.substr(1, token.size() - 2)}};
      co_await files->call("dav_unlock", loc.path, unlock_body, true);
      started = true;
      co_await wire.respond(204, headers);
      co_return;
    }
    started = true;
    co_await wire.respond(405, headers);
  } catch (const error &e) {
    failure = dav_error(e.what());
    code = e.what();
  } catch (const json::exception &) {
    failure = 400;
    code = "invalid_request";
  } catch (...) {
    failure = 503;
    code = "transport_error";
  }
  if (files) {
    if (!cleanup_handle.empty())
      try {
        json close_body = {{"handle", cleanup_handle}, {"grant", last_grant}};
        co_await dav_rpc(s, last_grant.at("root").at("worker"), "dav_close", close_body);
      } catch (...) {
      }
    if (!cleanup_job.empty())
      try {
        json cancel_body = {{"job", cleanup_job}, {"grant", last_grant}};
        co_await dav_rpc(s, last_grant.at("root").at("worker"), "dav_abort", cancel_body);
      } catch (...) {
      }
  }
  if (failure && !started && socket.is_open())
    try {
      auto headers = dav_headers();
      headers["Content-Type"] = "application/xml; charset=utf-8";
      if (failure == 401)
        headers["WWW-Authenticate"] = "Basic realm=\"tauCloud WebDAV\", charset=\"UTF-8\"";
      co_await wire.respond(failure, headers,
                            "<D:error xmlns:D=\"DAV:\"><D:responsedescription>" +
                                dav::escape(code) + "</D:responsedescription></D:error>");
    } catch (...) {
    }
}
pace::task<void> dav_connection(dav_state &s, pace::tcp::stream socket,
                                const pace::tls::context &tls) {
  struct guard {
    std::atomic<int> &n;
    ~guard() { --n; }
  } count{s.connections};
  pace::tls::stream secure(std::move(socket), tls);
  s.sockets.insert(&secure);
  try {
    auto timeout = s.io->call_after(5s, [&secure] { secure.close(); });
    co_await secure.handshake();
    timeout.cancel();
    co_await serve_dav(s, secure);
    co_await secure.shutdown(250ms);
  } catch (...) {
  }
  secure.close();
  s.sockets.erase(&secure);
}
pace::task<void> dav_accept(dav_state &s, pace::tcp::listener &listener,
                            const pace::tls::context &tls, std::atomic_bool &stop) {
  try {
    while (!stop) {
      auto socket = co_await listener.accept();
      if (s.connections >= std::min(s.cfg.connections, 32)) {
        socket.close();
        continue;
      }
      ++s.connections;
      s.io->spawn(dav_connection(s, std::move(socket), tls));
    }
  } catch (...) {
    if (!stop)
      stop = true;
  }
}
} // namespace
int webdav(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  if (!c.dav_port)
    return worker("webdav", c, generation, stopping);
  file_lock lock(c.state / "webdav.lock");
  apply_resource_budget(c);
  dav_state s;
  s.cfg = c;
  pace::tls::context tls(pace::tls::role::server);
  tls.use_certificate_chain((c.state / "tls-cert.pem").string(),
                            (c.state / "tls-key.pem").string());
  tls.set_alpn_protocols({"http/1.1"});
  pace::tcp::listener listener(*s.io, {"127.0.0.1", c.dav_port}, {false, 32});
  auto info = [&] {
    auto p = process_info(own_pid());
    p["role"] = "webdav";
    p["generation"] = generation;
    p["business_ready"] = true;
    p["connections"] = s.connections.load();
    return p;
  };
  rpc_server server(c, "webdav", generation,
                    [&](const std::string &op, const json &, const call_context &) {
                      if (op == "ping")
                        return info();
                      if (op == "stop") {
                        stopping = true;
                        return json{{"stopping", true}};
                      }
                      throw error("not_supported");
                    });
  write_json(c.state / "webdav.instance.json", info());
  s.io->spawn(dav_accept(s, listener, tls, stopping));
  std::jthread loop([&] {
    try {
      s.io->run();
    } catch (...) {
      log("webdav", "runtime_failed", "internal_error");
    }
    stopping = true;
  });
  log("webdav", "started");
  while (!stopping)
    std::this_thread::sleep_for(20ms);
  s.io->post([&] {
    listener.close();
    for (auto *socket : s.sockets)
      socket->close();
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
  log("webdav", "stopped");
  return 0;
}
} // namespace tc
