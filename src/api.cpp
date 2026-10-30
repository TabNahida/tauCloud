#include <algorithm>
#include <iostream>
#include <pace/http.hpp>
#include <pace/tls.hpp>
#include <set>
#include <taucloud/core.hpp>
#include <taucloud/files.hpp>
#include <fstream>
#include <openssl/evp.h>
#include <taucloud/runtime/bounded_executor.hpp>
namespace tc {
static unsigned status_code(std::string_view code) {
  if (code == "unauthorized")
    return 401;
  if (code == "forbidden" || code == "csrf_denied" || code == "origin_denied")
    return 403;
  if (code == "dav_locked")
    return 423;
  if (code == "precondition_failed")
    return 412;
  if (code == "not_found")
    return 404;
  if (code == "rate_limited" || code == "session_limit")
    return 429;
  if (code == "idempotency_conflict" || code == "already_exists" || code == "case_collision" ||
      code == "locked" || code == "conflict")
    return 409;
  if (code == "invalid_request" || code == "invalid_credentials_format")
    return 400;
  if (code == "internal_error" || code == "database_error")
    return 500;
  if (code == "quota_exceeded" || code == "disk_full")
    return 507;
  if (code == "stale_handle" || code == "policy_revoked" || code == "lease_expired")
    return 409;
  if (code == "invalid_path" || code == "unsupported_name" || code == "reserved_name" ||
      code == "invalid_offset" || code == "invalid_identifier" || code == "invalid_quota" ||
      code == "invalid_owner")
    return 400;
  return 503;
}
static pace::http::response response(json value, unsigned status = 200) {
  auto r = pace::http::json(value.dump(), status);
  r.close = true;
  r.headers = {{"Cache-Control", "no-store"}, {"X-Content-Type-Options", "nosniff"}};
  return r;
}
struct api_state {
  config cfg;
  std::shared_ptr<pace::io_context> io;
  taucloud::bounded_executor pool{4, 32, 32 * ipc_frame_size};
  std::atomic<int> connections = 0;
};
static pace::task<json> dispatch(api_state &s, std::string target, std::string operation,
                                 json body = json::object()) {
  struct result {
    json value;
    std::exception_ptr error;
    bool done = false;
  };
  auto pending = std::make_shared<result>();
  taucloud::bounded_executor::ticket ticket;
  auto work = [pending, c = s.cfg, target, operation, body](std::stop_token stop) {
    pending->value = rpc(c, "api", target, operation, body, "", stop);
  };
  bool accepted = s.pool.submit(
      s.io, ipc_frame_size, std::chrono::steady_clock::now() + 5s, std::move(work),
      [pending](taucloud::bounded_executor::result outcome) {
        pending->error = outcome.error;
        if (outcome.state != taucloud::bounded_executor::status::completed && !pending->error)
          pending->error = std::make_exception_ptr(error("cancelled"));
        pending->done = true;
      },
      ticket);
  require(accepted, "overloaded");
  try {
    while (!pending->done)
      co_await s.io->sleep_for(2ms);
  } catch (...) {
    ticket.cancel();
    throw;
  }
  if (pending->error)
    std::rethrow_exception(pending->error);
  co_return pending->value;
}
static json credentials(const pace::http::request &r, const config &c, bool write) {
  auto authorization = std::string(r.header("Authorization")),
       cookie = std::string(r.header("Cookie"));
  require(authorization.empty() || cookie.empty(), "invalid_request");
  std::string token, kind;
  if (!authorization.empty()) {
    require(authorization.starts_with("Bearer "), "unauthorized");
    token = authorization.substr(7);
    kind = "cli";
  } else {
    kind = "browser";
    size_t pos = 0;
    bool found = false;
    while (pos < cookie.size()) {
      auto end = cookie.find(';', pos);
      if (end == std::string::npos)
        end = cookie.size();
      auto piece = cookie.substr(pos, end - pos);
      while (piece.starts_with(' '))
        piece.erase(0, 1);
      if (piece.starts_with("__Host-taucloud=")) {
        require(!found, "invalid_request");
        found = true;
        token = piece.substr(std::string_view("__Host-taucloud=").size());
      }
      pos = end + 1;
    }
    if (write)
      require(r.header("Origin") == c.origin(), "origin_denied");
  }
  require(token.size() == 64, "unauthorized");
  return {{"token", token}, {"kind", kind}, {"write", write}, {"csrf", r.header("X-CSRF-Token")}};
}
static pace::task<pace::http::server_response> handle(api_state &s, pace::http::request r) {
  try {
    std::set<std::string> seen;
    for (auto &h : r.headers) {
      auto name = h.name;
      std::transform(name.begin(), name.end(), name.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      require(seen.insert(name).second, "invalid_request");
    }
    require(r.header("Host") == "127.0.0.1:" + std::to_string(s.cfg.port), "invalid_request");
    require(r.header("Origin").empty() || r.header("Origin") == s.cfg.origin(), "origin_denied");
    if (r.method == "GET" && r.target == "/api/v1/health/live")
      co_return response({{"status", "ok"}});
    if (r.method == "GET" && r.target == "/api/v1/health/ready") {
      co_await dispatch(s, "identity", "ping");
      co_await dispatch(s, "supervisor", "ping");
      co_return response({{"status", "ready"}});
    }
    json body = json::object();
    if (!r.body.empty()) {
      require(r.header("Content-Type") == "application/json", "invalid_request");
      try {
        body = json::parse(r.body);
      } catch (...) {
        throw error("invalid_request");
      }
      require(body.is_object(), "invalid_request");
    }
    if (r.method == "POST" && r.target == "/api/v1/auth/login") {
      auto kind = body.value("kind", "cli");
      if (kind == "browser")
        require(r.header("Origin") == s.cfg.origin(), "origin_denied");
      auto session = co_await dispatch(s, "identity", "login", body);
      auto token = session.at("token").get<std::string>();
      if (kind == "browser")
        session.erase("token");
      auto out = response(session);
      if (kind == "browser")
        out.headers.push_back(
            {"Set-Cookie", "__Host-taucloud=" + token +
                               "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800"});
      co_return out;
    }
    bool write = r.method != "GET";
    static const std::set<std::string> resources = {
        "nfs-exports", "users", "groups", "memberships", "storage-roots", "spaces", "shares", "grants", "audit"};
    auto resource = r.target.starts_with("/api/v1/") ? r.target.substr(8) : std::string();
    bool file_request = r.target.starts_with("/api/v1/files/");
    auto file_op = file_request ? r.target.substr(14) : std::string();
    bool file_write = file_request && file_op != "stat" && file_op != "list" && file_op != "read" &&
                      file_op != "jobs" && file_op != "quota" && file_op != "close";
    if (file_op == "open")
      file_write = body.value("write", false);
    auto auth = credentials(r, s.cfg, write);
    auth["admin"] = r.target == "/api/v1/smb/credentials" ||
                    r.target == "/api/v1/services/restart" ||
                    (write && resources.contains(resource));
    auth["file_write"] = file_write;
    auto subject = co_await dispatch(s, "identity", "validate", auth);
    if (r.method == "POST" && r.target == "/api/v1/smb/credentials") {
      body["auth"] = auth;
      co_return response(co_await dispatch(s, "identity", "smb_enroll", body));
    }
    if (resources.contains(resource) && (r.method == "GET" || r.method == "POST")) {
      json request = {{"resource", resource}, {"auth", auth}};
      if (r.method == "POST") {
        require(!r.header("Idempotency-Key").empty(), "invalid_request");
        request["data"] = body;
        request["request_id"] = r.header("Idempotency-Key");
      }
      co_return response(co_await dispatch(
          s, "identity", r.method == "GET" ? "policy_list" : "policy_write", request));
    }
    if (file_request && r.method == "POST") {
      static const std::set<std::string> operations = {
          "open",   "close", "read",   "write", "flush", "list",  "stat",   "mkdir",      "rename",
          "remove", "lock",  "unlock", "quota", "begin", "chunk", "commit", "cancel_job", "jobs"};
      require(operations.contains(file_op), "not_found");
      json request = {{"auth", auth},
                      {"space", body.value("space", "")},
                      {"share", body.value("share", "")},
                      {"path", body.value("path", "")},
                      {"write", file_write}};
      auto grant = co_await dispatch(s, "identity", "authorize", request);
      body["grant"] = grant;
      if (file_op == "rename") {
        auto target = body.at("destination");
        target["auth"] = auth;
        target["write"] = true;
        body["target_grant"] = co_await dispatch(s, "identity", "authorize", target);
      }
      if (!r.header("Idempotency-Key").empty())
        body["request_id"] = r.header("Idempotency-Key");
      auto value = co_await dispatch(s, grant.at("root").at("worker"), file_op, body);
      if (value.is_object()) {
        value.erase("native");
        value.erase("stage");
        value.erase("previous");
      }
      co_return response(value);
    }
    if (r.target == "/api/v1/monitoring" && r.method == "GET") {
      require(subject.at("role") == "admin", "forbidden");
      co_return response(co_await dispatch(s, "monitor", "inventory"));
    }
    if (r.method == "GET" && r.target == "/api/v1/auth/me")
      co_return response(subject);
    if (r.method == "POST" && r.target == "/api/v1/auth/logout") {
      co_await dispatch(s, "identity", "logout", auth);
      auto out = response({{"revoked", true}});
      out.headers.push_back({"Set-Cookie", "__Host-taucloud=; Path=/; Secure; HttpOnly; "
                                           "SameSite=Strict; Max-Age=0"});
      co_return out;
    }
    if (r.method == "GET" && r.target == "/api/v1/capabilities")
      co_return response({{"milestone", "M7-preview"},
                          {"management", true},
                          {"file_service", true},
                          {"file_profile", "bounded-core-v1"},
                          {"path_profile", "portable-utf8-nfc-v1"},
                          {"quota_enforcement", "service_enforced"},
                          {"max_chunk_bytes", file_chunk_size},
                          {"protocols",
                           [&] {
                             json p = json::array();
                             if (s.cfg.dav_port)
                               p.push_back("webdav");
                             if (s.cfg.ftp_port)
                               p.push_back("ftp");
                             if (s.cfg.smb_port)
                               p.push_back("smb");
                             return p;
                           }()},
                          {"storage_mutation", false},
                          {"updater", false}});
    if (r.method == "GET" && r.target == "/api/v1/protocols") {
      json protocols = json::array();
      protocols.push_back({{"id", "webdav"},
                           {"implemented", true},
                           {"enabled", s.cfg.dav_port != 0},
                           {"listen", "127.0.0.1"},
                           {"port", s.cfg.dav_port},
                           {"tls", true},
                           {"classes", json::array({1, 2})}});
      protocols.push_back({{"id", "ftp"},
                           {"implemented", true},
                           {"enabled", s.cfg.ftp_port != 0},
                           {"listen", "127.0.0.1"},
                           {"port", s.cfg.ftp_port},
                           {"explicit_tls", true},
                           {"data_tls_session_reuse", "required"},
                           {"plaintext", s.cfg.ftp_plaintext},
                           {"active_mode", false},
                           {"passive_first", s.cfg.ftp_passive_first},
                           {"passive_last", s.cfg.ftp_passive_last}});
      protocols.push_back({{"id", "smb"},
                           {"implemented", true},
                           {"enabled", s.cfg.smb_port != 0},
                           {"listen", "127.0.0.1"},
                           {"port", s.cfg.smb_port},
                           {"dialect", "3.1.1"},
                           {"dialects", json::array({"2.1", "3.0", "3.0.2", "3.1.1"})},
                           {"signing", "required"},
                           {"encryption", true},
                           {"encryption_policy", "client-required-or-optional; SMB3 only"},
                           {"ciphers", json::array({"AES-128-GCM", "AES-128-CCM"})},
                           {"smb3_signing", "AES-CMAC"},
                           {"preauthentication", "SHA-512; SMB3.1.1"},
                           {"multichannel", false},
                           {"change_notify", false},
                           {"ntlm", "v2-mic"},
                           {"leases", false},
                           {"durable_handles", false},
                           {"persistent_acl", false}});
      protocols.push_back({{"id", "nfs"}, {"implemented", true},
                           {"enabled", s.cfg.nfs_port != 0}, {"port", s.cfg.nfs_port},
                           {"listen", "127.0.0.1"}, {"compatibility", "experimental"},
                           {"versions", json::array({"4.1-subset", "3-subset"})},
                           {"auth", "explicit-loopback-AUTH_SYS"}, {"root_squash", true},
                           {"write_stability", "FILE_SYNC"}, {"persistent_sessions", false},
                           {"nlm_nsm", false}, {"posix_locks", false},
                           {"full_conformance", false}});
      co_return response(protocols);
    }
    if (r.method == "GET" && r.target == "/api/v1/services") {
      require(subject.at("role") == "admin", "forbidden");
      co_return response(co_await dispatch(s, "supervisor", "services"));
    }
    if (r.method == "POST" && r.target == "/api/v1/services/restart") {
      require(!r.header("Idempotency-Key").empty(), "invalid_request");
      body["request_id"] = r.header("Idempotency-Key");
      co_return response(co_await dispatch(s, "supervisor", "restart", body), 202);
    }
    throw error("not_found");
  } catch (const error &e) {
    co_return response({{"error", {{"code", e.what()}}}}, status_code(e.what()));
  } catch (const json::exception &) {
    co_return response({{"error", {{"code", "invalid_request"}}}}, 400);
  } catch (...) {
    log("api", "request_failed", "internal_error");
    co_return response({{"error", {{"code", "internal_error"}}}}, 500);
  }
}
static pace::task<void> connection(api_state &s, pace::tcp::stream socket,
                                   const pace::tls::context &tls) {
  struct count_guard {
    std::atomic<int> &n;
    ~count_guard() { --n; }
  } guard{s.connections};
  try {
    pace::tls::stream secure(std::move(socket), tls);
    auto timeout = s.io->call_after(3s, [&secure] { secure.close(); });
    co_await secure.handshake();
    timeout.cancel();
    pace::http::server_options options;
    options.bounds.max_body_bytes = ipc_frame_size;
    options.admit = [](const pace::http::request_head &head) {
      return pace::http::admission::accept(
          head.target.starts_with("/api/v1/files/") ? ipc_frame_size : 8192);
    };
    options.bounds.max_header_bytes = 8192;
    options.bounds.max_requests_per_connection = 1;
    options.request_timeout = 3s;
    options.write_timeout = 3s;
    options.response_buffer_bytes = 65536;
    pace::http::server_handler handler = [&s](pace::http::request r) {
      return handle(s, std::move(r));
    };
    co_await pace::http::serve_connection(std::move(secure), handler, options);
  } catch (...) {
  } // Malformed/closed connections carry no request or credential logs.
}
static pace::task<void> accept_loop(api_state &s, pace::tcp::listener &listener,
                                    const pace::tls::context &tls, std::atomic_bool &stopping) {
  try {
    while (!stopping) {
      auto socket = co_await listener.accept();
      if (s.connections >= s.cfg.connections) {
        socket.close();
        continue;
      }
      ++s.connections;
      s.io->spawn(connection(s, std::move(socket), tls));
    }
  } catch (...) {
    if (!stopping) {
      log("api", "listener_failed", "io_error");
      stopping = true;
    }
  }
}
int api(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  file_lock lock(c.state / "api.lock");
  apply_resource_budget(c);
  api_state state{c, std::make_shared<pace::io_context>()};
  pace::tls::context tls(pace::tls::role::server);
  tls.use_certificate_chain((c.state / "tls-cert.pem").string(),
                            (c.state / "tls-key.pem").string());
  tls.set_alpn_protocols({"http/1.1"});
  pace::tcp::listener listener(*state.io, {"127.0.0.1", c.port}, {false, c.connections});
  auto info = [&] {
    auto p = process_info(own_pid());
    p["generation"] = generation;
    p["role"] = "api";
    p["connections"] = state.connections.load();
    return p;
  };
  rpc_server server(c, "api", generation,
                    [&](const std::string &op, const json &, const call_context &) {
                      if (op == "ping")
                        return info();
                      if (op == "stop") {
                        stopping = true;
                        return json{{"stopping", true}};
                      }
                      throw error("not_supported");
                    });
  write_json(c.state / "api.instance.json", info());
  state.io->spawn(accept_loop(state, listener, tls, stopping));
  std::jthread loop([&] {
    try {
      state.io->run();
    } catch (...) {
      log("api", "runtime_failed", "internal_error");
    }
    stopping = true;
  });
  log("api", "started");
  while (!stopping)
    std::this_thread::sleep_for(20ms);
  state.io->post([&listener] { listener.close(); });
  server.stop();
  auto deadline = now() + 5000;
  while (state.connections > 0 && now() < deadline)
    std::this_thread::sleep_for(20ms);
  state.pool.shutdown();
  while (state.pool.outstanding() > 0 && now() < deadline + 1000)
    std::this_thread::sleep_for(10ms);
  state.io->stop();
  loop.join();
  log("api", "stopped");
  return 0;
}
static pace::task<void> exchange(std::shared_ptr<pace::io_context> io, const config &c,
                                 pace::http::request request, json &result,
                                 std::exception_ptr &failure) {
  try {
    pace::tls::context tls(pace::tls::role::client, pace::tls::trust_source::application);
    tls.load_verify_file((c.state / "tls-cert.pem").string());
    auto reply = co_await pace::http::fetch(*io, tls, {"127.0.0.1", c.port}, "127.0.0.1",
                                            std::move(request));
    result = json::parse(reply.body);
    if (reply.status >= 400)
      throw error(result.at("error").at("code"));
  } catch (...) {
    failure = std::current_exception();
  }
  io->stop();
}
static pace::task<json> file_call(pace::io_context &io, pace::tls::context &tls, const config &c,
                                  const std::string &token, const std::string &operation, json body,
                                  std::string request_id = "") {
  pace::http::request request;
  request.method = "POST";
  request.target = "/api/v1/files/" + operation;
  request.version = "HTTP/1.1";
  request.keep_alive = false;
  request.headers = {{"Host", "127.0.0.1:" + std::to_string(c.port)},
                     {"Content-Type", "application/json"},
                     {"Authorization", "Bearer " + token}};
  if (!request_id.empty())
    request.headers.push_back({"Idempotency-Key", request_id});
  request.body = body.dump();
  auto reply =
      co_await pace::http::fetch(io, tls, {"127.0.0.1", c.port}, "127.0.0.1", std::move(request));
  auto result = json::parse(reply.body);
  if (reply.status >= 400)
    throw error(result.at("error").at("code"));
  co_return result;
}
static pace::task<void> transfer(std::shared_ptr<pace::io_context> io, const config &c,
                                 std::string command, std::string space, std::string path,
                                 fs::path local, std::string request_id, json &result,
                                 std::exception_ptr &failure) {
  fs::path temporary;
  std::string token;
  std::unique_ptr<pace::tls::context> connection;
  json close_request;
  try {
    token = read_json(c.state / "cli-session.json").at("token").get<std::string>();
    connection = std::make_unique<pace::tls::context>(pace::tls::role::client,
                                                      pace::tls::trust_source::application);
    auto &tls = *connection;
    tls.load_verify_file((c.state / "tls-cert.pem").string());
    json base = {{"space", space}, {"path", path}};
    uint64_t transferred = 0;
    if (command == "put") {
      std::ifstream input(local, std::ios::binary);
      require(bool(input), "io_error");
      auto total = fs::file_size(local);
      auto modified = fs::last_write_time(local);
      std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(),
                                                                   EVP_MD_CTX_free);
      require(hash && EVP_DigestInit_ex(hash.get(), EVP_sha256(), nullptr) == 1, "crypto_error");
      std::string buffer(file_chunk_size, '\0');
      while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        require(EVP_DigestUpdate(hash.get(), buffer.data(), static_cast<size_t>(input.gcount())) ==
                    1,
                "crypto_error");
      }
      require(input.eof(), "io_error");
      input.clear();
      unsigned char digest_bytes[32];
      unsigned digest_size = 0;
      require(EVP_DigestFinal_ex(hash.get(), digest_bytes, &digest_size) == 1 && digest_size == 32,
              "crypto_error");
      auto request = base;
      request["size"] = total;
      request["source_sha256"] =
          encode_bytes(std::string_view(reinterpret_cast<char *>(digest_bytes), 32));
      auto job = co_await file_call(*io, tls, c, token, "begin", request, request_id);
      if (job.at("status") != "completed") {
        require(job.at("status") == "staging", "uncertain_write");
        transferred = job.at("progress");
        while (transferred < total) {
          input.seekg(static_cast<std::streamoff>(transferred));
          auto count = static_cast<size_t>(std::min<uint64_t>(buffer.size(), total - transferred));
          input.read(buffer.data(), static_cast<std::streamsize>(count));
          require(static_cast<size_t>(input.gcount()) == count, "local_file_changed");
          request = base;
          request["job"] = job.at("id");
          request["offset"] = transferred;
          request["data"] = encode_bytes(std::string_view(buffer.data(), count));
          auto response = co_await file_call(*io, tls, c, token, "chunk", request);
          auto written = response.at("written").get<uint64_t>();
          require(written > 0, "io_error");
          transferred += written;
        }
        request = base;
        request["job"] = job.at("id");
        require(fs::file_size(local) == total && fs::last_write_time(local) == modified,
                "local_file_changed");
        job = co_await file_call(*io, tls, c, token, "commit", request);
      }
      result = {{"job", job.at("id")}, {"status", job.at("status")}, {"bytes", total}};
    } else {
      require(!fs::exists(local), "already_exists");
      temporary = local;
      temporary += ".tc-download-" + random_hex(8);
      std::ofstream output(temporary, std::ios::binary);
      require(bool(output), "io_error");
      auto opened = co_await file_call(*io, tls, c, token, "open", base);
      close_request = base;
      close_request["handle"] = opened.at("handle");
      auto size = opened.at("size").get<uint64_t>();
      while (transferred < size) {
        auto request = base;
        request["handle"] = opened.at("handle");
        request["offset"] = transferred;
        request["count"] = std::min<uint64_t>(file_chunk_size, size - transferred);
        auto value = co_await file_call(*io, tls, c, token, "read", request);
        auto data = decode_bytes(value.at("data").get<std::string>());
        require(!data.empty(), "remote_file_changed");
        output.write(data.data(), static_cast<std::streamsize>(data.size()));
        require(bool(output), "io_error");
        transferred += data.size();
      }
      auto request = base;
      request["handle"] = opened.at("handle");
      co_await file_call(*io, tls, c, token, "close", request);
      close_request = nullptr;
      output.flush();
      require(bool(output), "io_error");
      output.close();
      fs::rename(temporary, local);
      temporary.clear();
      result = {{"bytes", transferred}, {"status", "completed"}};
    }
  } catch (...) {
    failure = std::current_exception();
    if (!temporary.empty()) {
      std::error_code ignored;
      fs::remove(temporary, ignored);
    }
  }
  if (failure && !close_request.is_null() && connection) {
    try {
      co_await file_call(*io, *connection, c, token, "close", close_request);
    } catch (...) {
      // A failed domain or revoked grant already fences this handle.
    }
  }
  io->stop();
}
int cli(const config &c, const std::vector<std::string> &args) {
  require(!args.empty(), "invalid_arguments");
  auto command = args[0];
  if (command == "backup") {
    require(args.size() == 3 && args[1] == "--output", "invalid_arguments");
    std::cout << metadata_backup(c, args[2]).dump() << "\n";
    return 0;
  }
  auto option = [&](const std::string &name, const std::string &fallback = "") {
    auto it = std::find(args.begin(), args.end(), name);
    if (it == args.end())
      return fallback;
    require(it + 1 != args.end(), "invalid_arguments");
    return *(it + 1);
  };
  auto password = [&] {
    require(std::find(args.begin(), args.end(), "--password-stdin") != args.end(),
            "password_stdin_required");
    std::string value;
    std::getline(std::cin, value);
    require(value.size() <= 1024, "invalid_request");
    return value;
  };
  if (command == "bootstrap") {
    auto token = read_json(c.state / "bootstrap.json");
    auto result = rpc(c, "ctl", "identity", "bootstrap",
                      {{"username", option("--username")},
                       {"password", password()},
                       {"token", token.at("token")}});
    std::cout << result.dump() << '\n';
    return 0;
  }
  if (command == "status" || command == "stop") {
    std::cout << rpc(c, "ctl", "supervisor", command == "status" ? "services" : "stop").dump()
              << '\n';
    return 0;
  }
  if (command == "put" || command == "get") {
    auto io = std::make_shared<pace::io_context>();
    json result;
    std::exception_ptr failure;
    io->spawn(transfer(io, c, command, option("--space"), option("--path"), option("--file"),
                       option("--request-id", random_hex(16)), result, failure));
    io->run();
    if (failure)
      std::rethrow_exception(failure);
    std::cout << result.dump() << '\n';
    return 0;
  }
  pace::http::request request;
  request.method = "GET";
  request.version = "HTTP/1.1";
  request.keep_alive = false;
  request.headers = {{"Host", "127.0.0.1:" + std::to_string(c.port)},
                     {"Content-Type", "application/json"}};
  if (command == "login") {
    request.method = "POST";
    request.target = "/api/v1/auth/login";
    request.body = json{{"username", option("--username")},
                        {"password", password()},
                        {"kind", "cli"},
                        {"scope", option("--scope", "read")}}
                       .dump();
  } else {
    auto session = read_json(c.state / "cli-session.json");
    request.headers.push_back(
        {"Authorization", "Bearer " + session.at("token").get<std::string>()});
    if (command == "call") {
      request.target = option("--path");
      require(request.target.starts_with("/api/v1/"), "invalid_arguments");
      request.method = option("--method", "GET");
      require(request.method == "GET" || request.method == "POST", "invalid_arguments");
      if (request.method == "POST") {
        std::string input((std::istreambuf_iterator<char>(std::cin)), {});
        require(input.size() <= ipc_frame_size, "invalid_request");
        request.body = json::parse(input).dump();
        request.headers.push_back({"Idempotency-Key", option("--request-id", random_hex(16))});
      }
    } else if (command == "whoami")
      request.target = "/api/v1/auth/me";
    else if (command == "capabilities")
      request.target = "/api/v1/capabilities";
    else if (command == "services")
      request.target = "/api/v1/services";
    else if (command == "logout") {
      request.method = "POST";
      request.target = "/api/v1/auth/logout";
    } else if (command == "restart") {
      request.method = "POST";
      request.target = "/api/v1/services/restart";
      request.body = json{{"role", option("--role")}}.dump();
      request.headers.push_back({"Idempotency-Key", option("--request-id", random_hex(16))});
    } else
      throw error("invalid_arguments");
  }
  auto io = std::make_shared<pace::io_context>();
  json result;
  std::exception_ptr failure;
  auto timeout = io->call_after(10s, [io] { io->stop(); });
  io->spawn(exchange(io, c, std::move(request), result, failure));
  io->run();
  if (failure)
    std::rethrow_exception(failure);
  require(!result.is_null(), "deadline_exceeded");
  if (command == "login") {
    write_json(c.state / "cli-session.json", result);
    result.erase("token");
    result.erase("csrf");
  }
  if (command == "logout")
    fs::remove(c.state / "cli-session.json");
  std::cout << result.dump() << '\n';
  return 0;
}
} // namespace tc
