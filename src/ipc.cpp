#include <condition_variable>
#include <deque>
#include <map>
#include <taucloud/core.hpp>
#include <taucloud/files.hpp>
namespace tc {
static bool allowed(const std::string &caller, const std::string &target, const std::string &op) {
  if (op == "ping")
    return caller == "supervisor" || caller == "ctl" ||
           (caller == "api" && (target == "identity" || target == "supervisor"));
  if (op == "stop")
    return caller == "supervisor" || (caller == "ctl" && target == "supervisor");
  if (op == "cancel")
    return true; // Additional ownership check against the active request.
  if (target == "identity")
    return (caller == "nfs" && (op == "nfs_authorize" || op == "nfs_exports")) || (caller == "ctl" && op == "bootstrap") || (caller == "api" && op == "smb_enroll") ||
           (caller == "smb" && (op == "smb_negotiate" || op == "smb_authenticate" ||
                                op == "authorize" || op == "logout" || op == "policy_list")) ||
           ((caller == "api" || caller == "webdav" || caller == "ftp") &&
            (op == "login" || op == "validate" || op == "logout" || op == "policy_list" ||
             op == "policy_write" || op == "authorize"));
  if (file_role(target))
    return (caller == "nfs" && (op == "nfs_file" || op == "nfs_reap")) || (caller == "smb" && op.starts_with("smb_")) ||
           (caller == "ftp" && op == "ftp_recover") ||
           (caller == "identity" && (op == "inspect" || op == "provision" || op == "revoke")) ||
           ((caller == "api" || caller == "webdav" || caller == "ftp") &&
            (op == "ftp_abort" || op == "ftp_close" || op == "ftp_rmdir" || op == "dav_abort" ||
             op == "dav_close" || op == "open" || op == "close" || op == "read" || op == "write" ||
             op == "flush" || op == "list" || op == "stat" || op == "mkdir" || op == "rename" ||
             op == "remove" || op == "lock" || op == "unlock" || op == "quota" || op == "begin" ||
             op == "chunk" || op == "commit" || op == "seal" || op == "cancel_job" ||
             op == "jobs" || op == "dav_stat" || op == "dav_list" || op == "dav_props" ||
             op == "dav_lock" || op == "dav_unlock" || op == "dav_copy" || op == "dav_move" ||
             op == "dav_delete"));
  if (target == "monitor")
    return caller == "api" && op == "inventory";
  if (target == "supervisor")
    return (caller == "api" && (op == "services" || op == "restart")) ||
           (caller == "ctl" && op == "services");
  return false;
}
struct rpc_server::impl {
  config cfg;
  std::string role, generation;
  json keys;
  rpc_handler handler;
  local_listener listener;
  std::mutex mutex;
  std::condition_variable wake;
  std::deque<channel> queue;
  std::map<std::string, std::stop_source> active;
  bool closing = false;
  std::jthread acceptor;
  std::vector<std::jthread> workers;
  impl(const config &c, std::string r, std::string g, rpc_handler h)
      : cfg(c), role(std::move(r)), generation(std::move(g)),
        keys(read_json(c.state / "ipc-keys.json")), handler(std::move(h)), listener(c, role) {
    for (int i = 0; i < 2; ++i)
      workers.emplace_back([this](std::stop_token stop) { run(stop); });
    acceptor = std::jthread([this](std::stop_token stop) {
      try {
        while (!stop.stop_requested()) {
          auto conn = listener.accept(stop);
          if (!conn)
            break;
          std::lock_guard l(mutex);
          if (!closing && queue.size() < static_cast<size_t>(cfg.ipc_queue)) {
            queue.push_back(std::move(*conn));
            wake.notify_one();
          }
        }
      } catch (...) {
        log(role, "ipc_accept_failed", "io_error");
      }
    });
  }
  void run(std::stop_token stop) {
    for (;;) {
      channel conn;
      {
        std::unique_lock l(mutex);
        wake.wait(l, [&] { return closing || !queue.empty(); });
        if (closing)
          return;
        conn = std::move(queue.front());
        queue.pop_front();
      }
      try {
        serve(conn, stop);
      } catch (...) {
        log(role, "ipc_rejected", "invalid_request");
      }
    }
  }
  void serve(channel &conn, std::stop_token stop) {
    int64_t limit = now() + 5000;
    json hello = {
        {"version", 1}, {"target", role}, {"nonce", random_hex()}, {"generation", generation}};
    hello["mac"] = mac(keys.at(role).get<std::string>(), hello.dump());
    conn.send(hello, limit, stop);
    auto request = conn.receive(limit, stop);
    auto signature = request.at("mac").get<std::string>();
    request.erase("mac");
    auto caller = request.at("caller").get<std::string>(), id = request.at("id").get<std::string>(),
         op = request.at("operation").get<std::string>();
    require(keys.contains(caller) && id.size() == 32 && request.at("version") == 1 &&
                request.at("target") == role && request.at("nonce") == hello.at("nonce") &&
                request.at("generation") == generation,
            "ipc_auth_failed");
    require(equal(signature, mac(keys.at(caller).get<std::string>(), request.dump())),
            "ipc_auth_failed");
    int64_t deadline = request.at("deadline");
    require(deadline > now() && deadline <= limit + 1000, "deadline_exceeded");
    json result;
    std::string code = "ok", active_key = caller + ":" + id;
    std::stop_source source;
    std::stop_callback shutdown(stop, [&source] { source.request_stop(); });
    try {
      require(allowed(caller, role, op), "forbidden");
      if (op == "cancel") {
        std::lock_guard l(mutex);
        auto it = active.find(caller + ":" + request.at("body").at("id").get<std::string>());
        if (it != active.end())
          it->second.request_stop();
        result = {{"cancelled", it != active.end()}};
      } else {
        {
          std::lock_guard l(mutex);
          require(active.emplace(active_key, source).second, "duplicate_request");
        }
        call_context ctx{caller, id, deadline, source.get_token()};
        ctx.check();
        result = handler(op, request.at("body"), ctx);
      }
    } catch (const error &e) {
      code = e.what();
    } catch (...) {
      code = "internal_error";
    }
    {
      std::lock_guard l(mutex);
      active.erase(active_key);
    }
    json reply = {
        {"version", 1}, {"id", id},        {"nonce", hello.at("nonce")}, {"generation", generation},
        {"code", code}, {"result", result}};
    reply["mac"] = mac(keys.at(role).get<std::string>(), reply.dump());
    conn.send(reply, limit, stop);
  }
  void shutdown() {
    acceptor.request_stop();
    if (acceptor.joinable())
      acceptor.join();
    {
      std::lock_guard l(mutex);
      closing = true;
      queue.clear();
      for (auto &[id, source] : active)
        source.request_stop();
    }
    for (auto &w : workers)
      w.request_stop();
    wake.notify_all();
    for (auto &w : workers)
      if (w.joinable())
        w.join();
  }
  ~impl() { shutdown(); }
};
rpc_server::rpc_server(const config &c, std::string r, std::string g, rpc_handler h)
    : impl_(std::make_unique<impl>(c, std::move(r), std::move(g), std::move(h))) {}
rpc_server::~rpc_server() = default;
void rpc_server::stop() { impl_->shutdown(); }
json rpc(const config &c, const std::string &caller, const std::string &target,
         const std::string &op, json body, std::string generation, std::stop_token stop,
         std::string id, int timeout_ms) {
  auto keys = read_json(c.state / "ipc-keys.json");
  require(timeout_ms > 0 && timeout_ms <= 4000, "invalid_deadline");
  int64_t deadline = now() + timeout_ms;
  auto conn = channel::connect(c, target, deadline);
  auto hello = conn.receive(deadline, stop);
  std::string signature = hello.at("mac");
  hello.erase("mac");
  require(hello.at("version") == 1 && hello.at("target") == target &&
              equal(signature, mac(keys.at(target).get<std::string>(), hello.dump())),
          "ipc_auth_failed");
  require(generation.empty() || hello.at("generation") == generation, "stale_generation");
  if (id.empty())
    id = random_hex(16);
  json request = {{"version", 1},
                  {"caller", caller},
                  {"target", target},
                  {"id", id},
                  {"operation", op},
                  {"body", body},
                  {"nonce", hello.at("nonce")},
                  {"generation", hello.at("generation")},
                  {"deadline", deadline}};
  request["mac"] = mac(keys.at(caller).get<std::string>(), request.dump());
  conn.send(request, deadline, stop);
  auto reply = conn.receive(deadline, stop);
  signature = reply.at("mac");
  reply.erase("mac");
  require(reply.at("version") == 1 && reply.at("id") == id &&
              reply.at("nonce") == hello.at("nonce") &&
              reply.at("generation") == hello.at("generation") &&
              equal(signature, mac(keys.at(target).get<std::string>(), reply.dump())),
          "ipc_auth_failed");
  if (reply.at("code") != "ok")
    throw error(reply.at("code").get<std::string>());
  return reply.at("result");
}
} // namespace tc
