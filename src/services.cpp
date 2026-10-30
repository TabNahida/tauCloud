#include <algorithm>
#include <csignal>
#include <taucloud/core.hpp>
#include <taucloud/files.hpp>
#ifdef _WIN32
#include <windows.h>
#endif
namespace tc {
static json ping(const std::string &role, const std::string &generation) {
  auto p = process_info(own_pid());
  p["role"] = role;
  p["generation"] = generation;
  p["ipc_version"] = 1;
  p["business_ready"] = role == "identity" || role == "api" || file_role(role) || role == "monitor";
  return p;
}
int worker(const std::string &role, const config &c, const std::string &generation,
           std::atomic_bool &stopping) {
  file_lock lock(c.state / (role + ".lock"));
  apply_resource_budget(c);
  std::unique_ptr<identity_store> db;
  std::unique_ptr<file_store> files;
  if (role == "identity")
    db = std::make_unique<identity_store>(c);
  if (file_role(role))
    files = std::make_unique<file_store>(c, role, generation);
  rpc_server server(c, role, generation,
                    [&](const std::string &op, const json &body, const call_context &ctx) {
                      if (op == "ping")
                        return ping(role, generation);
                      if (op == "stop") {
                        stopping = true;
                        return json{{"stopping", true}};
                      }
                      if (db)
                        return db->dispatch(op, body, ctx);
                      if (files)
                        return files->dispatch(op, body, ctx);
                      if (role == "monitor" && op == "inventory")
                        return system_inventory(ctx);
                      throw error("not_supported");
                    });
  write_json(c.state / (role + ".instance.json"), ping(role, generation));
  log(role, "started");
  while (!stopping)
    std::this_thread::sleep_for(20ms);
  server.stop();
  log(role, "stopped");
  return 0;
}
int supervisor(const config &c, const fs::path &binaries, std::atomic_bool &stopping) {
  file_lock lock(c.state / "supervisor.lock");
  // M1 states acquire keys for newly introduced domain workers before launch.
  auto keys = read_json(c.state / "ipc-keys.json");
  bool changed = false;
  for (auto &role : roles())
    if (!keys.contains(role)) {
      keys[role] = random_hex();
      changed = true;
    }
  if (changed)
    write_json(c.state / "ipc-keys.json", keys);
  std::mutex mutex;
  auto path = c.state / "supervisor.json";
  json journal =
      fs::exists(path)
          ? read_json(path)
          : json{{"schema", 1}, {"services", json::object()}, {"operations", json::object()}};
  require(journal.at("schema") == 1, "schema_too_new");
  auto save = [&] { write_json(path, journal); };
  for (auto &role : roles())
    if (!journal["services"].contains(role))
      journal["services"][role] = {{"generation", random_hex(16)},
                                   {"failures", json::array()},
                                   {"next", 0},
                                   {"identity", nullptr},
                                   {"status", "starting"}};
  auto generation = random_hex(16);
  rpc_server server(c, "supervisor", generation,
                    [&](const std::string &op, const json &body, const call_context &) {
                      if (op == "ping")
                        return ping("supervisor", generation);
                      if (op == "stop") {
                        stopping = true;
                        return json{{"stopping", true}};
                      }
                      std::lock_guard l(mutex);
                      if (op == "services")
                        return journal.at("services");
                      if (op == "restart") {
                        auto role = body.at("role").get<std::string>(),
                             id = body.at("request_id").get<std::string>();
                        require(std::find(roles().begin(), roles().end(), role) != roles().end() &&
                                    id.size() >= 16 && id.size() <= 64,
                                "invalid_request");
                        auto &ops = journal["operations"];
                        if (ops.contains(id)) {
                          require(ops[id].at("role") == role, "idempotency_conflict");
                          return ops[id];
                        }
                        require(ops.size() < 4096, "operation_limit");
                        auto next = random_hex(16);
                        ops[id] = {{"role", role}, {"generation", next}, {"status", "pending"}};
                        auto &s = journal["services"][role];
                        s["generation"] = next;
                        s["failures"] = json::array();
                        s["next"] = 0;
                        s["status"] = "restarting";
                        save();
                        return ops[id];
                      }
                      throw error("not_supported");
                    });
  log("supervisor", "started");
  while (!stopping) {
    {
      std::lock_guard l(mutex);
      for (auto &role : roles()) {
        if (stopping)
          break;
        auto &s = journal["services"][role];
        auto executable = fs::absolute(binaries / ("taucloud_" + role
#ifdef _WIN32
                                                   + ".exe"
#endif
                                                   ));
        try {
          // A child publishes its own identity after taking the service lock.
          // This closes spawn-before-supervisor-journal crash windows.
          if (s["identity"].is_null() && fs::exists(c.state / (role + ".instance.json"))) {
            auto candidate = read_json(c.state / (role + ".instance.json"));
            if (verified_alive(candidate)) {
              require(fs::equivalent(candidate.at("exe").get<std::string>(), executable),
                      "adoption_refused");
              auto reply =
                  rpc(c, "supervisor", role, "ping", json::object(), candidate.at("generation"));
              require(reply.at("pid") == candidate.at("pid") &&
                          reply.at("birth") == candidate.at("birth"),
                      "adoption_refused");
              s["identity"] = candidate;
              bool pending = false;
              for (auto &[id, op] : journal["operations"].items())
                if (op.at("role") == role && op.at("status") == "pending")
                  pending = true;
              if (!pending)
                s["generation"] = candidate.at("generation");
              save();
            }
          }
          if (!s["identity"].is_null() && verified_alive(s["identity"])) {
            auto id = s["identity"];
            if (id.at("generation") != s.at("generation")) {
              terminate_verified(id);
              s["status"] = "restarting";
              continue;
            }
            try {
              auto reply = rpc(c, "supervisor", role, "ping", json::object(), s.at("generation"));
              require(reply.at("pid") == id.at("pid") && reply.at("birth") == id.at("birth"),
                      "adoption_refused");
              require(reply.at("rss").get<uint64_t>() <
                          static_cast<uint64_t>(c.memory_mb) * 1024 * 1024,
                      "resource_exhausted");
              s["status"] = "running";
              s["rss"] = reply.at("rss");
              for (auto &[key, op] : journal["operations"].items())
                if (op.at("role") == role && op.at("generation") == s.at("generation"))
                  op["status"] = "done";
              continue;
            } catch (...) {
              terminate_verified(id);
              s["status"] = "unhealthy";
              continue;
            }
          }
          if (!s["identity"].is_null()) {
            if (s["identity"].at("generation") == s.at("generation"))
              s["generation"] = random_hex(16);
            s["identity"] = nullptr;
            s["failures"].push_back(now());
            auto count = s["failures"].size();
            s["next"] = now() + std::min<int64_t>(5000, 100LL << std::min<size_t>(count, 5));
            s["status"] = "backoff";
            save();
          }
          auto &failures = s["failures"];
          while (!failures.empty() && failures[0].get<int64_t>() < now() - 60000)
            failures.erase(failures.begin());
          if (failures.size() >= static_cast<size_t>(c.restart_limit)) {
            s["status"] = "crash_loop";
            continue;
          }
          if (now() < s.at("next").get<int64_t>())
            continue;
          // Persist the desired generation before launch; one native lock per
          // role fences duplicates.
          s["status"] = "starting";
          save();
          s["identity"] = spawn(executable, c, s.at("generation"));
          s["started"] = now();
          save();
          // Allow startup before the first health probe (Argon2/database/TLS
          // initialization).
          std::this_thread::sleep_for(100ms);
        } catch (const error &e) {
          s["status"] = e.what();
          s["next"] = now() + 1000;
          log("supervisor", "reconcile_failed", e.what());
        } catch (...) {
          s["status"] = "reconcile_failed";
          s["next"] = now() + 1000;
        }
      }
      save();
    }
    reap_children();
    for (int i = 0; i < 10 && !stopping; ++i)
      std::this_thread::sleep_for(20ms);
  }
  server.stop();
  // Stop network admission first, then workers, and identity last.
  for (auto it = roles().rbegin(); it != roles().rend(); ++it) {
    auto id = journal["services"][*it]["identity"];
    if (id.is_null() || !verified_alive(id))
      continue;
    try {
      rpc(c, "supervisor", *it, "stop", json::object(), id.at("generation"));
    } catch (...) {
    }
    auto deadline = now() + 6000;
    while (verified_alive(id) && now() < deadline)
      std::this_thread::sleep_for(20ms);
    terminate_verified(id);
    auto &service = journal["services"][*it];
    service["status"] = "stopped";
    if (!verified_alive(id)) {
      service["identity"] = nullptr;
      service["generation"] = random_hex(16);
    }
  }
  save();
  reap_children();
  log("supervisor", "stopped");
  return 0;
}
#ifdef _WIN32
namespace {
SERVICE_STATUS_HANDLE scm_handle = nullptr;
SERVICE_STATUS scm_status{};
std::atomic_bool scm_stop = false;
const config *scm_config = nullptr;
fs::path scm_binaries;
void report(DWORD state, DWORD code = NO_ERROR) {
  scm_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  scm_status.dwCurrentState = state;
  scm_status.dwWin32ExitCode = code;
  scm_status.dwControlsAccepted =
      state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
  scm_status.dwWaitHint = state == SERVICE_STOP_PENDING ? 60000 : 10000;
  SetServiceStatus(scm_handle, &scm_status);
}
DWORD WINAPI control(DWORD code, DWORD, LPVOID, LPVOID) {
  if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
    report(SERVICE_STOP_PENDING);
    scm_stop = true;
  }
  return NO_ERROR;
}
void WINAPI entry(DWORD, LPWSTR *) {
  scm_handle = RegisterServiceCtrlHandlerExW(L"tauCloud", control, nullptr);
  if (!scm_handle)
    return;
  report(SERVICE_START_PENDING);
  try {
    report(SERVICE_RUNNING);
    supervisor(*scm_config, scm_binaries, scm_stop);
    report(SERVICE_STOPPED);
  } catch (...) {
    report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
  }
}
} // namespace
#endif
int service_main(const config &c, const fs::path &b) {
#ifdef _WIN32
  scm_config = &c;
  scm_binaries = b;
  SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(L"tauCloud"), entry}, {nullptr, nullptr}};
  require(StartServiceCtrlDispatcherW(table) != 0, "service_dispatch_failed");
  return 0;
#else
  (void)c;
  (void)b;
  throw error("not_supported");
#endif
}
} // namespace tc
