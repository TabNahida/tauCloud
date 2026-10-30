#include <future>
#include <iostream>
#include <sqlite3.h>
#include <taucloud/core.hpp>
using namespace tc;
static std::atomic<int> checks = 0;
static void check(bool value) {
  require(value, "test_failed");
  ++checks;
}
template <class F> static void rejects(F f, const std::string &code) {
  try {
    f();
    throw error("test_expected_rejection");
  } catch (const error &e) {
    check(e.what() == code);
  }
}
int main() {
  auto root = fs::temp_directory_path() / ("tc-unit-" + random_hex(6));
  try {
    initialize(root, 38443);
    auto cfg = config::load(root);
    rejects([&] { initialize(root, 38443); }, "already_initialized");
    auto settings = read_json(root / "config.json");
    settings["unexpected"] = true;
    write_json(root / "config.json", settings);
    rejects([&] { config::load(root); }, "invalid_config");
    settings.erase("unexpected");
    settings["port"] = 4294967296LL + 38443;
    write_json(root / "config.json", settings);
    rejects([&] { config::load(root); }, "invalid_config");
    settings["port"] = 38443;
    write_json(root / "config.json", settings);
    {
      file_lock first(root / "test.lock");
      rejects([&] { file_lock second(root / "test.lock"); }, "owner_already_running");
    }
    auto keys = read_json(root / "ipc-keys.json");
    std::string generation = random_hex(16);
    std::atomic_bool entered = false;
    rpc_server server(cfg, "helper", generation,
                      [&](const std::string &, const json &body, const call_context &ctx) {
                        if (body.value("wait", false)) {
                          entered = true;
                          for (;;) {
                            ctx.check();
                            std::this_thread::sleep_for(5ms);
                          }
                        }
                        return json{{"ok", true}};
                      });
    check(rpc(cfg, "ctl", "helper", "ping").at("ok"));
    rejects([&] { rpc(cfg, "ctl", "helper", "stop"); }, "forbidden");
    rejects([&] { rpc(cfg, "ctl", "helper", "ping", json::object(), "old"); }, "stale_generation");
    auto wrong = keys;
    wrong["ctl"] = random_hex();
    write_json(root / "ipc-keys.json", wrong);
    rejects([&] { rpc(cfg, "ctl", "helper", "ping"); }, "transport_closed");
    write_json(root / "ipc-keys.json", keys);
    auto malicious = [&](const std::string &change) {
      auto conn = channel::connect(cfg, "helper", now() + 4000);
      auto hello = conn.receive(now() + 4000);
      json request = {{"version", 1},
                      {"caller", "ctl"},
                      {"target", "helper"},
                      {"id", random_hex(16)},
                      {"operation", "ping"},
                      {"body", json::object()},
                      {"nonce", hello.at("nonce")},
                      {"generation", generation},
                      {"deadline", now() + 3000}};
      if (change == "expired")
        request["deadline"] = now() - 1;
      if (change == "version")
        request["version"] = 2;
      if (change == "nonce")
        request["nonce"] = random_hex();
      request["mac"] = mac(keys.at("ctl").get<std::string>(), request.dump());
      conn.send(request, now() + 4000);
      conn.receive(now() + 4000);
    };
    for (auto attack : {"expired", "version", "nonce"})
      rejects([&] { malicious(attack); }, "transport_closed");
    auto id = random_hex(16);
    auto pending = std::async(std::launch::async, [&] {
      rejects([&] { rpc(cfg, "ctl", "helper", "ping", {{"wait", true}}, "", {}, id); },
              "cancelled");
    });
    while (!entered)
      std::this_thread::sleep_for(5ms);
    check(!rpc(cfg, "supervisor", "helper", "cancel", {{"id", id}}).at("cancelled").get<bool>());
    check(rpc(cfg, "ctl", "helper", "cancel", {{"id", id}}).at("cancelled"));
    pending.get();
    server.stop();
    auto bootstrap = read_json(root / "bootstrap.json");
    call_context context{"ctl", random_hex(16), now() + 30000, {}};
    {
      identity_store identity(cfg);
      auto body =
          json{{"username", "admin"}, {"password", "unit-test-password-123"}, {"token", "wrong"}};
      rejects([&] { identity.dispatch("bootstrap", body, context); }, "bootstrap_denied");
      body["token"] = bootstrap.at("token");
      identity.dispatch("bootstrap", body, context);
      rejects([&] { identity.dispatch("bootstrap", body, context); }, "bootstrap_denied");
      auto session = identity.dispatch(
          "login", {{"username", "admin"}, {"password", "unit-test-password-123"}}, context);
      auto auth = json{{"token", session.at("token")}, {"kind", "cli"}};
      check(identity.dispatch("validate", auth, context).at("username") == "admin");
      auto denied = auth;
      denied["write"] = true;
      denied["admin"] = true;
      rejects([&] { identity.dispatch("validate", denied, context); }, "forbidden");
      identity.dispatch("logout", auth, context);
      rejects([&] { identity.dispatch("validate", auth, context); }, "unauthorized");
      for (int i = 0; i < 4; ++i)
        rejects(
            [&] {
              identity.dispatch("login", {{"username", "admin"}, {"password", "bad"}}, context);
            },
            "unauthorized");
      rejects(
          [&] {
            identity.dispatch(
                "login", {{"username", "admin"}, {"password", "unit-test-password-123"}}, context);
          },
          "rate_limited");
    }
    // Simulate a committed v1 database plus an interrupted migration
    // transaction.
    sqlite3 *db = nullptr;
    check(sqlite3_open((root / "identity.db").string().c_str(), &db) == SQLITE_OK);
    check(sqlite3_exec(db,
                       "DROP TABLE records; DROP TABLE memberships; DROP TABLE grants; DROP TABLE "
                       "policy_state; DROP TABLE policy_audit; DROP TABLE policy_requests; ALTER "
                       "TABLE users DROP COLUMN role; ALTER TABLE users DROP COLUMN enabled; DROP "
                       "TABLE sessions; DROP TABLE attempts; PRAGMA user_version=1; "
                       "BEGIN IMMEDIATE; CREATE TABLE interrupted(value TEXT);",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(db);
    {
      identity_store migrated(cfg);
      check(fs::exists(root / "identity.pre-v2.db"));
    }
    check(sqlite3_open((root / "identity.db").string().c_str(), &db) == SQLITE_OK);
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master WHERE name='interrupted'", -1, &stmt,
                       nullptr);
    sqlite3_step(stmt);
    check(sqlite3_column_int(stmt, 0) == 0);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    fs::remove_all(root);
    std::cout << json{{"status", "passed"}, {"checks", checks.load()}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << " (fixture " << root << ")\n";
    return 1;
  }
}
