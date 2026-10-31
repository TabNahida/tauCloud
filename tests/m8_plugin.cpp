// Test fixture for the public process IPC contract; never installed by default.
#include <taucloud/core.hpp>
#include <cstdlib>
int main(int argc, char **argv) {
  try {
    tc::fs::path state;
    std::string generation;
    for (int i = 1; i + 1 < argc; i += 2) {
      if (std::string(argv[i]) == "--state")
        state = argv[i + 1];
      else if (std::string(argv[i]) == "--generation")
        generation = argv[i + 1];
      else
        return 2;
    }
    auto c = tc::config::load(state);
    tc::file_lock lock(c.state / "plugin.lock");
    std::atomic_bool stop = false;
    auto identity = tc::process_info(tc::own_pid());
    identity["generation"] = generation;
    identity["ipc_version"] = 1;
    if (tc::fs::exists(c.state / "configuration" / "crash"))
      std::_Exit(42);
    if (tc::fs::exists(c.state / "configuration" / "delay.json")) {
      auto delay = tc::read_json(c.state / "configuration" / "delay.json").at("ms").get<int>();
      tc::require(delay >= 0 && delay <= 1500, "invalid_request");
      std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }
    tc::rpc_server server(
        c, "plugin", generation,
        [&](const std::string &op, const tc::json &body, const tc::call_context &) -> tc::json {
          if (op == "ping")
            return identity;
          if (op == "stop") {
            stop = true;
            return {{"stopping", true}};
          }
          tc::require(op == "invoke", "not_supported");
          if (body.value("crash", false))
            std::_Exit(42);
          tc::write_json(c.state / "data" / "last.json", body);
          return {{"echo", body},
                  {"private_keys", tc::read_json(c.state / "ipc-keys.json").size()},
                  {"has_engines", !tc::read_json(c.state / "plugin.json").at("engines").empty()}};
        });
    tc::write_json(c.state / "plugin.instance.json", identity);
    while (!stop)
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    server.stop();
    return 0;
  } catch (...) {
    return 1;
  }
}
