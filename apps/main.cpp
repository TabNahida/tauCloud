#include <algorithm>
#include <csignal>
#include <iostream>
#include <taucloud/core.hpp>
#include <taucloud/plugins.hpp>
#ifndef _WIN32
#include <sys/stat.h>
#endif
static std::atomic_bool stopping = false;
static void stop(int) { stopping = true; }
int main(int argc, char **argv) {
#ifndef _WIN32
  umask(0077);
  std::signal(SIGPIPE, SIG_IGN);
#endif
  std::signal(SIGINT, stop);
  std::signal(SIGTERM, stop);
  try {
    std::vector<std::string> args;
    tc::fs::path state;
    std::string generation;
    bool service = false;
    for (int i = 1; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--state" || a == "--generation") {
        tc::require(i + 1 < argc, "invalid_arguments");
        if (a == "--state")
          state = argv[++i];
        else
          generation = argv[++i];
      } else if (a == "--service")
        service = true;
      else
        args.push_back(a);
    }
    tc::require(!state.empty(), "state_required");
    std::string role = TAUCLOUD_ROLE;
    if (role == "ctl" && !args.empty() && args[0] == "init") {
      int port = 8443;
      if (args.size() == 3 && args[1] == "--port")
        port = std::stoi(args[2]);
      else
        tc::require(args.size() == 1, "invalid_arguments");
      tc::initialize(state, port);
      std::cout << "{\"initialized\":true}\n";
      return 0;
    }
    if (role == "ctl" && args.size() == 3 && args[0] == "restore" && args[1] == "--input") {
      std::cout << tc::metadata_restore(state, args[2]).dump() << "\n";
      return 0;
    }
    auto config = tc::config::load(state);
    tc::set_log_directory(config.state / "logs");
    if (role == "ctl")
      return tc::cli(config, args);
    if (role == "supervisor") {
      auto bin =
          tc::fs::path(tc::process_info(tc::own_pid()).at("exe").get<std::string>()).parent_path();
      return service ? tc::service_main(config, bin) : tc::supervisor(config, bin, stopping);
    }
    tc::require(generation.size() == 32, "generation_required");
    if (role == "plugins")
      return tc::plugins(config, generation, stopping);
    if (role == "docker")
      return tc::docker_plugin(config, generation, stopping);
    if (role == "nfs")
      return tc::nfs(config, generation, stopping);
    if (role == "smb")
      return tc::smb(config, generation, stopping);
    if (role == "ftp")
      return tc::ftp(config, generation, stopping);
    if (role == "webdav")
      return tc::webdav(config, generation, stopping);
    if (role == "api")
      return tc::api(config, generation, stopping);
    return tc::worker(role, config, generation, stopping);
  } catch (const tc::error &e) {
    tc::log(TAUCLOUD_ROLE, "failed", e.what());
    return 1;
  } catch (...) {
    tc::log(TAUCLOUD_ROLE, "failed", "invalid_configuration_or_io");
    return 1;
  }
}
