#pragma once
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>
namespace tc {
using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std::chrono_literals;
struct error : std::runtime_error {
  explicit error(std::string code) : runtime_error(std::move(code)) {}
};
void require(bool value, const char *code);
int64_t now();
std::string random_hex(size_t bytes = 32);
std::string digest(std::string_view value);
std::string mac(std::string_view key, std::string_view value);
bool equal(std::string_view a, std::string_view b);
std::string password_hash(std::string_view password, std::string_view salt);
json read_json(const fs::path &file);
void write_json(const fs::path &file, const json &value);
void secure_directory(const fs::path &dir);
void log(std::string_view role, std::string_view event, std::string_view code = "ok");
void set_log_directory(const fs::path &directory);
const std::vector<std::string> &roles();
struct config {
  fs::path state;
  uint16_t port = 8443, dav_port = 0, smb_port = 0, nfs_port = 0, ftp_port = 0, ftp_passive_first = 50000,
           ftp_passive_last = 50031;
  bool ftp_plaintext = false;
  int connections = 32, ipc_queue = 16, restart_limit = 5;
  int memory_mb = 512;
  std::string origin() const;
  static config load(const fs::path &state);
};
void initialize(const fs::path &state, int port);
json metadata_backup(const config &, const fs::path &);
json metadata_restore(const fs::path &, const fs::path &);
class file_lock {
  intptr_t handle_ = -1;

public:
  explicit file_lock(const fs::path &path);
  ~file_lock();
  file_lock(const file_lock &) = delete;
};
json process_info(int64_t pid);
int64_t own_pid();
json spawn(const fs::path &executable, const config &cfg, const std::string &generation);
bool verified_alive(const json &identity);
void terminate_verified(const json &identity);
void reap_children();
void apply_resource_budget(const config &cfg);
class channel {
  intptr_t handle_ = -1;

public:
  explicit channel(intptr_t handle = -1) : handle_(handle) {}
  ~channel();
  channel(channel &&other) noexcept;
  channel &operator=(channel &&other) noexcept;
  channel(const channel &) = delete;
  void transfer(void *data, size_t size, bool writing, int64_t deadline, std::stop_token stop = {});
  void send(const json &value, int64_t deadline, std::stop_token stop = {});
  json receive(int64_t deadline, std::stop_token stop = {});
  static channel connect(const config &, const std::string &role, int64_t deadline);
};
class local_listener {
  struct impl;
  std::unique_ptr<impl> impl_;

public:
  local_listener(const config &, const std::string &role);
  ~local_listener();
  std::optional<channel> accept(std::stop_token stop);
};
struct call_context {
  std::string caller, id;
  int64_t deadline;
  std::stop_token cancellation;
  void check() const;
};
using rpc_handler = std::function<json(const std::string &, const json &, const call_context &)>;
class rpc_server {
  struct impl;
  std::unique_ptr<impl> impl_;

public:
  rpc_server(const config &, std::string role, std::string generation, rpc_handler handler);
  ~rpc_server();
  void stop();
};
json rpc(const config &, const std::string &caller, const std::string &target,
         const std::string &operation, json body = json::object(), std::string generation = "",
         std::stop_token stop = {}, std::string request_id = "", int timeout_ms = 4000);
class identity_store {
  struct impl;
  std::unique_ptr<impl> impl_;

public:
  explicit identity_store(const config &);
  ~identity_store();
  json dispatch(const std::string &, const json &, const call_context &);
};
int worker(const std::string &role, const config &, const std::string &generation,
           std::atomic_bool &stopping);
int supervisor(const config &, const fs::path &binaries, std::atomic_bool &stopping);
int api(const config &, const std::string &generation, std::atomic_bool &stopping);
int nfs(const config &, const std::string &generation, std::atomic_bool &stopping);
int smb(const config &, const std::string &generation, std::atomic_bool &stopping);
int ftp(const config &, const std::string &generation, std::atomic_bool &stopping);
int webdav(const config &, const std::string &generation, std::atomic_bool &stopping);
int cli(const config &, const std::vector<std::string> &args);
int service_main(const config &, const fs::path &binaries);
} // namespace tc
