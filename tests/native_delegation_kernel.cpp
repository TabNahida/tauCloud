// Real native_file provider tests. Run normally for capability detection, or as
// PID 1 in the isolated Linux 6.19 QEMU guest for mandatory positive acceptance.
#include <taucloud/files.hpp>
#include <taucloud/native_delegation_owner.hpp>
#include <chrono>
#include <iostream>
#include <thread>
#include <functional>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
using namespace tc;
using namespace std::chrono_literals;
static int checks;
static void check(bool value, const char *message) { require(value, message); ++checks; }

// A child executes an ordinary host syscall, outside the file-domain API.
// Prove it stays blocked until explicit release, then completes successfully.
static void conflict(native_cache_guard &guard, const std::function<int()> &operation) {
  auto child = fork();
  check(child >= 0, "fork_failed");
  if (!child) _exit(operation() == 0 ? 0 : 1);
  bool reaped = false;
  try {
    int status = 0;
    auto end = std::chrono::steady_clock::now() + 3s;
    bool breaking = false;
    while (!(breaking = guard.breaking()) && std::chrono::steady_clock::now() < end) {
      if (waitpid(child, &status, WNOHANG) == child) { reaped = true; break; }
      std::this_thread::sleep_for(5ms);
    }
    check(breaking, "host_mutation_did_not_recall");
    std::this_thread::sleep_for(50ms);
    if (waitpid(child, &status, WNOHANG) == child) reaped = true;
    check(!reaped, "host_mutation_completed_before_release");
    guard.release();
    end = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < end) {
      if (waitpid(child, &status, WNOHANG) == child) { reaped = true; break; }
      std::this_thread::sleep_for(5ms);
    }
    check(reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0, "host_mutation_failed_after_release");
    check(!guard.breaking(), "released_guard_still_breaking");
  } catch (...) {
    if (!reaped) { kill(child, SIGKILL); waitpid(child, nullptr, 0); }
    throw;
  }
}
static bool suite(const fs::path &base, bool mandatory) {
  fs::create_directories(base);
  auto root = native_file::root(base);
  {
    auto f = root.open("probe", false, true, true); f.write(0, "contents");
  }
  {
    auto f = root.open("probe");
    auto guard = f.delegation_guard(false);
    if (!guard) {
      check(!mandatory, "required_kernel_delegation_unavailable");
      // An unsuccessful request must not poison cache_owned or leave a hidden
      // lease. Exercise the old primitive and an ordinary writer afterward.
      auto ordinary = f.cache_guard(false);
      check(bool(ordinary), "failed_delegation_poisoned_ordinary_lease");
      ordinary.reset(); f = native_file();
      auto writer = root.open("probe", false, false, true);
      writer.write(0, "ok");
      std::cout << "UNSUPPORTED F_SETDELEG; no fallback claimed as delegation\n";
      return false;
    }
    check(!guard->breaking(), "new_guard_breaking");
    check(!f.cache_guard(false) && !f.delegation_guard(false), "duplicate_guard");
    auto retained = f.retain();
    check(!retained.delegation_guard(false), "retained_duplicate_guard");
    auto reader = root.open("probe");
    check(reader.read(0, 8) == "contents" && !guard->breaking(), "compatible_reader_recalled");
    check(!f.delegation_guard(true), "read_description_granted_write");
    guard->release(); guard->release();
    check(!f.delegation_guard(true), "released_read_description_granted_write");
    // Destroying the guard releases exclusion even when another native_file
    // retains the same open description. No hidden lease may survive RAII.
    guard = f.delegation_guard(false);
    check(bool(guard), "reacquire_after_release");
    guard.reset();
    auto writer = root.open("probe", false, false, true);
    check(writer.write(0, "contents") == 8, "destructor_failed_to_release");
  }
  int index = 0;
  auto run = [&](const char *name, bool write, const std::function<int(const fs::path &)> &op) {
    auto relative = "file-" + std::to_string(++index);
    { auto f = root.open(relative, false, true, true); f.write(0, "before"); }
    auto f = root.open(relative, false, false, write);
    auto guard = f.delegation_guard(write);
    check(bool(guard), "delegation_acquire_failed");
    try { conflict(*guard, [&] { return op(base / relative); }); }
    catch (...) { std::cerr << "FAIL " << base << " " << name << '\n'; throw; }
    std::cout << "PASS " << base << " " << name << '\n';
  };
  run("READ/writer", false, [](auto p) { int fd = open(p.c_str(), O_WRONLY); if (fd < 0) return -1; return close(fd); });
  run("READ/truncate", false, [](auto p) { return truncate(p.c_str(), 1); });
  run("READ/rename", false, [](auto p) { return rename(p.c_str(), (p.string()+"-renamed").c_str()); });
  run("READ/unlink", false, [](auto p) { return unlink(p.c_str()); });
  run("READ/chmod", false, [](auto p) { return chmod(p.c_str(), 0400); });
  run("READ/utimens", false, [](auto p) { timespec ts[2]{{100,0},{100,0}}; return utimensat(AT_FDCWD, p.c_str(), ts, 0); });
  run("READ/xattr", false, [](auto p) { return setxattr(p.c_str(), "user.delegation", "x", 1, 0); });
  run("READ/chown", false, [](auto p) { return chown(p.c_str(), getuid(), getgid()); });
  run("READ/link", false, [](auto p) { return link(p.c_str(), (p.string()+"-link").c_str()); });
  run("WRITE/reader", true, [](auto p) { int fd = open(p.c_str(), O_RDONLY); if (fd < 0) return -1; return close(fd); });
  run("WRITE/writer", true, [](auto p) { int fd = open(p.c_str(), O_WRONLY); if (fd < 0) return -1; return close(fd); });
  {
    auto reader = root.open("probe"), writer = root.open("probe", false, false, true);
    check(!reader.delegation_guard(false) && !writer.delegation_guard(true), "existing_open_conflict_ignored");
  }
  {
    auto directory = root.open("directory", true, true);
    check(!directory.delegation_guard(true), "directory_write_delegation");
    auto guard = directory.delegation_guard(false);
    check(bool(guard), "directory_read_delegation_unavailable");
    conflict(*guard, [&] { int fd = open((base / "directory/new").c_str(), O_CREAT | O_WRONLY, 0600); if (fd < 0) return -1; return close(fd); });
    std::cout << "PASS " << base << " DIRECTORY/create\n";
    guard = directory.delegation_guard(false);
    check(bool(guard), "directory_reacquire");
    conflict(*guard, [&] { return unlink((base / "directory/new").c_str()); });
    std::cout << "PASS " << base << " DIRECTORY/unlink\n";
    guard = directory.delegation_guard(false);
    check(bool(guard), "directory_reacquire");
    conflict(*guard, [&] { return rename((base / "directory").c_str(), (base / "renamed-directory").c_str()); });
    std::cout << "PASS " << base << " DIRECTORY/rename\n";
    auto destination = root.open("destination", true, true);
    guard = directory.delegation_guard(false);
    check(bool(guard), "directory_reacquire");
    conflict(*guard, [&] { return rename((base / "renamed-directory").c_str(), (base / "destination/moved").c_str()); });
    std::cout << "PASS " << base << " DIRECTORY/cross-parent-rename\n";
    // Reacquisition follows the retained incarnation's current parent, not
    // native_file's originally traversed parent or its obsolete pathname.
    guard = directory.delegation_guard(false);
    check(bool(guard), "moved_directory_reacquire");
    conflict(*guard, [&] { return rmdir((base / "destination/moved").c_str()); });
    std::cout << "PASS " << base << " DIRECTORY/rmdir-after-move\n";
  }
  return true;
}
static void owner_suite(const fs::path &base, bool mandatory) {
  auto root = native_file::root(base);
  { auto f = root.open("owned", false, true, true); f.write(0, "retained"); }
  auto file = root.open("owned");
  native_delegation_owner owner;
  check(!owner.acquire(file, 5000, 5000, true), "owner_added_write_rights");
  auto id = owner.acquire(file, 5000, 5000);
  if (!id) {
    check(!mandatory, "required_owner_delegation_unavailable");
    auto ordinary = file.cache_guard(false);
    check(bool(ordinary), "owner_refusal_poisoned_descriptor");
    std::cout << "UNSUPPORTED owner F_SETDELEG; ordinary descriptor remains usable\n";
    return;
  }
  check(owner.inspect(id).at("state") == "active", "owner_not_active");
  try { owner.inspect(id + 1000); throw error("unknown_owner_id_accepted"); }
  catch (const error &e) { check(std::string_view(e.what()) == "stale_handle", "owner_wrong_unknown_id_error"); }
  check(!file.cache_guard(false) && !owner.acquire(file, 5000, 5000), "owner_local_duplicate");
  check(file.read(0, 8) == "retained", "owner_read_access");
  { auto reader = root.open("owned"); check(reader.read(0, 8) == "retained", "owner_compatible_reader"); }
  owner.recall(id);
  auto remaining = owner.inspect(id).at("recall_remaining_ms").get<int64_t>();
  auto until = std::chrono::steady_clock::now() + 7s;
  json snapshot;
  do {
    std::this_thread::sleep_for(100ms);
    snapshot = owner.inspect(id);
    if (snapshot.at("state") == "revoked") break;
    try { owner.renew(id, 5000); }
    catch (const error &e) {
      if (std::string_view(e.what()) != "stale_handle" || owner.inspect(id).at("state") != "revoked") throw;
    }
    check(snapshot.at("recall_remaining_ms").get<int64_t>() <= remaining, "owner_renew_extended_recall");
    remaining = snapshot.at("recall_remaining_ms").get<int64_t>();
  } while (std::chrono::steady_clock::now() < until);
  check(snapshot.at("state") == "revoked", "owner_recall_not_revoked");
  // Acknowledging an old tombstone cannot clear a newly acquired local guard.
  auto local = file.cache_guard(false);
  check(bool(local), "owner_expiry_not_released");
  owner.release(id);
  check(!file.cache_guard(false), "old_owner_release_cleared_new_guard");
  local.reset();
  id = owner.acquire(file, 5000, 5000);
  check(id != 0, "owner_reacquire");
  int writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "owner_did_not_block_writer");
  until = std::chrono::steady_clock::now() + 2s;
  while (owner.inspect(id).at("state") == "active" && std::chrono::steady_clock::now() < until)
    std::this_thread::sleep_for(5ms);
  check(owner.inspect(id).at("state") == "recalling", "owner_did_not_observe_native_recall");
  owner.release(id);
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "owner_explicit_return_failed"); close(writer);
  std::cout << "PASS " << base << " OWNER/renew-recall-revoke-return\n";
  // Detach, including ordinary C++ destruction, must retain the last accepted
  // lease. There is no implicit RELEASE frame on control-channel closure.
  {
    native_delegation_owner detached;
    check(detached.acquire(file, 5000, 1200) != 0, "owner_detach_acquire");
  }
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "owner_detach_released_early");
  until = std::chrono::steady_clock::now() + 3s;
  do {
    std::this_thread::sleep_for(20ms);
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  } while (writer < 0 && errno == EWOULDBLOCK && std::chrono::steady_clock::now() < until);
  check(writer >= 0, "orphan_owner_did_not_expire"); close(writer);
  check(!file.cache_guard(false), "detached_description_unfenced_without_ack");
  file = native_file();
  std::cout << "PASS " << base << " OWNER/detach-retention-expiry\n";
  // A real worker is SIGKILLed after the owner ACK. The independent owner must
  // keep exclusion, then release at the accepted deadline without that worker.
  int ready[2]; check(pipe2(ready, O_CLOEXEC) == 0, "owner_crash_pipe");
  auto worker = fork(); check(worker >= 0, "owner_crash_fork");
  if (!worker) {
    close(ready[0]);
    try {
      auto f = root.open("owned"); native_delegation_owner keeper;
      if (!keeper.acquire(f, 5000, 1800)) _exit(2);
      char marker = 'R'; if (write(ready[1], &marker, 1) != 1) _exit(3);
      for (;;) pause();
    } catch (...) { _exit(4); }
  }
  close(ready[1]);
  pollfd notification{ready[0], POLLIN, 0}; char marker = 0;
  bool acknowledged = poll(&notification, 1, 3000) > 0 && read(ready[0], &marker, 1) == 1 && marker == 'R';
  close(ready[0]); kill(worker, SIGKILL); int status; waitpid(worker, &status, 0);
  check(acknowledged && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "worker_guard_not_acknowledged");
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "worker_crash_released_native_guard");
  auto start = std::chrono::steady_clock::now();
  do {
    std::this_thread::sleep_for(20ms);
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  } while (writer < 0 && errno == EWOULDBLOCK && std::chrono::steady_clock::now() - start < 4s);
  check(writer >= 0 && std::chrono::steady_clock::now() - start > 500ms, "worker_crash_retention_deadline");
  close(writer);
  std::cout << "PASS " << base << " OWNER/SIGKILL-worker-retention-expiry\n";
  // NFS recovery retains private pins and unlinked open incarnations. The
  // descriptor handoff must preserve those already-validated native flags.
  auto original = root.open("pin-source", false, true, true);
  original.write(0, "pinned");
  auto name = ".tc-nfs-" + random_hex(16);
  auto pinned = original.pin(root, name);
  original = native_file();
  auto pin_id = owner.acquire(pinned, 5000, 5000, true);
  check(pin_id != 0 && pinned.read(0, 6) == "pinned", "owner_private_pin_handoff");
  owner.release(pin_id);
  auto retained = pinned.retain(); pinned = native_file();
  check(unlink((base / "pin-source").c_str()) == 0 && unlink((base / name).c_str()) == 0, "owner_unlink_fixture");
  pin_id = owner.acquire(retained, 5000, 5000, true);
  check(pin_id != 0 && retained.read(0, 6) == "pinned", "owner_unlinked_incarnation_handoff");
  owner.release(pin_id);
  std::cout << "PASS " << base << " OWNER/private-pin-and-unlinked-incarnation\n";
}
int main(int argc, char **argv) {
  if (auto result = native_delegation_owner::entry(argc, argv); result >= 0) return result;
  bool guest = getpid() == 1;
  int code = 1;
  fs::path base;
  try {
    if (guest) {
      check(mount("proc", "/proc", "proc", 0, nullptr) == 0, "mount_proc");
      check(mount("devtmpfs", "/dev", "devtmpfs", 0, nullptr) == 0, "mount_dev");
      check(mount("tmpfs", "/tmp", "tmpfs", 0, nullptr) == 0, "mount_tmpfs");
      check(mount("/dev/vda", "/disk", "ext4", 0, nullptr) == 0, "mount_ext4");
      suite("/tmp/delegation", true);
      owner_suite("/tmp/delegation", true);
      suite("/disk/delegation", true);
      owner_suite("/disk/delegation", true);
    } else {
      base = fs::temp_directory_path() / ("tc-native-delegation-" + random_hex(6));
      suite(base, argc > 1 && std::string_view(argv[1]) == "--require");
      owner_suite(base, argc > 1 && std::string_view(argv[1]) == "--require");
    }
    std::cout << "PASS native delegation " << checks << " checks\n";
    if (guest) std::cout << "TAUCLOUD_DELEGATION_VM_PASS\n";
    code = 0;
  } catch (const std::exception &e) { std::cerr << "FAIL " << e.what() << '\n'; }
  if (!base.empty()) fs::remove_all(base);
  std::cout.flush(); std::cerr.flush();
  if (guest) { sync(); reboot(RB_POWER_OFF); for (;;) pause(); }
  return code;
}
