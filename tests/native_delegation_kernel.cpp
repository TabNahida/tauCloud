// Real native_file provider tests. Run normally for capability detection, or as
// PID 1 in the isolated Linux 6.19 QEMU guest for mandatory positive acceptance.
#include <taucloud/files.hpp>
#include <chrono>
#include <iostream>
#include <thread>
#include <functional>
#include <fcntl.h>
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
int main(int argc, char **argv) {
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
      suite("/disk/delegation", true);
    } else {
      base = fs::temp_directory_path() / ("tc-native-delegation-" + random_hex(6));
      suite(base, argc > 1 && std::string_view(argv[1]) == "--require");
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
