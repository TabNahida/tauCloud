// Real native_file provider tests. Run normally for capability detection, or as
// PID 1 in the isolated Linux 6.19 QEMU guest for mandatory positive acceptance.
#include <taucloud/files.hpp>
#include <taucloud/native_delegation_owner.hpp>
#include <chrono>
#include <array>
#include <cstring>
#include <iostream>
#include <thread>
#include <functional>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
using namespace tc;
using namespace std::chrono_literals;
static int checks;
static void check(bool value, const char *message) { require(value, message); ++checks; }
static int64_t monotonic_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}

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
static void owner_recovery_suite(native_file &root, const fs::path &base) {
  auto denied = [&](const std::function<void()> &action) {
    bool rejected = false;
    try { action(); } catch (const error &e) { rejected = std::string_view(e.what()) == "forbidden"; }
    check(rejected, "recovery_authority_not_isolated");
  };
  auto recover = [&](const json &capability) {
    auto until = std::chrono::steady_clock::now() + 2s;
    for (;;) {
      try { return std::make_unique<native_delegation_owner>(capability); }
      catch (const error &e) {
        auto code = std::string_view(e.what());
        if (std::chrono::steady_clock::now() >= until ||
            (code != "forbidden" && code != "delegation_owner_lost" && code != "delegation_owner_unavailable")) throw;
        std::this_thread::sleep_for(10ms);
      }
    }
  };
  { auto f = root.open("recovery", false, true, true); f.write(0, "protected"); }
  {
    auto f = root.open("recovery");
    auto identity = f.stable_identity();
    auto owner = std::make_unique<native_delegation_owner>();
    check(owner->inventory().empty(), "new_owner_inventory_not_empty");
    auto capability = owner->recovery_capability(); // Can be persisted before acquisition.
    auto id = owner->acquire(f, 5000, 5000);
    check(id != 0, "recovery_acquire");
    auto pid = owner->process_id();
    auto reserved = owner->reservation_capability(id);
    auto old_channel = std::make_unique<native_delegation_reservation_channel>(reserved);
    auto before = owner->recall(id, monotonic_ms() + 5000);
    denied([&] { native_delegation_owner takeover(capability); });
    owner.reset();
    bool disconnected = false;
    auto until = std::chrono::steady_clock::now() + 2s;
    while (!disconnected && std::chrono::steady_clock::now() < until) {
      try { old_channel->inspect(); }
      catch (const error &e) { disconnected = std::string_view(e.what()) == "delegation_owner_lost"; }
      if (!disconnected) std::this_thread::sleep_for(5ms);
    }
    check(disconnected, "recovery_did_not_fence_old_reservation_channel");
    auto forged = capability;
    auto secret = forged.at("capability").get<std::string>(); secret.back() = secret.back() == '0' ? '1' : '0';
    forged["capability"] = secret;
    denied([&] { native_delegation_owner bad(forged); });
    auto promoted = reserved; promoted["type"] = "owner-recovery-v1";
    denied([&] { native_delegation_owner bad(promoted); });
    auto restored = recover(capability);
    auto after = restored->inspect(id);
    check(restored->process_id() == pid && after.at("state") == "recalling", "recovery_replaced_owner_or_recall");
    check(after.at("lease_expires_ms") == before.at("lease_expires_ms") &&
        after.at("recall_deadline_ms") == before.at("recall_deadline_ms"), "recovery_extended_deadline");
    denied([&] { native_delegation_owner takeover(capability); });
    denied([&] { native_delegation_reservation_channel stale(reserved); });
    auto fresh = restored->reservation_capability(id);
    check(fresh != reserved, "recovery_reused_stale_reservation_secret");
    native_delegation_reservation_channel channel(fresh);
    check(channel.inspect().at("held"), "recovered_reservation_channel_failed");
    check(restored->recovery_capability() == capability, "recovery_endpoint_changed");
    restored.reset();
    restored = recover(capability);
    after = restored->inspect(id);
    check(after.at("lease_expires_ms") == before.at("lease_expires_ms") &&
        after.at("recall_deadline_ms") == before.at("recall_deadline_ms"), "repeated_recovery_extended_deadline");
    auto inventory = restored->inventory();
    check(inventory.size() == 1 && inventory[0].at("id") == id &&
        inventory[0].at("identity_sha256") == digest(identity) &&
        inventory[0].at("lease_expires_ms") == before.at("lease_expires_ms") &&
        inventory[0].at("recall_deadline_ms") == before.at("recall_deadline_ms"), "recovery_inventory_changed_identity_or_deadlines");
    bool mismatch = false;
    try { restored->restore(id, identity + "wrong"); }
    catch (const error &e) { mismatch = std::string_view(e.what()) == "stale_handle"; }
    check(mismatch, "restore_accepted_wrong_incarnation");
    auto description = restored->restore(id, identity);
    auto duplicate = restored->restore(id, identity);
    check(description.stable_identity() == identity && description.read(0, 9) == "protected" &&
        !description.writable(), "restore_changed_description_or_access");
    check(!description.cache_guard(false) && !duplicate.delegation_guard(false), "restore_did_not_fence_shared_description");
    after = restored->inspect(id);
    check(after.at("lease_expires_ms") == before.at("lease_expires_ms") &&
        after.at("recall_deadline_ms") == before.at("recall_deadline_ms"), "restore_extended_deadline");
    int writer = open((base / "recovery").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer < 0 && errno == EWOULDBLOCK, "recovery_released_native_exclusion");
    restored->release(id);
    check(restored->inventory().empty(), "released_record_in_inventory");
    check(bool(description.delegation_guard(false)), "restored_description_not_unfenced_on_release");
    check(bool(duplicate.delegation_guard(false)), "duplicate_description_not_unfenced_on_release");
    writer = open((base / "recovery").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer >= 0, "recovered_owner_cannot_release"); close(writer);
  }
  std::cout << "PASS " << base << " OWNER/recovery-auth-single-controller-fixed-deadlines-channel-rotation\n";
  {
    auto owner = std::make_unique<native_delegation_owner>();
    auto capability = owner->recovery_capability();
    std::string identity;
    uint64_t id;
    {
      auto file = root.open("recovery-write", false, true, true);
      file.write(0, "original"); identity = file.stable_identity();
      id = owner->acquire(file, 5000, 5000, true);
      check(id != 0, "restore_write_acquire");
    }
    owner.reset(); owner = recover(capability);
    auto file = owner->restore(id, identity);
    check(file.writable() && file.read(0, 8) == "original" && file.write(0, "restored") == 8,
        "restore_write_description_not_preserved");
    int reader = open((base / "recovery-write").c_str(), O_RDONLY | O_NONBLOCK);
    check(reader < 0 && errno == EWOULDBLOCK, "restore_write_guard_lost");
    owner->release(id);
    reader = open((base / "recovery-write").c_str(), O_RDONLY | O_NONBLOCK);
    check(reader >= 0, "restore_write_release_failed"); close(reader);
  }
  {
    auto short_file = root.open("recovery");
    auto long_file = root.open("recovery-write");
    native_delegation_owner owner;
    auto first = owner.acquire(short_file, 5000, 300);
    auto second = owner.acquire(long_file, 5000, 5000);
    check(first && second > first, "inventory_order_fixture");
    auto restored = owner.restore(first, short_file.stable_identity());
    auto inventory = owner.inventory();
    check(inventory.size() == 2 && inventory[0].at("id") == first && inventory[1].at("id") == second,
        "inventory_live_order");
    std::this_thread::sleep_for(400ms);
    inventory = owner.inventory();
    check(inventory.size() == 1 && inventory[0].at("id") == second, "inventory_did_not_skip_expired_guard");
    bool stale = false;
    try { owner.restore(first, short_file.stable_identity()); }
    catch (const error &e) { stale = std::string_view(e.what()) == "stale_handle"; }
    check(stale, "restore_revived_expired_record");
    check(!owner.inspect(first).at("held").get<bool>() && bool(restored.delegation_guard(false)),
        "restore_terminal_observation_did_not_unfence");
    owner.release(first); owner.release(second);
  }
  std::cout << "PASS " << base << " OWNER/restored-write-description-and-expired-inventory\n";
  {
    auto directory = root.open("recovery-directory", true, true);
    auto identity = directory.stable_identity();
    auto owner = std::make_unique<native_delegation_owner>();
    auto capability = owner->recovery_capability();
    auto id = owner->acquire(directory, 5000, 5000);
    check(id != 0, "restore_directory_acquire");
    directory = native_file(); owner.reset(); owner = recover(capability);
    directory = owner->restore(id, identity);
    check(directory.info().at("directory") && !directory.delegation_guard(false), "restore_directory_not_fenced");
    auto mover = fork(); check(mover >= 0, "restore_directory_fork");
    if (!mover) _exit(rename((base / "recovery-directory").c_str(), (base / "recovery-moved").c_str()) ? 1 : 0);
    bool reaped = false;
    try {
      auto end = monotonic_ms() + 2000;
      while (owner->inspect(id).at("state") == "active" && monotonic_ms() < end) std::this_thread::sleep_for(5ms);
      check(owner->inspect(id).at("state") == "recalling", "restore_directory_parent_not_retained");
      int status = 0; reaped = waitpid(mover, &status, WNOHANG) == mover;
      check(!reaped, "restore_directory_rename_not_blocked");
      owner->release(id);
      end = monotonic_ms() + 2000;
      while (!(reaped = waitpid(mover, &status, WNOHANG) == mover) && monotonic_ms() < end)
        std::this_thread::sleep_for(5ms);
      check(reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0, "restore_directory_rename_after_release");
      check(directory.stable_identity() == identity && bool(directory.delegation_guard(false)),
          "restore_directory_identity_or_release_lost");
    } catch (...) { if (!reaped) { kill(mover, SIGKILL); waitpid(mover, nullptr, 0); } throw; }
  }
  std::cout << "PASS " << base << " OWNER/restored-directory-parent-namespace-exclusion\n";
  // Persist the capability/identity, then kill the real controller process.
  // A replacement process object must reach the same surviving native owner.
  for (bool committed : {true, false}) {
    auto journal = base / "owner-recovery.json";
    int ready[2]; check(pipe2(ready, O_CLOEXEC) == 0, "recovery_crash_pipe");
    auto worker = fork(); check(worker >= 0, "recovery_crash_fork");
    if (!worker) {
      close(ready[0]);
      try {
        auto f = root.open("recovery"); native_delegation_owner owner;
        auto capability = owner.recovery_capability();
        json intent = {{"capability", capability}, {"identity", f.stable_identity()}, {"pid", owner.process_id()}};
        write_json(journal, intent);
        auto id = owner.acquire(f, 5000, 5000);
        if (!id) _exit(2);
        if (committed) {
          intent["id"] = id; intent["snapshot"] = owner.inspect(id);
          write_json(journal, intent);
        }
        char mark = 'R'; if (write(ready[1], &mark, 1) != 1) _exit(3);
        for (;;) pause();
      } catch (...) { _exit(4); }
    }
    close(ready[1]);
    pollfd notification{ready[0], POLLIN, 0}; char mark = 0;
    bool acknowledged = poll(&notification, 1, 3000) > 0 && read(ready[0], &mark, 1) == 1 && mark == 'R';
    close(ready[0]);
    check(kill(worker, SIGKILL) == 0, "recovery_crash_signal");
    int status = 0; check(waitpid(worker, &status, 0) == worker && WIFSIGNALED(status), "recovery_crash_wait");
    check(acknowledged, "recovery_journal_not_acknowledged");
    auto saved = read_json(journal);
    struct stat journal_info{};
    check(stat(journal.c_str(), &journal_info) == 0 && (journal_info.st_mode & 0777) == 0600, "recovery_journal_not_private");
    auto restored = recover(saved.at("capability"));
    auto inventory = restored->inventory();
    check(inventory.size() == 1 && inventory[0].at("identity_sha256") == digest(saved.at("identity").get<std::string>()),
        "crash_recovery_cannot_reconcile_intent");
    auto id = inventory[0].at("id").get<uint64_t>();
    if (committed) check(id == saved.at("id"), "crash_recovery_changed_id");
    auto before = restored->inspect(id);
    check(restored->process_id() == saved.at("pid").get<int64_t>() &&
        (!committed || before.at("lease_expires_ms") == saved.at("snapshot").at("lease_expires_ms")),
        "crash_recovery_replaced_or_renewed_guard");
    auto description = restored->restore(id, saved.at("identity"));
    check(description.read(0, 9) == "protected" && !description.cache_guard(false), "crash_recovery_description_not_retained");
    std::this_thread::sleep_for(20ms);
    auto renewed = restored->renew(id, 5000);
    check(renewed.at("lease_expires_ms") > before.at("lease_expires_ms"), "recovered_owner_cannot_acknowledge_renewal");
    int writer = open((base / "recovery").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer < 0 && errno == EWOULDBLOCK, "crash_recovery_lost_native_guard");
    restored->release(id);
    writer = open((base / "recovery").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer >= 0, "crash_recovery_release_failed"); close(writer);
    restored.reset(); fs::remove(journal);
    std::cout << "PASS " << base << (committed ? " OWNER/persisted-capability-SIGKILL-controller-reattach-renew-release\n" :
        " OWNER/pre-acquire-intent-SIGKILL-inventory-descriptor-reconciliation\n");
  }
  json expired;
  {
    auto f = root.open("recovery"); native_delegation_owner owner;
    expired = owner.recovery_capability();
    check(owner.acquire(f, 5000, 800) != 0, "recovery_expiry_acquire");
  }
  std::this_thread::sleep_for(1000ms);
  bool rejected = false;
  try { native_delegation_owner late(expired); }
  catch (const error &e) {
    auto code = std::string_view(e.what());
    rejected = code == "delegation_owner_unavailable" || code == "stale_handle" || code == "delegation_owner_lost";
  }
  check(rejected, "recovery_revived_expired_owner");
  int writer = open((base / "recovery").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "recoverable_orphan_did_not_expire"); close(writer);
  std::cout << "PASS " << base << " OWNER/recovery-cannot-revive-expired-guards\n";
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
  owner_recovery_suite(root, base);
  int index = 0;
  auto run = [&](const char *name, bool write, const std::function<int(const fs::path &)> &op) {
    auto relative = "file-" + std::to_string(++index);
    { auto f = root.open(relative, false, true, true); f.write(0, "before"); }
    auto f = root.open(relative, false, false, write);
    auto guard = f.delegation_guard(write);
    check(bool(guard), "delegation_acquire_failed");
    check(root.metadata(relative).at("object") == f.info().at("object") && !guard->breaking(),
          "metadata_observation_recalled_delegation");
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
  auto confirmed = owner.inspect(id);
  check(confirmed.at("protected_until_ms") == confirmed.at("lease_expires_ms") &&
      confirmed.at("recall_deadline_ms") == 0, "owner_deadline_not_absolute");
  auto original_expiry = confirmed.at("lease_expires_ms").get<int64_t>();
  std::this_thread::sleep_for(100ms);
  auto observed_at = monotonic_ms();
  confirmed = owner.inspect(id);
  check(confirmed.at("lease_expires_ms") == original_expiry &&
      confirmed.at("lease_remaining_ms").get<int64_t>() <= original_expiry - observed_at,
      "owner_observation_extended_expiry");
  try { owner.inspect(id + 1000); throw error("unknown_owner_id_accepted"); }
  catch (const error &e) { check(std::string_view(e.what()) == "stale_handle", "owner_wrong_unknown_id_error"); }
  check(!file.cache_guard(false) && !owner.acquire(file, 5000, 5000), "owner_local_duplicate");
  check(file.read(0, 8) == "retained", "owner_read_access");
  { auto reader = root.open("owned"); check(reader.read(0, 8) == "retained", "owner_compatible_reader"); }
  owner.recall(id);
  confirmed = owner.inspect(id);
  auto remaining = confirmed.at("recall_remaining_ms").get<int64_t>();
  auto recall_deadline = confirmed.at("recall_deadline_ms").get<int64_t>();
  auto until = std::chrono::steady_clock::now() + 7s;
  json snapshot;
  do {
    std::this_thread::sleep_for(100ms);
    snapshot = owner.inspect(id);
    if (snapshot.at("state") == "revoked") break;
    try {
      auto acknowledged = owner.renew(id, 5000);
      check(acknowledged.at("recall_deadline_ms") == recall_deadline &&
          acknowledged.at("protected_until_ms").get<int64_t>() ==
              std::min(acknowledged.at("lease_expires_ms").get<int64_t>(), recall_deadline),
          "owner_renew_ack_exceeded_recall");
    }
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
  // The child remains unreaped until controller destruction, so its PID cannot
  // be reused while these verified waitid observations and signals execute.
  {
    auto f = root.open("owned"); native_delegation_owner stopped;
    auto pid = static_cast<pid_t>(stopped.process_id()); siginfo_t event{};
    check(kill(pid, SIGSTOP) == 0 && waitid(P_PID, pid, &event, WSTOPPED | WNOWAIT) == 0 &&
        event.si_code == CLD_STOPPED, "owner_stop_not_observed");
    bool lost = false;
    try { stopped.acquire(f, 5000, 800); }
    catch (const error &e) { lost = std::string_view(e.what()) == "delegation_owner_lost"; }
    kill(pid, SIGCONT);
    check(lost, "stopped_owner_acquire_not_timed_out");
    auto limit = std::chrono::steady_clock::now() + 500ms;
    do {
      event = {}; check(waitid(P_PID, pid, &event, WEXITED | WNOHANG | WNOWAIT) == 0, "late_owner_wait");
      if (event.si_pid) break;
      std::this_thread::sleep_for(5ms);
    } while (std::chrono::steady_clock::now() < limit);
    check(event.si_pid == pid, "late_acquire_restarted_expired_lease");
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer >= 0, "late_acquire_left_guard"); close(writer);
    check(!f.cache_guard(false), "uncertain_acquire_description_unfenced");
  }
  {
    auto f = root.open("owned"); native_delegation_owner killed;
    auto held = killed.acquire(f, 5000, 5000);
    check(held != 0, "killed_owner_acquire");
    auto pid = static_cast<pid_t>(killed.process_id()); siginfo_t event{};
    check(kill(pid, SIGSTOP) == 0 && waitid(P_PID, pid, &event, WSTOPPED | WNOWAIT) == 0,
        "release_owner_stop");
    bool refused = false;
    try { killed.release(held); }
    catch (const error &e) { refused = std::string_view(e.what()) == "delegation_owner_lost"; }
    check(refused && !f.cache_guard(false), "live_owner_release_unfenced_description");
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer < 0 && errno == EWOULDBLOCK, "live_owner_release_unlocked_guard");
    check(kill(pid, SIGKILL) == 0 && waitid(P_PID, pid, &event, WEXITED | WNOWAIT) == 0,
        "owner_death_not_observed");
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer < 0 && errno == EWOULDBLOCK, "owner_death_lost_retained_guard");
    killed.release(held);
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer >= 0, "dead_owner_explicit_release_failed"); close(writer);
    check(bool(f.delegation_guard(false)), "dead_owner_release_left_local_fence");
  }
  std::cout << "PASS " << base << " OWNER/absolute-expiry-and-confirmed-death-cleanup\n";
  // NFS recovery retains private pins and unlinked open incarnations. The
  // descriptor handoff must preserve those already-validated native flags.
  auto original = root.open("pin-source", false, true, true);
  original.write(0, "pinned");
  auto name = ".tc-nfs-" + random_hex(16);
  auto pinned = original.pin(root, name);
  original = native_file();
  auto pin_id = owner.acquire(pinned, 5000, 5000, true);
  check(pin_id != 0 && pinned.read(0, 6) == "pinned", "owner_private_pin_handoff");
  auto pin_restored = owner.restore(pin_id, pinned.stable_identity());
  check(pin_restored.read(0, 6) == "pinned" && pin_restored.writable() &&
      !pin_restored.delegation_guard(true), "restore_private_pin_or_write_access_lost");
  owner.release(pin_id);
  auto retained = pinned.retain(); pinned = native_file();
  check(unlink((base / "pin-source").c_str()) == 0 && unlink((base / name).c_str()) == 0, "owner_unlink_fixture");
  pin_id = owner.acquire(retained, 5000, 5000, true);
  check(pin_id != 0 && retained.read(0, 6) == "pinned", "owner_unlinked_incarnation_handoff");
  auto unlinked_restored = owner.restore(pin_id, retained.stable_identity());
  check(unlinked_restored.read(0, 6) == "pinned" && !unlinked_restored.cache_guard(true),
      "restore_unlinked_incarnation_lost");
  owner.release(pin_id);
  std::cout << "PASS " << base << " OWNER/private-pin-and-unlinked-incarnation\n";

  // A request acknowledged before expiry keeps exclusion while execution or
  // reply delivery is delayed. Completing it starts a full post-reply lease.
  auto reserved_file = root.open("owned");
  auto reserved_id = owner.acquire(reserved_file, 5000, 300);
  check(reserved_id != 0, "reservation_acquire");
  auto first = owner.reserve(reserved_id).at("reservation").get<uint64_t>();
  auto second = owner.reserve(reserved_id).at("reservation").get<uint64_t>();
  check(first && second && first != second, "reservation_tokens_not_unique");
  std::this_thread::sleep_for(450ms);
  auto held = owner.inspect(reserved_id);
  check(held.at("held") && held.at("reservations") == 2 && held.at("lease_remaining_ms") == 0,
        "pending_request_expired");
  try { owner.reserve(reserved_id); throw error("late_arrival_reserved"); }
  catch (const error &e) { check(std::string_view(e.what()) == "stale_handle", "late_arrival_wrong_error"); }
  check(owner.complete(reserved_id, first, false).at("held"), "first_cancel_dropped_other_request");
  auto completion_time = monotonic_ms();
  auto completed = owner.complete(reserved_id, second, true);
  check(completed.at("reservations") == 0 && completed.at("lease_expires_ms").get<int64_t>() >= completion_time + 5000,
        "completion_missing_full_lease");
  auto final_expiry = completed.at("lease_expires_ms");
  try { owner.complete(reserved_id, second, true); throw error("duplicate_completion_accepted"); }
  catch (const error &e) { check(std::string_view(e.what()) == "stale_handle", "duplicate_completion_wrong_error"); }
  check(owner.inspect(reserved_id).at("lease_expires_ms") == final_expiry, "duplicate_completion_renewed");
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "postreply_lease_not_native");
  owner.release(reserved_id);
  std::cout << "PASS " << base << " OWNER/request-reservation-postreply-lease\n";

  reserved_id = owner.acquire(reserved_file, 5000, 5000);
  check(reserved_id != 0, "reservation_capacity_acquire");
  std::vector<uint64_t> tokens;
  for (int i = 0; i < 32; ++i) tokens.push_back(owner.reserve(reserved_id).at("reservation"));
  try { owner.reserve(reserved_id); throw error("reservation_capacity_unbounded"); }
  catch (const error &e) { check(std::string_view(e.what()) == "operation_limit", "reservation_capacity_wrong_error"); }
  try { owner.complete(reserved_id, second, true); throw error("foreign_reservation_accepted"); }
  catch (const error &e) { check(std::string_view(e.what()) == "stale_handle", "foreign_reservation_wrong_error"); }
  for (auto token : tokens) owner.complete(reserved_id, token, false);
  check(owner.inspect(reserved_id).at("reservations") == 0, "cancel_capacity_not_released");
  auto recycled = owner.reserve(reserved_id).at("reservation").get<uint64_t>();
  check(recycled > tokens.back(), "reservation_token_reused");
  owner.complete(reserved_id, recycled, false); owner.release(reserved_id);

  reserved_id = owner.acquire(reserved_file, 5000, 200);
  check(reserved_id != 0, "reservation_cancel_acquire");
  auto cancelled = owner.reserve(reserved_id).at("reservation").get<uint64_t>();
  std::this_thread::sleep_for(300ms);
  check(owner.complete(reserved_id, cancelled, false).at("state") == "expired", "cancel_renewed_lease");
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "cancel_did_not_release_native_guard"); close(writer);
  owner.release(reserved_id);
  std::cout << "PASS " << base << " OWNER/reservation-capacity-cancellation-and-token-binding\n";

  reserved_id = owner.acquire(reserved_file, 5000, 5000);
  check(reserved_id != 0, "recall_cutoff_acquire");
  auto cutoff = monotonic_ms() + 300;
  owner.reserve(reserved_id);
  check(owner.recall(reserved_id, cutoff).at("recall_deadline_ms") == cutoff, "recall_cutoff_not_imported");
  check(owner.recall(reserved_id, cutoff + 1000).at("recall_deadline_ms") == cutoff, "recall_cutoff_extended");
  std::this_thread::sleep_for(450ms);
  check(owner.inspect(reserved_id).at("state") == "revoked", "recall_cutoff_pending_not_revoked");
  owner.release(reserved_id);
  reserved_id = owner.acquire(reserved_file, 5000, 5000);
  check(reserved_id != 0, "past_recall_cutoff_acquire");
  owner.reserve(reserved_id);
  check(owner.recall(reserved_id, monotonic_ms() - 1).at("state") == "revoked", "past_recall_cutoff_not_revoked");
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "past_recall_cutoff_kept_native_guard"); close(writer);
  owner.release(reserved_id);
  std::cout << "PASS " << base << " OWNER/original-recall-cutoff-and-delayed-delivery\n";

  reserved_id = owner.acquire(reserved_file, 5000, 300);
  check(reserved_id != 0, "reservation_recall_acquire");
  auto recalling = owner.reserve(reserved_id).at("reservation").get<uint64_t>();
  std::this_thread::sleep_for(450ms);
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "reserved_native_guard_lost");
  until = std::chrono::steady_clock::now() + 6s;
  while (owner.inspect(reserved_id).at("state") != "revoked" && std::chrono::steady_clock::now() < until)
    std::this_thread::sleep_for(20ms);
  check(owner.inspect(reserved_id).at("state") == "revoked", "reservation_extended_recall");
  check(owner.complete(reserved_id, recalling, true).at("state") == "revoked", "late_completion_revived_guard");
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "reserved_recall_did_not_release_native_guard"); close(writer);
  owner.release(reserved_id); reserved_file = native_file();
  std::cout << "PASS " << base << " OWNER/reservation-cannot-postpone-native-recall\n";

  check(pipe2(ready, O_CLOEXEC) == 0, "reserved_crash_pipe");
  worker = fork(); check(worker >= 0, "reserved_crash_fork");
  if (!worker) {
    close(ready[0]);
    try {
      auto f = root.open("owned"); native_delegation_owner keeper;
      auto owned = keeper.acquire(f, 5000, 300);
      if (!owned || !keeper.reserve(owned).at("reservation").get<uint64_t>()) _exit(2);
      std::this_thread::sleep_for(450ms);
      char marker = 'R'; if (write(ready[1], &marker, 1) != 1) _exit(3);
      for (;;) pause();
    } catch (...) { _exit(4); }
  }
  close(ready[1]); notification = {ready[0], POLLIN, 0}; marker = 0;
  acknowledged = poll(&notification, 1, 3000) > 0 && read(ready[0], &marker, 1) == 1 && marker == 'R';
  close(ready[0]); kill(worker, SIGKILL); waitpid(worker, &status, 0);
  check(acknowledged && WIFSIGNALED(status), "reserved_worker_not_killed_after_ack");
  auto detached_at = std::chrono::steady_clock::now();
  writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "reserved_worker_death_released_early");
  do {
    std::this_thread::sleep_for(20ms);
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
  } while (writer < 0 && errno == EWOULDBLOCK && std::chrono::steady_clock::now() - detached_at < 7s);
  check(writer >= 0 && std::chrono::steady_clock::now() - detached_at >= 4500ms,
        "reserved_worker_death_missing_full_lease"); close(writer);
  std::cout << "PASS " << base << " OWNER/reservation-worker-death-bounded-full-lease\n";
}
// This runs even when the host lacks F_SETDELEG. It tests the private client
// transport only, never claims that a simulated response holds a native guard.
static void reservation_channel_authentication_suite() {
  struct packet {
    uint32_t magic = 0x54434434, op = 0, native_flags = 0, reserved = 0;
    uint64_t id = 0;
    int64_t period = 0, remaining = 0;
    uint64_t reservation = 0;
    std::array<char, 32> capability{};
  };
  static_assert(sizeof(packet) == 80);
  for (bool reflect_client_proof : {true, false}) {
    auto endpoint = decode_bytes(random_hex(16)), secret = decode_bytes(random_hex(16));
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    check(listener >= 0, "channel_auth_listener");
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    auto name = "taucloud-nfs-" + encode_bytes(endpoint);
    std::memcpy(address.sun_path + 1, name.data(), name.size());
    check(bind(listener, reinterpret_cast<sockaddr *>(&address), offsetof(sockaddr_un, sun_path) + 1 + name.size()) == 0 &&
        listen(listener, 1) == 0, "channel_auth_bind");
    auto server = fork(); check(server >= 0, "channel_auth_fork");
    if (!server) {
      pollfd pending{listener, POLLIN, 0};
      if (poll(&pending, 1, 2000) <= 0) _exit(2);
      int peer = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
      if (peer < 0) _exit(3);
      auto reply = [&](bool handshake) {
        pollfd readable{peer, POLLIN, 0}; packet request;
        if (poll(&readable, 1, 2000) <= 0 || recv(peer, &request, sizeof(request), 0) != sizeof(request)) _exit(4);
        if (request.magic != 0x54434434 || request.op != (handshake ? 11u : 3u) || request.id != 1) _exit(5);
        auto nonce = std::string(request.capability.data(), 16);
        auto tag = decode_bytes(mac(secret, "TCD4-client:" + endpoint + "1:" + nonce).substr(0, 32));
        if (handshake && std::string(request.capability.data(), 32) != nonce + tag) _exit(6);
        packet response = request; response.period = monotonic_ms() + 5000;
        if (handshake && !reflect_client_proof) {
          tag = decode_bytes(mac(secret, "TCD4-server:" + endpoint + "1:" + nonce).substr(0, 32));
          std::copy(tag.begin(), tag.end(), response.capability.begin() + 16);
        }
        if (send(peer, &response, sizeof(response), MSG_NOSIGNAL) != sizeof(response)) _exit(7);
      };
      reply(true);
      if (!reflect_client_proof) reply(false);
      close(peer); close(listener); _exit(0);
    }
    close(listener); int status = 0; bool reaped = false;
    try {
      json capability = {{"id", uint64_t(1)}, {"capability", encode_bytes(endpoint + secret)}};
      bool refused = false;
      try {
        native_delegation_reservation_channel channel(capability);
        check(!reflect_client_proof && channel.inspect().at("held"), "channel_auth_valid_exchange");
      } catch (const error &e) { refused = std::string_view(e.what()) == "forbidden"; }
      check(refused == reflect_client_proof, "channel_accepted_reflected_client_proof");
      check(waitpid(server, &status, 0) == server, "channel_auth_wait"); reaped = true;
      check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "channel_auth_server_failed");
    } catch (...) { if (!reaped) { kill(server, SIGKILL); waitpid(server, nullptr, 0); } throw; }
  }
  std::cout << "PASS CHANNEL/independent-client-server-proofs-and-client-packet-lifetime\n";
}
static void reservation_channel_suite(const fs::path &base, bool required) {
  auto root = native_file::root(base);
  auto file = root.open("owned");
  native_delegation_owner owner;
  auto id = owner.acquire(file, 5000, 5000);
  if (!id) { check(!required, "required_channel_provider_unavailable"); return; }
  { auto other = root.open("channel-other", false, true, true); other.write(0, "other"); }
  auto other_file = root.open("channel-other");
  auto other_id = owner.acquire(other_file, 5000, 5000);
  check(other_id != 0, "channel_other_acquire");
  auto other_capability = owner.reservation_capability(other_id);
  auto capability = owner.reservation_capability(id);
  check(other_capability.at("capability") != capability.at("capability"), "record_capabilities_not_unique");
  check(owner.reservation_capability(id) == capability, "capability_retry_rotated_secret");
  auto rejected = [&](const std::function<void()> &operation, std::string_view code) {
    bool denied = false;
    try { operation(); } catch (const error &e) { denied = std::string_view(e.what()) == code; }
    check(denied, "reservation_channel_wrong_error");
  };
  auto forged = capability;
  auto encoded = forged.at("capability").get<std::string>();
  encoded.back() = encoded.back() == '0' ? '1' : '0'; forged["capability"] = encoded;
  rejected([&] { native_delegation_reservation_channel denied(forged); }, "forbidden");
  forged = capability; forged["id"] = other_id;
  rejected([&] { native_delegation_reservation_channel denied(forged); }, "forbidden");
  owner.release(other_id);
  forged = capability; forged["capability"] = "00";
  rejected([&] { native_delegation_reservation_channel denied(forged); }, "invalid_request");
  native_delegation_reservation_channel first(capability), second(capability);
  check(first.inspect().at("held") && second.inspect().at("reservations") == 0, "channel_bind_not_live");
  auto token = first.reserve().at("reservation").get<uint64_t>();
  rejected([&] { second.complete(token, true); }, "stale_handle");
  rejected([&] { owner.complete(id, token, true); }, "stale_handle");
  auto expiry = first.inspect().at("lease_expires_ms");
  check(first.complete(token, false).at("lease_expires_ms") == expiry, "channel_cancel_renewed");
  rejected([&] { first.complete(token, true); }, "stale_handle");
  std::vector<uint64_t> tokens;
  for (int i = 0; i < 32; ++i) tokens.push_back(first.reserve().at("reservation"));
  rejected([&] { second.reserve(); }, "operation_limit");
  for (auto value : tokens) first.complete(value, false);
  check(second.inspect().at("reservations") == 0, "channel_capacity_not_shared");

  // Exercise the capability boundary with raw private packets. The limited
  // public API alone would not prove that a compromised peer cannot release.
  struct packet {
    uint32_t magic = 0x54434434, op = 0, native_flags = 0, reserved = 0;
    uint64_t id = 0;
    int64_t period = 0, remaining = 0;
    uint64_t reservation = 0;
    std::array<char, 32> capability{};
  };
  static_assert(sizeof(packet) == 80);
  int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  check(fd >= 0, "channel_raw_socket");
  try {
    auto value = decode_bytes(capability.at("capability").get<std::string>());
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    auto name = "taucloud-nfs-" + encode_bytes(std::string_view(value).substr(0, 16));
    std::memcpy(address.sun_path + 1, name.data(), name.size());
    check(connect(fd, reinterpret_cast<sockaddr *>(&address), offsetof(sockaddr_un, sun_path) + 1 + name.size()) == 0,
        "channel_raw_connect");
    auto exchange = [&](packet request) {
      check(send(fd, &request, sizeof(request), MSG_NOSIGNAL) == sizeof(request), "channel_raw_send");
      pollfd p{fd, POLLIN, 0};
      check(poll(&p, 1, 1500) > 0, "channel_raw_reply_timeout");
      packet response;
      check(recv(fd, &response, sizeof(response), 0) == sizeof(response), "channel_raw_reply_size");
      return response;
    };
    packet request; request.op = 11; request.id = id;
    auto nonce = decode_bytes(random_hex(16));
    auto tag = decode_bytes(mac(std::string_view(value).substr(16),
        "TCD4-client:" + value.substr(0, 16) + std::to_string(id) + ":" + nonce).substr(0, 32));
    std::copy(nonce.begin(), nonce.end(), request.capability.begin());
    std::copy(tag.begin(), tag.end(), request.capability.begin() + 16);
    auto bound = exchange(request);
    auto expected_tag = decode_bytes(mac(std::string_view(value).substr(16),
        "TCD4-server:" + value.substr(0, 16) + std::to_string(id) + ":" + nonce).substr(0, 32));
    check(bound.op == 11 && std::string(bound.capability.data(), bound.capability.size()) == nonce + expected_tag,
        "channel_raw_bind_mutual_proof");
    for (uint32_t op : {1u, 2u, 4u, 5u, 6u, 10u, 11u, 12u, 13u, 14u, 15u}) {
      request = packet(); request.op = op; request.id = id;
      check((exchange(request).op >> 16) == 6, "limited_channel_accepted_privileged_operation");
    }
    request = packet(); request.op = 3; request.id = id + 1;
    check((exchange(request).op >> 16) == 6, "limited_channel_escaped_record_binding");
  } catch (...) { close(fd); throw; }
  close(fd);
  check(owner.inspect(id).at("held"), "forged_channel_request_released_guard");

  // EOF consumes only this controller's tokens, retaining a full lease. A
  // sibling controller's reservation remains live and cannot be stolen.
  auto sibling = second.reserve().at("reservation").get<uint64_t>();
  auto disconnected_at = monotonic_ms();
  {
    native_delegation_reservation_channel disconnected(capability);
    disconnected.reserve();
    disconnected_at = monotonic_ms();
  }
  auto deadline = std::chrono::steady_clock::now() + 1s;
  json observed;
  do {
    observed = owner.inspect(id);
    if (observed.at("reservations") == 1) break;
    std::this_thread::sleep_for(5ms);
  } while (std::chrono::steady_clock::now() < deadline);
  check(observed.at("reservations") == 1 && observed.at("lease_expires_ms").get<int64_t>() >= disconnected_at + 5000,
      "channel_eof_stole_sibling_or_dropped_lease");
  second.complete(sibling, false);
  owner.release(id);
  rejected([&] { first.inspect(); }, "delegation_owner_lost");
  rejected([&] { native_delegation_reservation_channel stale(capability); }, "forbidden");
  file = native_file();
  std::cout << "PASS " << base << " CHANNEL/capability-binding-limited-operations-token-ownership-EOF\n";

  // A stopped file worker cannot process its primary IPC channel. Another
  // process still receives ACKs directly from the independent owner.
  int ready[2]; check(pipe2(ready, O_CLOEXEC) == 0, "channel_pause_pipe");
  auto worker = fork(); check(worker >= 0, "channel_pause_fork");
  if (!worker) {
    close(ready[0]);
    try {
      auto f = root.open("owned"); native_delegation_owner keeper;
      auto owned = keeper.acquire(f, 5000, 1000);
      if (!owned) _exit(2);
      auto data = keeper.reservation_capability(owned).dump();
      if (write(ready[1], data.data(), data.size()) != static_cast<ssize_t>(data.size())) _exit(3);
      raise(SIGSTOP);
      for (;;) pause();
    } catch (...) { _exit(4); }
  }
  close(ready[1]); int status = 0; bool reaped = false;
  try {
    pollfd p{ready[0], POLLIN, 0}; std::array<char, 256> data{};
    check(poll(&p, 1, 3000) > 0, "channel_pause_missing_capability");
    auto count = read(ready[0], data.data(), data.size()); close(ready[0]); ready[0] = -1;
    check(count > 0, "channel_pause_empty_capability");
    check(waitpid(worker, &status, WUNTRACED) == worker && WIFSTOPPED(status), "file_worker_not_stopped");
    native_delegation_reservation_channel independent(json::parse(std::string(data.data(), count)));
    auto pending = independent.reserve().at("reservation").get<uint64_t>();
    std::this_thread::sleep_for(1200ms);
    auto held = independent.inspect();
    check(held.at("held") && held.at("lease_remaining_ms") == 0 && held.at("reservations") == 1,
        "stopped_worker_request_expired");
    auto completed_at = monotonic_ms();
    check(independent.complete(pending, true).at("lease_expires_ms").get<int64_t>() >= completed_at + 5000,
        "stopped_worker_completion_not_acknowledged");
    independent.reserve();
    check(kill(worker, SIGKILL) == 0 && waitpid(worker, &status, 0) == worker && WIFSIGNALED(status),
        "stopped_worker_not_killed"); reaped = true;
    auto died_at = std::chrono::steady_clock::now();
    // Controller death closes its exported capabilities and retains all
    // outstanding work conservatively; stale channels cannot keep renewing.
    std::this_thread::sleep_for(50ms);
    rejected([&] { independent.inspect(); }, "delegation_owner_lost");
    int writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer < 0 && errno == EWOULDBLOCK, "channel_worker_death_released_early");
    do {
      std::this_thread::sleep_for(20ms);
      writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    } while (writer < 0 && errno == EWOULDBLOCK && std::chrono::steady_clock::now() - died_at < 7s);
    check(writer >= 0 && std::chrono::steady_clock::now() - died_at >= 4500ms,
        "channel_worker_death_not_bounded_full_lease"); close(writer);
  } catch (...) {
    if (ready[0] >= 0) close(ready[0]);
    if (!reaped) { kill(worker, SIGKILL); waitpid(worker, nullptr, 0); }
    throw;
  }
  std::cout << "PASS " << base << " CHANNEL/SIGSTOP-file-worker-independent-ACK-and-SIGKILL-retention\n";
}
static void nonblocking_owner_suite(const fs::path &base, bool required) {
  auto root = native_file::root(base);
  auto file = root.open("owned");
  native_delegation_owner owner;
  auto id = owner.acquire(file, 5000, 5000);
  if (!id) { check(!required, "required_async_owner_unavailable"); return; }
  using reservation_channel = native_delegation_reservation_channel;
  auto capability = owner.reservation_capability(id);
  reservation_channel channel(capability, reservation_channel::mode::nonblocking);
  auto result = [&] {
    for (;;) {
      if (auto ack = channel.poll()) return *ack;
      std::this_thread::sleep_for(1ms);
    }
  };
  check(result().at("held"), "async_owner_handshake");
  channel.begin_reserve(); auto token = result().at("reservation").get<uint64_t>();
  auto pid = static_cast<pid_t>(owner.process_id()); bool stopped = false;
  auto stop = [&] {
    check(kill(pid, SIGSTOP) == 0, "async_owner_stop"); stopped = true;
    int status = 0;
    check(waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status), "async_owner_not_stopped");
  };
  auto resume = [&] { check(kill(pid, SIGCONT) == 0, "async_owner_resume"); stopped = false; };
  try {
    stop();
    auto started = monotonic_ms();
    channel.begin_complete(token, true);
    for (int i = 0; i < 20; ++i) check(!channel.poll(), "async_stopped_owner_blocked");
    check(monotonic_ms() - started < 500, "async_stopped_owner_delayed_caller");
    resume();
    auto completed = result();
    check(completed.at("reservations") == 0 && completed.at("lease_expires_ms").get<int64_t>() >= started + 5000,
        "async_owner_completion_lost_full_lease");

    channel.begin_reserve(); check(result().at("reservation").get<uint64_t>() != token, "async_owner_reused_token");
    stop(); channel.begin_inspect();
    bool timed_out = false;
    try { result(); } catch (const error &e) { timed_out = std::string_view(e.what()) == "delegation_owner_lost"; }
    check(timed_out, "async_stopped_owner_not_timed_out");
    auto resumed = monotonic_ms(); resume();
    json retained;
    do {
      retained = owner.inspect(id);
      if (retained.at("reservations") == 0) break;
      std::this_thread::sleep_for(5ms);
    } while (monotonic_ms() < resumed + 1000);
    check(retained.at("held") && retained.at("reservations") == 0 &&
        retained.at("lease_expires_ms").get<int64_t>() >= resumed + 5000,
        "async_timeout_released_uncertain_token");
    int writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer < 0 && errno == EWOULDBLOCK, "async_timeout_lost_native_guard");
    owner.release(id);
    writer = open((base / "owned").c_str(), O_WRONLY | O_NONBLOCK);
    check(writer >= 0, "async_release_still_blocks_writer"); close(writer);
  } catch (...) { if (stopped) kill(pid, SIGCONT); throw; }
  std::cout << "PASS " << base << " CHANNEL/nonblocking-SIGSTOP-timeout-uncertain-token-native-retention\n";
}
static void file_domain_suite(const fs::path &base) {
  initialize(base / "state", 38443);
  auto cfg = config::load(base / "state"); cfg.nfs_lease_seconds = 5;
  fs::create_directories(base / "root");
  auto root = inspect_root(base / "root"); root["id"] = "root"; root["worker"] = "file";
  json space = {{"id", "space"}, {"root", "root"}, {"path", "space"},
      {"owner", "alice"}, {"group", ""}, {"quota", 1048576}};
  auto ctx = [](std::string who = "nfs") { return call_context{who, random_hex(16), now() + 30000, {}}; };
  auto store = std::make_unique<file_store>(cfg, "file", random_hex(16));
  space = store->dispatch("provision", {{"root", root}, {"space", space}}, ctx("identity"));
  auto signing = read_json(cfg.state / "ipc-keys.json").at("identity").get<std::string>();
  auto export_id = random_hex(16), client = random_hex(16);
  int64_t epoch = 2;
  auto grant = [&] {
    json g = {{"actor", "alice"}, {"root", root}, {"space", space}, {"path", ""},
        {"write", true}, {"share", "nfs"}, {"epoch", epoch}, {"expires", now() + 2000},
        {"protocol", "nfs"}, {"nfs_uid", 1000}, {"nfs_gid", 1000}, {"groups", {"unix"}},
        {"export", {{"uuid", export_id}, {"uids", {{"1000", "alice"}}}, {"gids", {{"1000", "unix"}}}}}};
    g["signature"] = mac(signing, g.dump()); return g;
  };
  auto nfs = [&](std::string op, std::string handle, json b = json::object()) {
    b["op"] = op; b["handle"] = handle; b["grant"] = grant(); b["request_id"] = random_hex(16);
    return store->dispatch("nfs_file", b, ctx());
  };
  { auto native = native_file::root(base / "root"); auto f = native.open("space/cached", false, true, true); f.write(0, "data"); }
  auto dir = nfs("root", "").at("handle").get<std::string>();
  auto fh = nfs("lookup", dir, {{"name", "cached"}}).at("handle").get<std::string>();
  auto control = [&](std::string op, json cookie = "", int remaining = 3000) {
    return json{{"op", op}, {"cookie", cookie}, {"handle", fh}, {"client", client},
        {"remaining_ms", remaining}, {"grant", grant()}};
  };
  auto call = [&](std::string op, json cookie = "", int remaining = 3000) {
    return store->dispatch("nfs_delegation", control(op, cookie, remaining), ctx());
  };
  auto gated = control("acquire"); gated["wire"] = true;
  check(!store->dispatch("nfs_delegation", gated, ctx()).at("granted"), "production_handout_gate_bypassed");
  auto d = call("acquire");
  check(d.at("granted") && d.at("provider") == "independent-owner" && d.at("owner_available"), "domain_owner_not_used");
  auto cookie = d.at("cookie");
  check(call("renew", cookie).at("granted"), "domain_owner_renew_failed");
  check(nfs("lookup", dir, {{"name", "cached"}}).at("handle") == fh, "domain_lookup_lost_incarnation");
  auto listed = nfs("list", dir).at("entries");
  check(listed.size() == 1 && listed.at(0).at("handle") == fh, "domain_list_lost_incarnation");
  check(call("poll", cookie).at("state") == "active", "domain_namespace_read_recalled_delegation");
  auto native_recall_started = monotonic_ms();
  int writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "domain_native_conflict_not_blocked");
  // Let the independent owner observe the native break before the file
  // authority polls. Importing it must not start a fresh five-second interval.
  std::this_thread::sleep_for(800ms);
  auto limit = std::chrono::steady_clock::now() + 1s;
  do { d = call("poll", cookie); if (d.at("state") == "recalling") break; std::this_thread::sleep_for(5ms); }
  while (std::chrono::steady_clock::now() < limit);
  check(d.at("state") == "recalling", "domain_native_recall_not_imported");
  check(d.at("recall_deadline_ms").get<int64_t>() <= native_recall_started + 5500,
      "domain_restarted_native_recall_deadline");
  check(d.at("protected_until_ms").get<int64_t>() ==
      std::min(d.at("lease_expires_ms").get<int64_t>(), d.at("recall_deadline_ms").get<int64_t>()),
      "domain_overstated_native_protection");
  check(call("return", cookie).at("state") == "returned", "domain_return_failed"); call("forget", cookie);
  d = call("acquire", "", 1000); check(d.at("granted"), "domain_cleanup_acquire"); cookie = d.at("cookie");
  auto cleanup = control("retain", cookie, 5000);
  cleanup["grant"]["expires"] = now() - 1; cleanup["grant"].erase("signature");
  cleanup["grant"]["signature"] = mac(signing, cleanup.at("grant").dump());
  d = store->dispatch("nfs_delegation", cleanup, ctx());
  check(d.at("granted") && d.at("state") == "recalling", "domain_cleanup_retention_failed");
  auto recall_remaining = d.at("recall_remaining_ms").get<int64_t>();
  std::this_thread::sleep_for(1200ms);
  d = store->dispatch("nfs_delegation", cleanup, ctx());
  check(d.at("granted") && d.at("recall_remaining_ms").get<int64_t>() < recall_remaining,
      "domain_cleanup_extended_recall");
  writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "domain_cleanup_lost_native_protection");
  cleanup["op"] = "return";
  check(store->dispatch("nfs_delegation", cleanup, ctx()).at("state") == "returned", "domain_cleanup_return_failed");
  call("forget", cookie);
  std::cout << "PASS " << base << " FILE-DOMAIN/expired-authority-coherence-retention\n";
  auto reservation = [&](std::string op, uint64_t token) {
    auto request = control(op, cookie); request["reservation"] = token;
    return store->dispatch("nfs_delegation", request, ctx());
  };
  auto rejected = [&](json request, std::string_view expected) {
    bool refused = false;
    try { store->dispatch("nfs_delegation", request, ctx()); }
    catch (const error &e) { refused = std::string_view(e.what()) == expected; }
    check(refused, "domain_reservation_wrong_error");
  };
  auto rejected_token = [&](std::string op, uint64_t token, std::string_view expected) {
    auto request = control(op, cookie); request["reservation"] = token; rejected(request, expected);
  };
  d = call("acquire", "", 1000); check(d.at("granted"), "domain_reservation_acquire"); cookie = d.at("cookie");
  auto expiry = d.at("lease_expires_ms");
  check(reservation("reserve", 10).at("reservations") == 1, "domain_first_reservation");
  check(reservation("reserve", 20).at("reservations") == 2, "domain_second_reservation");
  d = reservation("reserve", 10);
  check(d.at("reservations") == 2 && d.at("lease_expires_ms") == expiry, "domain_retry_renewed_or_duplicated");
  for (auto invalid : {json(0), json(-1), json(1.5), json("1")}) {
    auto request = control("reserve", cookie); request["reservation"] = invalid;
    rejected(request, "invalid_request");
  }
  for (auto field : {"client", "handle", "actor", "root", "export"}) {
    auto request = control("reserve", cookie); request["reservation"] = 30;
    std::string name(field);
    if (name == "client") request[name] = random_hex(16);
    else if (name == "handle") request[name] = dir;
    else {
      if (name == "actor") request["grant"][name] = "bob";
      if (name == "root") request["grant"][name]["id"] = "another-root";
      if (name == "export") request["grant"][name]["uuid"] = random_hex(16);
      request["grant"].erase("signature");
      request["grant"]["signature"] = mac(signing, request.at("grant").dump());
    }
    rejected(request, "forbidden");
    request["op"] = "channel";
    rejected(request, "forbidden");
  }
  std::this_thread::sleep_for(1200ms);
  d = call("poll", cookie);
  check(d.at("granted") && d.at("reservations") == 2 && d.at("lease_remaining_ms") == 0,
      "domain_pending_request_expired");
  check(d.at("protected_until_ms").get<int64_t>() == INT64_MAX, "domain_pending_protection_not_reported");
  rejected_token("reserve", 30, "stale_handle");
  // The signed cleanup capability remains usable after data grant expiry.
  cleanup = control("complete", cookie); cleanup["reservation"] = 10;
  cleanup["grant"]["expires"] = now() - 1; cleanup["grant"].erase("signature");
  cleanup["grant"]["signature"] = mac(signing, cleanup.at("grant").dump());
  auto completed_at = monotonic_ms();
  d = store->dispatch("nfs_delegation", cleanup, ctx());
  check(d.at("granted") && d.at("reservations") == 1 &&
      d.at("lease_expires_ms").get<int64_t>() >= completed_at + 5000, "domain_completion_missing_full_lease");
  expiry = d.at("lease_expires_ms");
  rejected_token("complete", 10, "stale_handle");
  rejected_token("reserve", 10, "stale_handle");
  rejected_token("cancel", 99, "stale_handle");
  d = reservation("cancel", 20);
  check(d.at("reservations") == 0 && d.at("lease_expires_ms") == expiry, "domain_cancel_renewed");
  check(call("return", cookie).at("state") == "returned", "domain_reserved_return"); call("forget", cookie);

  d = call("acquire", "", 5000); check(d.at("granted"), "domain_capacity_acquire"); cookie = d.at("cookie");
  for (uint64_t i = 1; i <= 32; ++i)
    check(reservation("reserve", i).at("reservations") == i, "domain_capacity_count");
  rejected_token("reserve", 33, "operation_limit");
  check(reservation("cancel", 1).at("reservations") == 31, "domain_capacity_cancel");
  check(reservation("reserve", 33).at("reservations") == 32, "domain_capacity_reuse");
  d = call("return", cookie);
  check(d.at("state") == "returned" && d.at("reservations") == 0, "domain_return_leaked_reservations");
  rejected_token("complete", 2, "stale_handle"); call("forget", cookie);

  d = call("acquire", "", 300); check(d.at("granted"), "domain_cancel_acquire"); cookie = d.at("cookie");
  reservation("reserve", 1); std::this_thread::sleep_for(500ms);
  d = reservation("cancel", 1);
  check(!d.at("granted") && d.at("state") == "expired" && d.at("reservations") == 0,
      "domain_last_cancel_not_expired");
  writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "domain_cancel_kept_native_guard"); close(writer); call("forget", cookie);

  d = call("acquire", "", 400); check(d.at("granted"), "domain_channel_acquire"); cookie = d.at("cookie");
  auto capability = call("channel", cookie).at("reservation_capability");
  check(call("channel", cookie).at("reservation_capability") == capability, "domain_channel_retry_changed_capability");
  check(!call("poll", cookie).contains("reservation_capability"), "domain_poll_leaked_capability");
  {
    native_delegation_reservation_channel direct(capability);
    auto token = direct.reserve().at("reservation").get<uint64_t>();
    std::this_thread::sleep_for(600ms); // No file-domain call observes the reservation until after its old lease.
    d = call("poll", cookie);
    check(d.at("granted") && d.at("reservations") == 1 && d.at("lease_remaining_ms") == 0,
        "domain_stale_snapshot_released_independent_reservation");
    check(nfs("read", fh, {{"offset", 0}, {"count", 4}}).at("data") == encode_bytes("data"),
        "domain_channel_pending_read");
    auto confirmed = direct.complete(token, true);
    d = call("poll", cookie);
    check(d.at("granted") && d.at("reservations") == 0 &&
        d.at("lease_expires_ms") == confirmed.at("lease_expires_ms"), "domain_independent_extension_not_imported");
    token = direct.reserve().at("reservation").get<uint64_t>();
    check(reservation("reserve", 10000).at("reservations") == 2, "domain_mixed_controller_count");
    check(reservation("cancel", 10000).at("reservations") == 1, "domain_primary_cancel_discarded_side_token");
    direct.complete(token, true);
    check(call("poll", cookie).at("reservations") == 0, "domain_side_completion_not_imported");
    token = direct.reserve().at("reservation").get<uint64_t>();
    auto fixed_recall = call("recall", cookie).at("recall_deadline_ms");
    check(direct.inspect().at("recall_deadline_ms") == fixed_recall, "domain_recall_cutoff_not_forwarded");
    direct.complete(token, true);
    d = call("poll", cookie);
    check(d.at("state") == "recalling" && d.at("recall_deadline_ms") == fixed_recall,
        "domain_independent_completion_extended_recall");
    direct.reserve();
    check(call("return", cookie).at("reservations") == 0, "domain_return_kept_side_reservation");
    bool disconnected = false;
    try { direct.inspect(); } catch (const error &) { disconnected = true; }
    check(disconnected, "domain_return_kept_side_channel");
  }
  bool invalidated = false;
  try { native_delegation_reservation_channel stale_channel(capability); }
  catch (const error &) { invalidated = true; }
  check(invalidated, "domain_return_kept_capability"); call("forget", cookie);

  d = call("acquire", "", 400); check(d.at("granted"), "domain_channel_cancel_acquire"); cookie = d.at("cookie");
  {
    native_delegation_reservation_channel direct(call("channel", cookie).at("reservation_capability"));
    auto token = direct.reserve().at("reservation").get<uint64_t>();
    std::this_thread::sleep_for(600ms);
    direct.complete(token, false);
    d = call("poll", cookie);
    check(!d.at("granted") && d.at("state") == "expired" && d.at("reservations") == 0,
        "domain_independent_cancel_not_expired");
  }
  writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "domain_independent_cancel_kept_native_guard"); close(writer); call("forget", cookie);

  d = call("acquire", "", 400); check(d.at("granted"), "domain_channel_eof_acquire"); cookie = d.at("cookie");
  auto eof_at = monotonic_ms();
  {
    native_delegation_reservation_channel direct(call("channel", cookie).at("reservation_capability"));
    direct.reserve(); std::this_thread::sleep_for(600ms); eof_at = monotonic_ms();
  }
  limit = std::chrono::steady_clock::now() + 1s;
  do { d = call("poll", cookie); if (d.at("reservations") == 0) break; std::this_thread::sleep_for(5ms); }
  while (std::chrono::steady_clock::now() < limit);
  check(d.at("granted") && d.at("reservations") == 0 && d.at("lease_expires_ms").get<int64_t>() >= eof_at + 5000,
      "domain_independent_eof_extension_not_imported");
  call("return", cookie); call("forget", cookie);
  std::cout << "PASS " << base << " FILE-DOMAIN/independent-channel-publication-expiry-completion-EOF-return\n";

  d = call("acquire", "", 1000); check(d.at("granted"), "domain_revocation_acquire"); cookie = d.at("cookie");
  reservation("reserve", 1);
  cleanup = control("complete", cookie); cleanup["reservation"] = 1;
  store->dispatch("revoke", {{"epoch", ++epoch}}, ctx("identity"));
  auto denied = cleanup; denied["op"] = "read"; denied["offset"] = 0; denied["count"] = 4;
  bool denied_io = false;
  try { store->dispatch("nfs_file", denied, ctx()); }
  catch (const error &e) { denied_io = std::string_view(e.what()) == "policy_revoked"; }
  check(denied_io, "domain_revoked_cleanup_authorized_data");
  auto deadline = call("poll", cookie).at("recall_deadline_ms");
  auto revoked_channel_request = cleanup; revoked_channel_request["op"] = "channel";
  {
    native_delegation_reservation_channel direct(
        store->dispatch("nfs_delegation", revoked_channel_request, ctx()).at("reservation_capability"));
    auto token = direct.reserve().at("reservation").get<uint64_t>();
    direct.complete(token, true);
    check(call("poll", cookie).at("recall_deadline_ms") == deadline, "domain_revoked_channel_extended_recall");
  }
  d = store->dispatch("nfs_delegation", cleanup, ctx());
  check(d.at("granted") && d.at("state") == "recalling" && d.at("reservations") == 0 &&
      d.at("recall_deadline_ms") == deadline, "domain_revoked_completion_changed_recall");
  call("return", cookie); call("forget", cookie);
  std::cout << "PASS " << base << " FILE-DOMAIN/reservation-binding-retry-completion-capacity-revocation\n";
  d = call("acquire", "", 5000); check(d.at("granted"), "domain_reacquire_failed"); cookie = d.at("cookie");
  auto before_recovery = call("poll", cookie);
  auto old_capability = call("channel", cookie).at("reservation_capability");
  auto journal_path = cfg.state / "file.nfs-delegations.json";
  auto journal = read_json(journal_path);
  check(journal.at("body").at("records").contains(cookie.get<std::string>()) &&
      equal(journal.at("signature").get<std::string>(), mac(signing, journal.at("body").dump())), "domain_journal_not_committed");
  struct stat journal_stat{};
  check(stat(journal_path.c_str(), &journal_stat) == 0 && (journal_stat.st_mode & 0777) == 0600,
      "domain_journal_not_private");
  store.reset();
  writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "domain_destruction_released_lease");
  store = std::make_unique<file_store>(cfg, "file", random_hex(16));
  auto recovered = call("poll", cookie);
  check(recovered.at("requires_revalidation") && !recovered.at("granted") && recovered.at("owner_available") &&
      recovered.at("lease_expires_ms") == before_recovery.at("lease_expires_ms"), "domain_recovery_changed_or_reauthorized_lease");
  rejected(control("channel", cookie), "delegation_revalidation_required");
  auto stale_authority = control("renew", cookie);
  stale_authority["grant"]["epoch"] = epoch - 1; stale_authority["grant"].erase("signature");
  stale_authority["grant"]["signature"] = mac(signing, stale_authority.at("grant").dump());
  rejected(stale_authority, "policy_revoked");
  for (auto field : {"actor", "space_object"}) {
    auto foreign = control("renew", cookie);
    if (std::string_view(field) == "actor") foreign["grant"]["actor"] = "bob";
    else foreign["grant"]["space"]["object"] = "replaced-space";
    foreign["grant"].erase("signature"); foreign["grant"]["signature"] = mac(signing, foreign.at("grant").dump());
    rejected(foreign, "forbidden");
  }
  check(nfs("read", fh, {{"offset", 0}, {"count", 4}}).at("data") == encode_bytes("data"),
      "domain_recovery_did_not_use_retained_descriptor");
  auto cutoff = call("poll", cookie).at("recall_deadline_ms");
  d = call("renew", cookie, 5000);
  check(d.at("granted") && !d.at("requires_revalidation") && d.at("recall_deadline_ms") == cutoff,
      "domain_fresh_revalidation_failed_or_extended_recall");
  check(call("channel", cookie).at("reservation_capability") != old_capability, "domain_recovery_reused_channel_secret");
  bool old_rejected = false;
  try { native_delegation_reservation_channel old(old_capability); } catch (const error &) { old_rejected = true; }
  check(old_rejected, "domain_recovery_left_old_channel_authority");
  store.reset(); store = std::make_unique<file_store>(cfg, "file", random_hex(16));
  check(call("poll", cookie).at("requires_revalidation") && call("poll", cookie).at("recall_deadline_ms") == cutoff,
      "domain_second_recovery_changed_recall");
  call("return", cookie); call("forget", cookie);
  writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer >= 0, "domain_recovered_return_kept_guard"); close(writer);
  std::cout << "PASS " << base << " FILE-DOMAIN/journal-private-recovery-fresh-authority-epoch-and-channel-fencing\n";
  store.reset();
  int ready[2]; check(pipe2(ready, O_CLOEXEC) == 0, "domain_crash_pipe");
  auto worker = fork(); check(worker >= 0, "domain_crash_fork");
  if (!worker) {
    close(ready[0]);
    try {
      store = std::make_unique<file_store>(cfg, "file", random_hex(16));
      dir = nfs("root", "").at("handle").get<std::string>();
      fh = nfs("lookup", dir, {{"name", "cached"}}).at("handle").get<std::string>();
      auto acquired = call("acquire", "", 300);
      cookie = acquired.at("cookie");
      if (reservation("reserve", 1).at("reservations") != 1) _exit(5);
      std::this_thread::sleep_for(500ms);
      if (!acquired.at("granted") || acquired.at("provider") != "independent-owner") _exit(2);
      char marker = 'R'; if (write(ready[1], &marker, 1) != 1) _exit(3);
      for (;;) pause();
    } catch (...) { _exit(4); }
  }
  close(ready[1]); pollfd notification{ready[0], POLLIN, 0}; char marker = 0;
  bool acknowledged = poll(&notification, 1, 5000) > 0 && read(ready[0], &marker, 1) == 1 && marker == 'R';
  close(ready[0]); kill(worker, SIGKILL); int status; waitpid(worker, &status, 0);
  check(acknowledged && WIFSIGNALED(status), "domain_worker_guard_not_acknowledged");
  journal = read_json(journal_path);
  check(journal.at("body").at("records").size() == 1, "domain_crash_record_missing");
  cookie = journal.at("body").at("records").begin().key();
  store = std::make_unique<file_store>(cfg, "file", random_hex(16));
  d = call("poll", cookie);
  check(d.at("requires_revalidation") && !d.at("granted") && d.at("reservations") == 0,
      "domain_crash_reused_old_authority_or_tokens");
  check(call("renew", cookie, 5000).at("granted"), "domain_crash_fresh_renew_failed");
  rejected_token("reserve", 1, "stale_handle");
  check(reservation("reserve", 2).at("reservations") == 1 && reservation("cancel", 2).at("reservations") == 0,
      "domain_crash_new_reservation_failed");
  writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "domain_worker_crash_lost_protection");
  auto started = std::chrono::steady_clock::now();
  do { std::this_thread::sleep_for(20ms); writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK); }
  while (writer < 0 && errno == EWOULDBLOCK && std::chrono::steady_clock::now() - started < 7s);
  check(writer >= 0 && std::chrono::steady_clock::now() - started > 4s, "domain_worker_crash_expiry"); close(writer);
  call("forget", cookie);
  store.reset();
  std::cout << "PASS " << base << " FILE-DOMAIN/owner-renew-recall-return-replacement-SIGKILL\n";
  for (unsigned point : {1u, 2u, 3u, 4u}) {
    worker = fork(); check(worker >= 0, "domain_boundary_fork");
    if (!worker) {
      try {
        store = std::make_unique<file_store>(cfg, "file", random_hex(16));
        if (point < 4) test_delegation_crash_point(point);
        auto acquired = call("acquire", "", 5000);
        if (!acquired.at("granted")) _exit(2);
        if (point == 4) { test_delegation_crash_point(4); call("return", acquired.at("cookie")); }
        _exit(3); // Every chosen boundary must stop inside the real file domain.
      } catch (...) { _exit(4); }
    }
    bool stopped = false, reaped = false;
    try {
      auto until = monotonic_ms() + 5000;
      while (monotonic_ms() < until) {
        auto result = waitpid(worker, &status, WUNTRACED | WNOHANG);
        if (result == worker) { stopped = WIFSTOPPED(status); reaped = !stopped; break; }
        std::this_thread::sleep_for(5ms);
      }
      check(stopped, "domain_crash_boundary_not_reached");
      auto stopped_at = monotonic_ms();
      journal = read_json(journal_path);
      auto records = journal.at("body").at("records");
      check(records.size() == 1, "domain_boundary_record_not_durable");
      cookie = records.begin().key();
      check(records.begin().value().at("intent").get<bool>() == (point <= 2) &&
          (records.begin().value().at("owner_id").get<uint64_t>() == 0) == (point <= 2),
          "domain_boundary_wrong_journal_phase");
      check(kill(worker, SIGKILL) == 0 && waitpid(worker, &status, 0) == worker && WIFSIGNALED(status),
          "domain_boundary_kill_failed"); reaped = true;
      store = std::make_unique<file_store>(cfg, "file", random_hex(16));
      if (point == 1) rejected(control("poll", cookie), "stale_handle");
      else if (point == 4) {
        check(call("poll", cookie).at("state") == "returned", "domain_release_intent_revived");
        call("forget", cookie);
      } else {
        d = call("poll", cookie);
        check(d.at("requires_revalidation") && d.at("owner_available") && !d.at("granted") &&
            d.at("lease_expires_ms").get<int64_t>() <= stopped_at + 5000,
            "domain_boundary_recovery_changed_lease_or_authority");
        writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
        check(writer < 0 && errno == EWOULDBLOCK, "domain_boundary_guard_lost");
        call("return", cookie); call("forget", cookie);
      }
      writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
      check(writer >= 0, "domain_boundary_cleanup_kept_guard"); close(writer);
      store.reset();
    } catch (...) { if (!reaped) { kill(worker, SIGKILL); waitpid(worker, nullptr, 0); } throw; }
  }
  std::cout << "PASS " << base << " FILE-DOMAIN/SIGKILL-intent-acquired-committed-and-return-intent-boundaries\n";
  journal = read_json(journal_path);
  auto corrupted = journal; corrupted["signature"] = std::string(64, '0');
  write_json(journal_path, corrupted);
  bool corrupt_rejected = false;
  try { store = std::make_unique<file_store>(cfg, "file", random_hex(16)); }
  catch (const error &e) { corrupt_rejected = std::string_view(e.what()) == "delegation_recovery_failed"; }
  check(corrupt_rejected, "domain_corrupt_journal_not_fenced");
  write_json(journal_path, journal); check(chmod(journal_path.c_str(), 0644) == 0, "domain_permission_fixture");
  corrupt_rejected = false;
  try { store = std::make_unique<file_store>(cfg, "file", random_hex(16)); }
  catch (const error &e) { corrupt_rejected = std::string_view(e.what()) == "delegation_recovery_failed"; }
  check(corrupt_rejected, "domain_public_capability_journal_accepted");
  check(chmod(journal_path.c_str(), 0600) == 0, "domain_permission_restore");
  store = std::make_unique<file_store>(cfg, "file", random_hex(16));
  check(read_json(journal_path).at("body").at("records").empty(), "domain_recovery_left_untracked_records");
  d = call("acquire", "", 300); check(d.at("granted"), "domain_late_restore_acquire"); cookie = d.at("cookie");
  store.reset(); std::this_thread::sleep_for(500ms);
  store = std::make_unique<file_store>(cfg, "file", random_hex(16));
  d = call("poll", cookie);
  check(!d.at("granted") && !d.at("requires_revalidation") && !d.at("owner_available"), "domain_dead_owner_revived");
  call("forget", cookie);
  d = call("acquire", "", 5000); check(d.at("granted"), "domain_stopped_owner_acquire"); cookie = d.at("cookie");
  journal = read_json(journal_path);
  auto process = journal.at("body").at("process");
  auto owner_pid = process.at("pid").get<pid_t>();
  check(process_info(owner_pid).at("birth") == process.at("birth"), "domain_stopped_owner_identity");
  check(kill(owner_pid, SIGSTOP) == 0, "domain_stopped_owner_signal");
  siginfo_t stopped_owner{};
  check(waitid(P_PID, owner_pid, &stopped_owner, WSTOPPED | WNOWAIT) == 0 && stopped_owner.si_pid == owner_pid,
      "domain_stopped_owner_not_confirmed");
  bool paused = true;
  try {
    store.reset();
    bool unavailable = false;
    try { store = std::make_unique<file_store>(cfg, "file", random_hex(16)); }
    catch (const error &e) { unavailable = std::string_view(e.what()) == "delegation_recovery_failed"; }
    check(unavailable && read_json(journal_path) == journal, "domain_unobservable_owner_not_fenced");
    check(kill(owner_pid, SIGCONT) == 0, "domain_stopped_owner_resume"); paused = false;
    store = std::make_unique<file_store>(cfg, "file", random_hex(16));
    check(call("poll", cookie).at("requires_revalidation"), "domain_resumed_owner_not_restored");
    call("return", cookie); call("forget", cookie);
  } catch (...) { if (paused) kill(owner_pid, SIGCONT); throw; }
  d = call("acquire", "", 5000); check(d.at("granted"), "domain_io_failure_acquire"); cookie = d.at("cookie");
  auto saved_journal = journal_path; saved_journal += ".saved";
  fs::rename(journal_path, saved_journal); fs::create_directory(journal_path);
  bool write_failed = false;
  try { call("return", cookie); } catch (const error &) { write_failed = true; }
  check(write_failed, "domain_journal_write_failure_not_reported");
  rejected(control("poll", cookie), "delegation_recovery_failed");
  bool io_fenced = false;
  try { nfs("read", fh, {{"offset", 0}, {"count", 4}}); }
  catch (const error &e) { io_fenced = std::string_view(e.what()) == "delegation_recovery_failed"; }
  check(io_fenced, "domain_journal_failure_still_served_io");
  writer = open((base / "root/space/cached").c_str(), O_WRONLY | O_NONBLOCK);
  check(writer < 0 && errno == EWOULDBLOCK, "domain_failed_return_released_guard");
  fs::remove(journal_path); fs::rename(saved_journal, journal_path);
  store.reset(); store = std::make_unique<file_store>(cfg, "file", random_hex(16));
  check(call("poll", cookie).at("requires_revalidation"), "domain_write_failure_cannot_recover");
  call("return", cookie); call("forget", cookie);
  store.reset();
  std::cout << "PASS " << base << " FILE-DOMAIN/corrupt-public-failed-journal-and-unobservable-owner-fencing\n";
}
int nfs_delegation_protocol_suite(bool require_native);
int native_delegation_channel_suite();
int main(int argc, char **argv) {
  if (auto result = native_delegation_owner::entry(argc, argv); result >= 0) return result;
  bool guest = getpid() == 1;
  int code = 1;
  fs::path base;
  try {
    if (guest) {
      auto mounted = mount("proc", "/proc", "proc", 0, nullptr);
      struct statfs proc{};
      check((mounted == 0 || errno == EBUSY) && statfs("/proc", &proc) == 0 && proc.f_type == PROC_SUPER_MAGIC,
          "mount_proc");
      check(mount("devtmpfs", "/dev", "devtmpfs", 0, nullptr) == 0, "mount_dev");
      check(mount("tmpfs", "/tmp", "tmpfs", 0, nullptr) == 0, "mount_tmpfs");
      check(mount("/dev/vda", "/disk", "ext4", 0, nullptr) == 0, "mount_ext4");
      reservation_channel_authentication_suite();
      checks += native_delegation_channel_suite();
      suite("/tmp/delegation", true);
      owner_suite("/tmp/delegation", true);
      reservation_channel_suite("/tmp/delegation", true);
      nonblocking_owner_suite("/tmp/delegation", true);
      file_domain_suite("/tmp/domain");
      suite("/disk/delegation", true);
      owner_suite("/disk/delegation", true);
      reservation_channel_suite("/disk/delegation", true);
      nonblocking_owner_suite("/disk/delegation", true);
      file_domain_suite("/disk/domain");
      check(nfs_delegation_protocol_suite(true) == 0, "native_protocol_routing");
    } else {
      reservation_channel_authentication_suite();
      checks += native_delegation_channel_suite();
      if (argc > 1 && std::string_view(argv[1]) == "--channel-only") return 0;
      base = fs::temp_directory_path() / ("tc-native-delegation-" + random_hex(6));
      suite(base, argc > 1 && std::string_view(argv[1]) == "--require");
      owner_suite(base, argc > 1 && std::string_view(argv[1]) == "--require");
      reservation_channel_suite(base, argc > 1 && std::string_view(argv[1]) == "--require");
      nonblocking_owner_suite(base, argc > 1 && std::string_view(argv[1]) == "--require");
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
