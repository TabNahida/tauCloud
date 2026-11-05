#include <taucloud/files.hpp>
#include <taucloud/database.hpp>
#include <fstream>
#include <iostream>
#include <future>
#include <thread>
#include <source_location>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/resource.h>
#endif
using namespace tc;
static int checks = 0;
void check(bool value, std::source_location loc = std::source_location::current()) {
  if (!value) std::cerr << "failed_line=" << loc.line() << '\n';
  require(value, "test_failed");
  ++checks;
}
template <class F> void rejects(F call, const std::string &code,
                               std::source_location loc = std::source_location::current()) {
  try {
    call();
    throw error("rejection_expected");
  } catch (const error &e) {
    if (code != e.what())
      std::cerr << "expected " << code << ", got " << e.what() << '\n';
    check(code == e.what(), loc);
  }
}
int main() {
  auto temp = fs::temp_directory_path() / ("tc2-unit-" + random_hex(6));
  try {
    auto state = temp / "state", root_path = temp / "root";
    fs::create_directories(root_path);
    {
      auto directory = native_file::root(root_path);
      auto file = directory.open("cache-exclusion", false, true, true);
      file.write(0, "old"); file.flush();
#ifdef _WIN32
      // RW remains available for ordinary data caching, but it must not be
      // represented as a Linux-style namespace-protecting delegation.
      check(!file.delegation_guard(true));
#endif
      // The future is destroyed after the guard, so a failed assertion still
      // releases the lease before waiting for a blocked external open.
      std::future<std::string> external;
      auto guard = file.cache_guard(true);
      check(bool(guard) && !guard->breaking());
      check(directory.metadata("cache-exclusion").at("object") == file.info().at("object"));
      check(!guard->breaking());
      check(!file.cache_guard(true));
      auto retained = file.retain();
      check(!retained.cache_guard(false));
      rejects([&] { directory.open("cache-exclusion"); }, "locked");
      check(guard->breaking());
      external = std::async(std::launch::async, [&] {
#ifdef _WIN32
        // MSVC fstream does not share DELETE. Use an ordinary blocking native
        // open with the same share flags as real protocol-backed handles.
        auto handle = CreateFileW((root_path / "cache-exclusion").c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        require(handle != INVALID_HANDLE_VALUE, "external_open_failed");
        std::string result(3, '\0');
        DWORD size = 0;
        auto ok = ReadFile(handle, result.data(), 3, &size, nullptr);
        CloseHandle(handle);
        require(ok && size == 3, "external_read_failed");
        return result;
#else
        std::ifstream stream(root_path / "cache-exclusion", std::ios::binary);
        require(bool(stream), "external_open_failed");
        return std::string(std::istreambuf_iterator<char>(stream), {});
#endif
      });
      check(external.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout);
      // A protocol holder must be able to flush while contenders are blocked.
      file.write(0, "new"); file.flush();
      guard->release(); guard->release();
      check(external.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
      check(external.get() == "new");
      check(!guard->breaking());
      guard.reset(); retained = native_file(); file = native_file();

      auto reader = directory.open("cache-exclusion");
      {
        check(!reader.writable());
        auto strong_read_guard = reader.cache_guard(true);
        check(bool(strong_read_guard));
        rejects([&] { directory.open("cache-exclusion", false, false, true); }, "locked");
        check(strong_read_guard->breaking() && reader.read(0, 3) == "new");
        strong_read_guard->release();
        check(!reader.writable());
      }
#ifdef _WIN32
      // Native Windows R breaks do not block a writer, so they cannot promise
      // this primitive's delayed admission guarantee.
      check(!reader.cache_guard(false));
#else
      auto read_guard = reader.cache_guard(false);
      check(bool(read_guard) && !read_guard->breaking());
      { auto other = directory.open("cache-exclusion"); check(other.read(0, 3) == "new"); }
      check(!read_guard->breaking());
      rejects([&] { directory.open("cache-exclusion", false, false, true); }, "locked");
      check(read_guard->breaking());
      read_guard.reset();
      auto writer = directory.open("cache-exclusion", false, false, true);
      check(writer.write(0, "ack") == 3);
      check(!reader.cache_guard(false)); // Existing writer prevents a read lease.
      check(!writer.cache_guard(true));  // Existing reader prevents exclusivity.
#endif
      check(!directory.cache_guard(true));
      // An already-open native reader prevents granting exclusive caching.
      auto competitor = directory.open("cache-exclusion", false, false, true);
      check(!competitor.cache_guard(true));
    }
    {
      auto directory = native_file::root(root_path);
      auto file = directory.open("cache-cancel", false, true, true);
      auto retained = file.retain();
      // Repeated voluntary cancellation drains the notification, including
      // Windows OVERLAPPED storage, without closing retained descriptors.
      for (int i = 0; i < 8; ++i) {
        auto guard = file.cache_guard(true);
        check(bool(guard) && !guard->breaking());
      }
      check(retained.write(0, "cancelled") == 9);
      file.flush();
      { auto other = directory.open("cache-cancel"); check(other.read(0, 9) == "cancelled"); }
      auto guard = file.cache_guard(true);
      check(bool(guard));
      // Offset, sparse writes and metadata must keep working after the native
      // file has been converted to overlapped I/O on Windows.
      auto offset = uint64_t(4) * 1024 * 1024 * 1024 + 7;
      check(file.write(offset, "Z") == 1);
      check(file.read(offset, 1) == "Z");
      check(file.read(offset + 1, 1).empty());
      file.allocate(8192);
      check(file.info().at("size") == 8192);
      file.truncate(9); file.flush();
      check(retained.read(0, 9) == "cancelled");
      file.set_times({}, uint64_t(1700000000) * 1000000000);
      check(file.info().at("modified_ns") == uint64_t(1700000000) * 1000000000);
      guard.reset();
      check(directory.open("cache-cancel").read(0, 9) == "cancelled");
    }
    {
      auto directory = native_file::root(root_path);
      auto file = directory.open("allocation-failure", false, true, true);
      std::string content(8192, 'a');
      check(file.write(0, content) == content.size());
      test_write_budget(0);
      rejects([&] { file.allocate(4096); }, "disk_full");
      test_write_budget(-1);
      check(file.info().at("size") == content.size() && file.read(0, content.size()) == content);
    }
    initialize(state, 38443);
    auto cfg = config::load(state);
    auto key = read_json(state / "ipc-keys.json").at("identity").get<std::string>();
    auto root = inspect_root(root_path);
    root["id"] = "root";
    root["worker"] = "file";
    json space = {{"id", "space"},   {"root", "root"},
                  {"path", "space"}, {"owner", "alice"},
                  {"group", ""},     {"quota", uint64_t(6) * 1024 * 1024 * 1024}};
    auto generation = random_hex(16);
    auto files = std::make_unique<file_store>(cfg, "file", generation);
    auto context = [](std::string caller = "api") {
      return call_context{caller, random_hex(16), now() + 30000, {}};
    };
    space = files->dispatch("provision",
                            {{"root", root}, {"space", space}, {"request_id", random_hex(16)}},
                            context("identity"));
    auto grant = [&](std::string path, bool write = true, int64_t expiry = 0) {
      json g = {{"actor", "alice"},  {"root", root},
                {"space", space},    {"path", path},
                {"write", write},    {"share", ""},
                {"epoch", 2},        {"expires", expiry ? expiry : now() + 2000},
                {"protocol", "core"}};
      g["signature"] = mac(key, g.dump());
      return g;
    };
    auto call = [&](std::string op, std::string path, json body = json::object()) {
      auto started = now();
      for (unsigned attempt = 0;; ++attempt) {
        body["grant"] = grant(path);
        try { return files->dispatch(op, body, context()); }
        catch (const error &e) {
          if (!attempt && std::string_view(e.what()) == "grant_refresh_required") continue;
          if (std::string_view(e.what()) == "lease_expired" || std::string_view(e.what()) == "grant_refresh_required")
            std::cerr << e.what() << " operation=" << op << " path=" << path
                      << " elapsed_ms=" << now() - started << " after_checks=" << checks << '\n';
          throw;
        }
      }
    };
    auto denied = grant("", true, now() - 1);
    rejects([&] { files->dispatch("quota", {{"grant", denied}}, context()); }, "lease_expired");
    denied = grant("");
    denied["actor"] = "bob";
    rejects([&] { files->dispatch("quota", {{"grant", denied}}, context()); }, "grant_denied");
    for (auto bad :
         {"../escape", "/absolute", "a//b", "a/", "a\\b", "file:stream", "NUL", "a. ", "\xff"}) {
      try {
        portable_path(bad);
        throw error("unsafe_path_accepted");
      } catch (const error &e) {
        check(std::string_view(e.what()) != "unsafe_path_accepted");
      }
    }
    // Delay the first root access after signature/expiry verification. Cold
    // attachment may outlast authorization, but cannot execute the mkdir.
    auto cold = grant("cold-prepare");
    test_root_delay(2100);
    rejects([&] { files->dispatch("mkdir", {{"grant", cold}}, context()); }, "grant_refresh_required");
    check(!fs::exists(root_path / "space/cold-prepare"));
    call("mkdir", "cold-prepare");
    check(fs::is_directory(root_path / "space/cold-prepare"));
    rejects([&] { files->dispatch("mkdir", {{"grant", cold}}, context()); }, "lease_expired");
    std::cout << "PASS cold attachment expiry refuses mutation, fresh authorization succeeds and an already-expired grant remains invalid\n";
    call("mkdir", "nested");
    auto j = call("begin", "nested/data", {{"size", 8}, {"request_id", random_hex(16)}});
    test_write_budget(3);
    auto partial = call("chunk", "nested/data",
                        {{"job", j.at("id")}, {"offset", 0}, {"data", encode_bytes("abcdefgh")}});
    check(partial.at("written") == 3);
    rejects(
        [&] {
          call("chunk", "nested/data",
               {{"job", j.at("id")}, {"offset", 3}, {"data", encode_bytes("defgh")}});
        },
        "disk_full");
    check(call("quota", "").at("reserved") == 8);
    test_write_budget(-1);
    call("chunk", "nested/data",
         {{"job", j.at("id")}, {"offset", 3}, {"data", encode_bytes("defgh")}});
    call("commit", "nested/data", {{"job", j.at("id")}});
    check(call("quota", "").at("used") == 8);
    check(call("quota", "").at("reserved") == 0);
    auto h = call("open", "nested/data", {{"write", true}});
    test_write_budget(0);
    auto operation = random_hex(16);
    rejects(
        [&] {
          call("write", "nested/data",
               {{"handle", h.at("handle")},
                {"offset", 8},
                {"data", encode_bytes("x")},
                {"request_id", operation}});
        },
        "disk_full");
    test_write_budget(-1);
    rejects(
        [&] {
          call("write", "nested/data",
               {{"handle", h.at("handle")},
                {"offset", 8},
                {"data", encode_bytes("x")},
                {"request_id", operation}});
        },
        "uncertain_write");
    check(call("quota", "").at("used") == 8);
    auto offset = uint64_t(4) * 1024 * 1024 * 1024 + 7;
    auto result = call("write", "nested/data",
                       {{"handle", h.at("handle")},
                        {"offset", offset},
                        {"data", encode_bytes("Z")},
                        {"request_id", random_hex(16)},
                        {"flush", true}});
    check(result.at("size") == offset + 1);
    check(
        call("read", "nested/data", {{"handle", h.at("handle")}, {"offset", offset}, {"count", 1}})
            .at("data") == encode_bytes("Z"));
    files->dispatch("revoke", {{"epoch", 3}}, context("identity"));
    rejects(
        [&] {
          call("read", "nested/data", {{"handle", h.at("handle")}, {"offset", 0}, {"count", 1}});
        },
        "policy_revoked");
    files.reset();
    files = std::make_unique<file_store>(cfg, "file", random_hex(16));
    rejects(
        [&] {
          call("read", "nested/data", {{"handle", h.at("handle")}, {"offset", 0}, {"count", 1}});
        },
        "stale_handle");
    // Unknown native writes are reconciled after a restart, never replayed as success.
    j = call("begin", "uncertain", {{"size", 10}, {"request_id", random_hex(16)}});
    files.reset();
    {
      std::ofstream file(root_path / "space" / j.at("stage").get<std::string>(), std::ios::binary);
      file << "unlogged";
    }
    files = std::make_unique<file_store>(cfg, "file", random_hex(16));
    rejects([&] { call("commit", "uncertain", {{"job", j.at("id")}}); }, "uncertain_write");
    call("cancel_job", "uncertain", {{"job", j.at("id")}});
    check(call("quota", "").at("reserved") == 0);
    // Simulate both crash cuts around publish: durable commit intent, then optional
    // native rename, with no metadata acknowledgement. Recovery identifies the same object.
    for (bool published : {false, true}) {
      auto path = published ? "after-publish" : "before-publish";
      auto task = call("begin", path, {{"size", 4}, {"request_id", random_hex(16)}});
      call("chunk", path, {{"job", task.at("id")}, {"offset", 0}, {"data", encode_bytes("safe")}});
      files.reset();
      {
        database db(state / "file.db");
        statement q(db, "SELECT body FROM jobs WHERE id=?");
        q.bind(1, task.at("id"));
        check(q.row());
        task = json::parse(q.text(0));
        task["status"] = "committing";
        statement update(db, "UPDATE jobs SET body=? WHERE id=?");
        update.bind(1, task.dump());
        update.bind(2, task.at("id"));
        update.row();
      }
      if (published) {
        auto directory = native_file::root(root_path / "space");
        directory.rename(task.at("stage"), path);
      }
      files = std::make_unique<file_store>(cfg, "file", random_hex(16));
      check(call("commit", path, {{"job", task.at("id")}}).at("status") == "completed");
      auto read = call("open", path);
      check(call("read", path, {{"handle", read.at("handle")}, {"offset", 0}, {"count", 4}})
                .at("data") == encode_bytes("safe"));
      call("close", path, {{"handle", read.at("handle")}});
    }
    auto read_only = grant("before-publish", false);
    rejects(
        [&] {
          files->dispatch("begin",
                          {{"grant", read_only}, {"size", 1}, {"request_id", random_hex(16)}},
                          context());
        },
        "forbidden");
    auto open = call("open", "before-publish");
    auto other = grant("before-publish");
    other.erase("signature");
    other["actor"] = "bob";
    other["signature"] = mac(key, other.dump());
    rejects(
        [&] {
          files->dispatch(
              "read",
              {{"grant", other}, {"handle", open.at("handle")}, {"offset", 0}, {"count", 1}},
              context());
        },
        "forbidden");
    call("close", "before-publish", {{"handle", open.at("handle")}});
    files.reset();
    // Native handle-relative confinement against a concurrently swapped symlink.
    auto outside = temp / "outside";
    {
      std::ofstream f(outside);
      f << "secret";
    }
    auto root_handle = native_file::root(root_path);
    root_handle.open("race", true, true);
    std::error_code ec;
    fs::create_symlink(outside, root_path / "race/link", ec);
    if (!ec) {
      std::atomic_bool stop = false;
      std::jthread attacker([&] {
        while (!stop) {
          std::error_code ignored;
          fs::remove(root_path / "race/link", ignored);
          fs::create_symlink(outside, root_path / "race/link", ignored);
        }
      });
      bool escaped = false;
      for (int i = 0; i < 500; ++i) {
        try {
          auto value = root_handle.open("race/link");
          escaped = true;
        } catch (const error &) {
        }
        try {
          root_handle.metadata("race/link");
          escaped = true;
        } catch (const error &) {
        }
      }
      stop = true;
      attacker.join();
      check(!escaped);
    }
    // All links to an outside object are denied even when they remain under the root name.
    fs::create_hard_link(outside, root_path / "hardlink");
    rejects([&] { root_handle.open("hardlink"); }, "hardlink_denied");
    rejects([&] { root_handle.metadata("hardlink"); }, "hardlink_denied");
    root_handle = native_file();
    fs::remove_all(temp);
    std::cout << json{{"status", "passed"},
                      {"checks", checks},
                      {"disk_full", "native-adapter fault injection"},
                      {"offset_bits", 64}}
                     .dump()
              << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << " after_checks=" << checks << " fixture=" << temp << '\n';
    return 1;
  }
}
