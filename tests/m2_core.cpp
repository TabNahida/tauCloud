#include <taucloud/files.hpp>
#include <taucloud/database.hpp>
#include <fstream>
#include <iostream>
#ifndef _WIN32
#include <sys/resource.h>
#endif
using namespace tc;
static int checks = 0;
void check(bool value) {
  require(value, "test_failed");
  ++checks;
}
template <class F> void rejects(F call, const std::string &code) {
  try {
    call();
    throw error("rejection_expected");
  } catch (const error &e) {
    if (code != e.what())
      std::cerr << "expected " << code << ", got " << e.what() << '\n';
    check(code == e.what());
  }
}
int main() {
  auto temp = fs::temp_directory_path() / ("tc2-unit-" + random_hex(6));
  try {
    auto state = temp / "state", root_path = temp / "root";
    fs::create_directories(root_path);
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
      body["grant"] = grant(path);
      return files->dispatch(op, body, context());
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
      }
      stop = true;
      attacker.join();
      check(!escaped);
    }
    // All links to an outside object are denied even when they remain under the root name.
    fs::create_hard_link(outside, root_path / "hardlink");
    rejects([&] { root_handle.open("hardlink"); }, "hardlink_denied");
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
