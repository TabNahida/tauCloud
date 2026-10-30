#include <taucloud/nfs.hpp>
#include <taucloud/files.hpp>
#include <iostream>
using namespace tc;
using namespace tc::nfs_detail;
int main() {
  int checks = 0;
  auto ok = [&](bool b) {
    require(b, "test_failed");
    ++checks;
  };
  auto rejected = [&](auto fn, const std::string &code) {
    try {
      fn();
      throw error("expected_rejection");
    } catch (const error &e) {
      if (code != e.what())
        std::cerr << code << " != " << e.what() << '\n';
      ok(code == e.what());
    }
  };
  try {
    writer w;
    w.u32(0x12345678).u64(UINT64_MAX).boolean(true).opaque("abc");
    reader r(w.data);
    ok(r.u32() == 0x12345678);
    ok(r.u64() == UINT64_MAX);
    ok(r.boolean());
    ok(r.opaque() == "abc");
    r.end();
    for (size_t n = 0; n < w.data.size(); ++n) {
      try {
        reader truncated(std::string_view(w.data).substr(0, n));
        truncated.u32();
        truncated.u64();
        truncated.boolean();
        truncated.opaque();
        throw error("accepted_truncation");
      } catch (const xdr_error &) {
        ++checks;
      }
    }
    record_decoder d;
    ok(d.fragment(3) == 3);
    ok(!d.append(3, "abc"));
    ok(d.fragment(0x80000002) == 2);
    ok(d.append(0x80000002, "de"));
    ok(d.data == "abcde");
    for (auto marker : {0u, 0x80000000u, uint32_t(max_record + 1)}) {
      try {
        record_decoder bad;
        bad.fragment(marker);
        throw error("accepted_marker");
      } catch (const xdr_error &) {
        ++checks;
      }
    }
    auto root = fs::current_path() / "build" / ("tc7-native-" + random_hex(6));
    fs::create_directories(root);
    {
      auto dir = native_file::root(root);
      auto f = dir.open("before", false, true, true);
      f.write(0, "payload");
      f.flush();
      auto id = f.stable_identity();
      f = native_file();
      dir.rename("before", "after");
      auto moved = dir.open("after");
      ok(moved.stable_identity() == id);
      moved = native_file();
      dir.remove("after");
      auto replacement = dir.open("after", false, true, true);
      ok(replacement.stable_identity() != id);
      replacement.write(0, "retained");
      auto pinned = replacement.retain();
      replacement = native_file();
      dir.remove("after");
      ok(pinned.read(0, 8) == "retained");
      pinned.write(0, "R");
      pinned.flush();
      ok(pinned.info().at("size") == 8);
      ok(pinned.retain().read(0, 8) == "Retained");
    }
    initialize(root / "state", 38443);
    auto cfg = config::load(root / "state");
    auto original = read_json(cfg.state / "config.json");
    for (auto bad : {json(1023), json(38443), json(65536), json("2049")}) {
      auto c = original;
      c["nfs_port"] = bad;
      write_json(cfg.state / "config.json", c);
      rejected([&] { config::load(cfg.state); }, "invalid_config");
    }
    write_json(cfg.state / "config.json", original);
    fs::create_directories(root / "files");
    auto storage = inspect_root(root / "files");
    storage["id"] = "data";
    storage["worker"] = "file";
    json space = {{"id", "alice"},    {"root", "data"}, {"path", "alice"},
                  {"owner", "alice"}, {"group", ""},    {"quota", 1024}};
    auto ctx = [](std::string caller) {
      return call_context{caller, random_hex(16), now() + 30000, {}};
    };
    auto store = std::make_unique<file_store>(cfg, "file", random_hex(16));
    space = store->dispatch("provision", {{"root", storage}, {"space", space}}, ctx("identity"));
    auto key = read_json(cfg.state / "ipc-keys.json").at("identity").get<std::string>();
    auto export_id = random_hex(16);
    auto call = [&](std::string op, std::string handle, json b = json::object(),
                    std::string id = "") {
      json g = {{"actor", "alice"},  {"root", storage},
                {"space", space},    {"path", ""},
                {"write", true},     {"share", "nfs"},
                {"epoch", 2},        {"expires", now() + 2000},
                {"protocol", "nfs"}, {"export", {{"uuid", export_id}}}};
      g["signature"] = mac(key, g.dump());
      b["grant"] = g;
      b["op"] = op;
      b["handle"] = handle;
      b["request_id"] = id.empty() ? random_hex(16) : id;
      return store->dispatch("nfs_file", b, ctx("nfs"));
    };
    auto dir = call("root", "").at("handle").get<std::string>();
    auto file = call("create", dir, {{"name", "data"}}).at("handle").get<std::string>();
    auto request = random_hex(16);
    json write = {{"offset", 0}, {"data", encode_bytes("hello")}};
    auto result = call("write", file, write, request);
    ok(result.at("count") == 5);
    ok(call("write", file, write, request) == result);
    rejected(
        [&] { call("write", file, {{"offset", 0}, {"data", encode_bytes("different")}}, request); },
        "idempotency_conflict");
    rejected([&] { call("write", file, {{"offset", 1024}, {"data", encode_bytes("x")}}); },
             "quota_exceeded");
    auto altered = file;
    altered.back() = altered.back() == '0' ? '1' : '0';
    rejected([&] { call("stat", altered); }, "stale_handle");
    fs::rename(root / "files/alice/data", root / "files/alice/moved");
    ok(call("stat", file).at("used") == 5);
    store.reset();
    store = std::make_unique<file_store>(cfg, "file", random_hex(16));
    auto read = call("read", file, {{"offset", 0}, {"count", 10}});
    ok(decode_bytes(read.at("data").get<std::string>()) == "hello");
    ok(read.at("handle") == file);
    auto quota = call("stat", file);
    ok(quota.at("used") == 5);
    rejected([&] { call("lookup", dir, {{"name", "../escape"}}); }, "invalid_path");
    auto saved_export = export_id;
    export_id = random_hex(16);
    rejected([&] { call("stat", file); }, "stale_handle");
    export_id = saved_export;
    call("remove", dir, {{"name", "moved"}});
    rejected([&] { call("stat", file); }, "stale_handle");
    auto fresh = call("create", dir, {{"name", "moved"}}).at("handle").get<std::string>();
    ok(fresh != file);
    // Short writes must not be acknowledged, replayed or hidden from quota accounting.
    test_write_budget(2);
    auto partial = random_hex(16);
    rejected([&] { call("write", fresh, write, partial); }, "disk_full");
    test_write_budget(-1);
    rejected([&] { call("write", fresh, write, partial); }, "uncertain_write");
    ok(call("stat", fresh).at("size") == 2);
    store.reset();
    fs::remove_all(root);
    std::cout << json{{"status", "passed"}, {"checks", checks}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
