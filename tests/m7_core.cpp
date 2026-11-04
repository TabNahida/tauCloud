#include <taucloud/nfs.hpp>
#include <taucloud/nfs_ssv.hpp>
#include <taucloud/files.hpp>
#include <iostream>
using namespace tc;
using namespace tc::nfs_detail;
#include "nfs_ssv_vectors.inc"
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
    for (const auto &v : ssv_vectors) {
      ssv_context context(v.hash, v.cipher, 2);
      auto delta = decode_bytes(v.delta), request = decode_bytes(v.request_digest);
      auto client_mic = decode_bytes(v.client_mic), client_wrap = decode_bytes(v.client_wrap);
      rejected([&] { context.sign("message"); }, "ssv_context");
      rejected([&] { context.wrap("message"); }, "ssv_context");
      ok(!context.verify("message", client_mic));
      rejected([&] { context.update("short", "request", request, "response"); }, "ssv_length");
      rejected([&] { context.update(delta, "request", "wrong", "response"); }, "ssv_digest");
      ok(context.sequence() == 0);
      ok(context.update(delta, "request", request, "response") == decode_bytes(v.response_digest));
      ok(context.sign("message") == decode_bytes(v.server_mic));
      ok(context.verify("message", client_mic));
      ok(!context.verify("message", decode_bytes(v.server_mic)));
      ok(!context.verify("changed", client_mic));
      ok(context.unwrap(client_wrap) == "message");
      for (size_t n = 0; n < client_mic.size(); ++n)
        ok(!context.verify("message", std::string_view(client_mic).substr(0, n)));
      for (size_t n = 0; n < client_wrap.size(); ++n) {
        auto damaged = client_wrap; damaged[n] ^= 1;
        bool refused = false;
        try { context.unwrap(damaged); }
        catch (const error &) { refused = true; }
        catch (const xdr_error &) { refused = true; }
        ok(refused);
      }
      for (uint32_t n = 0; n < 64; ++n) {
        auto token = context.wrap(std::string(n, 'a'));
        ok(context.wrap_size_limit(uint32_t(token.size())) >= n);
        auto limit = context.wrap_size_limit(uint32_t(token.size()) - 1);
        if (limit) ok(context.wrap(std::string(limit, 'a')).size() < token.size());
      }
    }
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
      auto timed_directory = dir.open("timed-directory", true, true);
      timed_directory.flush();
      timed_directory.set_times(uint64_t(1700000000123456700), uint64_t(1700000000765432100));
      ok(timed_directory.info().at("modified_ns") == uint64_t(1700000000765432100));
      timed_directory = native_file();
      auto reopened_directory = dir.open("timed-directory", true);
      reopened_directory.set_times(std::nullopt, uint64_t(1700000000765432200));
      ok(reopened_directory.info().at("modified_ns") == uint64_t(1700000000765432200));
      reopened_directory = native_file();
      dir.remove("timed-directory", true);
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
      auto durable = dir.open("durable", false, true, true);
      durable.write(0, "durable data");
      auto object = durable.info().at("object").get<std::string>();
      auto token = durable.stable_identity();
      auto name = ".tc-nfs-" + random_hex(16);
      auto link = durable.pin(dir, name);
      rejected([&] { dir.open("durable"); }, "hardlink_denied");
      rejected([&] { dir.open_pin(name, "wrong object"); }, "object_replaced");
      ok(dir.matches_pin("durable", object));
      durable = native_file();
      dir.remove("durable", false, object);
      ok(!dir.matches_pin("durable", object));
      link = native_file();
      auto reopened = dir.open_pin(name, object);
      ok(reopened.stable_identity() == token && reopened.read(0, 64) == "durable data");
      reopened = native_file();
      dir.remove(name, false, object);
    }
    initialize(root / "state", 38443);
    auto cfg = config::load(root / "state");
    auto original = read_json(cfg.state / "config.json");
    ok(cfg.nfs_lease_seconds == 60);
    for (auto bad : {json(0), json(4), json(3601), json(-1), json("30"), json(5.5), json(true)}) {
      auto c = original;
      c["nfs_lease_seconds"] = bad;
      write_json(cfg.state / "config.json", c);
      rejected([&] { config::load(cfg.state); }, "invalid_config");
    }
    for (auto seconds : {5, 30, 60, 3600}) {
      auto c = original;
      c["nfs_lease_seconds"] = seconds;
      write_json(cfg.state / "config.json", c);
      ok(config::load(cfg.state).nfs_lease_seconds == uint32_t(seconds));
    }
    for (auto bad : {json(1023), json(38443), json(65536), json("2049")}) {
      auto c = original;
      c["nfs_port"] = bad;
      write_json(cfg.state / "config.json", c);
      rejected([&] { config::load(cfg.state); }, "invalid_config");
    }
    write_json(cfg.state / "config.json", original);
    {
      // Model an asynchronous close that has been requested but not yet
      // completed. A new backchannel must not receive a retry in this gap.
      std::vector<std::pair<std::string, std::string>> callbacks;
      std::vector<std::string> closes;
      server protocol(cfg, [](auto, auto, auto) { return json::object(); }, {},
                      [&](auto connection, auto packet) { callbacks.emplace_back(connection, packet); },
                      [&](auto connection) { closes.push_back(connection); });
      uint32_t xid = 100;
      auto compound = [&](writer operation, const std::string &connection) {
        writer request;
        request.u32(++xid).u32(0).u32(2).u32(100003).u32(4).u32(1)
            .u32(0).opaque("").u32(0).opaque("")
            .opaque("").u32(1).u32(1).fixed(operation.data);
        auto response = protocol.dispatch(request.data, connection);
        reader result(response);
        ok(result.u32() == xid && result.u32() == 1 && result.u32() == 0 &&
           result.u32() == 0 && result.opaque().empty() && result.u32() == 0);
        ok(result.u32() == 0 && result.opaque().empty() && result.u32() == 1);
        result.u32();
        ok(result.u32() == 0);
        return response.substr(result.pos);
      };
      auto exchanged = compound(writer().u32(42).fixed("12345678").opaque("callback-close-race")
                                    .u32(0).u32(0).u32(0), "one");
      reader exchange(exchanged);
      auto client = exchange.u64();
      auto create_sequence = exchange.u32();
      writer create;
      create.u32(43).u64(client).u32(create_sequence).u32(2);
      for (int i = 0; i < 2; ++i)
        create.u32(0).u32(4096).u32(4096).u32(0).u32(16).u32(4).u32(0);
      create.u32(0x40000004).u32(1).u32(0);
      auto created = compound(create, "one");
      reader session_result(created);
      auto session = session_result.fixed(16);
      auto reply = [&](const std::pair<std::string, std::string> &call, std::string body = "") {
        reader request(call.second);
        writer result;
        result.u32(request.u32()).u32(1).u32(0).u32(0).opaque("").u32(0).fixed(body);
        ok(protocol.dispatch(result.data, call.first).empty());
      };
      ok(callbacks.size() == 1);
      auto null = callbacks.back();
      reply(null);
      ok(callbacks.size() == 2);
      auto original_request = callbacks.back();
      compound(writer().u32(41).fixed(session).u32(2).boolean(false), "two");
      null = callbacks.back();
      reply(null);
      ok(callbacks.size() == 3);
      reply(original_request, "bad reply");
      ok(closes == std::vector<std::string>{"one"});
      protocol.maintenance();
      ok(callbacks.size() == 3); // A close request is not proof of disconnection.
      protocol.disconnect("one");
      protocol.maintenance();
      ok(callbacks.size() == 4 && callbacks.back().first == "two");
      ok(callbacks.back().second.substr(40) == original_request.second.substr(40));
      auto retried = callbacks.back();
      writer completed;
      completed.u32(0).opaque("").u32(1).u32(11).u32(0).fixed(session)
          .u32(1).u32(0).u32(0).u32(0);
      reply(retried, completed.data);
      protocol.maintenance();
      ok(callbacks.size() == 4 && closes.size() == 1);
    }
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
                    std::string id = "", bool discovery = false) {
      json g = {
          {"actor", "alice"},
          {"root", storage},
          {"space", space},
          {"path", ""},
          {"write", true},
          {"share", "nfs"},
          {"epoch", 2},
          {"expires", now() + 2000},
          {"protocol", "nfs"},
          {"nfs_uid", 1000},
          {"nfs_gid", 1000},
          {"groups", json::array({"unix"})},
          {"export",
           {{"uuid", export_id}, {"uids", {{"1000", "alice"}}}, {"gids", {{"1000", "unix"}}}}}};
      if (discovery) { g["security_discovery"] = true; g["write"] = false; }
      g["signature"] = mac(key, g.dump());
      b["grant"] = g;
      b["op"] = op;
      b["handle"] = handle;
      b["request_id"] = id.empty() ? random_hex(16) : id;
      return store->dispatch("nfs_file", b, ctx("nfs"));
    };
    auto dir = call("root", "").at("handle").get<std::string>();
    auto file = call("create", dir, {{"name", "data"}}).at("handle").get<std::string>();
    auto discovery = call("security_stat", file, json::object(), "", true);
    ok(discovery == json{{"handle", file}, {"directory", false}});
    ok(call("security_lookup", dir, {{"name", "data"}}, "", true) == discovery);
    for (const auto *operation : {"stat", "read", "write", "security_read", "create", "setattr"})
      rejected([&] { call(operation, file, json::object(), "", true); }, "grant_denied");
    rejected([&] { call("security_stat", file); }, "grant_denied");
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
