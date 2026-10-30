#include <taucloud/files.hpp>
#include <iostream>
using namespace tc;
int main() {
  int checks = 0;
  auto ok = [&](bool value) {
    require(value, "test_failed");
    ++checks;
  };
  auto rejected = [&](auto action, std::string code) {
    try {
      action();
      throw error("expected_rejection");
    } catch (const error &e) {
      if (code != e.what())
        std::cerr << code << " != " << e.what() << '\n';
      ok(code == e.what());
    }
  };
  auto base = fs::temp_directory_path() / ("tc4-unit-" + random_hex(6));
  try {
    initialize(base / "state", 38443);
    auto cfg = config::load(base / "state");
    ok(cfg.ftp_port == 0 && !cfg.ftp_plaintext);
    auto original = read_json(cfg.state / "config.json");
    for (auto bad : {json{{"ftp_port", 21}}, json{{"ftp_port", 38443}}, json{{"ftp_port", 65536}},
                     json{{"ftp_plaintext", "true"}},
                     json{{"ftp_passive_first", 65535}, {"ftp_passive_last", 65534}},
                     json{{"ftp_passive_first", 1024}, {"ftp_passive_last", 65535}},
                     json{{"ftp_port", 50000}}, json{{"unexpected_option", true}}}) {
      auto value = original;
      value.update(bad);
      write_json(cfg.state / "config.json", value);
      rejected([&] { config::load(cfg.state); }, "invalid_config");
    }
    write_json(cfg.state / "config.json", original);
    fs::create_directories(base / "files");
    auto root = inspect_root(base / "files");
    root["id"] = "data";
    root["worker"] = "file";
    json space = {{"id", "alice"},    {"root", "data"}, {"path", "alice"},
                  {"owner", "alice"}, {"group", ""},    {"quota", 1024 * 1024}};
    auto context = [](std::string role) {
      return call_context{role, random_hex(16), now() + 30000, {}};
    };
    auto files = std::make_unique<file_store>(cfg, "file", random_hex(16));
    space = files->dispatch("provision",
                            {{"root", root}, {"space", space}, {"request_id", random_hex(16)}},
                            context("identity"));
    auto key = read_json(cfg.state / "ipc-keys.json").at("identity").get<std::string>();
    auto grant = [&](std::string path, std::string protocol, bool expired = false) {
      json g = {{"actor", "alice"},    {"root", root},
                {"space", space},      {"path", path},
                {"write", true},       {"share", "ftp"},
                {"epoch", 2},          {"expires", now() + (expired ? -100 : 2000)},
                {"protocol", protocol}};
      g["signature"] = mac(key, g.dump());
      return g;
    };
    auto call = [&](std::string op, std::string path, std::string protocol,
                    json body = json::object()) {
      body["grant"] = grant(path, protocol);
      return files->dispatch(op, body, context(protocol == "core" ? "api" : protocol));
    };
    call("mkdir", "dir", "core");
    auto job = call("begin", "dir/data", "core", {{"size", 3}, {"request_id", random_hex(16)}});
    call("chunk", "dir/data", "core",
         {{"job", job.at("id")}, {"offset", 0}, {"data", encode_bytes("abc")}});
    call("commit", "dir/data", "core", {{"job", job.at("id")}});
    auto core = call("open", "dir/data", "core"), ftp = call("open", "dir/data", "ftp");
    rejected([&] { call("ftp_close", "dir/data", "ftp", {{"handle", core.at("handle")}}); },
             "forbidden");
    rejected([&] { call("ftp_close", "other", "ftp", {{"handle", ftp.at("handle")}}); },
             "forbidden");
    auto pending = call("begin", "pending", "ftp", {{"size", 4}, {"request_id", random_hex(16)}});
    auto durable = call("begin", "durable", "core", {{"size", 5}, {"request_id", random_hex(16)}});
    rejected([&] { files->dispatch("ftp_recover", {}, context("webdav")); }, "forbidden");
    files->dispatch("ftp_recover", {}, context("ftp"));
    rejected(
        [&] {
          call("read", "dir/data", "ftp",
               {{"handle", ftp.at("handle")}, {"offset", 0}, {"count", 3}});
        },
        "stale_handle");
    ok(call("read", "dir/data", "core",
            {{"handle", core.at("handle")}, {"offset", 0}, {"count", 3}})
           .at("data") == encode_bytes("abc"));
    ok(call("quota", "", "core").at("reserved") == 5);
    auto next = call("begin", "next", "ftp", {{"size", 4}, {"request_id", random_hex(16)}});
    auto old = grant("next", "ftp", true);
    rejected(
        [&] {
          files->dispatch("commit", {{"grant", old}, {"job", next.at("id")}}, context("ftp"));
        },
        "lease_expired");
    ok(files->dispatch("ftp_abort", {{"grant", old}, {"job", next.at("id")}}, context("ftp"))
           .at("cleaned"));
    rejected([&] { call("ftp_rmdir", "dir", "ftp", {{"request_id", random_hex(16)}}); },
             "directory_not_empty");
    files.reset();
    fs::remove_all(base);
    std::cout << json{{"status", "passed"}, {"checks", checks}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    std::error_code ignored;
    fs::remove_all(base, ignored);
    return 1;
  }
}
