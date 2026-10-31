#include <taucloud/smb.hpp>
#include <taucloud/files.hpp>
#include <iostream>
using namespace tc;
using namespace tc::smb_detail;
int main() {
  int checks = 0;
  auto ok = [&](bool v) {
    require(v, "test_failed");
    ++checks;
  };
  auto rejected = [&](auto fn, std::string code) {
    try {
      fn();
      throw error("expected_rejection");
    } catch (const error &e) {
      if (code != e.what())
        std::cerr << code << " != " << e.what() << '\n';
      ok(code == e.what());
    }
  };
  auto base = fs::temp_directory_path() / ("tc5-unit-" + random_hex(6));
  try {
    ok(encode_bytes(nt_hash("Password")) == "a4f49c406510bdcab6824ee7c30fd852");
    ok(encode_bytes(hmac(nt_hash("Password"), utf16("USERDomain"))) ==
       "0c868a403bfd7a93a3001ef22ef02e3f");
    ok(utf8(utf16("中文-é-😀")) == "中文-é-😀");
    rejected([&] { utf8(bytes("\x00\xd8", 2)); }, "invalid_path");
    rejected([&] { get("abc", 2, 2); }, "invalid_packet");
    auto key = decode_bytes(random_hex());
    auto sealed = seal(key, "credential", "alice");
    ok(unseal(key, sealed, "alice") == "credential");
    rejected([&] { unseal(key, sealed, "bob"); }, "credential_corrupt");
    sealed.back() ^= 1;
    rejected([&] { unseal(key, sealed, "alice"); }, "credential_corrupt");
    auto token = bytes("NTLMSSP\0", 8) + bytes(40, '\0');
    ok(ntlm_token(spnego(token)) == token);
    rejected([&] { ntlm_token(bytes("\xa1\x82\xff\xff", 4)); }, "invalid_packet");
    for (size_t i = 0; i < token.size(); ++i) {
      try {
        ntlm_token(std::string_view(spnego(token)).substr(0, i));
      } catch (const error &) {
        ++checks;
      }
    }
    initialize(base / "state", 38443);
    auto cfg = config::load(base / "state");
    ok(cfg.smb_port == 0);
    auto original = read_json(cfg.state / "config.json");
    for (auto bad : {json(445), json(38443), json(65536), json("4445")}) {
      auto j = original;
      j["smb_port"] = bad;
      write_json(cfg.state / "config.json", j);
      rejected([&] { config::load(cfg.state); }, "invalid_config");
    }
    write_json(cfg.state / "config.json", original);
    fs::create_directories(base / "files");
    auto root = inspect_root(base / "files");
    root["id"] = "data";
    root["worker"] = "file";
    json space = {{"id", "alice"},    {"root", "data"}, {"path", "alice"},
                  {"owner", "alice"}, {"group", ""},    {"quota", 1024}};
    auto ctx = [](std::string caller) {
      return call_context{caller, random_hex(16), now() + 30000, {}};
    };
    auto store = std::make_unique<file_store>(cfg, "file", random_hex(16));
    space = store->dispatch("provision", {{"root", root}, {"space", space}}, ctx("identity"));
    auto grantkey = read_json(cfg.state / "ipc-keys.json").at("identity").get<std::string>();
    auto grant = [&](std::string path, bool expired = false, bool writable = true) {
      json g = {{"actor", "alice"}, {"root", root},
                {"space", space},   {"path", path},
                {"write", writable}, {"share", "smb"},
                {"epoch", 2},       {"expires", now() + (expired ? -100 : 2000)},
                {"protocol", "smb"}};
      g["signature"] = mac(grantkey, g.dump());
      return g;
    };
    auto call = [&](std::string op, std::string path, json body = json::object()) {
      body["grant"] = grant(path);
      return store->dispatch("smb_" + op, body, ctx("smb"));
    };
    auto open = [&](std::string path, uint32_t access = 0x13019f, unsigned share = 7,
                    unsigned disposition = 3, unsigned options = 0x40) {
      return call("open", path,
                  {{"write", true},
                   {"access", access},
                   {"sharing", share},
                   {"disposition", disposition},
                   {"options", options}})
          .at("handle")
          .get<std::string>();
    };
    auto h = open("data", 0x13019f, 1);
    rejected([&] { open("data"); }, "sharing_violation");
    call("close", "data", {{"handle", h}});
    h = open("data", 0x1f01ff);
    call("close", "data", {{"handle", h}});
    for (uint32_t access : {0x40u, 0x40000u, 0x80000u, 0x1f01ffu})
      rejected([&] {
        store->dispatch("smb_open", {{"grant", grant("data", false, false)},
            {"write", false}, {"access", access}, {"sharing", 7},
            {"disposition", 1}, {"options", 0x40}}, ctx("smb"));
      }, "forbidden");
    auto metadata = open("data", 0x80, 0, 1);
    auto reader = open("data", 0x20, 7, 1);
    ok(call("stat", "data", {{"handle", reader}}).at("access") == 0x20);
    ok(call("read", "data", {{"handle", reader}, {"offset", 0}, {"count", 1}})
           .at("read") == 0);
    call("close", "data", {{"handle", reader}});
    call("close", "data", {{"handle", metadata}});
    h = open("data");
    auto second = open("data");
    ok(call("write", "data", {{"handle", h}, {"offset", INT64_MAX},
        {"data", ""}, {"request_id", random_hex(16)}}).at("written") == 0);
    ok(call("stat", "data", {{"handle", h}}).at("size") == 0);
    // Shared authority orders conflicting waiters independently of retry order.
    auto third = open("data");
    auto queue_lock = [&](const std::string &handle, unsigned flags, std::string token = "",
                          uint64_t offset = 32) {
      json body = {{"handle", handle},
                   {"locks", json::array({{{"offset", offset}, {"length", 8}, {"flags", flags}}})}};
      if (!token.empty())
        body["waiter"] = token;
      return call("lock", "data", body);
    };
    auto first_waiter = random_hex(16), second_waiter = random_hex(16);
    queue_lock(h, 0x11);
    ok(queue_lock(second, 2, first_waiter).at("pending"));
    ok(queue_lock(third, 1, second_waiter).at("pending"));
    rejected([&] { queue_lock(third, 0x11); }, "lock_not_granted");
    // Invalid retries cannot mutate a queued range or steal another open's token.
    rejected([&] { queue_lock(second, 2, first_waiter, 33); }, "invalid_request");
    rejected([&] { queue_lock(third, 2, first_waiter); }, "invalid_request");
    queue_lock(h, 4);
    ok(queue_lock(third, 1, second_waiter).at("pending"));
    ok(queue_lock(second, 2, first_waiter).at("locked"));
    queue_lock(second, 4);
    ok(queue_lock(third, 1, second_waiter).at("locked"));
    queue_lock(third, 4);
    queue_lock(h, 0x12);
    first_waiter = random_hex(16);
    second_waiter = random_hex(16);
    ok(queue_lock(second, 2, first_waiter).at("pending"));
    ok(queue_lock(third, 2, second_waiter).at("pending"));
    call("lock_cancel", "data", {{"handle", second}, {"waiter", first_waiter}});
    queue_lock(h, 4);
    ok(queue_lock(third, 2, second_waiter).at("locked"));
    queue_lock(third, 4);
    queue_lock(h, 0x12);
    ok(queue_lock(third, 2, random_hex(16)).at("pending"));
    call("close", "data", {{"handle", third}});
    queue_lock(h, 4);
    ok(queue_lock(second, 0x12).at("locked"));
    queue_lock(second, 4);
    // The uppermost byte is valid; only an end beyond UINT64_MAX overflows.
    call("lock", "data", {{"handle", h}, {"locks", json::array({
        {{"offset", UINT64_MAX}, {"length", 1}, {"flags", 0x12}}})}});
    rejected([&] { call("lock", "data", {{"handle", second}, {"locks", json::array({
        {{"offset", UINT64_MAX}, {"length", 1}, {"flags", 0x12}}})}}); }, "lock_not_granted");
    rejected([&] { call("lock", "data", {{"handle", h}, {"locks", json::array({
        {{"offset", UINT64_MAX}, {"length", 2}, {"flags", 0x12}}})}}); }, "invalid_lock_range");
    call("lock", "data", {{"handle", h}, {"locks", json::array({
        {{"offset", UINT64_MAX}, {"length", 1}, {"flags", 4}}})}});
    call("write", "data",
         {{"handle", h},
          {"offset", 0},
          {"data", encode_bytes("abcdef")},
          {"request_id", random_hex(16)}});
    call(
        "lock", "data",
        {{"handle", h}, {"locks", json::array({{{"offset", 0}, {"length", 3}, {"flags", 0x12}}})}});
    rejected([&] { call("read", "data", {{"handle", second}, {"offset", 0}, {"count", 3}}); },
             "locked");
    rejected(
        [&] {
          call("write", "data",
               {{"handle", second},
                {"offset", 1},
                {"data", encode_bytes("x")},
                {"request_id", random_hex(16)}});
        },
        "locked");
    ok(call("read", "data", {{"handle", second}, {"offset", 3}, {"count", 3}}).at("data") ==
       encode_bytes("def"));
    rejected(
        [&] {
          call("lock", "data",
               {{"handle", second},
                {"locks", json::array({{{"offset", 4}, {"length", 1}, {"flags", 0x12}},
                                       {{"offset", 1}, {"length", 1}, {"flags", 0x12}}})}});
        },
        "lock_not_granted");
    // The successful first item of a rejected lock vector must have rolled back.
    call(
        "lock", "data",
        {{"handle", h}, {"locks", json::array({{{"offset", 4}, {"length", 1}, {"flags", 0x12}}})}});
    ++checks;
    call("rename", "data", {{"handle", h}, {"target", grant("renamed")}});
    ok(call("read", "renamed", {{"handle", second}, {"offset", 3}, {"count", 1}}).at("data") ==
       encode_bytes("d"));
    rejected([&] { call("resize", "renamed", {{"handle", h}, {"size", 2048}}); }, "quota_exceeded");
    call("close", "renamed", {{"handle", second}});
    call("disposition", "renamed", {{"handle", h}, {"delete", true}});
    rejected([&] { open("renamed"); }, "delete_pending");
    // Pending deletion survives loss of both worker process and its volatile handle map.
    store.reset();
    store = std::make_unique<file_store>(cfg, "file", random_hex(16));
    store->dispatch("smb_recover", {}, ctx("smb"));
    ok(!fs::exists(base / "files/alice/renamed"));
    auto binary = open("binary");
    call("write", "binary",
         {{"handle", binary},
          {"offset", 0},
          {"data", encode_bytes(bytes("\0\xff", 2))},
          {"request_id", random_hex(16)}});
    call("close", "binary", {{"handle", binary}});
    ++checks;
    auto short_handle = open("short-write");
    test_write_budget(2);
    auto short_result = call("write", "short-write",
                             {{"handle", short_handle},
                              {"offset", 0},
                              {"data", encode_bytes("abcdef")},
                              {"request_id", random_hex(16)}});
    ok(short_result.at("written") == 2);
    auto failed_id = random_hex(16);
    auto failed_body = json{{"handle", short_handle},
                            {"offset", 2},
                            {"data", encode_bytes("x")},
                            {"request_id", failed_id}};
    rejected([&] { call("write", "short-write", failed_body); }, "disk_full");
    test_write_budget(-1);
    rejected([&] { call("write", "short-write", failed_body); }, "uncertain_write");
    ok(call("stat", "short-write", {{"handle", short_handle}}).at("size") == 2);
    call("close", "short-write", {{"handle", short_handle}});
    auto before_failed_create = call("quota", "").at("used");
    test_write_budget(0);
    for (int attempt = 0; attempt < 2; ++attempt) {
      rejected(
          [&] {
            call("open", "failed-allocation",
                 {{"write", true},
                  {"access", 0x13019f},
                  {"sharing", 7},
                  {"disposition", 3},
                  {"options", 0x40},
                  {"allocation", 512}});
          },
          "disk_full");
      ok(!fs::exists(base / "files/alice/failed-allocation"));
      ok(call("quota", "").at("used") == before_failed_create);
    }
    test_write_budget(-1);
    auto allocated = call("open", "failed-allocation",
                          {{"write", true},
                           {"access", 0x13019f},
                           {"sharing", 7},
                           {"disposition", 3},
                           {"options", 0x40},
                           {"allocation", 512}});
    ok(allocated.at("size") == 0 && allocated.at("allocated").get<uint64_t>() >= 512);
    ok(call("quota", "").at("used").get<uint64_t>() == before_failed_create.get<uint64_t>() + 512);
    call("close", "failed-allocation", {{"handle", allocated.at("handle")}});
    auto overwrite_handle = open("failed-overwrite");
    call("write", "failed-overwrite",
         {{"handle", overwrite_handle},
          {"offset", 0},
          {"data", encode_bytes("preserved")},
          {"request_id", random_hex(16)}});
    test_write_budget(0);
    rejected(
        [&] {
          call("open", "failed-overwrite",
               {{"write", true},
                {"access", 0x13019f},
                {"sharing", 7},
                {"disposition", 4},
                {"options", 0x40},
                {"allocation", 128}});
        },
        "disk_full");
    test_write_budget(-1);
    ok(call("read", "failed-overwrite", {{"handle", overwrite_handle}, {"offset", 0}, {"count", 9}})
           .at("data") == encode_bytes("preserved"));
    call("close", "failed-overwrite", {{"handle", overwrite_handle}});
    auto dir = open("dir", 0x13019f, 7, 3, 1);
    rejected([&] { open("dir", 0x120089, 7, 1, 0x40); }, "is_directory");
    call("close", "dir", {{"handle", dir}});
    h = open("stale");
    store->dispatch("smb_recover", {}, ctx("smb"));
    rejected([&] { call("read", "stale", {{"handle", h}, {"offset", 0}, {"count", 1}}); },
             "stale_handle");
    store.reset();
    fs::remove_all(base);
    std::cout << json{{"status", "passed"}, {"checks", checks}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    std::error_code ec;
    fs::remove_all(base, ec);
    return 1;
  }
}
