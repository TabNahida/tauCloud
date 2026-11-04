#include <taucloud/smb.hpp>
#include <taucloud/files.hpp>
#include <taucloud/database.hpp>
#include <taucloud/security.hpp>
#include <iostream>
#include <thread>
using namespace tc;
using namespace tc::smb_detail;
int main(int argc, char **argv) {
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
  json worker_identity;
  try {
    auto mode_owner = security::principal("mode-owner"),
         mode_group = security::principal("mode-group", true);
    auto mode_base = security::defaults(mode_owner, mode_group);
    for (unsigned mode = 0; mode <= 07777; ++mode) {
      auto descriptor = security::chmod(mode_base, mode, false);
      ok(security::mode(descriptor) == mode);
      auto other = security::allowed(
          descriptor, json::array({security::principal("other"), "010100000000000100000000"}));
      ok(bool(other & 1) == bool(mode & 4));
      auto twice = security::chmod(descriptor, mode, false);
      ok(twice == descriptor);
    }
    auto setgid_parent = security::chmod(mode_base, 02770, true);
    auto inherited_dir = security::inherit(setgid_parent, security::principal("child"),
                                           security::principal("other", true), true);
    auto inherited_file = security::inherit(setgid_parent, security::principal("child"),
                                            security::principal("other", true), false);
    ok(inherited_dir.at("group") == mode_group && (security::mode(inherited_dir) & 02000));
    ok(inherited_file.at("group") == mode_group && !(security::mode(inherited_file) & 07000));
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
    auto keytab = (cfg.state / "cifs.keytab").string();
    for (auto bad : {json{{"smb_gss_service", "cifs/localhost@REALM"}},
                     json{{"smb_gss_keytab", keytab}},
                     json{{"smb_gss_service", 1}, {"smb_gss_keytab", keytab}},
                     json{{"smb_gss_service", "nfs/localhost@REALM"}, {"smb_gss_keytab", keytab}},
                     json{{"smb_gss_service", "cifs/localhost@REALM"}, {"smb_gss_keytab", "relative.keytab"}}}) {
      auto j = original; j.update(bad);
      write_json(cfg.state / "config.json", j);
      rejected([&] { config::load(cfg.state); }, "invalid_config");
    }
    auto configured = original;
    configured["smb_gss_service"] = "cifs/localhost@REALM";
    configured["smb_gss_keytab"] = keytab;
    write_json(cfg.state / "config.json", configured);
#ifdef __linux__
    ok(config::load(cfg.state).smb_gss_service == "cifs/localhost@REALM");
#else
    rejected([&] { config::load(cfg.state); }, "gss_unavailable");
#endif
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
    {
      auto h = open("cache-domain", 0x1f01ff);
      auto cache_acl = security::defaults(security::principal("alice"), "");
      cache_acl["dacl"].insert(cache_acl["dacl"].begin(),
          json{{"type", 1}, {"flags", 0}, {"mask", 0x100},
               {"sid", security::principal("bob")}});
      call("set_security", "cache-domain", {{"handle", h}, {"information", 4},
          {"data", encode_bytes(security::encode(cache_acl, 4))}});
      auto write = [&](const std::string &text) {
        return call("write", "cache-domain", {{"handle", h}, {"offset", 0},
            {"data", encode_bytes(text)}, {"request_id", random_hex(16)}});
      };
      write("old");
      auto export_id = random_hex(16);
      auto nfs = [&](const std::string &op, const std::string &handle,
                     json body = json::object(), std::string request = "") {
        auto g = grant(""); g.erase("signature");
        g["protocol"] = "nfs"; g["share"] = "nfs";
        g["nfs_uid"] = 1000; g["nfs_gid"] = 1000;
        g["groups"] = json::array({"unix"});
        g["export"] = {{"uuid", export_id}, {"uids", {{"1000", "alice"}}},
                       {"gids", {{"1000", "unix"}}}};
        g["signature"] = mac(grantkey, g.dump());
        body["grant"] = g; body["op"] = op; body["handle"] = handle;
        body["request_id"] = request.empty() ? random_hex(16) : request;
        return store->dispatch("nfs_file", body, ctx("nfs"));
      };
      auto nfs_root = nfs("root", "").at("handle").get<std::string>();
      auto nfs_file = nfs("lookup", nfs_root, {{"name", "cache-domain"}})
                          .at("handle").get<std::string>();
      auto acquired = call("cache_acquire", "cache-domain", {{"handle", h}});
      ok(acquired.at("granted") && !acquired.at("breaking"));
      auto cookie = acquired.at("cookie").get<std::string>();
      ok(call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie") == cookie);
      auto control = [&] { return json{{"handle", h}, {"cookie", cookie}}; };
      auto attribute_open = json{{"access", 0x100180}, {"sharing", 0},
                                 {"disposition", 1}, {"options", 0x40}};
      auto attributes = call("open", "cache-domain", attribute_open).at("handle");
      ok(call("stat", "cache-domain", {{"handle", attributes}}).at("access") == 0x100180);
      rejected([&] { call("read", "cache-domain", {{"handle", attributes},
          {"offset", 0}, {"count", 1}}); }, "forbidden");
      call("close", "cache-domain", {{"handle", attributes}});
      auto limited_grant = grant("cache-domain", false, false);
      attribute_open["grant"] = limited_grant;
      rejected([&] { store->dispatch("smb_open", attribute_open, ctx("smb")); }, "forbidden");
      attribute_open["access"] = 0x100080;
      attributes = store->dispatch("smb_open", attribute_open, ctx("smb")).at("handle");
      call("close", "cache-domain", {{"handle", attributes}});
      limited_grant.erase("signature"); limited_grant["actor"] = "bob";
      limited_grant["write"] = true;
      limited_grant["signature"] = mac(grantkey, limited_grant.dump());
      attribute_open["grant"] = limited_grant; attribute_open["access"] = 0x100180;
      rejected([&] { store->dispatch("smb_open", attribute_open, ctx("smb")); }, "forbidden");
      ok(!call("cache_poll", "cache-domain", control()).at("breaking"));
      rejected([&] { call("cache_ack", "cache-domain", control()); }, "invalid_device_state");
      rejected([&] { call("cache_poll", "cache-domain", {{"handle", h}, {"cookie", "wrong"}}); },
               "invalid_request");
      auto unauthorized = control(); unauthorized["grant"] = grant("cache-domain");
      rejected([&] { store->dispatch("smb_cache_poll", unauthorized, ctx("api")); }, "forbidden");
      auto other_actor = grant("cache-domain"); other_actor.erase("signature");
      other_actor["actor"] = "bob"; other_actor["signature"] = mac(grantkey, other_actor.dump());
      unauthorized["grant"] = other_actor;
      rejected([&] { store->dispatch("smb_cache_poll", unauthorized, ctx("smb")); }, "forbidden");
      write("new"); call("flush", "cache-domain", {{"handle", h}});
      ok(!call("cache_poll", "cache-domain", control()).at("breaking"));
      auto sibling = open("cache-sibling");
      auto sibling_cache = call("cache_acquire", "cache-sibling", {{"handle", sibling}});
      ok(sibling_cache.at("granted"));
      rejected([&] { open("cache-domain"); }, "cache_break_pending");
      ok(!call("cache_poll", "cache-sibling", {{"handle", sibling},
          {"cookie", sibling_cache.at("cookie")}}).at("breaking"));
      call("cache_release", "cache-sibling", {{"handle", sibling},
          {"cookie", sibling_cache.at("cookie")}});
      call("disposition", "cache-sibling", {{"handle", sibling}, {"delete", true}});
      call("close", "cache-sibling", {{"handle", sibling}});
      auto breaking = call("cache_poll", "cache-domain", control());
      ok(breaking.at("breaking") && breaking.at("remaining_ms").get<int64_t>() > 0);
      auto limit = breaking.at("remaining_ms").get<int64_t>();
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      ok(call("cache_poll", "cache-domain", control()).at("remaining_ms").get<int64_t>() < limit);
      write("ack");
      ok(!call("cache_ack", "cache-domain", control()).at("granted"));
      auto other = open("cache-domain", 0x120089, 7, 1);
      ok(call("read", "cache-domain", {{"handle", other}, {"offset", 0}, {"count", 3}})
             .at("data") == encode_bytes("ack"));
      call("close", "cache-domain", {{"handle", other}});
      auto previous = cookie;
      cookie = call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie");
      ok(cookie != previous && !cookie.empty());
      rejected([&] { call("cache_ack", "cache-domain", {{"handle", h}, {"cookie", previous}}); },
               "invalid_request");
      auto core = [&](const std::string &op, json body) {
        auto g = grant("cache-domain"); g.erase("signature");
        g["protocol"] = "core"; g["signature"] = mac(grantkey, g.dump());
        body["grant"] = g;
        return store->dispatch(op, body, ctx("api"));
      };
      rejected([&] { core("open", {{"write", false}}); }, "cache_break_pending");
      ok(call("cache_poll", "cache-domain", control()).at("breaking"));
      call("cache_ack", "cache-domain", control());
      auto core_open = core("open", {{"write", false}}).at("handle");
      ok(core("read", {{"handle", core_open}, {"offset", 0}, {"count", 3}}).at("data") ==
         encode_bytes("ack"));
      core("close", {{"handle", core_open}});
      cookie = call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie");
      rejected([&] { nfs("read", nfs_file, {{"offset", 0}, {"count", 3}}); },
               "cache_break_pending");
      ok(call("cache_poll", "cache-domain", control()).at("breaking"));
      call("cache_ack", "cache-domain", control());
      ok(nfs("read", nfs_file, {{"offset", 0}, {"count", 3}}).at("data") == encode_bytes("ack"));
      cookie = call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie");
      auto nfs_write = json{{"offset", 0}, {"data", encode_bytes("nfs")}};
      auto nfs_request = random_hex(16);
      rejected([&] { nfs("write", nfs_file, nfs_write, nfs_request); }, "cache_break_pending");
      call("cache_ack", "cache-domain", control());
      ok(nfs("write", nfs_file, nfs_write, nfs_request).at("count") == 3);
      ok(call("read", "cache-domain", {{"handle", h}, {"offset", 0}, {"count", 3}})
             .at("data") == encode_bytes("nfs"));
      write("ack");
      cookie = call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie");
      auto native = native_file::root(base / "files");
      rejected([&] { native.open("alice/cache-domain"); }, "locked");
      ok(call("cache_poll", "cache-domain", control()).at("breaking"));
      call("cache_ack", "cache-domain", control());
      ok(native.open("alice/cache-domain").read(0, 3) == "ack");
      cookie = call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie");
      // A fresh but short authority lease allows a real timeout without test
      // clock injection. Maintenance runs independently of incoming RPC.
      auto short_grant = grant("cache-domain"); short_grant.erase("signature");
      short_grant["expires"] = now() + 500;
      short_grant["signature"] = mac(grantkey, short_grant.dump());
      auto poll = control(); poll["grant"] = short_grant;
      store->dispatch("smb_cache_poll", poll, ctx("smb"));
      std::this_thread::sleep_for(std::chrono::milliseconds(550));
      store->maintain();
      ok(native.open("alice/cache-domain").read(0, 3) == "ack");
      rejected([&] { write("bad"); }, "stale_handle");
      h = open("cache-domain");
      cookie = call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie");
      rejected([&] { open("cache-domain"); }, "cache_break_pending");
      // Fresh authorization cannot extend a pending break indefinitely.
      bool fenced = false;
      for (int i = 0; i < 60 && !fenced; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        try { call("cache_poll", "cache-domain", control()); }
        catch (const error &e) { ok(std::string_view(e.what()) == "stale_handle"); fenced = true; }
      }
      ok(fenced);
      rejected([&] { write("bad"); }, "stale_handle");
      h = open("cache-domain");
      cookie = call("cache_acquire", "cache-domain", {{"handle", h}}).at("cookie");
      call("cache_release", "cache-domain", control());
      ok(write("end").at("written") == 3);
      call("cache_acquire", "cache-domain", {{"handle", h}});
      store->dispatch("revoke", {{"epoch", 2}}, ctx("identity"));
      rejected([&] { write("bad"); }, "stale_handle");
      ok(native.open("alice/cache-domain").read(0, 3) == "end");
      h = open("cache-domain");
      call("cache_acquire", "cache-domain", {{"handle", h}});
      store->dispatch("smb_recover", json::object(), ctx("smb"));
      rejected([&] { write("bad"); }, "stale_handle");
      ok(native.open("alice/cache-domain").read(0, 3) == "end");
      h = open("cache-domain");
      ok(call("cache_acquire", "cache-domain", {{"handle", h}}).at("granted"));
      call("close", "cache-domain", {{"handle", h}});
      h = open("cache-domain");
      call("disposition", "cache-domain", {{"handle", h}, {"delete", true}});
      ok(!call("cache_acquire", "cache-domain", {{"handle", h}}).at("granted"));
      call("close", "cache-domain", {{"handle", h}});
      rejected([&] { open("cache-domain", 0x120089, 7, 1); }, "not_found");
    }
    {
      const std::string path = "shared-cache";
      auto first = open(path);
      auto write = [&](const std::string &id, const std::string &value) {
        return call("write", path, {{"handle", id}, {"offset", 0},
            {"data", encode_bytes(value)}, {"request_id", random_hex(16)}});
      };
      auto read = [&](const std::string &id) {
        return call("read", path, {{"handle", id}, {"offset", 0}, {"count", 3}}).at("data");
      };
      auto state = [&](const std::string &id, const json &cookie) {
        return call("cache_poll", path, {{"handle", id}, {"cookie", cookie}});
      };
      auto ack = [&](const std::string &id, const json &cookie, unsigned level = 0) {
        return call("cache_ack", path, {{"handle", id}, {"cookie", cookie}, {"level", level}});
      };
      auto contender = [&] {
        return call("open", path, {{"access", 0x13019f}, {"sharing", 7},
            {"disposition", 1}, {"options", 0x40}, {"oplock", 8}}).at("handle").get<std::string>();
      };
      write(first, "old");
      auto initial = call("cache_acquire", path, {{"handle", first}});
      auto cookie1 = initial.at("cookie");
      ok(initial.at("level") == 8);
      rejected(contender, "cache_break_pending");
      ok(state(first, cookie1).at("break_level") == 1);
      write(first, "new");
      auto downgraded = ack(first, cookie1, 1);
      ok(downgraded.at("granted") && downgraded.at("level") == 1 &&
          !downgraded.at("breaking") && downgraded.at("cookie") == cookie1);
      auto second = contender();
      auto joined = call("cache_acquire", path, {{"handle", second}});
      auto cookie2 = joined.at("cookie");
      ok(joined.at("granted") && joined.at("level") == 1 && cookie1 != cookie2);
      ok(read(first) == encode_bytes("new") && read(second) == encode_bytes("new"));
      auto reader = store->dispatch("smb_open", {{"grant", grant(path, false, false)},
          {"access", 0x120089}, {"sharing", 7}, {"disposition", 1},
          {"options", 0x40}, {"oplock", 1}}, ctx("smb")).at("handle");
      auto reader_cache = store->dispatch("smb_cache_acquire",
          {{"grant", grant(path, false, false)}, {"handle", reader}, {"level", 1}}, ctx("smb"));
      ok(reader_cache.at("level") == 1 && read(reader) == encode_bytes("new"));
      rejected([&] { write(reader, "bad"); }, "forbidden");
      call("close", path, {{"handle", reader}});
      auto attrs = open(path, 0x100180, 0, 1);
      call("close", path, {{"handle", attrs}});
      ok(!state(first, cookie1).at("breaking") && !state(second, cookie2).at("breaking"));
      rejected([&] { call("lock", path, {{"handle", first}, {"locks", json::array({
          {{"offset", 0}, {"length", 1}, {"flags", 0x12}}})}}); }, "cache_break_pending");
      rejected([&] { write(first, "bad"); }, "cache_break_pending");
      ok(state(first, cookie1).at("break_level") == 0 && state(second, cookie2).at("breaking"));
      ok(read(second) == encode_bytes("new"));
      rejected([&] { ack(second, cookie2, 1); }, "invalid_request");
      ok(!ack(first, cookie1).at("granted"));
      auto native = native_file::root(base / "files");
      rejected([&] { native.open("alice/" + path); }, "locked");
      rejected([&] { write(first, "bad"); }, "cache_break_pending");
      ok(!ack(second, cookie2).at("granted"));
      write(first, "end");
      ok(read(second) == encode_bytes("end"));
      // The old uncached peer shares the native descriptor. It must prevent a
      // later acquisition from incorrectly claiming exclusive network caching.
      auto again = call("cache_acquire", path, {{"handle", first}});
      cookie1 = again.at("cookie");
      ok(again.at("level") == 1);
      joined = call("cache_acquire", path, {{"handle", second}, {"level", 1}});
      cookie2 = joined.at("cookie");
      ok(joined.at("level") == 1);
      auto expiring = grant(path); expiring.erase("signature");
      expiring["expires"] = now() + 100;
      expiring["signature"] = mac(grantkey, expiring.dump());
      store->dispatch("smb_cache_poll", {{"grant", expiring}, {"handle", first},
          {"cookie", cookie1}}, ctx("smb"));
      std::this_thread::sleep_for(std::chrono::milliseconds(130));
      ok(state(second, cookie2).at("granted"));
      rejected([&] { read(first); }, "stale_handle");
      call("close", path, {{"handle", first}});
      rejected([&] { native.open("alice/" + path); }, "locked");
      ok(state(second, cookie2).at("breaking"));
      ack(second, cookie2);
      ok(native.open("alice/" + path).read(0, 3) == "end");
      call("disposition", path, {{"handle", second}, {"delete", true}});
      call("close", path, {{"handle", second}});
    }
    {
      auto h = open("cache-escalation");
      auto cached = call("cache_acquire", "cache-escalation", {{"handle", h}});
      auto control = json{{"handle", h}, {"cookie", cached.at("cookie")}};
      rejected([&] { call("open", "cache-escalation", {{"access", 0x13019f},
          {"sharing", 7}, {"disposition", 1}, {"options", 0x40}, {"oplock", 8}}); },
          "cache_break_pending");
      auto initial = call("cache_poll", "cache-escalation", control);
      ok(initial.at("break_level") == 1);
      auto native = native_file::root(base / "files");
      rejected([&] { native.open("alice/cache-escalation"); }, "locked");
      auto tightened = call("cache_poll", "cache-escalation", control);
      ok(tightened.at("break_level") == 0 && tightened.at("remaining_ms") <= initial.at("remaining_ms"));
      control["level"] = 1;
      auto downgraded = call("cache_ack", "cache-escalation", control);
      ok(downgraded.at("level") == 1 && downgraded.at("breaking") &&
          downgraded.at("remaining_ms") <= tightened.at("remaining_ms"));
      rejected([&] { native.open("alice/cache-escalation"); }, "locked");
      control["level"] = 0;
      ok(!call("cache_ack", "cache-escalation", control).at("granted"));
      ok(native.open("alice/cache-escalation").info().at("size") == 0);
      call("disposition", "cache-escalation", {{"handle", h}, {"delete", true}});
      call("close", "cache-escalation", {{"handle", h}});
    }
    {
      auto writer = open("readonly-cache");
      call("write", "readonly-cache", {{"handle", writer}, {"offset", 0},
          {"data", encode_bytes("read")}, {"request_id", random_hex(16)}});
      call("close", "readonly-cache", {{"handle", writer}});
      auto ro = [&](const std::string &op, json body) {
        body["grant"] = grant("readonly-cache", false, false);
        return store->dispatch("smb_" + op, body, ctx("smb"));
      };
      auto reader = ro("open", {{"access", 0x120089}, {"sharing", 7},
          {"disposition", 1}, {"options", 0x40}}).at("handle");
      auto cache = ro("cache_acquire", {{"handle", reader}, {"level", 1}});
      ok(cache.at("granted") && cache.at("level") == 1);
      auto native = native_file::root(base / "files");
      rejected([&] { native.open("alice/readonly-cache", false, false, true); }, "locked");
      ok(!ro("cache_ack", {{"handle", reader}, {"cookie", cache.at("cookie")}}).at("granted"));
      ok(ro("cache_acquire", {{"handle", reader}, {"level", 1}}).at("granted"));
      ro("close", {{"handle", reader}});
      ok(native.open("alice/readonly-cache").read(0, 4) == "read");
      writer = open("readonly-cache");
      call("disposition", "readonly-cache", {{"handle", writer}, {"delete", true}});
      call("close", "readonly-cache", {{"handle", writer}});
    }
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
    // CREATE's delete-on-close is per-open, and becomes pending only at close.
    auto initial_delete = open("close-file", 0x13019f, 7, 3, 0x1040);
    auto held_delete = open("close-file");
    ok(!call("stat", "close-file", {{"handle", held_delete}}).at("delete_pending").get<bool>());
    call("close", "close-file", {{"handle", initial_delete}});
    rejected([&] { open("close-file"); }, "delete_pending");
    ok(fs::exists(base / "files/alice/close-file"));
    call("close", "close-file", {{"handle", held_delete}});
    ok(!fs::exists(base / "files/alice/close-file"));
    auto parent_delete = open("close-dir", 0x13019f, 7, 3, 0x1001);
    auto child_delete = open("close-dir/child");
    call("close", "close-dir/child", {{"handle", child_delete}});
    rejected([&] { call("disposition", "close-dir", {{"handle", parent_delete}, {"delete", true}}); },
             "directory_not_empty");
    call("close", "close-dir", {{"handle", parent_delete}});
    ok(fs::exists(base / "files/alice/close-dir/child"));
    parent_delete = open("close-dir", 0x13019f, 7, 1, 0x1001);
    call("close", "close-dir", {{"handle", parent_delete}});
    ok(fs::exists(base / "files/alice/close-dir/child"));
    // A rename follows the native incarnation, including recovery of either
    // side of the native/SQL commit boundary.
    initial_delete = open("close-old", 0x13019f, 7, 3, 0x1040);
    call("rename", "close-old", {{"handle", initial_delete}, {"target", grant("close-new")}});
    call("close", "close-new", {{"handle", initial_delete}});
    ok(!fs::exists(base / "files/alice/close-new"));
    initial_delete = open("close-crash", 0x13019f, 7, 3, 0x1040);
    open("close-crash-full", 0x13019f, 7, 3, 0x1001);
    open("close-crash-full/child");
    open("close-crash-empty", 0x13019f, 7, 3, 0x1001);
    {
      database journal(cfg.state / "file.db");
      sql(journal, "UPDATE smb_close_delete SET target='close-crash-moved' WHERE path='close-crash'");
    }
    fs::rename(base / "files/alice/close-crash", base / "files/alice/close-crash-moved");
    // A replacement at the former name must never inherit the old intent.
    open("close-crash");
    store.reset();
    store = std::make_unique<file_store>(cfg, "file", random_hex(16));
    store->dispatch("smb_recover", {}, ctx("smb"));
    ok(fs::exists(base / "files/alice/close-crash"));
    ok(!fs::exists(base / "files/alice/close-crash-moved"));
    ok(fs::exists(base / "files/alice/close-crash-full/child"));
    ok(!fs::exists(base / "files/alice/close-crash-empty"));
    {
      database journal(cfg.state / "file.db");
      statement left(journal, "SELECT count(*) FROM smb_close_delete");
      left.row(); ok(left.integer(0) == 0);
    }
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
    // Exercise the actual file-worker maintenance loop: after acquisition,
    // send no IPC at all until native access becomes possible again.
    require(argc > 0, "test_binary_path");
    auto file_binary = fs::absolute(argv[0]).parent_path() /
        ("taucloud_file" + fs::path(argv[0]).extension().string());
    auto worker_generation = random_hex(16);
    worker_identity = spawn(file_binary, cfg, worker_generation);
    bool ready = false;
    auto ready_deadline = now() + 5000;
    while (!ready && now() < ready_deadline) {
      try { rpc(cfg, "supervisor", "file", "ping", {}, worker_generation, {}, "", 200); ready = true; }
      catch (const error &) { std::this_thread::sleep_for(std::chrono::milliseconds(20)); }
    }
    require(ready, "cache_worker_not_ready"); ok(ready);
    auto remote = [&](const std::string &op, json body) {
      body["grant"] = grant("cache-worker");
      return rpc(cfg, "smb", "file", "smb_" + op, body, worker_generation);
    };
    auto remote_handle = remote("open", {{"write", true}, {"access", 0x13019f},
        {"sharing", 7}, {"disposition", 3}, {"options", 0x40}}).at("handle");
    remote("write", {{"handle", remote_handle}, {"offset", 0},
        {"data", encode_bytes("worker")}, {"request_id", random_hex(16)}});
    ok(remote("cache_acquire", {{"handle", remote_handle}}).at("granted"));
    auto native_root = native_file::root(base / "files");
    bool blocked = false, released = false;
    auto release_deadline = now() + 4000;
    while (!released && now() < release_deadline) {
      try {
        auto reader = native_root.open("alice/cache-worker");
        ok(reader.read(0, 6) == "worker"); released = true;
      } catch (const error &e) {
        require(std::string_view(e.what()) == "locked", "unexpected_native_cache_error");
        blocked = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
    }
    ok(blocked && released);
    rejected([&] { remote("write", {{"handle", remote_handle}, {"offset", 0},
        {"data", encode_bytes("stale!")}, {"request_id", random_hex(16)}}); }, "stale_handle");
    rpc(cfg, "supervisor", "file", "stop", {}, worker_generation);
    auto stop_deadline = now() + 5000;
    while (verified_alive(worker_identity) && now() < stop_deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ok(!verified_alive(worker_identity));
    reap_children(); worker_identity = nullptr;
    native_root = native_file();
    fs::remove_all(base);
    std::cout << json{{"status", "passed"}, {"checks", checks}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    if (!worker_identity.is_null()) {
      try { terminate_verified(worker_identity); reap_children(); } catch (...) {}
    }
    std::error_code ec;
    fs::remove_all(base, ec);
    return 1;
  }
}
