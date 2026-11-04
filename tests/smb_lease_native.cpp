#include <taucloud/files.hpp>
#include <taucloud/smb_lease.hpp>
#include <iostream>
#include <thread>
using namespace tc;
using namespace tc::smb_detail;
int main() {
  int checks = 0;
  auto base = fs::temp_directory_path() / ("tc-lease-native-" + random_hex(6));
  auto check = [&](bool value) { require(value, "lease_native_test_failed"); ++checks; };
  auto rejects = [&](auto call, std::string_view expected) {
    bool rejected = false;
    try { call(); } catch (const error &e) {
      if (e.what() != expected) std::cerr << "expected=" << expected << " actual=" << e.what() << '\n';
      rejected = e.what() == expected;
    }
    check(rejected);
  };
  try {
    initialize(base / "state", 38443);
    auto cfg = config::load(base / "state");
    fs::create_directories(base / "root");
    auto root = inspect_root(base / "root"); root["id"] = "root"; root["worker"] = "file";
    json space = {{"id", "space"}, {"root", "root"}, {"path", "space"},
                  {"owner", "alice"}, {"group", ""}, {"quota", 1048576}};
    auto ctx = [](std::string who = "smb") { return call_context{who, random_hex(16), now() + 30000, {}}; };
    auto store = std::make_unique<file_store>(cfg, "file", random_hex(16));
    space = store->dispatch("provision", {{"root", root}, {"space", space}}, ctx("identity"));
    auto signing = read_json(cfg.state / "ipc-keys.json").at("identity").get<std::string>();
    auto grant = [&](std::string path, bool write = true, int64_t lifetime = 2000) {
      json g = {{"actor", "alice"}, {"root", root}, {"space", space}, {"path", path},
          {"write", write}, {"share", "smb"}, {"epoch", 2}, {"expires", now() + lifetime}, {"protocol", "smb"}};
      g["signature"] = mac(signing, g.dump()); return g;
    };
    auto call = [&](std::string op, std::string path, json body = json::object()) {
      body["grant"] = grant(path); return store->dispatch("smb_" + op, body, ctx());
    };
    auto client = random_hex(16), peer = random_hex(16), key = decode_bytes(random_hex(16));
    bytes context(52, '\0'); context.replace(0, 16, key);
    put(context, 16, 7, 4); put(context, 48, 10, 2);
    auto lease = [&](std::string owner) { return json{{"client", owner}, {"context", encode_bytes(context)}}; };
    auto open = [&](std::string path, std::string owner, unsigned access = 0x13019f, unsigned sharing = 7) {
      json body = {{"access", access}, {"sharing", sharing}, {"disposition", 3}, {"options", 0x40}};
      if (!owner.empty()) body["lease"] = lease(owner);
      return call("open", path, body).at("handle").get<std::string>();
    };
    auto acquire = [&](std::string path, std::string h, unsigned state = 7) {
      return call("cache_acquire", path, {{"handle", h}, {"state", state}});
    };
    auto poll = [&](std::string path, std::string h, json cookie) {
      return call("cache_poll", path, {{"handle", h}, {"cookie", cookie}});
    };
    auto ack = [&](std::string path, std::string h, json cookie, unsigned state = 0) {
      return call("cache_ack", path, {{"handle", h}, {"cookie", cookie}, {"state", state}});
    };
    auto write = [&](std::string path, std::string h, std::string data) {
      return call("write", path, {{"handle", h}, {"offset", 0}, {"data", encode_bytes(data)},
                                  {"request_id", random_hex(16)}});
    };
    auto close = [&](std::string path, std::string h) { call("close", path, {{"handle", h}}); };
    {
      auto native = native_file::root(base / "root");
      const std::string path = "shared";
      auto a = open(path, client);
      write(path, a, "old");
      auto state = acquire(path, a); auto cookie = state.at("cookie");
      check(state.at("state") == 7 && state.at("epoch") == 11 && !state.at("breaking"));
      auto b = open(path, client);
      check(acquire(path, b, 1).at("state") == 7);
      check(poll(path, b, cookie).at("cookie") == cookie);
      auto attributes = open(path, "", 0x100180, 0);
      close(path, attributes);
      check(!poll(path, a, cookie).at("breaking") && poll(path, b, cookie).at("state") == 7);
      write(path, b, "new");
      check(!poll(path, a, cookie).at("breaking"));
      rejects([&] { open("wrong-path", client); }, "invalid_request");
      rejects([&] { native.open("space/wrong-path"); }, "not_found");
      rejects([&] { native.open("space/shared"); }, "locked");
      state = poll(path, a, cookie);
      check(state.at("breaking") && state.at("ack_required"));
      auto body = decode_bytes(state.at("notification").at("body").get<std::string>());
      check(get(body, 24, 4) == 7 && get(body, 28, 4) == 0);
      rejects([&] { poll(path, b, "bad-cookie"); }, "invalid_request");
      check(ack(path, b, cookie, 7).at("status") == 0xc00000d0u);
      check(ack(path, b, cookie).at("status") == 0);
      check(poll(path, a, cookie).at("state") == 0 && native.open("space/shared").read(0, 3) == "new");
      check(acquire(path, a).at("state") == 7);
      rejects([&] { open(path, peer); }, "cache_break_pending");
      state = poll(path, a, cookie);
      body = decode_bytes(state.at("notification").at("body").get<std::string>());
      check(get(body, 28, 4) == 3); // Compatible foreign open keeps HANDLE caching.
      auto during_break = open(path, client);
      check(acquire(path, during_break).at("breaking"));
      close(path, during_break);
      check(ack(path, b, cookie, 3).at("state") == 3);
      auto c = open(path, peer);
      auto peer_state = acquire(path, c); auto peer_cookie = peer_state.at("cookie");
      check(peer_state.at("state") == 3 && peer_cookie != cookie);
      rejects([&] { write(path, a, "one"); }, "cache_break_pending");
      check(!poll(path, a, cookie).at("breaking") && poll(path, c, peer_cookie).at("breaking"));
      check(ack(path, c, peer_cookie).at("status") == 0);
      write(path, a, "one");
      rejects([&] { write(path, c, "two"); }, "cache_break_pending");
      check(ack(path, b, cookie).at("status") == 0);
      write(path, c, "two");
      close(path, c);
      check(acquire(path, a).at("state") == 7);
      close(path, a);
      check(poll(path, b, cookie).at("state") == 7);
      rejects([&] { native.open("space/shared"); }, "locked");
      ack(path, b, cookie);
      check(native.open("space/shared").read(0, 3) == "two");
      close(path, b);
      std::cout << "PASS shared native exclusion, own IO, compatible foreign opens, same-key CREATE during break and final-close lifetime\n";

      {
        const std::string path = "chained";
        auto holder = open(path, client); write(path, holder, "cached");
        auto cookie = acquire(path, holder).at("cookie");
        auto overwrite = [&] {
          return call("open", path, {{"access", 0x13019f}, {"sharing", 7},
              {"disposition", 4}, {"options", 0x40}}).at("handle").get<std::string>();
        };
        rejects([&] { open(path, ""); }, "cache_break_pending");
        auto first = poll(path, holder, cookie).at("notification").at("serial");
        call("cache_sent", path, {{"handle", holder}, {"cookie", cookie}, {"serial", first}});
        rejects(overwrite, "cache_break_pending");
        auto state = ack(path, holder, cookie, 3);
        auto body = decode_bytes(state.at("notification").at("body").get<std::string>());
        check(get(body, 24, 4) == 3 && get(body, 28, 4) == 1 && get(body, 4, 4) == 1);
        rejects(overwrite, "cache_break_pending");
        rejects([&] { native.open("space/chained"); }, "locked");
        check(ack(path, holder, cookie, 3).at("status") == 0xc00000d0u);
        state = ack(path, holder, cookie, 1);
        body = decode_bytes(state.at("notification").at("body").get<std::string>());
        check(get(body, 24, 4) == 1 && get(body, 28, 4) == 0 && get(body, 4, 4) == 0);
        rejects(overwrite, "cache_break_pending");
        call("cache_sent", path, {{"handle", holder}, {"cookie", cookie}, {"serial", first}});
        rejects(overwrite, "cache_break_pending");
        call("cache_sent", path, {{"handle", holder}, {"cookie", cookie},
            {"serial", state.at("notification").at("serial")}});
        check(native.open("space/chained").read(0, 6) == "cached");
        auto writer = overwrite();
        check(native.open("space/chained").info().at("size") == 0);
        close(path, writer); close(path, holder);
        std::cout << "PASS chained recalls retain native exclusion through both ACKs and exact final notification delivery\n";
      }

      // A cached close can remove an incompatible sharing reservation.
      auto h = open("sharing", client, 0x13019f, 1);
      cookie = acquire("sharing", h).at("cookie");
      rejects([&] { open("sharing", peer); }, "cache_break_pending");
      check(poll("sharing", h, cookie).at("ack_required"));
      check(get(decode_bytes(poll("sharing", h, cookie).at("notification").at("body").get<std::string>()), 28, 4) == 5);
      rejects([&] { open("sharing", client); }, "sharing_violation");
      close("sharing", h);
      auto contender = open("sharing", peer); close("sharing", contender);
      check(native.open("space/sharing").info().at("size") == 0);
      std::cout << "PASS HANDLE recall permits cached close, while same-key sharing conflicts do not bypass access rules\n";

      // Classic Level II and a foreign lease share physical exclusion without
      // merging their client-visible authority or acknowledgment state.
      auto classic = open("mixed", ""); write("mixed", classic, "old");
      auto classic_cookie = call("cache_acquire", "mixed", {{"handle", classic}, {"level", 8}}).at("cookie");
      rejects([&] { open("mixed", client); }, "cache_break_pending");
      check(call("cache_poll", "mixed", {{"handle", classic}, {"cookie", classic_cookie}}).at("break_level") == 1);
      call("cache_ack", "mixed", {{"handle", classic}, {"cookie", classic_cookie}, {"level", 1}});
      h = open("mixed", client); cookie = acquire("mixed", h).at("cookie");
      // MS-FSA denies HANDLE caching when another open has a classic oplock.
      check(poll("mixed", h, cookie).at("state") == 1);
      rejects([&] { write("mixed", classic, "new"); }, "cache_break_pending");
      check(poll("mixed", h, cookie).at("breaking"));
      call("cache_ack", "mixed", {{"handle", classic}, {"cookie", classic_cookie}, {"level", 0}});
      rejects([&] { native.open("space/mixed"); }, "locked");
      auto read_break = poll("mixed", h, cookie);
      check(!read_break.at("ack_required").get<bool>());
      call("cache_sent", "mixed", {{"handle", h}, {"cookie", cookie},
          {"serial", read_break.at("notification").at("serial")}});
      write("mixed", classic, "new");
      close("mixed", classic); close("mixed", h);
      check(native.open("space/mixed").read(0, 3) == "new");
      std::cout << "PASS classic Level II and lease grants retain independent authority over one native guard\n";

      h = open("handle-cache", client);
      cookie = acquire("handle-cache", h, 3).at("cookie");
      classic = open("handle-cache", "");
      check(!call("cache_acquire", "handle-cache", {{"handle", classic}, {"level", 8}}).at("granted").get<bool>());
      check(poll("handle-cache", h, cookie).at("state") == 3);
      close("handle-cache", classic); close("handle-cache", h);

      h = open("expiry", client); auto sibling = open("expiry", client);
      cookie = acquire("expiry", h).at("cookie");
      store->dispatch("smb_cache_poll", {{"grant", grant("expiry", true, 100)},
          {"handle", h}, {"cookie", cookie}}, ctx());
      std::this_thread::sleep_for(std::chrono::milliseconds(130));
      check(poll("expiry", sibling, cookie).at("state") == 7);
      rejects([&] { call("read", "expiry", {{"handle", h}, {"offset", 0}, {"count", 1}}); }, "stale_handle");
      rejects([&] { native.open("space/expiry"); }, "locked");
      ack("expiry", sibling, cookie); close("expiry", sibling);
      std::cout << "PASS expiry fences only that open; a fresh sibling keeps exclusion until acknowledgment\n";

      h = open("cross-nfs", client); write("cross-nfs", h, "smb");
      auto export_id = random_hex(16);
      auto nfs = [&](std::string operation, std::string handle, json body = json::object()) {
        auto g = grant(""); g.erase("signature");
        g["protocol"] = "nfs"; g["share"] = "nfs";
        g["nfs_uid"] = 1000; g["nfs_gid"] = 1000; g["groups"] = json::array({"unix"});
        g["export"] = {{"uuid", export_id}, {"uids", {{"1000", "alice"}}},
                       {"gids", {{"1000", "unix"}}}};
        g["signature"] = mac(signing, g.dump());
        body["grant"] = g; body["op"] = operation; body["handle"] = handle;
        body["request_id"] = random_hex(16);
        return store->dispatch("nfs_file", body, ctx("nfs"));
      };
      auto nfs_root = nfs("root", "").at("handle").get<std::string>();
      auto nfs_file = nfs("lookup", nfs_root, {{"name", "cross-nfs"}}).at("handle").get<std::string>();
      cookie = acquire("cross-nfs", h).at("cookie");
      rejects([&] { nfs("read", nfs_file, {{"offset", 0}, {"count", 3}}); }, "cache_break_pending");
      ack("cross-nfs", h, cookie);
      check(nfs("read", nfs_file, {{"offset", 0}, {"count", 3}}).at("data") == encode_bytes("smb"));
      acquire("cross-nfs", h);
      rejects([&] { nfs("write", nfs_file, {{"offset", 0}, {"data", encode_bytes("nfs")}}); }, "cache_break_pending");
      ack("cross-nfs", h, cookie);
      check(nfs("write", nfs_file, {{"offset", 0}, {"data", encode_bytes("nfs")}}).at("count") == 3);
      check(call("read", "cross-nfs", {{"handle", h}, {"offset", 0}, {"count", 3}}).at("data") == encode_bytes("nfs"));
      close("cross-nfs", h);
      std::cout << "PASS NFS reads and writes recall SMB lease authority before accessing shared file data\n";

      // R-only invalidation has no ACK, but its send completion is the native
      // release boundary. A stale completion cannot bypass that boundary.
      h = open("read-only-cache", client);
      cookie = acquire("read-only-cache", h, 1).at("cookie");
      contender = open("read-only-cache", peer);
      rejects([&] { write("read-only-cache", contender, "new"); }, "cache_break_pending");
      state = poll("read-only-cache", h, cookie);
      check(state.at("breaking") && !state.at("ack_required"));
      auto serial = state.at("notification").at("serial").get<uint64_t>();
      check(ack("read-only-cache", h, cookie).at("status") == 0xc0000001u);
      call("cache_sent", "read-only-cache", {{"handle", h}, {"cookie", cookie}, {"serial", serial + 1}});
      rejects([&] { write("read-only-cache", contender, "new"); }, "cache_break_pending");
      call("cache_sent", "read-only-cache", {{"handle", h}, {"cookie", cookie}, {"serial", serial}});
      write("read-only-cache", contender, "new");
      check(poll("read-only-cache", h, cookie).at("state") == 0);
      close("read-only-cache", contender); close("read-only-cache", h);
      std::cout << "PASS R-only invalidation releases native exclusion only after the matching notification is sent\n";

      h = open("permissions", client); cookie = acquire("permissions", h).at("cookie");
      auto ro = store->dispatch("smb_open", {{"grant", grant("permissions", false)},
          {"access", 0x120089}, {"sharing", 7}, {"disposition", 1}, {"options", 0x40},
          {"lease", lease(client)}}, ctx()).at("handle").get<std::string>();
      rejects([&] { write("permissions", ro, "bad"); }, "forbidden");
      auto request = json{{"grant", grant("permissions")}, {"handle", h}, {"cookie", cookie}};
      rejects([&] { store->dispatch("smb_cache_poll", request, ctx("api")); }, "forbidden");
      request["grant"]["actor"] = "bob";
      rejects([&] { store->dispatch("smb_cache_poll", request, ctx()); }, "grant_denied");
      store->dispatch("revoke", {{"epoch", 3}}, ctx("identity"));
      rejects([&] { poll("permissions", ro, cookie); }, "policy_revoked");
      check(native.open("space/permissions").info().at("size") == 0);
      std::cout << "PASS same-key membership grants no extra file rights, caller authority or revocation exemption\n";
    }
    store.reset(); fs::remove_all(base);
    std::cout << json{{"status", "passed"}, {"checks", checks}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << " after_checks=" << checks << " fixture=" << base << '\n';
    return 1;
  }
}
