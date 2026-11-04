#include <taucloud/files.hpp>
#include <taucloud/nfs_delegation.hpp>
#include <taucloud/native_delegation_owner.hpp>
#include <iostream>
#include <thread>
#include <source_location>
using namespace tc;
using tc::nfs_detail::delegation_lifetime;
int main(int argc, char **argv) {
  if (auto result = native_delegation_owner::entry(argc, argv); result >= 0) return result;
  int checks = 0;
  auto base = fs::temp_directory_path() / ("tc-nfs-delegation-" + random_hex(6));
  auto check = [&](bool value, std::source_location location = std::source_location::current()) {
    if (!value) std::cerr << "failed_line=" << location.line() << '\n';
    require(value, "delegation_native_test_failed"); ++checks;
  };
  auto rejects = [&](auto call, std::string_view expected,
                     std::source_location location = std::source_location::current()) {
    bool rejected = false;
    try { call(); } catch (const error &e) {
      if (e.what() != expected) std::cerr << "expected=" << expected << " actual=" << e.what() << '\n';
      rejected = e.what() == expected;
    }
    check(rejected, location);
  };
  try {
    using state = delegation_lifetime::state;
    // Test deadline boundaries without scheduler-dependent sleeps. Lease
    // renewals and repeated conflicts cannot extend the first recall deadline.
    for (int64_t period : {5000, 30000, 60000, 3600000}) {
      delegation_lifetime d(1000, period, period);
      check(d.held() && d.status() == state::active);
      d.recall(1100);
      auto deadline = d.recall_until();
      for (int64_t delta : {0, 1, 99, 1000}) {
        check(d.renew(1100 + delta, period));
        d.recall(1100 + delta);
        check(d.recall_until() == deadline);
      }
      d.expire(deadline - 1); check(d.held());
      d.expire(deadline); check(!d.held() && d.status() == state::revoked);
      check(!d.renew(deadline, period));
      d.returned(deadline); check(d.status() == state::revoked);
      delegation_lifetime expired(0, period, 10);
      expired.recall(1); expired.expire(9); check(expired.held());
      expired.expire(10); check(expired.status() == state::expired);
      check(!expired.renew(10, period));
      delegation_lifetime returned(0, period, period);
      returned.returned(2); returned.recall(3);
      check(returned.status() == state::returned && !returned.renew(4, period));
      delegation_lifetime shorter(0, period, period);
      check(shorter.renew(1, 1) && shorter.expires() == period);
      check(!shorter.renew(1, 0) && !shorter.renew(1, period + 1));
      delegation_lifetime observed(1000, period, period);
      auto original_recall = 1100 + period / 2;
      observed.constrain(1000 + period, original_recall);
      check(observed.status() == state::recalling && observed.protected_until() == original_recall);
      observed.constrain(2000 + period, original_recall + 500);
      check(observed.expires() == 1000 + period && observed.recall_until() == original_recall);
      check(observed.renew(1200, period) && observed.protected_until() == original_recall);
      observed.expire(original_recall);
      check(observed.status() == state::revoked && observed.protected_until() == 0);
      observed.constrain(original_recall + period, 0);
      check(!observed.held() && !observed.renew(original_recall + 1, period));
      delegation_lifetime bounded(1000, period, period);
      bounded.constrain(1500, 0); bounded.expire(1500);
      check(bounded.status() == state::expired && bounded.protected_until() == 0);
    }
    std::cout << "PASS monotonic recall, expiry, return and non-resurrection boundaries\n";

    initialize(base / "state", 38443);
    auto cfg = config::load(base / "state");
    cfg.nfs_lease_seconds = 5;
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
    auto sign = [&](json g) { g.erase("signature"); g["signature"] = mac(signing, g.dump()); return g; };
    auto grant = [&] {
      return sign(json{{"actor", "alice"}, {"root", root}, {"space", space}, {"path", ""},
          {"write", true}, {"share", "nfs"}, {"epoch", epoch}, {"expires", now() + 2000},
          {"protocol", "nfs"}, {"nfs_uid", 1000}, {"nfs_gid", 1000}, {"groups", {"unix"}},
          {"export", {{"uuid", export_id}, {"uids", {{"1000", "alice"}}}, {"gids", {{"1000", "unix"}}}}}});
    };
    auto nfs = [&](std::string op, std::string handle, json body = json::object()) {
      body["op"] = op; body["handle"] = handle; body["grant"] = grant();
      body["request_id"] = random_hex(16);
      return store->dispatch("nfs_file", body, ctx());
    };
    auto native = native_file::root(base / "root");
    {
      auto f = native.open("space/cached", false, true, true);
      f.write(0, "original");
    }
    auto dir = nfs("root", "").at("handle").get<std::string>();
    auto fh = nfs("lookup", dir, {{"name", "cached"}}).at("handle").get<std::string>();
    auto control = [&](std::string op, json cookie = "", int64_t remaining = 5000) {
      return json{{"op", op}, {"cookie", cookie}, {"handle", fh}, {"client", client},
                  {"remaining_ms", remaining}, {"grant", grant()}};
    };
    auto call = [&](std::string op, json cookie = "", int64_t remaining = 5000) {
      return store->dispatch("nfs_delegation", control(op, cookie, remaining), ctx());
    };
    auto returned = [&](json cookie) {
      check(call("return", cookie).at("state") == "returned");
      check(call("return", cookie).at("state") == "returned");
      call("forget", cookie);
      rejects([&] { call("poll", cookie); }, "stale_handle");
    };
    rejects([&] { call("acquire", "", 5001); }, "invalid_request");
    rejects([&] { call("acquire", "", 0); }, "invalid_request");
    auto unauthorized = control("acquire");
    rejects([&] { store->dispatch("nfs_delegation", unauthorized, ctx("smb")); }, "forbidden");
    unauthorized["grant"]["write"] = false;
    rejects([&] { store->dispatch("nfs_delegation", unauthorized, ctx()); }, "grant_denied");
    auto d = call("acquire"); check(d.at("granted") && d.at("state") == "active");
    check(d.at("protected_until_ms") == d.at("lease_expires_ms") && d.at("recall_deadline_ms") == 0);
    auto cookie = d.at("cookie");
    auto retried = call("acquire");
    check(retried.at("cookie") == cookie && retried.at("lease_remaining_ms") <= d.at("lease_remaining_ms"));
    auto contender = control("acquire"); contender["client"] = random_hex(16);
    check(!store->dispatch("nfs_delegation", contender, ctx()).at("granted"));
    check(nfs("read", fh, {{"offset", 0}, {"count", 8}}).at("data") == encode_bytes("original"));
    check(native.metadata("space/cached").at("size") == 8);
    check(nfs("lookup", dir, {{"name", "cached"}}).at("handle") == fh);
    auto listed = nfs("list", dir).at("entries");
    check(listed.size() == 1 && listed.at(0).at("handle") == fh);
    check(call("poll", cookie).at("state") == "active");
    rejects([&] { call("forget", cookie); }, "locked");
    rejects([&] { call("poll", "wrong-cookie"); }, "stale_handle");
    for (auto field : {"actor", "path", "export"}) {
      auto b = control("return", cookie);
      if (std::string_view(field) == "actor") b["grant"][field] = "bob";
      if (std::string_view(field) == "path") b["grant"][field] = "elsewhere";
      if (std::string_view(field) == "export") b["grant"][field]["uuid"] = random_hex(16);
      b["grant"] = sign(b.at("grant"));
      rejects([&] { store->dispatch("nfs_delegation", b, ctx()); }, "forbidden");
    }
    auto other = control("return", cookie); other["client"] = random_hex(16);
    rejects([&] { store->dispatch("nfs_delegation", other, ctx()); }, "forbidden");
    other = control("return", cookie); other["handle"] = dir;
    rejects([&] { store->dispatch("nfs_delegation", other, ctx()); }, "forbidden");
    rejects([&] { native.open("space/cached", false, false, true); }, "locked");
    check(call("poll", cookie).at("state") == "recalling");
    rejects([&] { nfs("write", fh, {{"offset", 0}, {"data", encode_bytes("bad")}}); }, "cache_break_pending");
    returned(cookie);
    check(native.open("space/cached").read(0, 8) == "original");
    std::cout << "PASS native write exclusion, own filehandle reads, capability binding and explicit return\n";

#ifdef __linux__
    // The legacy component provider intentionally cannot protect namespace
    // changes. Exercise replacement there to prove lookup never trusts only
    // the delegation's cached pathname. The real F_SETDELEG guest separately
    // requires such a host rename to wait for recall and release.
    d = call("acquire"); check(d.at("granted")); cookie = d.at("cookie");
    if (d.at("provider") == "local-primitive") {
      fs::rename(base / "root/space/cached", base / "root/space/old-incarnation");
      {
        auto replacement = native.open("space/cached", false, true, true);
        replacement.write(0, "replacement");
      }
      auto current = nfs("lookup", dir, {{"name", "cached"}}).at("handle").get<std::string>();
      check(current != fh);
      check(nfs("read", current, {{"offset", 0}, {"count", 11}}).at("data") == encode_bytes("replacement"));
      returned(cookie);
      fs::remove(base / "root/space/cached");
      fs::rename(base / "root/space/old-incarnation", base / "root/space/cached");
      check(nfs("lookup", dir, {{"name", "cached"}}).at("handle") == fh);
      std::cout << "PASS pathname replacement cannot reuse a retained delegation incarnation\n";
    } else returned(cookie);
#endif

    // An expired data grant must not release a live delegation. The original
    // signed grant remains sufficient for cleanup, but never for renewal/IO.
    d = call("acquire"); check(d.at("granted")); cookie = d.at("cookie");
    auto stale = control("poll", cookie);
    stale["grant"]["expires"] = now() - 1; stale["grant"] = sign(stale.at("grant"));
    check(store->dispatch("nfs_delegation", stale, ctx()).at("state") == "active");
    stale["op"] = "renew";
    rejects([&] { store->dispatch("nfs_delegation", stale, ctx()); }, "lease_expired");
    auto bad_read = json{{"grant", stale.at("grant")}, {"op", "read"}, {"handle", fh}, {"offset", 0}, {"count", 8}};
    rejects([&] { store->dispatch("nfs_file", bad_read, ctx()); }, "lease_expired");
    rejects([&] { native.open("space/cached", false, false, true); }, "locked");
    stale["op"] = "return";
    check(store->dispatch("nfs_delegation", stale, ctx()).at("state") == "returned");
    call("forget", cookie);
    std::cout << "PASS expired access grants deny IO and renewal while retaining native protection\n";

    // An authenticated client may keep its lease live after losing data
    // authority. The old signed cookie can retain coherence only under recall.
    d = call("acquire", "", 1000); check(d.at("granted")); cookie = d.at("cookie");
    auto retained = control("retain", cookie);
    retained["grant"]["expires"] = now() - 1; retained["grant"] = sign(retained.at("grant"));
    auto foreign = retained; foreign["client"] = random_hex(16);
    rejects([&] { store->dispatch("nfs_delegation", foreign, ctx()); }, "forbidden");
    rejects([&] { store->dispatch("nfs_delegation", retained, ctx("smb")); }, "forbidden");
    d = store->dispatch("nfs_delegation", retained, ctx());
    check(d.at("granted") && d.at("state") == "recalling");
    auto recall_remaining = d.at("recall_remaining_ms").get<int64_t>();
    auto recall_deadline = d.at("recall_deadline_ms").get<int64_t>();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    d = store->dispatch("nfs_delegation", retained, ctx());
    check(d.at("granted") && d.at("recall_remaining_ms").get<int64_t>() < recall_remaining);
    check(d.at("recall_deadline_ms") == recall_deadline &&
          d.at("protected_until_ms").get<int64_t>() ==
              std::min(d.at("lease_expires_ms").get<int64_t>(), recall_deadline));
    rejects([&] { native.open("space/cached", false, false, true); }, "locked");
    retained["op"] = "renew";
    rejects([&] { store->dispatch("nfs_delegation", retained, ctx()); }, "lease_expired");
    auto denied_io = json{{"grant", retained.at("grant")}, {"op", "read"}, {"handle", fh}, {"offset", 0}, {"count", 8}};
    rejects([&] { store->dispatch("nfs_file", denied_io, ctx()); }, "lease_expired");
    retained["op"] = "return";
    check(store->dispatch("nfs_delegation", retained, ctx()).at("state") == "returned");
    retained["op"] = "retain";
    rejects([&] { store->dispatch("nfs_delegation", retained, ctx()); }, "stale_handle");
    call("forget", cookie);
    std::cout << "PASS expired cleanup capability retains coherence through fixed recall without authorizing IO or resurrecting state\n";

    d = call("acquire"); check(d.at("granted")); cookie = d.at("cookie");
    auto smb = [&](std::string op, json body) {
      auto g = grant(); g["protocol"] = "smb"; g["share"] = "smb"; g["path"] = "cached";
      body["grant"] = sign(g);
      return store->dispatch("smb_" + op, body, ctx("smb"));
    };
    json open_body = {{"access", 0x13019f}, {"sharing", 7}, {"disposition", 1}, {"options", 0x40}};
    rejects([&] { smb("open", open_body); }, "cache_break_pending");
    check(call("poll", cookie).at("state") == "recalling");
    returned(cookie);
    auto h = smb("open", open_body).at("handle");
    check(!call("acquire").at("granted"));
    smb("close", {{"handle", h}});
    std::cout << "PASS SMB conflict recalls before open and existing SMB opens prevent handout\n";

    for (const std::string protocol : {"webdav", "ftp"}) {
      d = call("acquire"); check(d.at("granted")); cookie = d.at("cookie");
      auto b = json{{"write", true}};
      auto g = grant(); g["protocol"] = protocol; g["share"] = protocol; g["path"] = "cached";
      b["grant"] = sign(g);
      rejects([&] { store->dispatch("open", b, ctx(protocol)); }, "cache_break_pending");
      check(call("poll", cookie).at("state") == "recalling");
      returned(cookie);
      b["grant"] = grant(); b["grant"]["protocol"] = protocol;
      b["grant"]["share"] = protocol; b["grant"]["path"] = "cached"; b["grant"] = sign(b["grant"]);
      auto opened = store->dispatch("open", b, ctx(protocol));
      check(!call("acquire").at("granted"));
      store->dispatch(protocol == "ftp" ? "ftp_close" : "dav_close",
          {{"grant", b["grant"]}, {"handle", opened.at("handle")}}, ctx(protocol));
    }
    std::cout << "PASS DAV and FTP writes recall before opening; their live handles prevent handout\n";

    auto read_only = control("acquire");
    read_only["grant"]["write"] = false; read_only["grant"] = sign(read_only["grant"]);
    d = store->dispatch("nfs_delegation", read_only, ctx());
    check(d.at("granted")); cookie = d.at("cookie");
    auto forbidden_write = json{{"grant", read_only["grant"]}, {"op", "write"}, {"handle", fh},
        {"offset", 0}, {"data", encode_bytes("bad")}, {"request_id", random_hex(16)}};
    rejects([&] { store->dispatch("nfs_file", forbidden_write, ctx()); }, "forbidden");
    check(call("poll", cookie).at("state") == "active");
    returned(cookie);
    nfs("setattr", fh, {{"mode", 0600}});
    auto denied = control("acquire"); denied["grant"]["actor"] = "bob";
    denied["grant"] = sign(denied["grant"]);
    rejects([&] { store->dispatch("nfs_delegation", denied, ctx()); }, "forbidden");
    std::cout << "PASS native exclusive protection adds no write authority and handout still checks the file ACL\n";

    d = call("acquire"); check(d.at("granted")); cookie = d.at("cookie");
    call("recall", cookie);
    auto started = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - started < std::chrono::milliseconds(4200)) {
      check(call("renew", cookie).at("state") == "recalling");
      check(call("recall", cookie).at("state") == "recalling");
      rejects([&] { native.open("space/cached", false, false, true); }, "locked");
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    call("renew", cookie);
    std::this_thread::sleep_until(started + std::chrono::milliseconds(5200));
    store->maintain();
    check(call("poll", cookie).at("state") == "revoked");
    rejects([&] { call("renew", cookie); }, "stale_handle");
    check(call("return", cookie).at("state") == "revoked");
    check(native.open("space/cached").read(0, 8) == "original");
    call("forget", cookie);
    std::cout << "PASS fixed recall deadline revokes despite continuous client renewal\n";

    d = call("acquire", "", 1000); check(d.at("granted")); cookie = d.at("cookie");
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    store->maintain();
    check(call("poll", cookie).at("state") == "expired");
    rejects([&] { call("renew", cookie); }, "stale_handle");
    check(native.open("space/cached").read(0, 8) == "original");
    call("forget", cookie);
    std::cout << "PASS autonomous client expiry releases exclusion without protocol traffic\n";

    d = call("acquire"); check(d.at("granted")); cookie = d.at("cookie");
    auto old = control("poll", cookie);
    store->dispatch("revoke", {{"epoch", 3}}, ctx("identity"));
    check(store->dispatch("nfs_delegation", old, ctx()).at("state") == "recalling");
    rejects([&] { call("renew", cookie); }, "policy_revoked");
    rejects([&] { nfs("read", fh, {{"offset", 0}, {"count", 8}}); }, "policy_revoked");
    rejects([&] { native.open("space/cached", false, false, true); }, "locked");
    old["op"] = "return";
    check(store->dispatch("nfs_delegation", old, ctx()).at("state") == "returned");
    epoch = 3; call("forget", cookie);
    check(native.open("space/cached").read(0, 8) == "original");
    std::cout << "PASS policy revocation denies data immediately and preserves protection until return\n";
    store.reset();
    native = native_file();
    fs::remove_all(base);
    std::cout << "PASS " << checks << " NFS delegation native/lifecycle checks\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << " after_checks=" << checks << " fixture=" << base << '\n';
    return 1;
  }
}
