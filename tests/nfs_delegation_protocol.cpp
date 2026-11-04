#include <taucloud/files.hpp>
#include <taucloud/native_delegation_owner.hpp>
#include <taucloud/nfs.hpp>
#include <deque>
#include <iostream>
#include <source_location>
#include <thread>
using namespace tc;
using namespace tc::nfs_detail;
int main(int argc, char **argv) {
  if (auto result = tc::native_delegation_owner::entry(argc, argv); result >= 0) return result;
  int checks = 0;
  auto base = fs::temp_directory_path() / ("tc-nfs-delegation-protocol-" + random_hex(6));
  auto ok = [&](bool value, std::source_location loc = std::source_location::current()) {
    if (!value) std::cerr << "failed_line=" << loc.line() << '\n';
    require(value, "delegation_protocol_test_failed"); ++checks;
  };
  try {
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
    auto export_id = random_hex(16);
    auto grant = [&](uint32_t uid = 1000, bool discovery = false) {
      json g = {{"actor", uid == 1000 ? "alice" : "bob"}, {"root", root}, {"space", space}, {"path", ""},
          {"write", !discovery}, {"share", "nfs"}, {"epoch", 2}, {"expires", now() + 2000},
          {"protocol", "nfs"}, {"nfs_uid", uid}, {"nfs_gid", 1000}, {"groups", {"unix"}},
          {"export", {{"uuid", export_id}, {"uids", {{"1000", "alice"}, {"1001", "bob"}}},
                      {"gids", {{"1000", "unix"}}}}}};
      if (discovery) g["security_discovery"] = true;
      g["signature"] = mac(signing, g.dump()); return g;
    };
    auto nfs = [&](std::string op, std::string handle, json body = json::object()) {
      body["grant"] = grant(); body["op"] = op; body["handle"] = handle; body["request_id"] = random_hex(16);
      return store->dispatch("nfs_file", body, ctx());
    };
    auto directory = nfs("root", "").at("handle").get<std::string>();
    auto handle = nfs("create", directory, {{"name", "file"}}).at("handle").get<std::string>();
    nfs("write", handle, {{"offset", 0}, {"data", encode_bytes("original")}});
    auto native = native_file::root(base / "root");
    bool component_provider = false, authorized = true, slow_read = false;
    std::deque<std::pair<std::string, std::string>> callbacks;
    std::vector<std::string> closes;
    auto protocol = std::make_unique<server>(cfg, [&](std::string target, std::string op, json body) -> json {
      if (target == "identity") {
        require(authorized, "forbidden");
        return grant(body.at("credential").value("uid", 1000u), body.value("security_discovery", false));
      }
      if (target != "file") return json::object();
      // Test-only provider injection. The production file domain's wire gate
      // is first tested below, then this component fixture supplies its native
      // primitive. This does NOT prove host metadata or crash-safe handout.
      if (component_provider && op == "nfs_delegation") body.erase("wire");
      auto result = store->dispatch(op, body, ctx());
      if (slow_read && op == "nfs_file" && body.value("op", "") == "read") {
        slow_read = false;
        std::this_thread::sleep_for(std::chrono::milliseconds(3500));
      }
      return result;
    }, callback_call{}, [&](auto connection, auto packet) { callbacks.emplace_back(connection, packet); },
       [&](auto connection) { closes.push_back(connection); });
    struct peer { std::string connection, session; uint64_t client = 0; uint32_t sequence = 0, uid = 1000; };
    uint32_t xid = 0, last_flags = 0;
    std::string last_request, last_response;
    auto send = [&](peer &p, std::vector<writer> operations, uint32_t expected = 0, bool session = true) {
      writer auth;
      auth.u32(1).opaque("component").u32(p.uid).u32(1000).u32(0);
      writer request;
      request.u32(++xid).u32(0).u32(2).u32(100003).u32(4).u32(1).u32(1).opaque(auth.data)
          .u32(0).opaque("").opaque("").u32(1).u32(uint32_t(operations.size()) + (session ? 1 : 0));
      if (session) request.u32(53).fixed(p.session).u32(++p.sequence).u32(0).u32(0).boolean(true);
      for (auto &operation : operations) request.fixed(operation.data);
      last_request = request.data;
      auto response = protocol->dispatch(request.data, p.connection);
      last_response = response;
      reader r(response);
      ok(r.u32() == xid && r.u32() == 1 && r.u32() == 0 && r.u32() == 0 && r.opaque().empty() && r.u32() == 0);
      auto status = r.u32();
      if (status != expected) std::cerr << "expected_status=" << expected << " actual=" << status << '\n';
      ok(status == expected && r.opaque().empty());
      auto count = r.u32();
      if (session) {
        ok(count >= 1 && r.u32() == 53);
        auto sequence_status = r.u32();
        if (sequence_status) { ok(sequence_status == expected && count == 1); r.end(); return std::string(); }
        ok(r.fixed(16) == p.session && r.u32() == p.sequence && r.u32() == 0);
        r.u32(); r.u32(); last_flags = r.u32(); --count;
      }
      for (uint32_t i = 0; i < count; ++i) {
        reader asked(operations.at(i).data);
        auto operation = asked.u32();
        ok(r.u32() == operation);
        auto result = r.u32();
        ok(result == (i + 1 == count ? expected : 0));
        if (i + 1 == count) return response.substr(r.pos);
        ok(operation == 22); // All intermediate operations here are PUTFH.
      }
      r.end(); return std::string();
    };
    auto connect = [&](std::string connection) {
      peer p{connection, ""};
      auto result = send(p, {writer().u32(42).fixed("12345678").opaque(connection).u32(0).u32(0).u32(0)}, 0, false);
      reader r(result); p.client = r.u64(); auto sequence = r.u32();
      writer create;
      create.u32(43).u64(p.client).u32(sequence).u32(2);
      for (int i = 0; i < 2; ++i) create.u32(0).u32(8192).u32(8192).u32(8192).u32(16).u32(4).u32(0);
      create.u32(0x40000004).u32(1).u32(0);
      result = send(p, {create}, 0, false); reader session(result); p.session = session.fixed(16);
      send(p, {writer().u32(58).boolean(false)});
      return p;
    };
    struct callback { std::string connection, session, state, file, packet; uint32_t xid, sequence = 0, operation = 0; bool compound; };
    auto receive_callback = [&] {
      ok(!callbacks.empty());
      auto [connection, packet] = callbacks.front(); callbacks.pop_front();
      reader r(packet); callback c{connection, "", "", "", packet, r.u32(), 0, 0, false};
      ok(r.u32() == 0 && r.u32() == 2 && r.u32() == 0x40000004 && r.u32() == 1);
      c.compound = r.u32() != 0; ok(r.u32() == 0 && r.opaque().empty() && r.u32() == 0 && r.opaque().empty());
      if (c.compound) {
        ok(r.opaque().empty() && r.u32() == 1 && r.u32() == 0);
        auto count = r.u32(); ok(count == 1 || count == 2); ok(r.u32() == 11);
        c.session = r.fixed(16); c.sequence = r.u32();
        ok(r.u32() == 0 && r.u32() == 0 && !r.boolean() && r.u32() == 0);
        if (count == 2) {
          c.operation = r.u32(); ok(c.operation == 4);
          c.state = r.fixed(16); ok(!r.boolean()); c.file = r.opaque(64);
        }
      }
      r.end(); return c;
    };
    auto reply_callback = [&](const callback &c, uint32_t status = 0, uint32_t override_op = 0) {
      writer result;
      result.u32(c.xid).u32(1).u32(0).u32(0).opaque("").u32(0);
      if (c.compound) {
        result.u32(status).opaque("").u32(c.operation ? 2 : 1).u32(11).u32(0).fixed(c.session)
            .u32(c.sequence).u32(0).u32(0).u32(0);
        if (c.operation) result.u32(override_op ? override_op : c.operation).u32(status);
      }
      ok(protocol->dispatch(result.data, c.connection).empty());
    };
    auto establish_callback = [&] {
      auto null = receive_callback(); ok(!null.compound); reply_callback(null);
      auto sequence = receive_callback(); ok(sequence.compound && !sequence.operation); reply_callback(sequence);
      ok(callbacks.empty());
    };
    auto put = [&](std::string h = "") { return writer().u32(22).opaque(decode_bytes(h.empty() ? handle : h)); };
    auto opening = [&](peer &p, uint32_t access, std::string delegated = "") {
      writer operation;
      operation.u32(18).u32(0).u32(access).u32(0).u64(p.client).opaque("owner").u32(0)
          .u32(delegated.empty() ? 4 : 5);
      if (!delegated.empty()) operation.fixed(delegated);
      return operation;
    };
    auto open_result = [&](const std::string &result, uint32_t expected_delegation) {
      reader r(result); auto state = r.fixed(16);
      r.boolean(); r.u64(); r.u64(); r.u32(); auto words = r.u32(); while (words--) r.u32();
      auto type = r.u32(); ok(type == expected_delegation);
      std::string delegated;
      if (type == 1) {
        delegated = r.fixed(16); ok(!r.boolean());
        ok(r.u32() == 1 && r.u32() == 0 && r.u32() == 0x1f01ff && r.opaque() == "EVERYONE@");
      } else if (type == 3) { ok(r.u32() == 2 && !r.boolean()); }
      r.end(); return std::pair{state, delegated};
    };
    auto held = [&] {
      bool locked = false;
      try { native.open("space/file", false, false, true); }
      catch (const error &e) { locked = std::string_view(e.what()) == "locked"; }
      ok(locked);
    };
    auto a = connect("one"); establish_callback();
    auto refused = open_result(send(a, {put(), opening(a, 0x101)}), 3);
    slow_read = true;
    send(a, {put(), writer().u32(25).fixed(refused.first).u64(0).u32(8)});
    ok(!slow_read);
    std::this_thread::sleep_for(std::chrono::milliseconds(1800));
    send(a, {put(), writer().u32(25).fixed(refused.first).u64(0).u32(8)});
    send(a, {put(), writer().u32(4).u32(0).fixed(refused.first)});
    ok(native.open("space/file").read(0, 8) == "original");
    std::cout << "PASS production file authority declines wire handout without creating a hidden native guard\n";
    std::cout << "PASS slow COMPOUND completion preserves a full client lease after execution\n";
    component_provider = true;
    auto opened = open_result(send(a, {put(), opening(a, 0x101)}), 1);
    auto state = opened.first, delegated = opened.second;
    ok(state != delegated);
    auto request = last_request;
    auto replay = protocol->dispatch(request, a.connection);
    ok(replay == last_response);
    // Lease maintenance for Alice must not add her file scope to Bob's empty
    // compound cache entry on a shared AUTH_SYS session.
    a.uid = 1001; send(a, {});
    ok(protocol->dispatch(last_request, a.connection) == last_response);
    a.uid = 1000;
    auto upgrade = send(a, {put(), writer().u32(56).u32(0x200).u32(4)});
    reader not_upgraded(upgrade); ok(not_upgraded.u32() == 3 && not_upgraded.u32() == 5); not_upgraded.end();
    send(a, {writer().u32(45).fixed(delegated)}, 10037);
    send(a, {put(), writer().u32(38).fixed(delegated).u64(0).u32(2).opaque("bad")}, 10038);
    send(a, {put(directory), writer().u32(8).fixed(delegated)}, 10025);
    a.uid = 1001;
    send(a, {put(), writer().u32(8).fixed(delegated)}, 10025);
    a.uid = 1000;
    auto b = connect("other"); establish_callback();
    send(b, {put(), writer().u32(8).fixed(delegated)}, 10025);
    auto materialized = open_result(send(a, {put(), opening(a, 1, delegated)}), 1);
    state = materialized.first; ok(materialized.second == delegated);
    send(a, {put(), writer().u32(4).u32(0).fixed(state)});
    auto data = send(a, {put(), writer().u32(25).fixed(delegated).u64(0).u32(8)});
    reader read(data); ok(read.boolean() && read.opaque() == "original"); read.end();
    protocol->disconnect(a.connection); a.connection = "reconnected";
    send(a, {put(), writer().u32(25).fixed(delegated).u64(0).u32(8)});
    send(a, {put(), writer().u32(8).fixed(delegated)});
    ok(native.open("space/file").read(0, 8) == "original");
    send(a, {put(), writer().u32(8).fixed(delegated)}, 10025);
    std::cout << "PASS distinct delegation state, CLAIM_DELEG_CUR_FH, CLOSE/disconnect independence and client/principal/file/access checks\n";

    // Rebind a backchannel after ordinary transport loss, retaining the same
    // client and session. No delegation is coupled to the old TCP connection.
    auto back = a; back.connection = "back-reconnected";
    send(back, {writer().u32(41).fixed(a.session).u32(2).boolean(false)}, 0, false);
    establish_callback();
    auto want = send(a, {put(), writer().u32(56).u32(0x100).u32(4)});
    reader granted(want); ok(granted.u32() == 1); delegated = granted.fixed(16);
    request = last_request;
    auto first_replay = protocol->dispatch(request, a.connection);
    ok(first_replay == last_response && protocol->dispatch(request, a.connection) == first_replay);
    send(b, {put(), opening(b, 3)}, 10008);
    protocol->maintenance();
    auto recall = receive_callback(); ok(recall.operation == 4 && recall.state == delegated && recall.file == decode_bytes(handle));
    reply_callback(recall, 10008);
    held();
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); protocol->maintenance();
    auto retry = receive_callback(); ok(retry.sequence == recall.sequence + 1 && retry.state == delegated);
    reply_callback(retry);
    held();
    send(b, {put(), opening(b, 3)}, 10008);
    send(a, {put(), writer().u32(8).fixed(delegated)});
    auto writer_open = open_result(send(b, {put(), opening(b, 3)}), 0);
    send(b, {put(), writer().u32(4).u32(0).fixed(writer_open.first)});
    std::cout << "PASS WANT replay, typed CB_RECALL, definitive DELAY retry and acknowledgment without premature release\n";

    want = send(a, {put(), writer().u32(56).u32(0x100).u32(4)});
    reader uncertain_grant(want); ok(uncertain_grant.u32() == 1); delegated = uncertain_grant.fixed(16);
    send(b, {put(), opening(b, 3)}, 10008);
    protocol->maintenance(); recall = receive_callback();
    reply_callback(recall, 0, 13); // Wrong CB_NOTIFY_LOCK arm for CB_RECALL.
    ok(!closes.empty() && closes.back() == recall.connection);
    held(); protocol->maintenance(); ok(callbacks.empty());
    auto replacement = a; replacement.connection = "retry-back";
    send(replacement, {writer().u32(41).fixed(a.session).u32(2).boolean(false)}, 0, false);
    auto null = receive_callback(); ok(!null.compound); reply_callback(null);
    ok(callbacks.empty()); // Closing the original path is still unconfirmed.
    protocol->disconnect(recall.connection); protocol->maintenance();
    retry = receive_callback();
    ok(retry.connection == replacement.connection && retry.sequence == recall.sequence &&
       retry.packet.substr(40) == recall.packet.substr(40));
    reply_callback(retry); held();
    send(a, {put(), writer().u32(8).fixed(delegated)});
    std::cout << "PASS wrong callback operation preserves the exact slot until confirmed disconnect and replays on a replacement backchannel\n";

    opened = open_result(send(a, {put(), opening(a, 0x101)}), 1);
    state = opened.first; delegated = opened.second;
    send(b, {put(), opening(b, 3)}, 10008);
    protocol->maintenance(); recall = receive_callback(); reply_callback(recall);
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(5400)) {
      send(a, {writer().u32(55).u32(1).fixed(delegated)});
      protocol->maintenance(); std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    auto tested = send(a, {writer().u32(55).u32(1).fixed(delegated)});
    reader statuses(tested); ok(statuses.u32() == 1 && statuses.u32() == 10087); statuses.end();
    ok(last_flags & 0x40);
    send(a, {put(), writer().u32(25).fixed(delegated).u64(0).u32(8)}, 10087);
    send(a, {put(), writer().u32(25).fixed(state).u64(0).u32(8)});
    send(a, {writer().u32(45).fixed(delegated)});
    send(a, {writer().u32(55).u32(1).fixed(delegated)});
    ok(!(last_flags & 0x40));
    send(a, {put(), writer().u32(4).u32(0).fixed(state)});
    std::cout << "PASS recall deadline survives continued renewals; TEST_STATEID/FREE_STATEID acknowledge revocation while OPEN remains valid\n";

    want = send(a, {put(), writer().u32(56).u32(0x100).u32(4)});
    reader final_grant(want); ok(final_grant.u32() == 1); delegated = final_grant.fixed(16);
    std::this_thread::sleep_for(std::chrono::milliseconds(3500));
    authorized = false;
    // SEQUENCE attempts a fresh renewal, notices policy loss and recalls using
    // the original signed cleanup capability. DELEGRETURN remains possible.
    send(a, {writer().u32(55).u32(1).fixed(delegated)});
    protocol->maintenance(); recall = receive_callback(); reply_callback(recall);
    held();
    std::this_thread::sleep_for(std::chrono::milliseconds(1800));
    send(a, {writer().u32(55).u32(1).fixed(delegated)});
    protocol->maintenance(); held();
    ok(protocol->dispatch(last_request, a.connection) == last_response);
    send(a, {put(), writer().u32(8).fixed(delegated)});
    authorized = true;
    ok(native.open("space/file").read(0, 8) == "original");
    std::cout << "PASS authority loss renews coherence past the old lease under fixed recall and still permits authenticated return\n";
    // Renew via the backchannel alone, then use a sibling session that has
    // stayed idle longer than its initial lease interval.
    auto sibling = a; sibling.connection = "lease-sibling"; sibling.sequence = 0;
    writer sibling_session;
    sibling_session.u32(43).u64(a.client).u32(2).u32(0);
    for (int i = 0; i < 2; ++i) sibling_session.u32(0).u32(8192).u32(8192).u32(8192).u32(16).u32(4).u32(0);
    sibling_session.u32(0).u32(0);
    auto sibling_created = send(sibling, {sibling_session}, 0, false);
    reader sibling_result(sibling_created); sibling.session = sibling_result.fixed(16);
    auto lease_back = a; lease_back.connection = "lease-callback";
    send(lease_back, {writer().u32(41).fixed(a.session).u32(2).boolean(false)}, 0, false);
    auto lease_null = receive_callback(); ok(!lease_null.compound); reply_callback(lease_null);
    auto lease_sequence = receive_callback(); ok(lease_sequence.compound && !lease_sequence.operation);
    std::this_thread::sleep_for(std::chrono::milliseconds(3500)); reply_callback(lease_sequence);
    std::this_thread::sleep_for(std::chrono::milliseconds(1800)); send(sibling, {});
    send(a, {});
    std::cout << "PASS validated CB_SEQUENCE renewal keeps an idle sibling session alive beyond its original lease\n";
    auto orphan = connect("orphan"); establish_callback();
    want = send(orphan, {put(), writer().u32(56).u32(0x100).u32(4)});
    reader detached(want); ok(detached.u32() == 1); delegated = detached.fixed(16);
    send(orphan, {writer().u32(44).fixed(orphan.session)});
    send(orphan, {writer().u32(57).u64(orphan.client)}, 10074, false);
    peer thief{"thief", "", 0, 0, 1001};
    send(thief, {writer().u32(42).fixed("87654321").opaque("orphan").u32(0).u32(0).u32(0)}, 10017, false);
    writer replacement_session;
    replacement_session.u32(43).u64(orphan.client).u32(2).u32(2);
    for (int i = 0; i < 2; ++i) replacement_session.u32(0).u32(8192).u32(8192).u32(8192).u32(16).u32(4).u32(0);
    replacement_session.u32(0x40000004).u32(1).u32(0);
    auto created = send(orphan, {replacement_session}, 0, false);
    reader recreated(created); orphan.session = recreated.fixed(16); orphan.sequence = 0;
    establish_callback();
    send(orphan, {put(), writer().u32(8).fixed(delegated)});
    send(orphan, {writer().u32(44).fixed(orphan.session)});
    send(orphan, {writer().u32(57).u64(orphan.client)}, 0, false);
    std::cout << "PASS session destruction retains client-owned delegation; foreign owner replacement and premature client destruction are refused\n";
    std::cout << "PASS " << checks << " delegation protocol/native component checks; production handout remains gated\n";
    // Keep destruction order explicit: protocol has no live delegations here.
    native = native_file(); protocol.reset(); store.reset();
    fs::remove_all(base);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << " checks=" << checks << " fixture=" << base << '\n'; return 1;
  }
}
