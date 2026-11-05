#include <taucloud/files.hpp>
#include <taucloud/database.hpp>
#include <taucloud/native_delegation_owner.hpp>
#include <taucloud/nfs.hpp>
#include <taucloud/nfs_output_queue.hpp>
#include <taucloud/runtime/priority_mutex.hpp>
#include <deque>
#include <atomic>
#include <iostream>
#include <source_location>
#include <set>
#include <thread>
#include <future>
#include <latch>
#ifdef __linux__
#include <csignal>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
using namespace tc;
using namespace tc::nfs_detail;
int nfs_delegation_protocol_suite(bool require_native = false) {
  int checks = 0;
  auto base = fs::temp_directory_path() / ("tc-nfs-delegation-protocol-" + random_hex(6));
  auto ok = [&](bool value, std::source_location loc = std::source_location::current()) {
    if (!value) std::cerr << "failed_line=" << loc.line() << '\n';
    require(value, "delegation_protocol_test_failed"); ++checks;
  };
  try {
    {
      callback_delivery sent(1000);
      ok(sent.deadline() == 6000 && !sent.expire_send(5999));
      ok(sent.finish(4000) && sent.deadline() == 9000);
      ok(!sent.expire_send(6000));
      ok(!sent.finish(7000) && sent.deadline() == 9000);
      callback_delivery stalled(1000);
      ok(stalled.expire_send(6000) && stalled.deadline() == 0);
      ok(!stalled.finish(5999) && !stalled.finish(7000) && stalled.deadline() == 0);
      callback_delivery late(1000);
      ok(!late.finish(6000) && late.deadline() == 0);
      callback_delivery boundary(1000);
      ok(boundary.finish(5999) && boundary.deadline() == 10999);
      for (unsigned i = 0; i < 16; ++i) {
        callback_delivery racing(1000);
        std::latch start(3);
        bool sent = false;
        std::jthread writer([&] { start.count_down(); start.wait(); sent = racing.finish(5999); });
        std::jthread timeout([&] { start.count_down(); start.wait(); racing.expire_send(6000); });
        start.count_down(); writer.join(); timeout.join();
        ok(racing.deadline() == (sent ? 10999 : 0));
        ok(!racing.finish(7000) && racing.deadline() == (sent ? 10999 : 0));
      }
      auto owner = std::make_shared<callback_delivery>(1000);
      output_queue queue;
      ok(queue.push({"retired-probe", 0, true, owner}));
      owner.reset();
      ok(queue.start().delivery.expired());
      ok(queue.finish() == 0 && queue.empty());
    }
    std::cout << "PASS callback delivery starts one response window, bounds unsent lifetime and cancels retired queued frames\n";
    {
      output_queue queue;
      std::set<uint64_t> completed;
      auto complete = [&](uint64_t id) { ok(completed.insert(id).second); };
      ok(queue.push({"partial-frame", 1}));
      const auto &active = queue.start();
      for (uint64_t i = 2; i <= 16; ++i) ok(queue.push({"ordinary", i}));
      ok(!queue.push({"over-normal-limit", 99}));
      for (uint64_t i = 100; i < 104; ++i) ok(queue.push({"callback", i, true}));
      ok(!queue.push({"over-callback-limit", 199, true}));
      ok(active.packet == "partial-frame" && active.completion == 1);
      // Priority may not replace an in-progress frame. Its budget and token
      // remain owned until write completion or cancellation.
      bool interleaved = false;
      try { queue.start(); } catch (const error &) { interleaved = true; }
      ok(interleaved); complete(queue.finish());
      for (uint64_t i = 100; i < 104; ++i) {
        ok(queue.start().completion == i); complete(queue.finish());
        ok(queue.push({"continuing-callback-traffic", i + 4, true}));
      }
      ok(queue.start().completion == 2); // Four callbacks cannot starve data.
      queue.drain(complete); // Includes active frame and both waiting classes.
      ok(queue.empty() && completed.size() == 24);
      for (uint64_t i = 1; i <= 16; ++i) ok(completed.contains(i));
      for (uint64_t i = 100; i < 108; ++i) ok(completed.contains(i));
      queue.drain(complete); ok(completed.size() == 24);
      ok(queue.push({"after-disconnect-cleanup", 200, true}));
      queue.drain(complete); ok(completed.contains(200));
    }
    {
      output_queue queue;
      for (uint64_t i = 1; i <= 4; ++i) ok(queue.push({std::string(max_record, 'd'), i}));
      queue.start(); // Moving to the writer must not free its byte budget.
      ok(!queue.push({"one-byte-too-many", 9}));
      ok(queue.push({std::string(max_record, 'c'), 5, true}));
      ok(!queue.push({"x", 10, true}));
      ok(!queue.push({std::string(max_record + 1, 'x'), 11, true}));
      ok(!queue.push({"", 12}));
      ok(queue.finish() == 1);
      ok(queue.push({std::string(max_record, 'r'), 6}));
      std::set<uint64_t> completed;
      queue.drain([&](uint64_t id) { ok(completed.insert(id).second); });
      ok((completed == std::set<uint64_t>{2, 3, 4, 5, 6}));
      ok(queue.empty());
    }
    std::cout << "PASS outbound callback reservation, frame integrity, bounded priority, in-flight byte accounting and exact completion cleanup\n";
    for (const auto &[priority, normal] : {std::pair{3u, 2u}, {8u, 2u}, {0u, 4u}, {8u, 0u}}) {
      taucloud::priority_mutex gate;
      std::vector<bool> order; order.reserve(priority + normal);
      std::vector<std::jthread> workers;
      std::unique_lock held(gate);
      auto enqueue = [&](bool control) {
        workers.emplace_back([&, control] {
          auto lock = gate.enter(control);
          order.push_back(control);
        });
      };
      // Queue normal work first, then callbacks, while neither can run.
      for (unsigned i = 0; i < normal; ++i) enqueue(false);
      for (unsigned i = 0; i < priority; ++i) enqueue(true);
      auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
      while (gate.pending() != std::pair{normal, priority} && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      bool ready = gate.pending() == std::pair{normal, priority};
      held.unlock(); workers.clear();
      ok(ready && order.size() == priority + normal);
      unsigned controls = 0, ordinary = 0, burst = 0;
      for (bool control : order) {
        if (control) {
          ok(ordinary == normal || burst < 4);
          ++controls; ++burst;
        } else {
          ok(controls == priority || burst == 4);
          ++ordinary; burst = 0;
        }
      }
      ok(controls == priority && ordinary == normal && gate.pending() == std::pair{0u, 0u});
      try { auto lock = gate.enter(true); throw error("gate-release"); }
      catch (const error &e) { ok(std::string_view(e.what()) == "gate-release"); }
      std::lock_guard acquired_after_exception(gate);
    }
    std::cout << "PASS callback dispatch priority precedes queued ordinary work, bounds bursts and releases on exceptions\n";
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
    nfs("create", directory, {{"name", "other"}});
    nfs("write", handle, {{"offset", 0}, {"data", encode_bytes("original")}});
    auto native = native_file::root(base / "root");
    bool component_provider = false, authorized = true, slow_read = false;
    unsigned authorizations = 0, prepare_failures = 0, prepared_mutations = 0;
    bool revoke_on_prepare = false;
    std::string prepare_error = "grant_refresh_required";
    std::string prepare_operation = "mkdir";
    std::vector<json> prepare_requests;
    std::vector<unsigned> prepare_authorizations;
    std::atomic_bool slow_read_entered = false;
    std::atomic_bool blocked_renewal = false, renewal_entered = false;
    json private_delegation;
    json reservation_capability;
    bool independent_owner = false;
    std::deque<std::pair<std::string, std::string>> callbacks;
    std::vector<std::string> closes;
    server *network = nullptr;
    unsigned adoption_fault = 0;
    auto domain = [&](std::string target, std::string op, json body) -> json {
      if (target == "identity") {
        ++authorizations;
        require(authorized, "forbidden");
        return grant(body.at("credential").value("uid", 1000u), body.value("security_discovery", false));
      }
      if (target != "file") return json::object();
      if (op == "nfs_file" && body.value("op", "") == prepare_operation) {
        auto recorded = body; recorded.erase("grant");
        prepare_requests.push_back(std::move(recorded));
        prepare_authorizations.push_back(authorizations);
        if (prepare_failures) {
          --prepare_failures;
          if (revoke_on_prepare) authorized = false;
          throw error(prepare_error);
        }
        ++prepared_mutations;
      }
      // Test-only provider injection. The production file domain's wire gate
      // is first tested below, then this component fixture supplies its native
      // primitive. This does NOT prove host metadata or crash-safe handout.
      if (component_provider && op == "nfs_delegation") body.erase("wire");
      if (blocked_renewal && op == "nfs_delegation" && body.value("op", "") == "renew") {
        renewal_entered = true;
        while (blocked_renewal) std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      if (op == "nfs_delegation" && body.value("op", "") == "adopt" && adoption_fault == 1) {
        adoption_fault = 0; throw error("delegation_recovery_failed");
      }
      auto result = store->dispatch(op, body, ctx());
      if (op == "nfs_delegation" && body.value("op", "") == "channel" && adoption_fault == 3) {
        adoption_fault = 0; throw error("io_error");
      }
      if (op == "nfs_delegation" && body.value("op", "") == "adopt" && adoption_fault == 2) {
        adoption_fault = 0; throw error("io_error");
      }
      if (op == "nfs_delegation" && body.value("op", "") == "return" && independent_owner)
        ok(network->poll_native()); // Deliberate return closes its owner channel before the file RPC ACK.
      if (op == "nfs_delegation" && body.value("op", "") == "channel")
        reservation_capability = result.at("reservation_capability");
      if (op == "nfs_delegation" && body.value("op", "") == "acquire" && result.at("granted")) {
        private_delegation = body; private_delegation["cookie"] = result.at("cookie");
        private_delegation["op"] = "poll";
        independent_owner = result.at("provider") == "independent-owner";
      }
      if (slow_read && op == "nfs_file" && body.value("op", "") == "read") {
        slow_read = false;
        slow_read_entered = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(3500));
      }
      return result;
    };
    auto server_cfg = cfg;
    std::unique_ptr<server> protocol;
    auto restart_protocol = [&] {
      protocol.reset(); network = nullptr; callbacks.clear(); closes.clear();
      protocol = std::make_unique<server>(server_cfg, domain, callback_call{},
          [&](auto connection, auto packet, auto delivery) {
            callbacks.emplace_back(connection, packet); ok(delivery->finish());
          }, [&](auto connection) { closes.push_back(connection); });
      network = protocol.get();
    };
    restart_protocol();
    struct peer { std::string connection, session; uint64_t client = 0; uint32_t sequence = 0, uid = 1000; };
    uint32_t xid = 0, last_flags = 0;
    bool track_reply = false;
    uint64_t completion = 0, admission = 0;
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
      auto received = admission; admission = 0;
      auto response = protocol->dispatch(request.data, p.connection, track_reply ? &completion : nullptr, received);
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
    auto connect = [&](std::string connection, bool complete = true, uint32_t uid = 1000,
                       std::string verifier = "12345678") {
      peer p{connection, "", 0, 0, uid};
      auto result = send(p, {writer().u32(42).fixed(verifier).opaque(connection).u32(0).u32(0).u32(0)}, 0, false);
      reader r(result); p.client = r.u64(); auto sequence = r.u32();
      writer create;
      create.u32(43).u64(p.client).u32(sequence).u32(2);
      for (int i = 0; i < 2; ++i) create.u32(0).u32(8192).u32(8192).u32(8192).u32(16).u32(4).u32(0);
      create.u32(0x40000004).u32(1).u32(0);
      result = send(p, {create}, 0, false); reader session(result); p.session = session.fixed(16);
      if (complete) send(p, {writer().u32(58).boolean(false)});
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
    auto named_claim = [&](peer &p, const std::string &delegated,
                           const std::string &name = "file", uint32_t access = 1) {
      return writer().u32(18).u32(0).u32(access).u32(0).u64(p.client).opaque("named-owner")
          .u32(0).u32(2).fixed(delegated).opaque(name);
    };
    auto open_result = [&](const std::string &result, uint32_t expected_delegation, bool recalling = false) {
      reader r(result); auto state = r.fixed(16);
      r.boolean(); r.u64(); r.u64(); r.u32(); auto words = r.u32(); while (words--) r.u32();
      auto type = r.u32(); ok(type == expected_delegation);
      std::string delegated;
      if (type == 1) {
        delegated = r.fixed(16); ok(r.boolean() == recalling);
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
    auto mkdir = [&](std::string name, unsigned expected = 0) {
      prepare_requests.clear(); prepare_authorizations.clear(); prepared_mutations = 0;
      return send(a, {put(directory), writer().u32(6).u32(2).opaque(name).u32(0).opaque("")}, expected);
    };
    prepare_failures = 1;
    mkdir("fresh-prepare");
    ok(prepare_requests.size() == 2 && prepared_mutations == 1);
    ok(prepare_requests[0] == prepare_requests[1] && prepare_requests[0].contains("request_id"));
    ok(prepare_authorizations[1] == prepare_authorizations[0] + 1);
    ok(fs::is_directory(base / "root/space/fresh-prepare"));
    prepare_failures = 2;
    mkdir("bounded-prepare", 10008);
    ok(prepare_requests.size() == 2 && !prepared_mutations && !prepare_failures);
    ok(!fs::exists(base / "root/space/bounded-prepare"));
    prepare_failures = 1; revoke_on_prepare = true;
    mkdir("revoked-prepare", 13);
    ok(prepare_requests.size() == 1 && !prepared_mutations && !authorized);
    ok(authorizations == prepare_authorizations[0] + 1);
    ok(!fs::exists(base / "root/space/revoked-prepare"));
    authorized = true; revoke_on_prepare = false;
    prepare_failures = 1; prepare_error = "lease_expired";
    mkdir("expired-prepare", 13);
    ok(prepare_requests.size() == 1 && !prepared_mutations);
    ok(authorizations == prepare_authorizations[0]);
    ok(!fs::exists(base / "root/space/expired-prepare"));
    prepare_failures = 1; prepare_error = "deadline_exceeded";
    mkdir("delayed-domain", 10008);
    ok(prepare_requests.size() == 1 && !prepared_mutations && !prepare_failures);
    ok(!fs::exists(base / "root/space/delayed-domain"));
    ok(protocol->dispatch(last_request, a.connection) == last_response);
    ok(prepare_requests.size() == 1 && !prepared_mutations);
    mkdir("delayed-domain"); // A new SEQUENCE can retry after the transient delay.
    ok(prepare_requests.size() == 1 && prepared_mutations == 1);
    ok(fs::is_directory(base / "root/space/delayed-domain"));
    std::cout << "PASS domain deadline returns DELAY without automatic mutation retry; cached replay is exact and a new SEQUENCE can recover\n";
    for (const auto *transient : {"transport_closed", "service_unavailable", "stale_generation"}) {
      prepare_error = transient; prepare_failures = 1;
      mkdir(transient, 10008);
      ok(prepare_requests.size() == 1 && !prepared_mutations && !prepare_failures);
      ok(!fs::exists(base / "root/space" / transient));
      ok(protocol->dispatch(last_request, a.connection) == last_response);
      ok(prepare_requests.size() == 1 && !prepared_mutations);
    }
    prepare_error = "deadline_exceeded";
    prepare_operation = "stat"; prepare_failures = 1;
    prepare_requests.clear(); prepared_mutations = 0;
    auto getattr3 = [&](uint32_t expected) {
      writer auth, request;
      auth.u32(1).opaque("component").u32(1000).u32(1000).u32(0);
      request.u32(++xid).u32(0).u32(2).u32(100003).u32(3).u32(1).u32(1).opaque(auth.data)
          .u32(0).opaque("").opaque(decode_bytes(handle));
      auto response = protocol->dispatch(request.data, "deadline-v3");
      reader r(response);
      ok(r.u32() == xid && r.u32() == 1 && r.u32() == 0 && r.u32() == 0 && r.opaque().empty() && r.u32() == 0);
      ok(r.u32() == expected);
      if (expected) r.end(); else ok(response.size() - r.pos == 84);
    };
    getattr3(10008);
    ok(prepare_requests.size() == 1 && !prepared_mutations && !prepare_failures);
    getattr3(0);
    ok(prepare_requests.size() == 2 && prepared_mutations == 1);
    std::cout << "PASS NFSv3 domain deadline returns JUKEBOX and a fresh RPC transaction can recover\n";
    prepare_error = "grant_refresh_required";
    prepare_operation = "lookup"; prepare_failures = 2;
    prepare_requests.clear(); prepare_authorizations.clear(); prepared_mutations = 0;
    send(a, {put(directory), writer().u32(28).opaque("fresh-prepare")}, 10008);
    ok(prepare_requests.size() == 2 && !prepared_mutations && !prepare_failures);
    ok(fs::is_directory(base / "root/space/fresh-prepare"));
    prepare_operation = "mkdir";
    std::cout << "PASS pre-operation authorization refresh retries once with stable mutation identity, fresh authority, revocation and ordinary expiry boundaries\n";
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
    ok(!require_native || independent_owner);
    if (independent_owner) {
      auto snapshot = [&] { return store->dispatch("nfs_delegation", private_delegation, ctx()); };
      auto receipt = protocol->admit_request(a.connection);
      ok(snapshot().at("reservations") == 1);
      std::this_thread::sleep_for(std::chrono::milliseconds(5300));
      auto observed = snapshot();
      ok(observed.at("granted") && observed.at("reservations") == 1 && observed.at("lease_remaining_ms") == 0);
      admission = receipt; track_reply = true;
      send(a, {put(), writer().u32(25).fixed(delegated).u64(0).u32(8)});
      track_reply = false;
      auto first_reply = completion;
      ok(first_reply && snapshot().at("reservations") == 1);
      auto replay_request = last_request;
      uint64_t replay_reply = 0;
      blocked_renewal = true;
      auto running = std::async(std::launch::async, [&] {
        return protocol->dispatch(replay_request, a.connection, &replay_reply);
      });
      struct unblock { std::atomic_bool &flag; ~unblock() { flag = false; } } release{blocked_renewal};
      auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
      while (!renewal_entered && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      ok(renewal_entered);
      uint64_t queued;
#ifdef __linux__
      // Identify only this fixture's owner through its private socket peer,
      // then confirm it is our child before sending a process-control signal.
      auto value = decode_bytes(reservation_capability.at("capability").get<std::string>());
      int peer_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0); ok(peer_fd >= 0);
      sockaddr_un address{}; address.sun_family = AF_UNIX;
      auto name = "taucloud-nfs-" + encode_bytes(std::string_view(value).substr(0, 16));
      std::memcpy(address.sun_path + 1, name.data(), name.size());
      auto connected = ::connect(peer_fd, reinterpret_cast<sockaddr *>(&address),
          offsetof(sockaddr_un, sun_path) + 1 + name.size());
      ucred peer{}; socklen_t peer_size = sizeof(peer);
      auto identified = getsockopt(peer_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size);
      close(peer_fd); ok(connected == 0 && identified == 0 && peer.uid == geteuid() && peer.pid > 1);
      int owner_status = 0;
      ok(waitpid(peer.pid, &owner_status, WNOHANG) == 0);
      ok(kill(peer.pid, SIGSTOP) == 0);
      struct resume_owner { pid_t pid; ~resume_owner() { if (pid > 0) kill(pid, SIGCONT); } } resume{peer.pid};
      ok(waitpid(peer.pid, &owner_status, WUNTRACED) == peer.pid && WIFSTOPPED(owner_status));
      auto began = std::chrono::steady_clock::now();
      queued = protocol->begin_request("queued-during-file-renewal");
      auto abandoned = protocol->begin_request("abandoned-during-native-stop");
      protocol->enqueue_reply_completion(first_reply);
      protocol->abandon_request(abandoned);
      protocol->transport_disconnected("unbound-during-native-stop");
      for (int i = 0; i < 20; ++i) { protocol->poll_native(); ok(!protocol->request_ready(queued)); }
      ok(std::chrono::steady_clock::now() - began < std::chrono::milliseconds(500));
      ok(kill(peer.pid, SIGCONT) == 0); resume.pid = -1;
      while (!protocol->request_ready(queued)) std::this_thread::sleep_for(std::chrono::milliseconds(1));
      protocol->cancel_request(0); // Synchronous component drain, outside the reactor.
      std::cout << "PASS reactor admission/completion/cancellation/disconnect stay nonblocking with native owner stopped and file renewal paused\n";
#else
      queued = protocol->admit_request("queued-during-file-renewal");
      protocol->complete_reply(first_reply);
#endif
      ok(snapshot().at("reservations") == 2);
      blocked_renewal = false;
      ok(running.get() == last_response && replay_reply != 0 && replay_reply != first_reply);
      protocol->cancel_request(queued); protocol->cancel_request(queued);
      ok(snapshot().at("reservations") == 1);
      protocol->complete_reply(replay_reply);
      observed = snapshot();
      ok(observed.at("reservations") == 0 && observed.at("lease_remaining_ms").get<int64_t>() > 4500);
      auto expiry = observed.at("lease_expires_ms");
      protocol->complete_reply(replay_reply);
      ok(snapshot().at("lease_expires_ms") == expiry);
      protocol->maintenance();
      expiry = snapshot().at("lease_expires_ms");
      admission = protocol->admit_request(a.connection);
      ok(snapshot().at("reservations") == 1);
      auto saved_sequence = a.sequence; a.sequence += 10;
      track_reply = true; completion = 999;
      send(a, {}, 10063); track_reply = false; a.sequence = saved_sequence;
      observed = snapshot();
      ok(completion == 0 && observed.at("reservations") == 0 && observed.at("lease_expires_ms") == expiry);
      std::cout << "PASS native request routing retains across queued expiry, admits and completes during blocked file RPC, and cancels invalid SEQUENCE without renewal\n";
    }
    send(a, {put(), writer().u32(25).fixed(delegated).u64(0).u32(8)});
    auto denied_replay = last_request;
    protocol->maintenance(); // Drain the preceding valid reply under valid authority.
    authorized = false;
    uint64_t denied_completion = 999;
    auto denied_response = protocol->dispatch(denied_replay, a.connection, &denied_completion);
    authorized = true;
    reader denied_reader(denied_response);
    denied_reader.u32();
    ok(denied_reader.u32() == 1 && denied_reader.u32() == 0 && denied_reader.u32() == 0 &&
        denied_reader.opaque().empty() && denied_reader.u32() == 0 && denied_reader.u32() == 10008);
    ok(denied_reader.opaque().empty() && denied_reader.u32() == 1 && denied_reader.u32() == 53 &&
        denied_reader.u32() == 10008 && denied_completion == 0);
    denied_reader.end();
    ok(protocol->dispatch(denied_replay, a.connection) == last_response);
    std::cout << "PASS denied cached SEQUENCE replay has no lease-renewing reply completion token\n";
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
    auto named = open_result(send(a, {put(directory), named_claim(a, delegated)}), 1);
    ok(named.second == delegated && named.first != state);
    ok(protocol->dispatch(last_request, a.connection) == last_response);
    send(a, {put(), writer().u32(25).fixed(named.first).u64(0).u32(8)});
    send(a, {put(), writer().u32(4).u32(0).fixed(named.first)});
    send(a, {put(directory), named_claim(a, state)}, 10025);
    send(a, {put(directory), named_claim(a, delegated, "other")}, 10025);
    send(a, {put(directory), named_claim(a, delegated, "missing")}, 2);
    send(a, {put(directory), named_claim(a, delegated, "file", 2)}, 10038);
    send(b, {put(directory), named_claim(b, delegated)}, 10025);
    a.uid = 1001;
    send(a, {put(directory), named_claim(a, delegated)}, 10025);
    a.uid = 1000;
    ok(callbacks.empty());
    std::cout << "PASS named CLAIM_DELEGATE_CUR materializes and replays without self-recall; foreign states, clients, principals and write access are rejected\n";
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
    auto recalled_open = open_result(send(a, {put(directory), named_claim(a, delegated)}), 1, true);
    ok(recalled_open.second == delegated);
    send(b, {put(), opening(b, 3)}, 10008);
    send(a, {put(), writer().u32(8).fixed(delegated)});
    send(a, {put(), writer().u32(25).fixed(recalled_open.first).u64(0).u32(8)});
    send(a, {put(), writer().u32(4).u32(0).fixed(recalled_open.first)});
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
    component_provider = false;
    auto pending = connect("pending-delivery"); establish_callback();
    auto pending_open = open_result(send(pending, {put(), opening(pending, 1)}), 0).first;
    track_reply = true;
    send(pending, {put(), writer().u32(25).fixed(pending_open).u64(0).u32(8)});
    auto first_completion = completion; ok(first_completion != 0);
    uint64_t replay_completion = 0;
    ok(protocol->dispatch(last_request, pending.connection, &replay_completion) == last_response);
    ok(replay_completion && replay_completion != first_completion);
    track_reply = false;
    slow_read = true; slow_read_entered = false;
    std::exception_ptr concurrent_failure;
    std::jthread executing([&] {
      try { send(pending, {put(), writer().u32(25).fixed(pending_open).u64(0).u32(8)}); }
      catch (...) { concurrent_failure = std::current_exception(); }
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!slow_read_entered && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    auto completed_at = std::chrono::steady_clock::now();
    protocol->complete_reply(first_completion);
    auto concurrent_admission = protocol->admit_request("queued-while-executing");
    protocol->cancel_request(concurrent_admission);
    auto completion_time = std::chrono::steady_clock::now() - completed_at;
    executing.join();
    if (concurrent_failure) std::rethrow_exception(concurrent_failure);
    ok(slow_read_entered && completion_time < std::chrono::seconds(1));
    protocol->complete_reply(first_completion);
    protocol->complete_reply(UINT64_MAX);
    std::this_thread::sleep_for(std::chrono::milliseconds(5300));
    protocol->maintenance();
    send(pending, {put(), writer().u32(25).fixed(pending_open).u64(0).u32(8)});
    protocol->complete_reply(replay_completion);
    std::this_thread::sleep_for(std::chrono::milliseconds(3500));
    protocol->complete_reply(replay_completion); // A late duplicate cannot renew.
    std::this_thread::sleep_for(std::chrono::milliseconds(1800));
    protocol->maintenance();
    track_reply = true; completion = 999;
    send(pending, {}, 10052); ok(completion == 0); track_reply = false;
    std::cout << "PASS independent reply/replay pins retain OPEN through delayed delivery; duplicate completion cannot extend expiry\n";

    auto dropped = connect("dropped-delivery"); establish_callback();
    auto dropped_open = open_result(send(dropped, {put(), opening(dropped, 1)}), 0).first;
    track_reply = true; send(dropped, {}); ok(completion != 0); track_reply = false;
    std::this_thread::sleep_for(std::chrono::milliseconds(3500));
    protocol->disconnect(dropped.connection);
    dropped.connection = "after-dropped-delivery";
    std::this_thread::sleep_for(std::chrono::milliseconds(1800));
    protocol->maintenance();
    send(dropped, {put(), writer().u32(25).fixed(dropped_open).u64(0).u32(8)});
    std::this_thread::sleep_for(std::chrono::milliseconds(5300));
    protocol->maintenance(); send(dropped, {}, 10052);
    std::cout << "PASS disconnect conservatively ends pending transmission with a full lease and leaves no immortal client pin\n";

    auto queued = connect("queued-arrival");
    auto queued_open = open_result(send(queued, {put(), opening(queued, 1)}), 0).first;
    admission = protocol->admit_request(queued.connection);
    std::this_thread::sleep_for(std::chrono::milliseconds(5300));
    protocol->maintenance();
    send(queued, {put(), writer().u32(25).fixed(queued_open).u64(0).u32(8)});
    send(queued, {put(), writer().u32(4).u32(0).fixed(queued_open)});
    std::cout << "PASS a request received before expiry retains its OPEN across executor delay and maintenance until validated SEQUENCE\n";

    auto rejected = connect("rejected-arrival");
    auto cancelled = connect("cancelled-arrival");
    auto late = connect("late-arrival");
    auto invalid_receipt = protocol->admit_request(rejected.connection);
    auto cancelled_receipt = protocol->admit_request(cancelled.connection);
    // A queued record cannot contain a client ID that did not yet exist.
    auto future = connect("created-after-arrival");
    std::this_thread::sleep_for(std::chrono::milliseconds(5300));
    auto late_receipt = protocol->admit_request(late.connection);
    protocol->maintenance();
    send(future, {}, 10052);
    admission = invalid_receipt; rejected.sequence += 10;
    track_reply = true; completion = 999;
    send(rejected, {}, 10063); ok(completion == 0); track_reply = false;
    protocol->cancel_request(cancelled_receipt);
    protocol->cancel_request(cancelled_receipt);
    protocol->cancel_request(UINT64_MAX);
    protocol->maintenance();
    send(rejected, {}, 10052);
    send(cancelled, {}, 10052);
    // This token arrived after expiry; its mere presence must not revive state.
    admission = late_receipt;
    send(late, {}, 10052);
    std::cout << "PASS rejected SEQUENCE, cancellation, duplicate cleanup and late arrivals cannot renew expired clients; old arrivals cannot pin future clients\n";

    std::vector<uint64_t> full;
    for (unsigned i = 0; i < max_call_records; ++i) full.push_back(protocol->admit_request("bounded-arrivals"));
    bool overloaded = false;
    try { protocol->admit_request("over-budget"); }
    catch (const error &e) { overloaded = std::string_view(e.what()) == "overloaded"; }
    ok(overloaded);
    auto reply_hint = writer().u32(123).u32(1).data;
    for (unsigned i = 0; i < max_reply_records; ++i)
      full.push_back(protocol->admit_request("reserved-reply-arrivals", reply_hint));
    overloaded = false;
    try { protocol->admit_request("over-reply-budget", reply_hint); }
    catch (const error &e) { overloaded = std::string_view(e.what()) == "overloaded"; }
    ok(overloaded);
    for (auto id : full) protocol->cancel_request(id);
    auto unused = protocol->admit_request("unused-arrival");
    protocol->disconnect("unused-arrival");
    bool abandoned = false;
    try { protocol->dispatch(last_request, "unused-arrival", nullptr, unused); }
    catch (const error &e) { abandoned = std::string_view(e.what()) == "cancelled"; }
    ok(abandoned);
    std::cout << "PASS request admission is bounded, cancellation restores capacity and disconnect invalidates undispatched tokens\n";
#ifdef __linux__
    if (require_native) {
      component_provider = true;
      auto recovered_file = nfs("create", directory, {{"name", "recovery"}}).at("handle").get<std::string>();
      nfs("write", recovered_file, {{"offset", 0}, {"data", encode_bytes("reclaimed")}});
      auto records = [&] {
        database saved(server_cfg.state / "nfs.db");
        statement q(saved, "SELECT body FROM recovery WHERE json_extract(body,'$.kind')='delegation'");
        json result = json::array();
        while (q.row()) result.push_back(json::parse(q.text(0)));
        return result;
      };
      auto want_reclaim = [&] { return writer().u32(56).u32(0x100).u32(1).u32(1); };
      auto read_delegation = [&](const std::string &result) {
        reader r(result); ok(r.u32() == 1); auto id = r.fixed(16);
        ok(r.boolean() && r.u32() == 1 && r.u32() == 0 && r.u32() == 0x1f01ff && r.opaque() == "EVERYONE@");
        r.end(); return id;
      };
      for (unsigned fault : {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u}) {
        if (fault == 6) {
          protocol.reset(); network = nullptr; store.reset();
          cfg.nfs_lease_seconds = 10; server_cfg.nfs_lease_seconds = 10;
          store = std::make_unique<file_store>(cfg, "file", random_hex(16));
        }
        server_cfg.state = base / ("reclaim-" + std::to_string(fault));
        secure_directory(server_cfg.state); restart_protocol();
        auto original = connect("reclaim-owner"); establish_callback();
        std::string old_state;
        if (fault == 8)
          old_state = open_result(send(original, {put(recovered_file), opening(original, 0x101)}), 1).second;
        else {
          auto result = send(original, {put(recovered_file), writer().u32(56).u32(0x100).u32(4)});
          reader initial(result); ok(initial.u32() == 1); old_state = initial.fixed(16);
        }
        auto saved = records(); ok(saved.size() == 1);
        auto binding = saved[0].at("binding");
        ok(binding.at("generation") == 0 && binding.at("client") == std::to_string(original.client) &&
            saved[0].at("verifier") == encode_bytes("12345678") && !saved[0].contains("credential"));
        auto old_capability = reservation_capability;
        native_delegation_reservation_channel old_channel(old_capability);
        old_channel.reserve();
        if (fault == 0 || fault == 6) {
          protocol.reset(); network = nullptr;
          store.reset();
          if (fault == 6) { cfg.nfs_lease_seconds = 5; server_cfg.nfs_lease_seconds = 5; }
          store = std::make_unique<file_store>(cfg, "file", random_hex(16));
        }
        restart_protocol();
        auto protected_before = store->dispatch("nfs_delegation", private_delegation, ctx());
        auto cutoff = protected_before.at("recall_deadline_ms");
        ok(cutoff.get<int64_t>() > 0 && protected_before.at("state") == "recalling");
        if (fault == 6) ok(protected_before.at("lease_period_ms") == 10000 &&
            protected_before.at("lease_remaining_ms").get<int64_t>() > 5000);
        bool blocked = false;
        try { native.open("space/recovery", false, false, true); }
        catch (const error &e) { blocked = std::string_view(e.what()) == "locked"; }
        ok(blocked);
        if (fault == 3) {
          auto completed = connect("reclaim-owner", false);
          send(completed, {put(recovered_file), writer().u32(58).boolean(true)});
          send(completed, {put(recovered_file), want_reclaim()}, 10033);
          ok(records().empty());
          ok(native.open("space/recovery", false, false, true).info().at("size") == 9);
          std::cout << "PASS per-filesystem RECLAIM_COMPLETE releases unreclaimed native guards before acknowledging completion\n";
          continue;
        }
        if (fault == 4) {
          std::this_thread::sleep_for(std::chrono::milliseconds(5300)); protocol->maintenance();
          ok(records().empty());
          auto expired = connect("reclaim-owner", false);
          send(expired, {put(recovered_file), want_reclaim()}, 10033);
          ok(native.open("space/recovery", false, false, true).info().at("size") == 9);
          std::cout << "PASS grace expiry retires unreclaimed native guards and does not revive expired protection\n";
          continue;
        }
        if (fault == 0) {
          auto foreign = connect("foreign-owner", false);
          send(foreign, {put(recovered_file), want_reclaim()}, 10034);
          auto wrong_verifier = connect("reclaim-owner", false, 1000, "87654321");
          send(wrong_verifier, {put(recovered_file), want_reclaim()}, 10034);
        }
        auto recovering = connect("reclaim-owner", false);
        if (fault == 0) {
          authorized = false; send(recovering, {put(recovered_file), want_reclaim()}, 13); authorized = true;
          ok(records()[0].at("binding").at("generation") == 0);
        } else if (fault == 1 || fault == 2 || fault == 5 || fault == 9) {
          if (fault == 9) {
            {
              database saved(server_cfg.state / "nfs.db");
              sql(saved, "CREATE TRIGGER reject_adoption BEFORE INSERT ON recovery "
                  "WHEN json_type(NEW.body,'$.adoption') IS NOT NULL "
                  "BEGIN SELECT RAISE(FAIL,'test adoption write failure'); END;");
            }
            send(recovering, {put(recovered_file), want_reclaim()}, 5);
            ok(!records()[0].contains("adoption"));
            database saved(server_cfg.state / "nfs.db"); sql(saved, "DROP TRIGGER reject_adoption");
          }
          adoption_fault = fault == 5 ? 3 : fault == 9 ? 1 : fault;
          send(recovering, {put(recovered_file), want_reclaim()}, 5);
          ok(adoption_fault == 0 && records()[0].contains("adoption") == (fault != 5));
          restart_protocol(); // Recover an intent either before execution or after a lost successful reply.
          recovering = connect("reclaim-owner", false);
        }
        // No CB_NULL/CB_SEQUENCE reply has established this backchannel.
        std::string reclaimed, reclaimed_open;
        if (fault == 7 || fault == 8) {
          auto invalid = writer().u32(18).u32(0).u32(2).u32(0).u64(recovering.client)
              .opaque("owner").u32(0).u32(1).u32(1);
          send(recovering, {put(recovered_file), invalid}, 10034);
          auto claim = writer().u32(18).u32(0).u32(1).u32(0).u64(recovering.client)
              .opaque("owner").u32(0).u32(1).u32(1);
          auto result = open_result(send(recovering, {put(recovered_file), claim}), 1, true);
          reclaimed_open = result.first; reclaimed = result.second;
        } else reclaimed = read_delegation(send(recovering, {put(recovered_file), want_reclaim()}));
        ok(reclaimed != old_state && protocol->dispatch(last_request, recovering.connection) == last_response);
        auto durable = records()[0];
        ok(!durable.contains("adoption") && durable.at("binding").at("generation") ==
            ((fault == 1 || fault == 2 || fault == 5 || fault == 9) ? 2 : 1));
        auto after = private_delegation; after["client"] = durable.at("binding").at("client");
        auto snapshot = store->dispatch("nfs_delegation", after, ctx());
        ok(snapshot.at("granted") && snapshot.at("recall_deadline_ms") == cutoff);
        bool fenced = false;
        try { old_channel.inspect(); } catch (const error &) { fenced = true; }
        ok(fenced);
        ok(read_delegation(send(recovering, {put(recovered_file), want_reclaim()})) == reclaimed);
        ok(records()[0].at("binding").at("generation") == durable.at("binding").at("generation"));
        if (fault == 7 || fault == 8) {
          auto named_open = open_result(send(recovering,
              {put(directory), named_claim(recovering, reclaimed, "recovery")}), 0).first;
          auto fh_claim = writer().u32(18).u32(0).u32(1).u32(0).u64(recovering.client)
              .opaque("fh-owner").u32(0).u32(5).fixed(reclaimed);
          auto fh_open = open_result(send(recovering, {put(recovered_file), fh_claim}), 0).first;
          for (const auto &open : {named_open, fh_open, reclaimed_open})
            send(recovering, {put(recovered_file), writer().u32(4).u32(0).fixed(open)});
        }
        auto read = send(recovering, {put(recovered_file), writer().u32(25).fixed(reclaimed).u64(0).u32(9)});
        reader data(read); ok(data.boolean() && data.opaque() == "reclaimed"); data.end();
        send(recovering, {put(recovered_file), writer().u32(8).fixed(reclaimed)});
        ok(records().empty());
        ok(native.open("space/recovery", false, false, true).info().at("size") == 9);
        std::cout << "PASS delegation restart reclaim, original incarnation, fresh authority, forced recall and scenario " << fault << '\n';
      }
      // The original owner's destructor has a child-reaper thread after file
      // worker replacement. The later SIGKILL test needs its own fresh child.
      protocol.reset(); network = nullptr; store.reset();
      store = std::make_unique<file_store>(cfg, "file", random_hex(16));
      server_cfg.state = base / "after-reclaim"; secure_directory(server_cfg.state); restart_protocol();
    }
    if (require_native) {
      component_provider = true;
      callbacks.clear(); closes.clear();
      auto dying = connect("native-owner-loss"); establish_callback();
      auto fresh_file = nfs("create", directory, {{"name", "owner-loss"}}).at("handle").get<std::string>();
      auto protected_open = open_result(send(dying, {put(fresh_file), opening(dying, 0x101)}), 1);
      ok(independent_owner && !protected_open.second.empty());
      auto held_receipt = protocol->admit_request("held-before-native-loss");
      auto value = decode_bytes(reservation_capability.at("capability").get<std::string>());
      int peer_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0); ok(peer_fd >= 0);
      sockaddr_un address{}; address.sun_family = AF_UNIX;
      auto name = "taucloud-nfs-" + encode_bytes(std::string_view(value).substr(0, 16));
      std::memcpy(address.sun_path + 1, name.data(), name.size());
      auto connected = ::connect(peer_fd, reinterpret_cast<sockaddr *>(&address),
          offsetof(sockaddr_un, sun_path) + 1 + name.size());
      ucred peer{}; socklen_t peer_size = sizeof(peer);
      auto identified = getsockopt(peer_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size);
      close(peer_fd); ok(connected == 0 && identified == 0 && peer.uid == geteuid() && peer.pid > 1);
      int owner_status = 0; ok(waitpid(peer.pid, &owner_status, WNOHANG) == 0);
      blocked_renewal = true; renewal_entered = false;
      auto replay_packet = last_request;
      auto executing = std::async(std::launch::async, [&] { return protocol->dispatch(replay_packet, dying.connection); });
      struct unblock_loss { std::atomic_bool &flag; ~unblock_loss() { flag = false; } } release{blocked_renewal};
      auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
      while (!renewal_entered && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      ok(renewal_entered);
      // Detect owner death while the protocol mutex remains held by the
      // file callback; independent channel tests also prove idle EOF detection.
      ok(kill(peer.pid, SIGKILL) == 0 && waitpid(peer.pid, &owner_status, 0) == peer.pid && WIFSIGNALED(owner_status));
      auto started = std::chrono::steady_clock::now();
      ok(!protocol->poll_native());
      ok(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(500));
      bool new_refused = false, queued_refused = false, result_refused = false;
      try { protocol->begin_request("after-native-loss"); }
      catch (const error &e) { new_refused = std::string_view(e.what()) == "delegation_owner_lost"; }
      try { protocol->request_ready(held_receipt); }
      catch (const error &e) { queued_refused = std::string_view(e.what()) == "delegation_owner_lost"; }
      blocked_renewal = false;
      try { executing.get(); }
      catch (const error &e) { result_refused = std::string_view(e.what()) == "delegation_owner_lost"; }
      ok(new_refused && queued_refused && result_refused);
      protocol->abandon_request(held_receipt);
      protocol->transport_disconnected(dying.connection);
      ok(!protocol->poll_native() && !protocol->poll_native());
      std::cout << "PASS native owner SIGKILL fences new/queued requests and an in-flight file result without waiting for the protocol mutex" << std::endl;
    }
#endif
    std::cout << "PASS " << checks << " delegation protocol/native component checks; production handout remains gated\n";
    // Destroy protocol state before its file provider, including fenced state.
    native = native_file(); protocol.reset(); store.reset();
    fs::remove_all(base);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << " checks=" << checks << " fixture=" << base << '\n'; return 1;
  }
}
#ifndef TAUCLOUD_NATIVE_PROTOCOL_VM
int main(int argc, char **argv) {
  if (auto result = tc::native_delegation_owner::entry(argc, argv); result >= 0) return result;
  return nfs_delegation_protocol_suite();
}
#endif
