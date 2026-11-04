#include <taucloud/smb_lease.hpp>
#include <taucloud/files.hpp>
#include <iostream>
using namespace tc;
using namespace tc::smb_detail;
int main() {
  int checks = 0;
  auto check = [&](bool value) { require(value, "lease_test_failed"); ++checks; };
  auto rejects = [&](auto call) {
    bool rejected = false;
    try { call(); } catch (const error &) { rejected = true; }
    check(rejected);
  };
  try {
    auto key = decode_bytes("00112233445566778899aabbccddeeff");
    auto parent = decode_bytes("ffeeddccbbaa99887766554433221100");
    auto request = decode_bytes("00112233445566778899aabbccddeeff0700000004000000"
                               "0000000000000000ffeeddccbbaa99887766554433221100feff0000");
    auto r = lease_request::decode(request);
    check(r.key == key && r.parent == parent && r.state == 7 && r.version == 2 && r.epoch == 65534);
    for (size_t size = 0; size <= 56; ++size)
      if (size != 32 && size != 52) rejects([&] { lease_request::decode(bytes(size, '\0')); });
    auto bad = request; bad[19] = char(0x80);
    rejects([&] { lease_request::decode(bad); });
    // Request reserved fields are ignored; response reserved fields are zero.
    auto reserved = request; put(reserved, 20, 0xfffffffbu, 4);
    put(reserved, 24, UINT64_MAX, 8); put(reserved, 50, 65535, 2);
    check(lease_request::decode(reserved).parent.empty());
    lease_state v2(r);
    check(v2.promote(7, 7) && v2.epoch() == 65535);
    check(encode_bytes(v2.response()) ==
          "00112233445566778899aabbccddeeff0700000004000000"
          "0000000000000000ffeeddccbbaa99887766554433221100ffff0000");
    check(!v2.promote(1, 7) && !v2.promote(7, 1) && !v2.promote(7, 7));
    check(v2.state() == 7 && v2.epoch() == 65535);
    v2.recall(3);
    check(v2.epoch() == 0 && v2.breaking() && v2.state() == 7);
    auto first = *v2.pending();
    check(encode_bytes(first.encode(key)) ==
          "2c0000000100000000112233445566778899aabbccddeeff0700000003000000"
          "000000000000000000000000");
    check(get(v2.response(), 20, 4) == 6);
    check(v2.acknowledge(7) == 0xc00000d0 && v2.pending().has_value());
    v2.sent(first.serial + 1, 100, 5000);
    check(v2.pending().has_value() && v2.deadline() == 0);
    v2.sent(first.serial, 100, 5000);
    check(!v2.pending() && v2.deadline() == 5100);
    v2.sent(first.serial, 4000, 5000);
    check(v2.deadline() == 5100); // Duplicate completion cannot extend a timer.
    check(v2.acknowledge(7) == 0xc00000d0 && v2.state() == 7 && v2.deadline() == 5100);
    v2.recall(1); v2.recall(3); // Later weaker conflict cannot relax the target.
    check(!v2.promote(7, 7) && v2.epoch() == 0);
    check(v2.acknowledge(3) == 0 && v2.state() == 3 && v2.breaking());
    auto second = *v2.pending();
    check(second.current == 3 && second.target == 1 && second.epoch == 1);
    check(get(v2.acknowledgment_response(), 24, 4) == 3);
    v2.sent(first.serial, 101, 5000);
    check(v2.pending()->serial == second.serial && v2.deadline() == 0);
    v2.sent(second.serial, 102, 5000);
    check(!v2.timed_out(5101) && v2.timed_out(5102));
    check(v2.acknowledge(0) == 0 && v2.state() == 0 && !v2.unsettled());
    check(v2.acknowledge(0) == 0xc0000001);
    check(encode_bytes(v2.acknowledgment_response()) ==
          "240000000000000000112233445566778899aabbccddeeff000000000000000000000000");
    check(v2.promote(1, 1));
    v2.recall(0);
    auto read_break = *v2.pending();
    check(!read_break.acknowledgment && !v2.breaking() && v2.unsettled() && v2.state() == 1);
    check(!v2.promote(7, 7) && v2.acknowledge(0) == 0xc0000001);
    v2.sent(read_break.serial, 200, 5000);
    check(v2.state() == 0 && !v2.unsettled() && !v2.timed_out(INT64_MAX));

    {
      lease_state racing(r);
      racing.promote(7, 7); racing.recall(3);
      auto old = *racing.pending();
      racing.recall(1);
      // A separate connection can deliver an ACK before the sender's await
      // resumes. The stale send completion must not consume the new break.
      check(racing.acknowledge(3) == 0 && racing.pending()->serial != old.serial);
      auto next = *racing.pending();
      racing.sent(old.serial, 100, 5000);
      check(racing.pending()->serial == next.serial && racing.deadline() == 0);
      racing.recall(0);
      check(racing.acknowledge(1) == 0 && racing.state() == 1 && racing.unsettled());
      auto last = *racing.pending();
      check(!last.acknowledgment && last.target == 0 && !racing.breaking());
      racing.sent(next.serial, 101, 5000);
      check(racing.pending()->serial == last.serial && racing.state() == 1);
      racing.sent(last.serial, 102, 5000);
      check(racing.state() == 0 && !racing.unsettled());
    }
    // Exhaust every supported initial/target/ACK combination independently of
    // implementation branches. ACK may only remove bits of the notified target.
    for (unsigned version : {1u, 2u})
      for (unsigned initial : {1u, 3u, 5u, 7u})
        for (unsigned target : {0u, 1u, 3u, 5u})
          for (unsigned ack = 0; ack < 16; ++ack) {
            auto wanted = initial & target;
            lease_request req{key, {}, initial, version, 9};
            lease_state l(req);
            check(l.promote(initial, initial));
            l.recall(target);
            if (wanted == initial) {
              check(!l.pending() && l.state() == initial);
              continue;
            }
            auto b = *l.pending();
            check(b.current == initial && b.target == wanted && b.acknowledgment == (initial != 1));
            check(b.epoch == (version == 2 ? 11 : 0));
            l.sent(b.serial, 10, 5);
            auto status = l.acknowledge(ack);
            if (initial == 1) check(status == 0xc0000001 && l.state() == 0);
            else if (ack & ~wanted) {
              check(status == 0xc00000d0 && l.state() == initial && l.breaking());
              check(l.deadline() == 15 && !l.timed_out(14) && l.timed_out(15));
            } else check(status == 0 && l.state() == ack && !l.unsettled() && l.deadline() == 0);
            l.fence();
            check(l.state() == 0 && !l.unsettled() && !l.timed_out(INT64_MAX));
            l.sent(b.serial, 1000, 5000);
            check(l.state() == 0 && l.deadline() == 0);
          }
    // Caller obtains native exclusion before promote; partial availability
    // must never widen the requested authority or discard existing rights.
    for (unsigned initial : {0u, 1u, 3u, 5u, 7u})
      for (unsigned requested = 0; requested < 8; ++requested)
        for (unsigned available : {0u, 1u, 3u, 5u, 7u}) {
          lease_state l(lease_request{key, {}, 0, 1, 0});
          l.promote(initial, initial);
          l.promote(requested, available);
          check((l.state() & initial) == initial);
          check((l.state() & ~(initial | (requested & available))) == 0);
        }
    {
      lease_registry registry(3);
      auto client = bytes(16, 'a'), peer = bytes(16, 'b');
      auto first = registry.attach(client, r, "volume/space/a", "session1:handle1");
      first->promote(7, 7);
      first->recall(1);
      auto serial = first->pending()->serial;
      // Joining an existing lease during a break never waits, downgrades, or
      // allocates another independent state, including another session.
      auto other_request = r; other_request.state = 1; other_request.epoch = 123;
      auto second = registry.attach(client, other_request, "volume/space/a", "session2:handle2");
      check(second == first && second->state() == 7 && second->pending()->serial == serial);
      check(registry.find(client, key)->opens.size() == 2 && registry.size() == 1);
      rejects([&] { registry.validate(client, r, "other-volume/space/a"); });
      rejects([&] { registry.attach(client, r, "volume/space/a", "session2:handle2"); });
      auto independent = registry.attach(peer, r, "other-volume/space/a", "peer:handle1");
      check(independent != first && independent->state() == 0 && registry.size() == 2);
      rejects([&] { registry.attach(peer, r, "other-volume/space/a", "peer:handle2"); });
      check(registry.find(peer, key)->opens.size() == 1 && registry.size() == 2);
      registry.detach("session1:handle1");
      check(first->state() == 7 && first->unsettled());
      registry.rename(client, key, "volume/space/renamed");
      registry.validate(client, r, "volume/space/renamed");
      rejects([&] { registry.validate(client, r, "volume/space/a"); });
      registry.detach("session2:handle2");
      check(!registry.find(client, key) && first->state() == 0 && !first->unsettled());
      registry.detach("session2:handle2"); // Idempotent teardown.
      auto replacement = registry.attach(client, r, "volume/space/new", "session3:handle1", true);
      check(replacement != first);
      registry.validate(client, r, "volume/space/after-delete");
      registry.detach("peer:handle1"); registry.detach("session3:handle1");
      check(registry.size() == 0);
      auto invalid = r; invalid.parent = "invalid";
      rejects([&] { registry.attach(client, invalid, "volume/space/new", "bad"); });
      check(registry.size() == 0 && registry.find(client, key) == nullptr);
    }
    std::cout << json{{"status", "passed"}, {"checks", checks}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << " after_checks=" << checks << '\n';
    return 1;
  }
}
