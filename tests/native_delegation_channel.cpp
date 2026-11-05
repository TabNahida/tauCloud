// Independent private-wire peer: these checks do not claim native exclusion.
#include <taucloud/native_delegation_owner.hpp>
#include <array>
#include <cstring>
#include <iostream>
#include <thread>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace tc;
using namespace std::chrono_literals;
namespace {
using reservation_channel = native_delegation_reservation_channel;
int checks;
void check(bool value, const char *message) { require(value, message); ++checks; }
int64_t clock_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}
struct packet {
  uint32_t magic = 0x54434434, op = 0, native_flags = 0, reserved = 0;
  uint64_t id = 0;
  int64_t period = 0, remaining = 0;
  uint64_t reservation = 0;
  std::array<char, 32> capability{};
};
static_assert(sizeof(packet) == 80);
enum class fault { none, reflected, wrong_id, wrong_op, zero_token, bad_magic,
                   short_record, descriptor, state, count, eof, timeout, capacity, wrong_token,
                   restore_missing, restore_multiple, restore_error_fd, restore_identity, restore_flags,
                   inventory_full, inventory_overflow, inventory_loop, inventory_slow };
struct peer {
  int gate = -1;
  pid_t child = -1;
  json capability;
  explicit peer(fault scenario, bool recovery = false) {
    auto endpoint = decode_bytes(random_hex(16)), secret = decode_bytes(random_hex(16));
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    check(listener >= 0, "async_listener");
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    auto name = "taucloud-nfs-" + encode_bytes(endpoint);
    std::memcpy(address.sun_path + 1, name.data(), name.size());
    if (bind(listener, reinterpret_cast<sockaddr *>(&address), offsetof(sockaddr_un, sun_path) + 1 + name.size()) ||
        listen(listener, 1)) { close(listener); throw error("async_bind"); }
    int gates[2]; if (pipe2(gates, O_CLOEXEC)) { close(listener); throw error("async_pipe"); }
    child = fork();
    if (child < 0) { close(listener); close(gates[0]); close(gates[1]); throw error("async_fork"); }
    if (!child) {
      close(gates[1]);
      pollfd accepting{listener, POLLIN, 0};
      if (::poll(&accepting, 1, 4000) <= 0) _exit(2);
      int connection = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
      if (connection < 0) _exit(3);
      auto receive = [&](unsigned op) {
        packet p; pollfd readable{connection, POLLIN, 0};
        if (::poll(&readable, 1, 4000) <= 0 || recv(connection, &p, sizeof(p), 0) != sizeof(p) ||
            p.magic != 0x54434434 || p.op != op || (op != 14 && p.id != (op == 13 ? 0 : 1))) _exit(4);
        return p;
      };
      auto release = [&] {
        char marker = 0; pollfd readable{gates[0], POLLIN, 0};
        if (::poll(&readable, 1, 4000) <= 0 || read(gates[0], &marker, 1) != 1 || marker != 'R') _exit(5);
      };
      auto send = [&](const packet &p) {
        if (::send(connection, &p, sizeof(p), MSG_NOSIGNAL) != sizeof(p)) _exit(6);
      };
      auto response = receive(recovery ? 13 : 11);
      auto nonce = std::string(response.capability.data(), 16);
      auto suffix = endpoint + (recovery ? "0:" : "1:") + nonce;
      auto client_tag = decode_bytes(mac(secret, (recovery ? "TCD4-owner-client:" : "TCD4-client:") + suffix).substr(0, 32));
      if (std::string(response.capability.data(), 32) != nonce + client_tag) _exit(7);
      if (scenario != fault::reflected) {
        auto tag = decode_bytes(mac(secret, (recovery ? "TCD4-owner-server:" : "TCD4-server:") + suffix).substr(0, 32));
        std::copy(tag.begin(), tag.end(), response.capability.begin() + 16);
      }
      response.period = clock_ms() + 5000;
      release();
      if (recovery && scenario == fault::timeout) { release(); _exit(0); }
      send(response);
      if (recovery && scenario >= fault::restore_missing && scenario <= fault::restore_flags) {
        response = receive(15); response.period = clock_ms() + 5000;
        if (scenario == fault::restore_missing) { send(response); _exit(0); }
        if (scenario == fault::restore_error_fd) response.op |= 3 << 16;
        if (scenario == fault::restore_identity) response.capability[0] ^= 1;
        if (scenario == fault::restore_flags) response.native_flags = 4;
        int extra = open("/dev/null", O_RDONLY | O_CLOEXEC);
        int descriptors[2] = {extra, extra};
        auto size = scenario == fault::restore_multiple ? sizeof(descriptors) : sizeof(int);
        iovec data{&response, sizeof(response)};
        alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(descriptors))]{};
        msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
        message.msg_control = ancillary; message.msg_controllen = CMSG_SPACE(size);
        auto c = CMSG_FIRSTHDR(&message); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(size); std::memcpy(CMSG_DATA(c), descriptors, size);
        if (extra < 0 || sendmsg(connection, &message, MSG_NOSIGNAL) != sizeof(response)) _exit(9);
        _exit(0);
      }
      if (recovery && scenario >= fault::inventory_full) {
        for (unsigned i = 0; i < 257; ++i) {
          response = receive(14);
          if (response.id != i) _exit(11);
          response.id = i + 1; response.period = clock_ms() + 5000;
          if (scenario == fault::inventory_loop && i == 1) response.id = i;
          if (scenario == fault::inventory_full && i == 256) { response.id = 0; response.period = 0; }
          if (scenario == fault::inventory_slow) {
            std::this_thread::sleep_for(400ms);
            if (i == 3) {
              // The caller's one total budget must close this connection before
              // a peer can turn 256 individually timely replies into minutes.
              pollfd lost{connection, POLLIN, 0}; char byte;
              if (poll(&lost, 1, 500) <= 0 || recv(connection, &byte, 1, 0) != 0) _exit(12);
              _exit(0);
            }
          }
          send(response);
          if (scenario == fault::inventory_loop && i == 1) _exit(0);
        }
        _exit(0);
      }
      if (recovery) _exit(0);
      if (scenario == fault::reflected) _exit(0);
      response = receive(7); release();
      if (scenario == fault::eof) _exit(0);
      if (scenario == fault::timeout) { release(); _exit(0); }
      response.period = clock_ms() + 5000; response.reservation = 41; response.reserved = 1;
      switch (scenario) {
        case fault::wrong_id: ++response.id; break;
        case fault::wrong_op: response.op = 3; break;
        case fault::zero_token: response.reservation = 0; break;
        case fault::bad_magic: response.magic = 0; break;
        case fault::state: response.op |= 255 << 8; break;
        case fault::count: response.reserved = 33; break;
        case fault::capacity: response.op |= 5 << 16; break;
        case fault::short_record:
          if (::send(connection, &response, sizeof(response) - 1, MSG_NOSIGNAL) != sizeof(response) - 1) _exit(8);
          _exit(0);
        case fault::descriptor: {
          int extra = open("/dev/null", O_RDONLY | O_CLOEXEC);
          iovec data{&response, sizeof(response)};
          alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
          msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
          message.msg_control = control; message.msg_controllen = sizeof(control);
          auto c = CMSG_FIRSTHDR(&message); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
          c->cmsg_len = CMSG_LEN(sizeof(int)); std::memcpy(CMSG_DATA(c), &extra, sizeof(extra));
          if (extra < 0 || sendmsg(connection, &message, MSG_NOSIGNAL) != sizeof(response)) _exit(9);
          _exit(0);
        }
        default: break;
      }
      send(response);
      if (scenario == fault::capacity) {
        response = receive(7); response.period = clock_ms() + 5000;
        response.reservation = 41; response.reserved = 1; send(response);
      } else if (scenario != fault::none && scenario != fault::wrong_token) _exit(0);
      response = receive(8);
      if (response.reservation != 41) _exit(10);
      response.period = clock_ms() + 5000;
      if (scenario == fault::wrong_token) ++response.reservation;
      send(response);
      if (scenario == fault::wrong_token) _exit(0);
      response = receive(9); response.op |= 3 << 16; send(response); // consumed token cannot be reused
      response = receive(3); response.period = clock_ms() + 5000; send(response);
      _exit(0);
    }
    close(listener); close(gates[0]); gate = gates[1];
    capability = {{"id", uint64_t(1)}, {"capability", encode_bytes(endpoint + secret)}};
    if (recovery) capability["type"] = "owner-recovery-v1";
  }
  void release() { char marker = 'R'; check(write(gate, &marker, 1) == 1, "async_release"); }
  void finish() {
    int status = 0; check(waitpid(child, &status, 0) == child, "async_wait"); child = -1;
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "async_peer_failed");
  }
  ~peer() { if (gate >= 0) close(gate); if (child > 0) { kill(child, SIGKILL); waitpid(child, nullptr, 0); } }
};
json result(reservation_channel &c) {
  auto end = clock_ms() + 2500;
  do {
    if (auto value = c.poll()) return *value;
    std::this_thread::sleep_for(1ms);
  } while (clock_ms() < end);
  throw error("async_test_timeout");
}
template<class F> void rejected(F operation, std::string_view expected) {
  bool refused = false;
  try { operation(); } catch (const error &e) { refused = std::string_view(e.what()) == expected; }
  check(refused, "async_wrong_error");
}
}
int native_delegation_channel_suite() {
  checks = 0;
  for (auto scenario : {fault::none, fault::reflected, fault::timeout}) {
    peer server(scenario, true); server.release();
    auto start = clock_ms();
    if (scenario == fault::none) { native_delegation_owner restored(server.capability); }
    else rejected([&] { native_delegation_owner restored(server.capability); },
                  scenario == fault::reflected ? "forbidden" : "delegation_owner_lost");
    if (scenario == fault::timeout) {
      check(clock_ms() - start >= 1400 && clock_ms() - start < 2500, "recovery_handshake_deadline");
      server.release();
    }
    server.finish();
  }
  std::cout << "PASS CHANNEL/recovery-mutual-proof-domain-separation-and-fixed-timeout\n";
  for (auto scenario : {fault::restore_missing, fault::restore_multiple, fault::restore_error_fd,
       fault::restore_identity, fault::restore_flags, fault::inventory_full, fault::inventory_overflow,
       fault::inventory_loop, fault::inventory_slow}) {
    auto descriptor_count = [] {
      return std::distance(fs::directory_iterator("/proc/self/fd"), fs::directory_iterator());
    };
    auto before = descriptor_count();
    {
      peer server(scenario, true); server.release();
      native_delegation_owner owner(server.capability);
      auto start = clock_ms();
      if (scenario == fault::inventory_full) {
        auto records = owner.inventory();
        check(records.size() == 256 && records[0].at("id") == 1 && records[255].at("id") == 256,
            "inventory_full_boundary_failed");
      } else {
        auto expected = scenario == fault::restore_identity || scenario == fault::restore_flags ||
            scenario == fault::inventory_overflow ? "delegation_owner_io" : "delegation_owner_lost";
        rejected([&] {
          if (scenario >= fault::inventory_full) owner.inventory(); else owner.restore(1, "expected-incarnation");
        }, expected);
        rejected([&] { owner.inspect(1); }, "delegation_owner_lost");
        if (scenario == fault::inventory_slow)
          check(clock_ms() - start >= 1400 && clock_ms() - start < 2300, "inventory_total_deadline_slid");
      }
      server.finish();
    }
    check(descriptor_count() == before, "recovery_descriptor_leaked");
  }
  std::cout << "PASS CHANNEL/recovery-descriptor-validation-cleanup-and-bounded-inventory\n";
  for (auto scenario : {fault::none, fault::reflected, fault::wrong_id, fault::wrong_op, fault::zero_token,
       fault::bad_magic, fault::short_record, fault::descriptor, fault::state, fault::count, fault::eof,
       fault::timeout, fault::capacity, fault::wrong_token}) {
    peer server(scenario);
    reservation_channel c(server.capability, reservation_channel::mode::nonblocking);
    check(c.alive(), "async_live_pending_handshake");
    // The peer cannot answer until explicitly released. A blocking constructor
    // or poll therefore fails, instead of passing by scheduling coincidence.
    for (int i = 0; i < 10; ++i) check(!c.poll(), "async_handshake_waited");
    rejected([&] { c.begin_inspect(); }, "operation_pending");
    rejected([&] { c.inspect(); }, "invalid_request");
    server.release();
    if (scenario == fault::reflected) {
      rejected([&] { result(c); }, "forbidden");
      rejected([&] { c.begin_reserve(); }, "delegation_owner_lost");
      server.finish(); continue;
    }
    check(result(c).at("held"), "async_handshake_result");
    check(c.alive(), "async_live_idle_channel");
    rejected([&] { c.poll(); }, "invalid_request");
    c.begin_reserve();
    check(c.alive(), "async_live_pending_reserve");
    for (int i = 0; i < 10; ++i) check(!c.poll(), "async_reserve_waited");
    rejected([&] { c.begin_complete(1, false); }, "operation_pending");
    server.release();
    if (scenario == fault::capacity) {
      rejected([&] { result(c); }, "operation_limit");
      c.begin_reserve(); // A valid negative ACK is recoverable.
    } else if (scenario != fault::none && scenario != fault::wrong_token) {
      auto started = clock_ms();
      rejected([&] { result(c); }, scenario == fault::state || scenario == fault::count ?
          "delegation_owner_io" : "delegation_owner_lost");
      if (scenario == fault::timeout) {
        check(clock_ms() - started >= 1400 && clock_ms() - started < 2400, "async_deadline_slid");
        server.release();
      }
      rejected([&] { c.begin_reserve(); }, "delegation_owner_lost");
      server.finish(); continue;
    }
    auto reserved = result(c);
    check(reserved.at("reservation") == 41 && reserved.at("reservations") == 1, "async_reservation_ack");
    rejected([&] { c.begin_complete(0, true); }, "invalid_request");
    c.begin_complete(41, true);
    if (scenario == fault::wrong_token) {
      rejected([&] { result(c); }, "delegation_owner_lost");
      rejected([&] { c.begin_inspect(); }, "delegation_owner_lost");
      server.finish(); continue;
    }
    check(result(c).at("reservations") == 0, "async_completion_ack");
    rejected([&] { c.poll(); }, "invalid_request");
    c.begin_complete(41, false);
    rejected([&] { result(c); }, "stale_handle");
    c.begin_inspect(); check(result(c).at("held"), "async_valid_after_negative_ack");
    server.finish();
    check(!c.alive() && !c.alive(), "async_idle_eof_not_detected");
    rejected([&] { c.begin_inspect(); }, "delegation_owner_lost");
  }
  std::cout << "PASS CHANNEL/nonblocking-handshake-ACK-errors-fixed-timeout " << checks << " checks\n";
  return checks;
}
