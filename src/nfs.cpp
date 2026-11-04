#include <taucloud/nfs.hpp>
#include <taucloud/files.hpp>
#include <taucloud/runtime/bounded_executor.hpp>
#include <pace/tcp.hpp>
#include <pace/udp.hpp>
#include <map>
#include <deque>
namespace tc {
namespace {
struct outgoing_reply {
  std::string packet;
  uint64_t completion = 0;
};
struct nfs_connection {
  pace::tcp::stream socket;
  std::deque<outgoing_reply> output;
  size_t queued_bytes = 0;
  bool writing = false;
  explicit nfs_connection(pace::tcp::stream stream) : socket(std::move(stream)) {}
};
struct nfs_runtime {
  config cfg;
  std::shared_ptr<pace::io_context> io = std::make_shared<pace::io_context>();
  taucloud::bounded_executor pool{2, 16, 16 * nfs_detail::max_record};
  nfs_detail::server protocol;
  std::atomic<int> connections = 0;
  std::map<std::string, std::shared_ptr<nfs_connection>> sockets;
  void send(std::string connection, std::string packet);
  explicit nfs_runtime(const config &c)
      : cfg(c), protocol(c, [c](std::string target, std::string op, json body) {
          return rpc(c, "nfs", target, op, body);
        }, [c](uint32_t program, uint32_t version, uint32_t procedure, std::string body) {
          return nfs_detail::loopback_callback(c, program, version, procedure, body);
        }, [this](std::string connection, std::string packet) {
          send(std::move(connection), std::move(packet));
        }, [this](std::string connection) {
          io->post([this, connection = std::move(connection)] {
            auto found = sockets.find(connection);
            if (found != sockets.end()) found->second->socket.close();
          });
        }) {}
};
// One writer owns each stream. Reverse RPCs and ordinary replies cannot
// interleave record headers or payloads, even while a client pipelines requests.
pace::task<void> write_frames(nfs_runtime &s, std::shared_ptr<nfs_connection> c) {
  uint64_t current = 0;
  try {
    while (c->socket.is_open() && !c->output.empty()) {
      auto packet = std::move(c->output.front());
      c->output.pop_front();
      current = packet.completion;
      nfs_detail::writer header;
      header.u32(0x80000000u | uint32_t(packet.packet.size()));
      auto timer = s.io->call_after(5s, [c] { c->socket.close(); });
      co_await c->socket.write_all(header.data + packet.packet);
      s.protocol.complete_reply(current); current = 0;
      c->queued_bytes -= packet.packet.size();
    }
  } catch (...) { c->socket.close(); }
  s.protocol.complete_reply(current);
  c->writing = false;
  if (!c->socket.is_open()) {
    for (const auto &packet : c->output) s.protocol.complete_reply(packet.completion);
    c->output.clear(); c->queued_bytes = 0;
  }
}
void enqueue(nfs_runtime &s, const std::shared_ptr<nfs_connection> &c, outgoing_reply packet) {
  if (!c->socket.is_open() || packet.packet.empty()) { s.protocol.complete_reply(packet.completion); return; }
  if (packet.packet.size() > nfs_detail::max_record || c->output.size() >= 16 ||
      c->queued_bytes + packet.packet.size() > 4 * nfs_detail::max_record) {
    s.protocol.complete_reply(packet.completion);
    c->socket.close(); return;
  }
  c->queued_bytes += packet.packet.size();
  c->output.push_back(std::move(packet));
  if (!c->writing) {
    c->writing = true;
    s.io->spawn(write_frames(s, c));
  }
}
void nfs_runtime::send(std::string connection, std::string packet) {
  io->post([this, connection = std::move(connection), packet = std::move(packet)]() mutable {
    auto found = sockets.find(connection);
    if (found != sockets.end()) enqueue(*this, found->second, outgoing_reply{std::move(packet)});
  });
}
pace::task<outgoing_reply> process(nfs_runtime &s, std::string packet, std::string connection) {
  struct pending {
    outgoing_reply reply;
    std::exception_ptr failure;
    bool done = false;
    bool abandoned = false;
  };
  auto p = std::make_shared<pending>();
  // This runs on the transport reactor after record assembly, before either
  // the bounded executor or the protocol mutex can delay authentication.
  auto admission = s.protocol.admit_request(connection);
  struct admission_cleanup {
    nfs_detail::server &protocol;
    uint64_t id;
    ~admission_cleanup() { protocol.cancel_request(id); }
  } admitted{s.protocol, admission};
  taucloud::bounded_executor::ticket ticket;
  require(s.pool.submit(
              s.io, nfs_detail::max_record, std::chrono::steady_clock::now() + 5s,
              [&s, p, packet = std::move(packet), connection, admission](std::stop_token stop) {
                require(!stop.stop_requested(), "cancelled");
                p->reply.packet = s.protocol.dispatch(packet, connection, &p->reply.completion, admission);
              },
              [&s, p](taucloud::bounded_executor::result r) {
                p->failure = r.error;
                if (r.state != taucloud::bounded_executor::status::completed && !p->failure)
                  p->failure = std::make_exception_ptr(error("cancelled"));
                p->done = true;
                if (p->abandoned) s.protocol.complete_reply(p->reply.completion);
              },
              ticket),
          "overloaded");
  try {
    while (!p->done)
      co_await s.io->sleep_for(1ms);
  } catch (...) {
    p->abandoned = true;
    if (p->done) s.protocol.complete_reply(p->reply.completion);
    ticket.cancel();
    throw;
  }
  if (p->failure) {
    s.protocol.complete_reply(p->reply.completion);
    std::rethrow_exception(p->failure);
  }
  co_return std::move(p->reply);
}
pace::task<void> serve(nfs_runtime &s, pace::tcp::stream stream) {
  auto c = std::make_shared<nfs_connection>(std::move(stream));
  auto &socket = c->socket;
  auto connection = random_hex(16);
  s.sockets.emplace(connection, c);
  bool active = false;
  try {
    while (socket.is_open()) {
      nfs_detail::record_decoder record;
      {
        auto idle = s.io->call_after(active ? 120s : 15s, [&socket] { socket.close(); });
        auto first = co_await socket.read_exact(4, 4);
        idle.cancel();
        auto timer = s.io->call_after(15s, [&socket] { socket.close(); });
        for (;;) {
          auto prefix = std::move(first);
          first.clear();
          if (prefix.empty()) prefix = co_await socket.read_exact(4, 4);
          nfs_detail::reader r(prefix);
          auto marker = r.u32();
          auto n = record.fragment(marker);
          auto part = co_await socket.read_exact(n, nfs_detail::max_record);
          if (record.append(marker, part))
            break;
        }
      }
      auto response = co_await process(s, std::move(record.data), connection);
      active = true;
      if (response.packet.empty()) { s.protocol.complete_reply(response.completion); continue; }
      enqueue(s, c, std::move(response));
    }
  } catch (...) {
  }
  socket.close();
  s.protocol.disconnect(connection);
  s.sockets.erase(connection);
  --s.connections;
}
pace::task<void> accept(nfs_runtime &s, pace::tcp::listener &listener, std::atomic_bool &stopping) {
  try {
    while (!stopping) {
      auto socket = co_await listener.accept();
      if (s.connections >= std::min(s.cfg.connections, 16)) {
        socket.close();
        continue;
      }
      ++s.connections;
      s.io->spawn(serve(s, std::move(socket)));
    }
  } catch (...) {
    if (!stopping)
      stopping = true;
  }
}
pace::task<void> status_datagrams(nfs_runtime &s, pace::udp::socket &socket,
                                 std::atomic_bool &stopping) {
  std::array<char, 4096> buffer{};
  while (!stopping && socket.is_open()) {
    try {
      auto datagram = co_await socket.receive_from(buffer);
      if (datagram.truncated || datagram.size < 24 ||
          !datagram.sender.address.starts_with("127.")) continue;
      std::string packet(buffer.data(), datagram.size);
      nfs_detail::reader header(packet);
      header.u32(); header.u32(); header.u32();
      auto program = header.u32();
      // UDP is exclusively NSM and read-only service discovery, never NFS I/O.
      if (program != 100024 && program != 100000) continue;
      auto reply = co_await process(s, std::move(packet), "nsm-udp");
      if (reply.packet.size() <= buffer.size()) co_await socket.send_to(reply.packet, datagram.sender);
      s.protocol.complete_reply(reply.completion); // UDP admission never accepts NFSv4.
    } catch (...) {
      if (!socket.is_open() || stopping) break;
    }
  }
}
} // namespace
int nfs(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  if (!c.nfs_port)
    return worker("nfs", c, generation, stopping);
  file_lock lock(c.state / "nfs.lock");
  apply_resource_budget(c);
  nfs_runtime s(c);
  pace::tcp::listener listener(*s.io, {c.nfs_address, c.nfs_port}, {false, 32});
  pace::udp::socket status_socket(*s.io, {c.nfs_address, c.nfs_port});
  auto info = [&] {
    auto p = process_info(own_pid());
    p["role"] = "nfs";
    p["generation"] = generation;
    p["business_ready"] = true;
    p["connections"] = s.connections.load();
    p["compatibility"] = "experimental";
    return p;
  };
  rpc_server ipc(c, "nfs", generation,
                 [&](const std::string &op, const json &, const call_context &) {
                   if (op == "ping")
                     return info();
                   if (op == "stop") {
                     stopping = true;
                     return json{{"stopping", true}};
                   }
                   throw error("not_supported");
                 });
  write_json(c.state / "nfs.instance.json", info());
  s.io->spawn(accept(s, listener, stopping));
  s.io->spawn(status_datagrams(s, status_socket, stopping));
  std::jthread loop([&] {
    try {
      s.io->run();
    } catch (...) {
    }
    stopping = true;
  });
  log("nfs", "started");
  auto next_maintenance = now() + 1000;
  while (!stopping) {
    if (now() >= next_maintenance) {
      try { s.protocol.maintenance(); }
      catch (...) { log("nfs", "maintenance_failed", "internal_error"); }
      next_maintenance = now() + 1000;
    }
    std::this_thread::sleep_for(20ms);
  }
  s.io->post([&] {
    listener.close();
    status_socket.close();
    for (const auto &[id, connection] : s.sockets)
      connection->socket.close();
  });
  ipc.stop();
  auto deadline = now() + 7000;
  while (s.connections > 0 && now() < deadline)
    std::this_thread::sleep_for(20ms);
  s.pool.shutdown();
  while (s.pool.outstanding() > 0)
    std::this_thread::sleep_for(10ms);
  s.io->stop();
  loop.join();
  log("nfs", "stopped");
  return 0;
}
} // namespace tc
