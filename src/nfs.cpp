#include <taucloud/nfs.hpp>
#include <taucloud/files.hpp>
#include <taucloud/runtime/bounded_executor.hpp>
#include <pace/tcp.hpp>
#include <set>
namespace tc {
namespace {
struct nfs_runtime {
  config cfg;
  std::shared_ptr<pace::io_context> io = std::make_shared<pace::io_context>();
  taucloud::bounded_executor pool{2, 16, 16 * nfs_detail::max_record};
  nfs_detail::server protocol;
  std::atomic<int> connections = 0;
  std::set<pace::tcp::stream *> sockets;
  explicit nfs_runtime(const config &c)
      : cfg(c), protocol(c, [c](std::string target, std::string op, json body) {
          return rpc(c, "nfs", target, op, body);
        }) {}
};
pace::task<std::string> process(nfs_runtime &s, std::string packet, std::string connection) {
  struct pending {
    std::string reply;
    std::exception_ptr failure;
    bool done = false;
  };
  auto p = std::make_shared<pending>();
  taucloud::bounded_executor::ticket ticket;
  require(s.pool.submit(
              s.io, nfs_detail::max_record, std::chrono::steady_clock::now() + 5s,
              [&s, p, packet = std::move(packet), connection](std::stop_token stop) {
                require(!stop.stop_requested(), "cancelled");
                p->reply = s.protocol.dispatch(packet, connection);
              },
              [p](taucloud::bounded_executor::result r) {
                p->failure = r.error;
                if (r.state != taucloud::bounded_executor::status::completed && !p->failure)
                  p->failure = std::make_exception_ptr(error("cancelled"));
                p->done = true;
              },
              ticket),
          "overloaded");
  try {
    while (!p->done)
      co_await s.io->sleep_for(1ms);
  } catch (...) {
    ticket.cancel();
    throw;
  }
  if (p->failure)
    std::rethrow_exception(p->failure);
  co_return p->reply;
}
pace::task<void> serve(nfs_runtime &s, pace::tcp::stream socket) {
  s.sockets.insert(&socket);
  auto connection = random_hex(16);
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
      require(response.size() <= nfs_detail::max_record, "response_limit");
      nfs_detail::writer header;
      header.u32(0x80000000u | uint32_t(response.size()));
      auto timer = s.io->call_after(5s, [&socket] { socket.close(); });
      co_await socket.write_all(header.data + response);
    }
  } catch (...) {
  }
  socket.close();
  s.protocol.disconnect(connection);
  s.sockets.erase(&socket);
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
} // namespace
int nfs(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  if (!c.nfs_port)
    return worker("nfs", c, generation, stopping);
  file_lock lock(c.state / "nfs.lock");
  apply_resource_budget(c);
  nfs_runtime s(c);
  pace::tcp::listener listener(*s.io, {"127.0.0.1", c.nfs_port}, {false, 32});
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
    for (auto *socket : s.sockets)
      socket->close();
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
