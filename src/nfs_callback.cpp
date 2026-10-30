#include <taucloud/nfs.hpp>
#include <pace/tcp.hpp>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

namespace tc::nfs_detail {
namespace {
// The caller cannot select an address, port, program payload or transport.
// rpcbind only resolves the two fixed companion programs on the trusted host.
std::string exchange(const config &cfg, uint16_t port, uint32_t program,
                     uint32_t version, uint32_t procedure, const std::string &body) {
  require(body.size() <= 4096, "request_limit");
  auto io = std::make_shared<pace::io_context>();
  pace::tcp::stream socket(*io, pace::address_family::ipv4);
  sockaddr_in source{};
  source.sin_family = AF_INET;
  require(inet_pton(AF_INET, cfg.nfs_address.c_str(), &source.sin_addr) == 1 &&
      ::bind(socket.native_handle(), reinterpret_cast<sockaddr *>(&source), sizeof(source)) == 0,
      "callback_unavailable");
  auto xid = uint32_t(now());
  writer credential;
  credential.u32(0).opaque("tauCloud").u32(0).u32(0).u32(0);
  writer call;
  call.u32(xid).u32(0).u32(2).u32(program).u32(version).u32(procedure)
      .u32(1).opaque(credential.data).u32(0).opaque("").fixed(body);
  writer frame;
  frame.u32(0x80000000u | uint32_t(call.data.size())).fixed(call.data);
  std::string result;
  std::exception_ptr failure;
  auto task = [&]() -> pace::task<void> {
    auto deadline = io->call_after(750ms, [&] { socket.close(); });
    try {
      co_await socket.connect({"127.0.0.1", port});
      co_await socket.write_all(frame.data);
      record_decoder record;
      for (;;) {
        auto prefix = co_await socket.read_exact(4, 4);
        reader r(prefix);
        auto marker = r.u32();
        auto length = record.fragment(marker);
        require(length <= 4096 && record.data.size() + length <= 4096, "response_limit");
        auto bytes = co_await socket.read_exact(length, 4096);
        if (record.append(marker, bytes)) break;
      }
      reader r(record.data);
      require(r.u32() == xid && r.u32() == 1 && r.u32() == 0, "callback_rejected");
      r.u32(); r.opaque(400);
      require(r.u32() == 0, "callback_rejected");
      result = std::string(r.data.substr(r.pos));
    } catch (...) { failure = std::current_exception(); }
    deadline.cancel();
    socket.close();
    io->stop();
  };
  io->spawn(task());
  io->run();
  if (failure) std::rethrow_exception(failure);
  return result;
}
} // namespace
std::string loopback_callback(const config &cfg, uint32_t program, uint32_t version,
                              uint32_t procedure, const std::string &body) {
  require((program == 100021 && version == 4 &&
      (procedure == 5 || (procedure >= 11 && procedure <= 16) || procedure == 24)) ||
      (program == 100024 && version == 1 && procedure == 6), "forbidden");
  writer query;
  query.u32(program).u32(version).u32(6).u32(0);
  auto reply = exchange(cfg, cfg.nfs_peer_rpcbind_port, 100000, 2, 3, query.data);
  reader r(reply);
  auto port = r.u32(); r.end();
  require(port >= 1024 && port <= 65535 &&
      (cfg.nfs_address != "127.0.0.1" || port != cfg.nfs_port), "callback_unavailable");
  return exchange(cfg, uint16_t(port), program, version, procedure, body);
}
} // namespace tc::nfs_detail
