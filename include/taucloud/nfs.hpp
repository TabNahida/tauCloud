#pragma once
#include <taucloud/core.hpp>
#include <taucloud/nfs_callback_delivery.hpp>
#include <string_view>
namespace tc::nfs_detail {
constexpr size_t max_record = 256 * 1024;
constexpr unsigned max_call_records = 24;
constexpr unsigned max_reply_records = 8;
struct xdr_error : std::exception {};
struct reader {
  std::string_view data;
  size_t pos = 0;
  explicit reader(std::string_view d) : data(d) {}
  std::string fixed(size_t n);
  uint32_t u32();
  uint64_t u64();
  bool boolean();
  std::string opaque(size_t limit = 65536);
  void end() const;
};
struct writer {
  std::string data;
  writer &u32(uint32_t);
  writer &u64(uint64_t);
  writer &boolean(bool);
  writer &fixed(std::string_view);
  writer &opaque(std::string_view);
};
// Cumulative fragment, fragment count and record bounds are all independent.
struct record_decoder {
  std::string data;
  unsigned fragments = 0;
  size_t fragment(uint32_t marker);
  bool append(uint32_t marker, std::string_view bytes);
};
using domain_call = std::function<json(std::string, std::string, json)>;
// Only typed NLM/NSM messages to the single trusted loopback peer are permitted.
using callback_call = std::function<std::string(uint32_t, uint32_t, uint32_t, std::string)>;
// Reverse RPCs use only an already-bound transport, never a client-supplied address.
// Queue only a weak delivery reference; pin it while writing the active frame,
// then call finish() after the entire frame is accepted by the transport.
using backchannel_send = std::function<void(std::string, std::string, std::shared_ptr<callback_delivery>)>;
// Closing is asynchronous; protocol.disconnect confirms transport loss before
// an outstanding CB_COMPOUND may be retried on another bound connection.
using backchannel_close = std::function<void(std::string)>;
std::string loopback_callback(const config &, uint32_t program, uint32_t version,
                              uint32_t procedure, const std::string &body);
class server {
  struct impl;
  std::unique_ptr<impl> impl_;

public:
  server(const config &, domain_call, callback_call = {}, backchannel_send = {}, backchannel_close = {});
  ~server();
  // Register a complete received record before waiting in the executor. This
  // preserves still-live state for authentication; it does not renew a lease.
  // Every token must be dispatched once or cancelled, including submit failure.
  uint64_t admit_request(std::string connection, std::string_view record = {});
  void cancel_request(uint64_t admission);
  // Reactor variants never wait for native ACKs or the protocol mutex. Drive
  // poll_native while idle and request_ready before submitting a dispatch.
  // Every begun request must be dispatched or abandoned, including errors.
  // A supplied record contributes only an untrusted RPC reply header hint;
  // callback authentication and sequence validation still happen in dispatch.
  uint64_t begin_request(std::string connection, std::string_view record = {});
  bool request_ready(uint64_t admission);
  void abandon_request(uint64_t admission);
  // False latches native protection loss for this server instance. The reactor
  // must close transports and refuse new connections; it cannot reset the latch.
  bool poll_native();
  void enqueue_reply_completion(uint64_t completion);
  void transport_disconnected(const std::string &connection);
  // A transport may request a private completion token. A nonzero token pins
  // the client lease until complete_reply or disconnect; it is never on wire.
  // Without a token, the caller treats return from dispatch as delivery.
  std::string dispatch(std::string_view record, std::string connection = "test", uint64_t *completion = nullptr,
                       uint64_t admission = 0);
  void complete_reply(uint64_t completion);
  void disconnect(const std::string &connection);
  void maintenance();
};
} // namespace tc::nfs_detail
