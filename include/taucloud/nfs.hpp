#pragma once
#include <taucloud/core.hpp>
#include <string_view>
namespace tc::nfs_detail {
constexpr size_t max_record = 256 * 1024;
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
using backchannel_send = std::function<void(std::string, std::string)>;
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
  std::string dispatch(std::string_view record, std::string connection = "test");
  void disconnect(const std::string &connection);
  void maintenance();
};
} // namespace tc::nfs_detail
