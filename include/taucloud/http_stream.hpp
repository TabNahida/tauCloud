#pragma once
#include <taucloud/core.hpp>
#include <pace/tls.hpp>
#include <map>
namespace tc::http_stream {
constexpr size_t chunk_size = 64 * 1024;
std::string lower(std::string value);
std::string trim(std::string value);
uint64_t decimal(std::string_view value);
struct head {
  std::string method, target;
  std::map<std::string, std::string> headers;
  std::optional<uint64_t> length;
  bool chunked = false;
  std::string get(const std::string &key) const;
};
head parse_head(std::string_view value);
std::string reason(unsigned status);
bool etag_matches(std::string_view field, const std::string &etag, bool exists, bool weak = false);
class stream {
  pace::tls::stream &socket_;
  std::string buffer_;
  uint64_t remaining_ = 0, total_ = 0, limit_ = 0;
  bool chunked_ = false, admitted_ = false, ended_ = false, chunk_end_ = false;
  pace::task<void> fill();
  pace::task<std::string> line(size_t limit);

public:
  explicit stream(pace::tls::stream &socket) : socket_(socket) {}
  pace::task<head> read_head();
  void admit(const head &, uint64_t limit);
  pace::task<std::string> read();
  pace::task<void> write(std::string_view bytes);
  pace::task<void> respond(unsigned status, std::map<std::string, std::string> headers = {},
                           std::string body = "", bool head_only = false);
  pace::task<void> write_head(unsigned status, std::map<std::string, std::string> headers);
};
} // namespace tc::http_stream
