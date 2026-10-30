#include <taucloud/http_stream.hpp>
#include <algorithm>
#include <array>
#include <charconv>
namespace tc::http_stream {
std::string lower(std::string v) {
  for (auto &c : v)
    if (c >= 'A' && c <= 'Z')
      c += 'a' - 'A';
  return v;
}
std::string trim(std::string v) {
  auto a = v.find_first_not_of(" \t"), b = v.find_last_not_of(" \t");
  return a == std::string::npos ? "" : v.substr(a, b - a + 1);
}
uint64_t decimal(std::string_view v) {
  uint64_t n = 0;
  auto [p, e] = std::from_chars(v.data(), v.data() + v.size(), n);
  require(!v.empty() && e == std::errc() && p == v.data() + v.size() && n <= INT64_MAX, "bad_http");
  return n;
}
std::string head::get(const std::string &key) const {
  auto it = headers.find(key);
  return it == headers.end() ? "" : it->second;
}
static bool token(std::string_view v) {
  if (v.empty())
    return false;
  for (unsigned char c : v)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
          std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos))
      return false;
  return true;
}
head parse_head(std::string_view value) {
  require(value.size() <= 16384, "headers_too_large");
  head out;
  auto end = value.find("\r\n");
  require(end != std::string_view::npos, "bad_http");
  auto first = value.substr(0, end);
  auto a = first.find(' '), b = first.rfind(' ');
  require(a != std::string_view::npos && a != b && first.substr(b + 1) == "HTTP/1.1", "bad_http");
  out.method = first.substr(0, a);
  out.target = first.substr(a + 1, b - a - 1);
  require(token(out.method) && out.target.size() <= 4096 && !out.target.empty(), "bad_http");
  for (unsigned char c : out.target)
    require(c > 32 && c < 127, "bad_http");
  size_t pos = end + 2, count = 0;
  while (pos < value.size()) {
    end = value.find("\r\n", pos);
    require(end != std::string_view::npos, "bad_http");
    if (end == pos) {
      require(end + 2 == value.size(), "bad_http");
      break;
    }
    auto line = value.substr(pos, end - pos);
    auto colon = line.find(':');
    require(colon != std::string_view::npos && token(line.substr(0, colon)) && ++count <= 64,
            "bad_http");
    auto key = lower(std::string(line.substr(0, colon))),
         val = trim(std::string(line.substr(colon + 1)));
    for (unsigned char c : val)
      require(c == '\t' || (c >= 32 && c != 127), "bad_http");
    require(out.headers.emplace(key, val).second, "bad_http");
    pos = end + 2;
  }
  require(!out.get("host").empty(), "bad_http");
  if (out.headers.contains("content-length"))
    out.length = decimal(out.get("content-length"));
  if (out.headers.contains("transfer-encoding")) {
    require(!out.length && lower(out.get("transfer-encoding")) == "chunked", "bad_http");
    out.chunked = true;
  }
  require(!out.headers.contains("upgrade"), "bad_http");
  return out;
}
bool etag_matches(std::string_view field, const std::string &etag, bool exists, bool weak) {
  if (trim(std::string(field)) == "*")
    return exists;
  while (!field.empty()) {
    auto comma = field.find(',');
    auto candidate = trim(std::string(field.substr(0, comma)));
    if (weak && candidate.starts_with("W/"))
      candidate.erase(0, 2);
    if (exists && candidate == etag)
      return true;
    if (comma == std::string_view::npos)
      break;
    field.remove_prefix(comma + 1);
  }
  return false;
}
std::string reason(unsigned s) {
  switch (s) {
  case 100:
    return "Continue";
  case 200:
    return "OK";
  case 201:
    return "Created";
  case 204:
    return "No Content";
  case 206:
    return "Partial Content";
  case 207:
    return "Multi-Status";
  case 301:
    return "Moved Permanently";
  case 304:
    return "Not Modified";
  case 400:
    return "Bad Request";
  case 401:
    return "Unauthorized";
  case 403:
    return "Forbidden";
  case 404:
    return "Not Found";
  case 405:
    return "Method Not Allowed";
  case 409:
    return "Conflict";
  case 412:
    return "Precondition Failed";
  case 413:
    return "Content Too Large";
  case 415:
    return "Unsupported Media Type";
  case 416:
    return "Range Not Satisfiable";
  case 417:
    return "Expectation Failed";
  case 422:
    return "Unprocessable Content";
  case 423:
    return "Locked";
  case 424:
    return "Failed Dependency";
  case 429:
    return "Too Many Requests";
  case 501:
    return "Not Implemented";
  case 503:
    return "Service Unavailable";
  case 507:
    return "Insufficient Storage";
  default:
    return "Internal Server Error";
  }
}
pace::task<void> stream::fill() {
  std::array<char, 8192> bytes{};
  auto timeout = socket_.context().call_after(5s, [this] { socket_.close(); });
  auto n = co_await socket_.read_some(bytes);
  timeout.cancel();
  require(n > 0, "disconnected");
  buffer_.append(bytes.data(), n);
  require(buffer_.size() <= chunk_size + 16384, "bad_http");
}
pace::task<std::string> stream::line(size_t limit) {
  for (;;) {
    auto end = buffer_.find("\r\n");
    if (end != std::string::npos) {
      require(end <= limit, "bad_http");
      auto out = buffer_.substr(0, end);
      buffer_.erase(0, end + 2);
      co_return out;
    }
    require(buffer_.size() <= limit, "bad_http");
    co_await fill();
  }
}
pace::task<head> stream::read_head() {
  auto deadline = socket_.context().call_after(5s, [this] { socket_.close(); });
  for (;;) {
    auto end = buffer_.find("\r\n\r\n");
    if (end != std::string::npos) {
      auto result = parse_head(std::string_view(buffer_).substr(0, end + 4));
      buffer_.erase(0, end + 4);
      deadline.cancel();
      co_return result;
    }
    require(buffer_.size() < 16384, "headers_too_large");
    co_await fill();
  }
}
void stream::admit(const head &h, uint64_t limit) {
  require(!admitted_ && (!h.length || *h.length <= limit), "body_too_large");
  admitted_ = true;
  chunked_ = h.chunked;
  remaining_ = h.length.value_or(0);
  limit_ = limit;
  ended_ = !chunked_ && remaining_ == 0;
}
pace::task<std::string> stream::read() {
  require(admitted_, "body_not_admitted");
  if (ended_)
    co_return std::string();
  if (chunked_ && remaining_ == 0) {
    if (chunk_end_) {
      require((co_await line(0)).empty(), "bad_http");
      chunk_end_ = false;
    }
    auto size = co_await line(128);
    auto end = size.find(';');
    auto digits = std::string_view(size).substr(0, end);
    uint64_t n = 0;
    auto [p, e] = std::from_chars(digits.data(), digits.data() + digits.size(), n, 16);
    require(!digits.empty() && e == std::errc() && p == digits.data() + digits.size() &&
                n <= limit_ - total_,
            "body_too_large");
    remaining_ = n;
    if (!n) {
      size_t trailer_bytes = 0;
      for (;;) {
        auto trailer = co_await line(4096);
        trailer_bytes += trailer.size() + 2;
        require(trailer_bytes <= 8192, "bad_http");
        if (trailer.empty())
          break;
        auto colon = trailer.find(':');
        require(colon != std::string::npos && token(trailer.substr(0, colon)), "bad_http");
        auto key = lower(trailer.substr(0, colon));
        require(key == "digest" || key == "content-digest", "bad_http");
      }
      ended_ = true;
      co_return std::string();
    }
  }
  while (buffer_.size() < std::min<uint64_t>(remaining_, chunk_size))
    co_await fill();
  auto n = static_cast<size_t>(std::min<uint64_t>({remaining_, buffer_.size(), chunk_size}));
  require(n <= limit_ - total_, "body_too_large");
  auto value = buffer_.substr(0, n);
  buffer_.erase(0, n);
  remaining_ -= n;
  total_ += n;
  if (!remaining_) {
    if (chunked_)
      chunk_end_ = true;
    else
      ended_ = true;
  }
  co_return value;
}
pace::task<void> stream::write(std::string_view bytes) {
  auto timeout = socket_.context().call_after(5s, [this] { socket_.close(); });
  co_await socket_.write_all(bytes);
  timeout.cancel();
}
pace::task<void> stream::write_head(unsigned status, std::map<std::string, std::string> headers) {
  headers["Connection"] = "close";
  headers["X-Content-Type-Options"] = "nosniff";
  auto value = "HTTP/1.1 " + std::to_string(status) + " " + reason(status) + "\r\n";
  for (auto &[key, val] : headers) {
    require(token(key) && val.find_first_of("\r\n") == std::string::npos, "bad_http");
    value += key + ": " + val + "\r\n";
  }
  value += "\r\n";
  co_await write(value);
}
pace::task<void> stream::respond(unsigned status, std::map<std::string, std::string> headers,
                                 std::string body, bool head_only) {
  headers["Content-Length"] = std::to_string(body.size());
  co_await write_head(status, std::move(headers));
  if (!head_only && !body.empty())
    co_await write(body);
}
} // namespace tc::http_stream
