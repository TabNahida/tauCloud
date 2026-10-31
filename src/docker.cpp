#include <taucloud/plugins.hpp>
#include <taucloud/http_stream.hpp>
#include <taucloud/files.hpp>
#include <algorithm>
#include <array>
#include <charconv>
#include <regex>
#include <set>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#endif
namespace tc {
namespace {
constexpr size_t response_limit = 256 * 1024;
void fields(const json &j, std::initializer_list<const char *> allowed) {
  require(j.is_object(), "invalid_request");
  for (auto &[k, v] : j.items())
    require(std::any_of(allowed.begin(), allowed.end(), [&](auto p) { return k == p; }),
            "invalid_request");
}
bool identifier(const std::string &s) {
  return !s.empty() && s.size() <= 128 &&
         std::all_of(s.begin(), s.end(),
                     [](unsigned char c) {
                       return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
                     }) &&
         s != "." && s != "..";
}
struct reply {
  int status;
  std::map<std::string, std::string> headers;
  std::string body;
};
std::optional<reply> parse_response(const std::string &wire, bool eof = false) {
  require(wire.size() <= response_limit + 32768, "engine_response_limit");
  auto end = wire.find("\r\n\r\n");
  if (end == std::string::npos) {
    require(!eof && wire.size() <= 16384, "bad_engine_http");
    return {};
  }
  require(end <= 16384, "bad_engine_http");
  auto line = wire.find("\r\n");
  require(line >= 12 && (wire.starts_with("HTTP/1.1 ") || wire.starts_with("HTTP/1.0 ")),
          "bad_engine_http");
  int status = 0;
  auto [ptr, ec] = std::from_chars(wire.data() + 9, wire.data() + 12, status);
  require(ec == std::errc() && ptr == wire.data() + 12 && status >= 200 && status <= 599,
          "bad_engine_http");
  require(line == 12 || wire[12] == ' ', "bad_engine_http");
  // Reuse the strict header grammar; a synthetic request line/Host supplies the
  // request-only fields without accepting duplicate or ambiguous framing.
  auto h = http_stream::parse_head("GET / HTTP/1.1\r\nHost: docker\r\n" +
                                   wire.substr(line + 2, end - line + 2));
  require(!h.headers.contains("content-encoding"), "bad_engine_http");
  reply out{status, h.headers, {}};
  size_t pos = end + 4;
  if (status == 204 || status == 304) {
    require(!h.chunked && (!h.length || *h.length == 0) && wire.size() == pos, "bad_engine_http");
    return out;
  }
  if (h.length) {
    require(*h.length <= response_limit, "engine_response_limit");
    if (wire.size() - pos < *h.length) {
      require(!eof, "engine_disconnected");
      return {};
    }
    require(wire.size() - pos == *h.length, "bad_engine_http");
    out.body = wire.substr(pos);
    return out;
  }
  if (h.chunked) {
    size_t chunks = 0;
    for (;;) {
      auto e = wire.find("\r\n", pos);
      if (e == std::string::npos) {
        require(!eof && wire.size() - pos <= 128, "bad_engine_http");
        return {};
      }
      require(e - pos <= 128 && ++chunks <= 4096, "bad_engine_http");
      auto v = std::string_view(wire).substr(pos, e - pos);
      size_t n = 0;
      auto [p, c] = std::from_chars(v.data(), v.data() + v.size(), n, 16);
      require(!v.empty() && c == std::errc() && p == v.data() + v.size(), "bad_engine_http");
      require(n <= response_limit - out.body.size(), "engine_response_limit");
      pos = e + 2;
      if (n == 0) {
        // Docker does not use trailers; rejecting them avoids hidden metadata.
        if (wire.size() - pos < 2) {
          require(!eof, "engine_disconnected");
          return {};
        }
        require(wire.substr(pos) == "\r\n", "bad_engine_http");
        return out;
      }
      if (wire.size() - pos < n + 2) {
        require(!eof, "engine_disconnected");
        return {};
      }
      require(wire.compare(pos + n, 2, "\r\n") == 0, "bad_engine_http");
      out.body.append(wire, pos, n);
      pos += n + 2;
    }
  }
  require(wire.size() - pos <= response_limit, "engine_response_limit");
  if (!eof)
    return {};
  out.body = wire.substr(pos);
  return out;
}
#ifndef _WIN32
struct local_stream {
  int fd = -1;
  ~local_stream() {
    if (fd >= 0)
      ::close(fd);
  }
  void ready(bool writing, const call_context &ctx) {
    for (;;) {
      ctx.check();
      pollfd p{fd, short(writing ? POLLOUT : POLLIN), 0};
      auto n = ::poll(
          &p, 1,
          static_cast<int>(std::min<int64_t>(50, std::max<int64_t>(1, ctx.deadline - now()))));
      if (n > 0)
        return;
      require(n == 0 || errno == EINTR, "engine_disconnected");
    }
  }
  void connect(const std::string &path, const call_context &ctx) {
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    require(path.size() < sizeof(a.sun_path), "invalid_endpoint");
    std::copy(path.begin(), path.end(), a.sun_path);
    fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    require(fd >= 0, "engine_unavailable");
    auto result = ::connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a));
    require(result == 0 || errno == EINPROGRESS, "engine_unavailable");
    if (result) {
      ready(true, ctx);
      int e = 0;
      socklen_t n = sizeof(e);
      require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &n) == 0 && e == 0, "engine_unavailable");
    }
  }
  void write(std::string_view s, const call_context &ctx) {
    while (!s.empty()) {
      ctx.check();
      auto n = ::send(fd, s.data(), s.size(), MSG_NOSIGNAL);
      if (n > 0)
        s.remove_prefix(n);
      else {
        require(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR),
                "engine_disconnected");
        ready(true, ctx);
      }
    }
  }
  size_t read(std::span<char> b, const call_context &ctx) {
    for (;;) {
      ctx.check();
      auto n = ::recv(fd, b.data(), b.size(), 0);
      if (n >= 0)
        return n;
      require(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR, "engine_disconnected");
      ready(false, ctx);
    }
  }
};
#else
struct local_stream {
  HANDLE handle = INVALID_HANDLE_VALUE;
  ~local_stream() {
    if (handle != INVALID_HANDLE_VALUE)
      CloseHandle(handle);
  }
  void connect(const std::string &path, const call_context &ctx) {
    auto name = fs::path(path).wstring();
    for (;;) {
      ctx.check();
      handle = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED, nullptr);
      if (handle != INVALID_HANDLE_VALUE)
        return;
      require(GetLastError() == ERROR_PIPE_BUSY, "engine_unavailable");
      WaitNamedPipeW(name.c_str(), 25);
    }
  }
  size_t transfer(void *data, size_t n, bool writing, const call_context &ctx) {
    ctx.check();
    OVERLAPPED o{};
    o.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    require(o.hEvent, "io_error");
    DWORD done = 0;
    BOOL ok = writing ? WriteFile(handle, data, static_cast<DWORD>(n), &done, &o)
                      : ReadFile(handle, data, static_cast<DWORD>(n), &done, &o);
    DWORD code = ok ? ERROR_SUCCESS : GetLastError();
    try {
      if (!ok && code == ERROR_IO_PENDING) {
        while (WaitForSingleObject(o.hEvent, 25) == WAIT_TIMEOUT)
          ctx.check();
        ok = GetOverlappedResult(handle, &o, &done, FALSE);
        code = ok ? ERROR_SUCCESS : GetLastError();
      }
      if (!writing && code == ERROR_BROKEN_PIPE)
        done = 0;
      else
        require(ok, "engine_disconnected");
    } catch (...) {
      CancelIoEx(handle, &o);
      GetOverlappedResult(handle, &o, &done, TRUE);
      CloseHandle(o.hEvent);
      throw;
    }
    CloseHandle(o.hEvent);
    return done;
  }
  void write(std::string_view s, const call_context &ctx) {
    while (!s.empty()) {
      auto n = transfer(const_cast<char *>(s.data()), s.size(), true, ctx);
      require(n > 0, "engine_disconnected");
      s.remove_prefix(n);
    }
  }
  size_t read(std::span<char> b, const call_context &ctx) {
    return transfer(b.data(), b.size(), false, ctx);
  }
};
#endif
pace::task<void> tls_request(pace::io_context &io, pace::tls::stream &stream, const json &e,
                             const std::string &request, const call_context &ctx,
                             std::optional<reply> &out, std::exception_ptr &failure) {
  try {
    co_await stream.connect({e.at("address"), e.at("port").get<uint16_t>()}, e.at("server_name"));
    co_await stream.write_all(request);
    std::string wire;
    std::array<char, 8192> b{};
    while (!out) {
      ctx.check();
      auto n = co_await stream.read_some(b);
      wire.append(b.data(), n);
      out = parse_response(wire, n == 0);
    }
  } catch (...) {
    failure = std::current_exception();
  }
  stream.close();
  io.stop();
}
reply request(const json &e, const std::string &method, const std::string &path, const json &body,
              const call_context &ctx) {
  ctx.check();
  auto payload = body.is_null() ? std::string() : body.dump();
  require(payload.size() <= 16384, "invalid_request");
  auto wire = method + " " + path +
              " HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nAccept: "
              "application/json\r\nContent-Type: application/json\r\nContent-Length: " +
              std::to_string(payload.size()) + "\r\n\r\n" + payload;
  std::optional<reply> out;
  if (e.at("transport") == "tls") {
    try {
      pace::io_context io;
      pace::tls::context tls(pace::tls::role::client, pace::tls::trust_source::application);
      tls.load_verify_file(e.at("ca"));
      tls.use_certificate_chain(e.at("certificate"), e.at("key"));
      pace::tls::stream stream(io, tls);
      std::exception_ptr failure;
      auto timer =
          io.call_after(std::chrono::milliseconds(std::max<int64_t>(1, ctx.deadline - now())),
                        [&] { stream.close(); });
      std::stop_callback cancel(ctx.cancellation, [&] { io.post([&] { stream.close(); }); });
      io.spawn(tls_request(io, stream, e, wire, ctx, out, failure));
      io.run();
      if (failure)
        std::rethrow_exception(failure);
    } catch (const error &) {
      throw;
    } catch (...) {
      ctx.check();
      throw error("engine_tls_failed");
    }
  } else {
    local_stream s;
    s.connect(e.at("path"), ctx);
    s.write(wire, ctx);
    std::array<char, 8192> b{};
    std::string response;
    while (!out) {
      auto n = s.read(b, ctx);
      response.append(b.data(), n);
      out = parse_response(response, n == 0);
    }
  }
  require(out.has_value(), "engine_disconnected");
  require(out->status != 401 && out->status != 403, "engine_forbidden");
  require(out->status != 404, "engine_not_found");
  require(out->status >= 200 && out->status < 300,
          "engine_rejected"); // No redirects, upgrades or daemon proxy.
  return *out;
}
json decode(const reply &r) {
  try {
    auto j = json::parse(r.body, [](int depth, json::parse_event_t, json &) {
      require(depth <= 32, "bad_engine_json");
      return true;
    });
    require(j.is_object() || j.is_array(), "bad_engine_json");
    return j;
  } catch (const error &) {
    throw;
  } catch (...) {
    throw error("bad_engine_json");
  }
}
int api_version(const std::string &v) {
  require(v.starts_with("1.") && v.size() <= 6, "engine_api_incompatible");
  int n = 0;
  auto [p, c] = std::from_chars(v.data() + 2, v.data() + v.size(), n);
  require(c == std::errc() && p == v.data() + v.size() && n > 0, "engine_api_incompatible");
  return n;
}
json selected(const json &j, std::initializer_list<const char *> keys) {
  require(j.is_object(), "bad_engine_json");
  json r = json::object();
  for (auto k : keys)
    if (j.contains(k))
      r[k] = j[k];
  return r;
}
} // namespace
json docker_endpoint(const json &j) {
  fields(j, {"id", "transport", "path", "address", "port", "server_name", "ca", "certificate",
             "key", "platform", "permissions"});
  require(std::regex_match(j.at("id").get<std::string>(), std::regex("[a-z][a-z0-9-]{0,47}")),
          "invalid_endpoint");
  auto type = j.at("transport").get<std::string>(), platform = j.at("platform").get<std::string>();
  require(platform == "linux-native" || platform == "windows-native" || platform == "linux-vm" ||
              platform == "remote-linux" || platform == "remote-windows",
          "invalid_endpoint");
  require(j.at("permissions").is_array() && j.at("permissions").size() <= 3, "invalid_endpoint");
  std::set<std::string> seen;
  for (auto &v : j.at("permissions")) {
    auto p = v.get<std::string>();
    require((p == "docker.read" || p == "docker.logs" || p == "docker.control") &&
                seen.insert(p).second,
            "invalid_endpoint");
  }
  require(seen.contains("docker.read"), "invalid_endpoint");
  json e = j;
  if (type == "tls") {
    require(!j.contains("path") && (platform == "remote-linux" || platform == "remote-windows"),
            "invalid_endpoint");
    auto address = j.at("address").get<std::string>();
    // Numeric transport avoids an unbounded resolver and DNS rebinding. PACE
    // validates the endpoint; server_name is independently certificate-checked.
    require(address.size() <= 45 && !address.empty() &&
                address.find_first_not_of("0123456789abcdefABCDEF:.") == std::string::npos,
            "invalid_endpoint");
    auto port = j.at("port").get<int64_t>();
    require(port > 0 && port <= 65535, "invalid_endpoint");
    auto name = j.at("server_name").get<std::string>();
    require(!name.empty() && name.size() <= 253 &&
                name.find_first_not_of(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:") ==
                    std::string::npos,
            "invalid_endpoint");
    for (auto key : {"ca", "certificate", "key"}) {
      auto p = fs::path(j.at(key).get<std::string>());
      require(p.is_absolute() && fs::is_regular_file(p) && fs::file_size(p) <= 65536,
              "invalid_endpoint");
      e[key] = fs::canonical(p).string();
    }
  } else {
    for (auto key : {"address", "port", "server_name", "ca", "certificate", "key"})
      require(!j.contains(key), "invalid_endpoint");
    auto path = j.at("path").get<std::string>();
#ifdef _WIN32
    require(type == "pipe" && (platform == "windows-native" || platform == "linux-vm"),
            "invalid_endpoint");
    require(path.starts_with("\\\\.\\pipe\\") && identifier(path.substr(9)), "invalid_endpoint");
#else
    require(type == "unix" && platform == "linux-native", "invalid_endpoint");
    require(fs::path(path).is_absolute() && path.size() < 104 &&
                path.find('\0') == std::string::npos,
            "invalid_endpoint");
    // Missing sockets are valid configured endpoints; inventory reports unavailable.
    require(fs::path(path).lexically_normal() == fs::path(path), "invalid_endpoint");
#endif
  }
  return e;
}
json docker_call(const json &e, const std::string &op, const json &b, const call_context &ctx) {
  fields(b, {"engine", "operation", "resource", "id", "action", "tail", "timeout", "name"});
  auto permission =
      (op == "logs" ? "docker.logs" : (op == "lifecycle" ? "docker.control" : "docker.read"));
  require(std::find(e.at("permissions").begin(), e.at("permissions").end(), permission) !=
              e.at("permissions").end(),
          "forbidden");
  require(op == "inventory" || op == "stats" || op == "logs" || op == "lifecycle" || op == "info",
          "invalid_request");
  auto version = decode(request(e, "GET", "/version", nullptr, ctx));
  auto maximum = api_version(version.at("ApiVersion")),
       minimum = api_version(version.value("MinAPIVersion", "1.24"));
  auto use = std::min(maximum, 52);
  require(use >= std::max(minimum, 41), "engine_api_incompatible");
  auto prefix = "/v1." + std::to_string(use);
  auto info = decode(request(e, "GET", prefix + "/info", nullptr, ctx));
  auto os = info.at("OSType").get<std::string>();
  auto platform = e.at("platform").get<std::string>();
  require(os ==
              (platform == "windows-native" || platform == "remote-windows" ? "windows" : "linux"),
          "engine_platform_mismatch");
  json capabilities = {{"platform", platform},
                       {"os", os},
                       {"api_version", "1." + std::to_string(use)},
                       {"paths", "engine-filesystem"},
                       {"host_path_translation", false},
                       {"bind_mount_creation", false},
                       {"exec_attach_build_pull", false},
                       {"permissions", e.at("permissions")}};
  if (op == "info")
    return {{"engine", e.at("id")},
            {"capabilities", capabilities},
            {"info", selected(info, {"ID", "Name", "ServerVersion", "OSType", "Architecture",
                                     "NCPU", "MemTotal", "Containers", "Images"})}};
  auto resource = b.value("resource", "containers");
  require(resource == "containers" || resource == "images" || resource == "volumes" ||
              resource == "networks",
          "invalid_request");
  if (op == "inventory") {
    std::string path = resource == "containers" ? "/containers/json?all=true"
                       : resource == "images"   ? "/images/json"
                       : resource == "volumes"  ? "/volumes"
                                                : "/networks";
    auto data = decode(request(e, "GET", prefix + path, nullptr, ctx));
    json warnings = json::array();
    if (resource == "volumes") {
      warnings = data.value("Warnings", json::array());
      data = data.value("Volumes", json::array());
      if (data.is_null())
        data = json::array();
    }
    require(data.is_array() && data.size() <= 128, "engine_response_limit");
    json items = json::array();
    for (auto &v : data) {
      if (resource == "containers")
        items.push_back(selected(v, {"Id", "Names", "Image", "ImageID", "Command", "Created",
                                     "State", "Status", "Ports", "Labels", "Mounts"}));
      else if (resource == "images")
        items.push_back(
            selected(v, {"Id", "RepoTags", "RepoDigests", "Created", "Size", "Labels"}));
      else if (resource == "volumes")
        items.push_back(selected(v, {"Name", "Driver", "Mountpoint", "Labels", "Scope", "Status"}));
      else
        items.push_back(selected(
            v, {"Id", "Name", "Driver", "Scope", "Internal", "Attachable", "Ingress", "Labels"}));
    }
    return {{"items", items},
            {"warnings", warnings},
            {"complete", true},
            {"capabilities", capabilities}};
  }
  auto id = b.value("id", "");
  require(identifier(id) ||
              (resource == "images" && std::regex_match(id, std::regex("sha256:[0-9a-f]{64}"))),
          "invalid_identifier");
  if (op == "stats") {
    require(resource == "containers", "invalid_request");
    return decode(request(e, "GET",
                          prefix + "/containers/" + id + "/stats?stream=false&one-shot=true",
                          nullptr, ctx));
  }
  if (op == "logs") {
    require(resource == "containers", "invalid_request");
    int tail = b.value("tail", 100);
    require(tail >= 1 && tail <= 1000, "invalid_request");
    auto r = request(e, "GET",
                     prefix + "/containers/" + id +
                         "/logs?stdout=true&stderr=true&follow=false&timestamps=true&tail=" +
                         std::to_string(tail),
                     nullptr, ctx);
    // Preserve Docker's raw/multiplexed bytes losslessly; no false UTF-8 or TTY
    // assumptions, and no unbounded follow/hijack stream.
    require(r.body.size() <= 32768, "engine_response_limit");
    return {{"encoding", "hex"},
            {"data", encode_bytes(r.body)},
            {"content_type", r.headers["content-type"]},
            {"bytes", r.body.size()},
            {"tail", tail},
            {"follow", false}};
  }
  auto action = b.at("action").get<std::string>();
  std::string method = "POST", path;
  json body = nullptr;
  if (resource == "containers") {
    require(action == "start" || action == "stop" || action == "restart" || action == "remove",
            "invalid_request");
    path = "/containers/" + id;
    if (action == "remove") {
      method = "DELETE";
      path += "?force=false&v=false";
    } else {
      path += "/" + action;
      if (action != "start") {
        int timeout = b.value("timeout", 1);
        require(timeout >= 0 && timeout <= 2, "invalid_request");
        path += "?t=" + std::to_string(timeout);
      }
    }
  } else {
    require(action == "remove", "invalid_request");
    method = "DELETE";
    path = "/" + resource + "/" + id;
    if (resource == "images")
      path += "?force=false&noprune=true";
    if (resource == "volumes")
      path += "?force=false";
  }
  auto r = request(e, method, prefix + path, body, ctx);
  return {{"accepted", true},
          {"status", r.status},
          {"resource", resource},
          {"id", id},
          {"action", action}};
}
int docker_plugin(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  file_lock lock(c.state / "plugin.lock");
  apply_resource_budget(c);
  auto identity = process_info(own_pid());
  identity["generation"] = generation;
  identity["ipc_version"] = 1;
  rpc_server server(c, "plugin", generation,
                    [&](const std::string &op, const json &body, const call_context &ctx) -> json {
                      if (op == "ping")
                        return identity;
                      if (op == "stop") {
                        stopping = true;
                        return {{"stopping", true}};
                      }
                      require(op == "invoke", "not_supported");
                      auto runtime = read_json(c.state / "plugin.json");
                      auto engine = body.at("engine").get<std::string>();
                      require(runtime.at("engines").contains(engine), "forbidden");
                      auto operation = body.at("operation").get<std::string>();
                      auto capability = operation == "logs"        ? "docker.logs"
                                        : operation == "lifecycle" ? "docker.control"
                                                                   : "docker.read";
                      require(std::find(runtime.at("capabilities").begin(),
                                        runtime.at("capabilities").end(),
                                        capability) != runtime.at("capabilities").end(),
                              "forbidden");
                      return docker_call(runtime.at("engines").at(engine), operation, body, ctx);
                    });
  write_json(c.state / "plugin.instance.json", identity);
  while (!stopping)
    std::this_thread::sleep_for(20ms);
  server.stop();
  return 0;
}
} // namespace tc
