#include "ftp_transport.hpp"
#include <taucloud/files.hpp>
#include <taucloud/runtime/bounded_executor.hpp>
#include <charconv>
#include <ctime>
#include <set>
namespace tc {
namespace {
using ftp_detail::wire;
struct connection;
struct ftp_state {
  config cfg;
  std::shared_ptr<pace::io_context> io = std::make_shared<pace::io_context>();
  taucloud::bounded_executor pool{4, 32, 32 * ipc_frame_size};
  std::atomic<int> connections = 0;
  std::set<connection *> clients;
  std::map<std::string, json> sessions;
};
pace::task<json> ftp_rpc(ftp_state &s, std::string target, std::string op,
                         json body = json::object()) {
  struct result {
    json value;
    std::exception_ptr failure;
    bool done = false;
  };
  auto pending = std::make_shared<result>();
  taucloud::bounded_executor::ticket ticket;
  bool accepted = s.pool.submit(
      s.io, ipc_frame_size, std::chrono::steady_clock::now() + 5s,
      [pending, c = s.cfg, target, op, body](std::stop_token stop) {
        pending->value = rpc(c, "ftp", target, op, body, "", stop);
      },
      [pending](taucloud::bounded_executor::result r) {
        pending->failure = r.error;
        if (r.state != taucloud::bounded_executor::status::completed && !pending->failure)
          pending->failure = std::make_exception_ptr(error("cancelled"));
        pending->done = true;
      },
      ticket);
  require(accepted, "overloaded");
  try {
    while (!pending->done)
      co_await s.io->sleep_for(1ms);
  } catch (...) {
    ticket.cancel();
    throw;
  }
  if (pending->failure)
    std::rethrow_exception(pending->failure);
  co_return pending->value;
}
struct reply_error : error {
  int code;
  reply_error(int c, const char *s) : error(s), code(c) {}
};
void check(bool value, int code, const char *message) {
  if (!value)
    throw reply_error(code, message);
}
std::string upper(std::string value) {
  for (char &c : value)
    if (c >= 'a' && c <= 'z')
      c -= 'a' - 'A';
  return value;
}
uint64_t decimal(const std::string &value) {
  uint64_t n = 0;
  auto result = std::from_chars(value.data(), value.data() + value.size(), n);
  check(!value.empty() && result.ec == std::errc() && result.ptr == value.data() + value.size() &&
            n <= uint64_t(INT64_MAX),
        501, "Invalid number");
  return n;
}
std::string location(const std::string &cwd, const std::string &arg) {
  auto value = arg.empty() ? cwd : arg.starts_with('/') ? arg : cwd + (cwd == "/" ? "" : "/") + arg;
  std::vector<std::string> components;
  size_t start = 1;
  while (start <= value.size()) {
    auto end = value.find('/', start);
    if (end == std::string::npos)
      end = value.size();
    auto part = value.substr(start, end - start);
    if (part == "..") {
      check(!components.empty(), 550, "Outside root");
      components.pop_back();
    } else if (!part.empty() && part != ".") {
      portable_path(part);
      components.push_back(part);
    }
    start = end + 1;
  }
  std::string result;
  for (auto &part : components)
    result += "/" + part;
  check(result.size() <= 1024, 550, "Path too long");
  return result.empty() ? "/" : result;
}
std::pair<std::string, std::string> split(const std::string &path) {
  check(path != "/", 550, "Select a share");
  auto slash = path.find('/', 1);
  return {path.substr(1, slash == std::string::npos ? slash : slash - 1),
          slash == std::string::npos ? "" : path.substr(slash + 1)};
}
std::string timestamp(const json &meta) {
  auto value = static_cast<time_t>(meta.value("modified_ns", int64_t(0)) / 1000000000);
  std::tm time{};
#ifdef _WIN32
  gmtime_s(&time, &value);
#else
  gmtime_r(&value, &time);
#endif
  char result[32];
  std::strftime(result, sizeof(result), "%Y%m%d%H%M%S", &time);
  return result;
}
std::string facts(const json &meta, const std::string &name,
                  const std::set<std::string> &selected) {
  std::string out;
  if (selected.contains("TYPE"))
    out += std::string("type=") + (meta.at("directory").get<bool>() ? "dir;" : "file;");
  if (selected.contains("SIZE") && !meta.at("directory").get<bool>())
    out += "size=" + std::to_string(meta.at("size").get<uint64_t>()) + ";";
  if (selected.contains("MODIFY"))
    out += "modify=" + timestamp(meta) + ";";
  return out + " " + name + "\r\n";
}
struct connection : std::enable_shared_from_this<connection> {
  ftp_state &s;
  wire control;
  ftp_detail::tls_context tls{nullptr, SSL_CTX_free};
  std::unique_ptr<pace::tcp::listener> passive;
  std::unique_ptr<wire> data;
  std::string input, username, cwd = "/", rename_from;
  json auth = json::object(), rename_meta;
  std::map<std::string, json> grant_cache;
  std::set<std::string> selected{"TYPE", "SIZE", "MODIFY"};
  bool binary = false, pbsz = false, protected_data = false, epsv_all = false;
  bool active = false, aborted = false, closing = false, replying = false;
  std::optional<uint64_t> restart;
  connection(ftp_state &state, pace::tcp::stream socket) : s(state), control(std::move(socket)) {}
  void cancel() {
    aborted = true;
    if (passive)
      passive->close();
    if (data)
      data->close();
  }
  void close() {
    closing = true;
    cancel();
    control.close();
  }
  pace::task<void> reply(int code, std::string message) {
    while (replying)
      co_await s.io->sleep_for(1ms);
    replying = true;
    struct guard {
      bool &b;
      ~guard() { b = false; }
    } lock{replying};
    auto line = std::to_string(code) + (message.find("\r\n") == std::string::npos ? " " : "-") +
                message + "\r\n";
    co_await control.write(line);
  }
  pace::task<std::string> line() {
    auto timer = s.io->call_after(300s, [this] { control.close(); });
    for (;;) {
      auto end = input.find("\r\n");
      if (end != std::string::npos) {
        check(end <= 2048, 500, "Command too long");
        auto value = input.substr(0, end);
        input.erase(0, end + 2);
        for (unsigned char c : value)
          check(c >= 32 && c != 127 && c != 255, 501, "Invalid command byte");
        co_return value;
      }
      check(input.size() <= 2048, 500, "Command too long");
      std::array<char, 2048> bytes;
      auto n = co_await control.read(bytes, 300s);
      require(n != 0, "disconnected");
      input.append(bytes.data(), n);
    }
  }
  pace::task<json> grant(const std::string &path, bool write) {
    auto key = path + (write ? ":w" : ":r");
    auto found = grant_cache.find(key);
    if (found != grant_cache.end() && found->second.at("expires").get<int64_t>() > now() + 500)
      co_return found->second;
    auto [share, relative] = split(path);
    json body = {{"auth", auth},
                 {"share", share},
                 {"path", relative},
                 {"write", write},
                 {"protocol", "ftp"}};
    auto value = co_await ftp_rpc(s, "identity", "authorize", body);
    if (grant_cache.size() >= 256)
      grant_cache.clear();
    grant_cache[key] = value;
    co_return value;
  }
  pace::task<json> file(const std::string &path, const std::string &op, json body = json::object(),
                        bool write = false) {
    body["grant"] = co_await grant(path, write);
    co_return co_await ftp_rpc(s, body.at("grant").at("root").at("worker"), op, body);
  }
  pace::task<json> listing(const std::string &path) {
    if (path == "/") {
      json body = {{"auth", auth}, {"resource", "shares"}};
      auto shares = co_await ftp_rpc(s, "identity", "policy_list", body);
      json result = json::array();
      for (auto share : shares)
        if (!share.at("exposures").value("ftp", "").empty()) {
          bool visible = false;
          try {
            co_await grant("/" + share.at("id").get<std::string>(), false);
            visible = true;
          } catch (...) {
          }
          if (visible)
            result.push_back({{"path", share.at("id")}, {"directory", true}, {"size", 0}});
        }
      co_return result;
    }
    json request = {{"depth", 1}};
    auto result = co_await file(path, "dav_list", request);
    if (result.size() > 0 && result[0].at("directory").get<bool>())
      result.erase(result.begin());
    co_return result;
  }
  pace::task<void> logout() {
    // Internal file-scope sessions are shared across equal credentials, as for
    // DAV Basic auth. Closing a connection must not revoke sibling connections.
    grant_cache.clear();
    auth = json::object();
    co_return;
  }
  pace::task<void> transfer(std::string command, std::string path, uint64_t offset) {
    std::string job, handle;
    json last_grant;
    int failure = 0;
    std::string message;
    try {
      json meta, items;
      if (command == "RETR") {
        meta = co_await file(path, "dav_stat");
        check(!meta.at("directory").get<bool>() && offset <= meta.at("size").get<uint64_t>(), 551,
              "Invalid restart offset");
      } else if (command == "STOR") {
        check(!split(path).second.empty(), 550, "Cannot replace share root");
        last_grant = co_await grant(path, true);
        if (offset) {
          meta = co_await file(path, "dav_stat");
          check(!meta.at("directory").get<bool>() && offset <= meta.at("size").get<uint64_t>(), 551,
                "Invalid restart offset");
        }
      } else
        items = co_await listing(path);
      check(passive != nullptr, 425, "Use EPSV or PASV first");
      co_await reply(150, "Opening data connection");
      auto timeout = s.io->call_after(5s, [this] {
        if (passive)
          passive->close();
      });
      auto socket = co_await passive->accept();
      timeout.cancel();
      passive.reset();
      check(socket.remote_endpoint().address == control.tcp.remote_endpoint().address, 425,
            "Data peer mismatch");
      data = std::make_unique<wire>(std::move(socket));
      if (protected_data)
        co_await data->upgrade(tls.get(), true);
      check(!aborted, 426, "Transfer aborted");
      if (command == "STOR") {
        auto quota = co_await file(path, "quota");
        uint64_t limit = quota.at("limit"), used = quota.at("used"),
                 reserved = quota.at("reserved");
        uint64_t budget = std::min<uint64_t>(1024ULL * 1024 * 1024,
                                             limit > used + reserved ? limit - used - reserved : 0);
        check(offset <= budget, 552, "Quota exceeded");
        json request = {{"request_id", random_hex(16)}, {"size", budget}};
        if (offset)
          request["conditions"] = {{"if_match", meta.at("etag")}};
        auto started = co_await file(path, "begin", request, true);
        job = started.at("id");
        uint64_t position = 0;
        if (offset) {
          auto opened = co_await file(path, "open");
          handle = opened.at("handle");
          while (position < offset) {
            json read = {{"handle", handle},
                         {"offset", position},
                         {"count", std::min<uint64_t>(65536, offset - position)}};
            auto bytes = co_await file(path, "read", read);
            check(bytes.at("read").get<size_t>() != 0, 451, "Source changed");
            json chunk = {{"job", job}, {"offset", position}, {"data", bytes.at("data")}};
            auto wrote = co_await file(path, "chunk", chunk, true);
            position += wrote.at("written").get<uint64_t>();
            check(!aborted, 426, "Transfer aborted");
          }
          json close = {{"handle", handle}};
          co_await file(path, "close", close);
          handle.clear();
        }
        std::array<char, 65536> buffer;
        for (;;) {
          auto assembly = s.io->call_after(5s, [this] {
            if (data)
              data->close();
          });
          size_t count = 0;
          bool eof = false;
          while (count < buffer.size()) {
            auto n = co_await data->read(std::span<char>(buffer).subspan(count));
            if (!n) {
              eof = true;
              break;
            }
            count += n;
          }
          assembly.cancel();
          check(!aborted, 426, "Transfer aborted");
          if (count) {
            check(position <= budget && count <= budget - position, 552,
                  "Quota or upload limit exceeded");
            json chunk = {{"job", job},
                          {"offset", position},
                          {"data", encode_bytes(std::string_view(buffer.data(), count))}};
            auto wrote = co_await file(path, "chunk", chunk, true);
            check(wrote.at("written").get<size_t>() == count, 451, "Partial storage write");
            position += count;
          }
          if (eof)
            break;
        }
        check(!aborted && !closing, 426, "Transfer aborted");
        json complete = {{"job", job}};
        co_await file(path, "seal", complete, true);
        check(!aborted && !closing, 426, "Transfer aborted");
        co_await file(path, "commit", complete, true);
        job.clear();
      } else if (command == "RETR") {
        last_grant = co_await grant(path, false);
        auto opened = co_await file(path, "open");
        handle = opened.at("handle");
        uint64_t end = meta.at("size");
        while (offset < end) {
          json request = {{"handle", handle},
                          {"offset", offset},
                          {"count", std::min<uint64_t>(65536, end - offset)}};
          auto value = co_await file(path, "read", request);
          auto bytes = decode_bytes(value.at("data").get<std::string>());
          check(!bytes.empty() && !aborted, 426, "Transfer interrupted");
          co_await data->write(bytes);
          offset += bytes.size();
        }
        json close = {{"handle", handle}};
        co_await file(path, "close", close);
        handle.clear();
      } else {
        for (auto item : items) {
          // Recheck access even when a cached directory listing is being sent.
          if (path != "/")
            co_await grant(path, false);
          auto name = item.at("path").get<std::string>();
          name = name.substr(
              name.find_last_of('/') == std::string::npos ? 0 : name.find_last_of('/') + 1);
          std::string value;
          if (command == "MLSD")
            value = facts(item, name, selected);
          else if (command == "NLST")
            value = name + "\r\n";
          else
            value = std::string(item.at("directory").get<bool>() ? "dr-xr-xr-x" : "-r--r--r--") +
                    " 1 owner group " + std::to_string(item.at("size").get<uint64_t>()) +
                    " Jan 01  1970 " + name + "\r\n";
          co_await data->write(value);
          check(!aborted, 426, "Transfer aborted");
        }
      }
      // A verified EOF has already been consumed (STOR), or all bytes sent
      // (RETR). Clients such as curl close TCP after their close_notify instead
      // of waiting for ours. A best-effort reciprocal shutdown must not turn an
      // already committed upload into a false 426 response.
      try {
        co_await data->finish();
      } catch (...) {
      }
    } catch (const reply_error &e) {
      failure = e.code;
      message = e.what();
    } catch (const error &e) {
      auto code = std::string(e.what());
      failure = code == "data_session_mismatch"                   ? 522
                : code == "tls_failed" || code == "tls_truncated" ? 426
                : code == "quota_exceeded"                        ? 552
                : code == "disk_full"                             ? 452
                                                                  : 550;
      message = code;
    } catch (...) {
      failure = 426;
      message = "Data connection failed";
    }
    if (data) {
      data->close();
      data.reset();
    }
    passive.reset();
    if (!last_grant.empty()) {
      if (!handle.empty())
        try {
          json body = {{"grant", last_grant}, {"handle", handle}};
          co_await ftp_rpc(s, last_grant.at("root").at("worker"), "ftp_close", body);
        } catch (...) {
        }
      if (!job.empty())
        try {
          json body = {{"grant", last_grant}, {"job", job}};
          co_await ftp_rpc(s, last_grant.at("root").at("worker"), "ftp_abort", body);
        } catch (...) {
        }
    }
    if (!closing)
      try {
        co_await reply(failure ? failure : 226, failure ? message : "Transfer complete");
      } catch (...) {
        close();
      }
    active = false;
  }
  pace::task<void> command(std::string cmd, std::string arg) {
    if (cmd == "QUIT") {
      closing = true;
      cancel();
      while (active)
        co_await s.io->sleep_for(1ms);
      co_await reply(221, "Goodbye");
      co_return;
    }
    if (cmd == "ABOR") {
      bool was_active = active;
      cancel();
      while (active)
        co_await s.io->sleep_for(1ms);
      passive.reset();
      restart.reset();
      co_await reply(was_active ? 226 : 225, "Abort complete");
      co_return;
    }
    if (cmd == "NOOP") {
      co_await reply(200, "OK");
      co_return;
    }
    check(!active, 450, "Transfer in progress");
    auto offset = restart.value_or(0);
    if (cmd != "REST")
      restart.reset();
    if (cmd != "RNTO" && cmd != "RNFR")
      rename_from.clear();
    if (cmd == "FEAT") {
      co_await reply(211, "Features\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n EPSV\r\n PASV\r\n UTF8\r\n "
                          "SIZE\r\n MDTM\r\n REST STREAM\r\n MLST type*;size*;modify*;\r\n211 End");
      co_return;
    }
    if (cmd == "SYST") {
      co_await reply(215, "UNIX Type: L8");
      co_return;
    }
    if (cmd == "AUTH") {
      check(upper(arg) == "TLS", 504, "Use AUTH TLS");
      check(!control.ssl && auth.empty() && input.empty(), 503, "Invalid AUTH sequence");
      tls = ftp_detail::make_tls(s.cfg);
      co_await reply(234, "Begin TLS");
      co_await control.upgrade(tls.get(), false);
      username.clear();
      passive.reset();
      cwd = "/";
      binary = false;
      epsv_all = false;
      co_return;
    }
    if (cmd == "PBSZ") {
      check(bool(control.ssl), 503, "AUTH TLS first");
      check(arg == "0", 501, "PBSZ must be zero");
      pbsz = true;
      co_await reply(200, "PBSZ=0");
      co_return;
    }
    if (cmd == "PROT") {
      check(bool(control.ssl) && pbsz, 503, "AUTH TLS and PBSZ first");
      check(upper(arg) == "P", 536, "Protected data required");
      protected_data = true;
      co_await reply(200, "PROT P");
      co_return;
    }
    if (cmd == "CCC")
      throw reply_error(534, "Control downgrade disabled");
    if (cmd == "PORT" || cmd == "EPRT")
      throw reply_error(502, "Active mode and FXP disabled");
    if (cmd == "USER") {
      co_await logout();
      username.clear();
      cwd = "/";
      passive.reset();
      check(bool(control.ssl) || s.cfg.ftp_plaintext, 534, "AUTH TLS required");
      check(!arg.empty() && upper(arg) != "ANONYMOUS" && upper(arg) != "FTP", 530,
            "Anonymous disabled");
      username = arg;
      co_await reply(331, "Password required");
      co_return;
    }
    if (cmd == "PASS") {
      check(!username.empty() && (control.ssl || s.cfg.ftp_plaintext), 503, "USER first");
      json request = {
          {"username", username}, {"password", arg}, {"kind", "cli"}, {"scope", "files"}};
      co_await logout();
      auto key = digest(json::array({username, arg}).dump());
      auto found = s.sessions.find(key);
      if (found != s.sessions.end() && found->second.at("expires").get<int64_t>() > now()) {
        json candidate = {{"token", found->second.at("token")}, {"kind", "cli"}};
        bool valid = false;
        try {
          co_await ftp_rpc(s, "identity", "validate", candidate);
          valid = true;
        } catch (const error &e) {
          if (std::string_view(e.what()) != "unauthorized")
            throw;
        }
        if (valid)
          auth = candidate;
      }
      if (auth.empty()) {
        auto session = co_await ftp_rpc(s, "identity", "login", request);
        if (s.sessions.size() >= 256)
          s.sessions.erase(s.sessions.begin());
        s.sessions[key] = session;
        auth = {{"token", session.at("token")}, {"kind", "cli"}};
      }
      co_await reply(230, "Logged in");
      co_return;
    }
    check(!auth.empty(), 530, "Login required");
    co_await ftp_rpc(s, "identity", "validate", auth);
    if (cmd == "TYPE") {
      auto type = upper(arg);
      check(type == "I" || type == "L 8" || type == "A" || type == "A N", 504, "Unsupported TYPE");
      binary = type == "I" || type == "L 8";
      co_await reply(200, binary ? "Binary" : "ASCII listings only; file transfers require TYPE I");
      co_return;
    }
    if (cmd == "MODE" || cmd == "STRU") {
      check(upper(arg) == (cmd == "MODE" ? "S" : "F"), 504, "Unsupported mode or structure");
      co_await reply(200, "OK");
      co_return;
    }
    if (cmd == "OPTS") {
      auto value = upper(arg);
      if (value != "UTF8 ON") {
        check(value == "MLST" || value.starts_with("MLST "), 501, "Unsupported option");
        std::set<std::string> next;
        auto names = value == "MLST" ? "" : value.substr(5);
        while (!names.empty()) {
          auto semi = names.find(';');
          check(semi != std::string::npos, 501, "Invalid MLST facts");
          auto name = names.substr(0, semi);
          if (name == "TYPE" || name == "SIZE" || name == "MODIFY")
            next.insert(name);
          names.erase(0, semi + 1);
        }
        selected = std::move(next);
      }
      co_await reply(200, "Options accepted");
      co_return;
    }
    if (cmd == "PWD" || cmd == "XPWD") {
      co_await reply(257, "\"" + cwd + "\"");
      co_return;
    }
    if (cmd == "CWD" || cmd == "XCWD" || cmd == "CDUP" || cmd == "XCUP") {
      auto path = location(cwd, cmd == "CDUP" || cmd == "XCUP" ? ".." : arg);
      if (path != "/") {
        auto meta = co_await file(path, "dav_stat");
        check(meta.at("directory"), 550, "Not a directory");
      }
      cwd = path;
      co_await reply(250, "Directory changed");
      co_return;
    }
    if (cmd == "EPSV" || cmd == "PASV") {
      check(!control.ssl || protected_data, 536, "PROT P required");
      if (cmd == "EPSV" && upper(arg) == "ALL") {
        epsv_all = true;
        passive.reset();
        co_await reply(200, "EPSV only");
        co_return;
      }
      check(cmd != "PASV" || !epsv_all, 501, "EPSV ALL in effect");
      check(arg.empty() || (cmd == "EPSV" && arg == "1"), 522, "Use IPv4 (1)");
      passive.reset();
      for (uint32_t port = s.cfg.ftp_passive_first; port <= s.cfg.ftp_passive_last; ++port) {
        try {
          passive = std::make_unique<pace::tcp::listener>(
              *s.io, pace::tcp::endpoint{"127.0.0.1", static_cast<uint16_t>(port)},
              pace::tcp::listen_options{false, 1});
          break;
        } catch (...) {
        }
      }
      check(bool(passive), 425, "Passive ports exhausted");
      auto port = passive->local_endpoint().port;
      co_await reply(cmd == "EPSV" ? 229 : 227,
                     cmd == "EPSV"
                         ? "Entering Extended Passive Mode (|||" + std::to_string(port) + "|)"
                         : "Entering Passive Mode (127,0,0,1," + std::to_string(port / 256) + "," +
                               std::to_string(port % 256) + ")");
      co_return;
    }
    if (cmd == "REST") {
      check(binary, 504, "REST requires TYPE I");
      restart = decimal(arg);
      co_await reply(350, "Restart marker accepted");
      co_return;
    }
    auto path = location(cwd, arg);
    if (cmd == "RETR" || cmd == "STOR" || cmd == "LIST" || cmd == "NLST" || cmd == "MLSD") {
      check((cmd != "RETR" && cmd != "STOR") || (binary && !arg.empty()), 504,
            "File transfers require TYPE I and a path");
      check(!control.ssl || protected_data, 536, "PROT P required");
      check(bool(passive), 425, "Use EPSV or PASV");
      active = true;
      aborted = false;
      s.io->spawn(transfer(cmd, path, offset));
      co_return;
    }
    if (cmd == "SIZE" || cmd == "MDTM" || cmd == "MLST") {
      if (cmd == "SIZE")
        check(binary, 504, "SIZE requires TYPE I");
      json meta = {{"directory", true}, {"size", 0}};
      if (path != "/")
        meta = co_await file(path, "dav_stat");
      if (cmd == "MLST") {
        co_await reply(250, "Listing\r\n " + facts(meta, path, selected) + "250 End");
        co_return;
      }
      check(!meta.at("directory").get<bool>(), 550, "Not a file");
      co_await reply(213, cmd == "SIZE" ? std::to_string(meta.at("size").get<uint64_t>())
                                        : timestamp(meta));
      co_return;
    }
    check(!arg.empty(), 501, "Path required");
    check(!split(path).second.empty(), 550, "Cannot mutate share root");
    if (cmd == "MKD" || cmd == "XMKD") {
      co_await file(path, "mkdir", json::object(), true);
      co_await reply(257, "\"" + path + "\" created");
      co_return;
    }
    if (cmd == "DELE" || cmd == "RMD" || cmd == "XRMD") {
      auto meta = co_await file(path, "dav_stat");
      check(meta.at("directory").get<bool>() == (cmd != "DELE"), 550, "Wrong object type");
      json request = {{"request_id", random_hex(16)}, {"if_match", meta.at("etag")}};
      co_await file(path, cmd == "DELE" ? "dav_delete" : "ftp_rmdir", request, true);
      co_await reply(250, "Removed");
      co_return;
    }
    if (cmd == "RNFR") {
      rename_from.clear();
      co_await grant(path, true);
      rename_meta = co_await file(path, "dav_stat");
      rename_from = path;
      co_await reply(350, "RNTO required");
      co_return;
    }
    if (cmd == "RNTO") {
      auto from = std::exchange(rename_from, "");
      check(!from.empty() && split(from).first == split(path).first, 503,
            "RNFR in same share required");
      json request = {{"request_id", random_hex(16)},
                      {"if_match", rename_meta.at("etag")},
                      {"overwrite", false}};
      request["target_grant"] = co_await grant(path, true);
      co_await file(from, "dav_move", request, true);
      co_await reply(250, "Renamed");
      co_return;
    }
    throw reply_error(502, "Command not implemented");
  }
  pace::task<void> run() {
    s.clients.insert(this);
    try {
      co_await reply(220, "tauCloud explicit FTPS ready");
      while (!closing) {
        int code = 0;
        std::string message;
        try {
          auto value = co_await line();
          auto space = value.find(' ');
          auto cmd = upper(value.substr(0, space));
          auto arg = space == std::string::npos ? "" : value.substr(space + 1);
          co_await command(cmd, arg);
        } catch (const reply_error &e) {
          code = e.code;
          message = e.what();
        } catch (const error &e) {
          message = e.what();
          code = message == "unauthorized" || message == "rate_limited" ? 530 : 550;
        }
        if (code) {
          co_await reply(code, message);
          if (code == 500 || !control.tcp.is_open())
            break;
        }
      }
    } catch (...) {
    }
    closing = true;
    cancel();
    while (active)
      co_await s.io->sleep_for(1ms);
    co_await logout();
    try {
      co_await control.finish();
    } catch (...) {
    }
    control.close();
    s.clients.erase(this);
    --s.connections;
  }
};
pace::task<void> serve(std::shared_ptr<connection> client) { co_await client->run(); }
pace::task<void> accept(ftp_state &s, pace::tcp::listener &listener, std::atomic_bool &stop) {
  try {
    while (!stop) {
      auto socket = co_await listener.accept();
      if (s.connections >= std::min(s.cfg.connections, 32)) {
        socket.close();
        continue;
      }
      ++s.connections;
      s.io->spawn(serve(std::make_shared<connection>(s, std::move(socket))));
    }
  } catch (...) {
    if (!stop)
      stop = true;
  }
}
} // namespace
int ftp(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  if (!c.ftp_port)
    return worker("ftp", c, generation, stopping);
  file_lock lock(c.state / "ftp.lock");
  apply_resource_budget(c);
  // Holding ftp.lock fences the old process before reclaiming its open handles
  // and unpublished stages. File services retain sole storage ownership.
  for (const auto &role : file_roles()) {
    bool ready = false;
    for (int attempt = 0; attempt < 20 && !stopping; ++attempt) {
      try {
        rpc(c, "ftp", role, "ftp_recover");
        ready = true;
        break;
      } catch (...) {
        std::this_thread::sleep_for(100ms);
      }
    }
    require(ready, "storage_unavailable");
  }
  ftp_state s;
  s.cfg = c;
  pace::tcp::listener listener(*s.io, {"127.0.0.1", c.ftp_port}, {false, 32});
  auto info = [&] {
    auto p = process_info(own_pid());
    p["role"] = "ftp";
    p["generation"] = generation;
    p["business_ready"] = true;
    p["connections"] = s.connections.load();
    return p;
  };
  rpc_server server(c, "ftp", generation,
                    [&](const std::string &op, const json &, const call_context &) {
                      if (op == "ping")
                        return info();
                      if (op == "stop") {
                        stopping = true;
                        return json{{"stopping", true}};
                      }
                      throw error("not_supported");
                    });
  write_json(c.state / "ftp.instance.json", info());
  s.io->spawn(accept(s, listener, stopping));
  std::jthread loop([&] {
    try {
      s.io->run();
    } catch (...) {
      log("ftp", "runtime_failed", "internal_error");
    }
    stopping = true;
  });
  log("ftp", "started");
  while (!stopping)
    std::this_thread::sleep_for(20ms);
  s.io->post([&] {
    listener.close();
    for (auto *client : s.clients)
      client->close();
  });
  server.stop();
  auto deadline = now() + 6000;
  while (s.connections > 0 && now() < deadline)
    std::this_thread::sleep_for(20ms);
  s.pool.shutdown();
  while (s.pool.outstanding() > 0 && now() < deadline + 1000)
    std::this_thread::sleep_for(10ms);
  s.io->stop();
  loop.join();
  log("ftp", "stopped");
  return 0;
}
} // namespace tc
