#include <cstring>
#include <fstream>
#include <sstream>
#include <taucloud/core.hpp>
#include <taucloud/files.hpp>
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif
namespace tc {
int64_t own_pid() {
#ifdef _WIN32
  return GetCurrentProcessId();
#else
  return getpid();
#endif
}
file_lock::file_lock(const fs::path &p) {
#ifdef _WIN32
  auto h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
  require(h != INVALID_HANDLE_VALUE, "owner_already_running");
  handle_ = reinterpret_cast<intptr_t>(h);
#else
  int fd = open(p.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  require(fd >= 0, "io_error");
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    close(fd);
    throw error("owner_already_running");
  }
  handle_ = fd;
#endif
}
file_lock::~file_lock() {
#ifdef _WIN32
  if (handle_ != -1)
    CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
  if (handle_ != -1)
    close(static_cast<int>(handle_));
#endif
}
json process_info(int64_t pid) {
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE,
                         static_cast<DWORD>(pid));
  require(h != nullptr, "process_missing");
  FILETIME create, exit, kernel, user;
  wchar_t path[32768];
  DWORD n = 32768, code = 0;
  bool ok = GetProcessTimes(h, &create, &exit, &kernel, &user) &&
            QueryFullProcessImageNameW(h, 0, path, &n) && GetExitCodeProcess(h, &code) &&
            code == STILL_ACTIVE;
  PROCESS_MEMORY_COUNTERS mem{};
  GetProcessMemoryInfo(h, &mem, sizeof(mem));
  CloseHandle(h);
  require(ok, "process_missing");
  return {{"pid", pid},
          {"birth", (static_cast<uint64_t>(create.dwHighDateTime) << 32) | create.dwLowDateTime},
          {"exe", fs::path(std::wstring(path, n)).string()},
          {"rss", mem.WorkingSetSize}};
#else
  std::ifstream f("/proc/" + std::to_string(pid) + "/stat");
  std::string line;
  std::getline(f, line);
  auto end = line.rfind(')');
  require(end != std::string::npos, "process_missing");
  std::istringstream fields(line.substr(end + 2));
  std::string field;
  uint64_t birth = 0, rss = 0;
  for (int i = 3; i <= 24; ++i) {
    fields >> field;
    if (i == 3)
      require(field != "Z", "process_missing");
    if (i == 22)
      birth = std::stoull(field);
    if (i == 24)
      rss = std::stoull(field) * static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
  }
  return {{"pid", pid},
          {"birth", birth},
          {"exe", fs::read_symlink("/proc/" + std::to_string(pid) + "/exe").string()},
          {"rss", rss}};
#endif
}
bool verified_alive(const json &id) {
  try {
    auto p = process_info(id.at("pid"));
    return p.at("birth") == id.at("birth") && p.at("exe") == id.at("exe");
  } catch (...) {
    return false;
  }
}
void terminate_verified(const json &id) {
  if (!verified_alive(id))
    return;
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                         id.at("pid").get<DWORD>());
  if (h) {
    FILETIME c, e, k, u;
    if (GetProcessTimes(h, &c, &e, &k, &u) && ((static_cast<uint64_t>(c.dwHighDateTime) << 32) |
                                               c.dwLowDateTime) == id.at("birth").get<uint64_t>())
      TerminateProcess(h, 1);
    CloseHandle(h);
  }
#else
  // pidfd binds the signal to a process instance, including PID reuse races.
  int fd = static_cast<int>(syscall(434, id.at("pid").get<pid_t>(), 0));
  if (fd >= 0) {
    if (verified_alive(id))
      syscall(424, fd, SIGKILL, nullptr, 0);
    close(fd);
  }
#endif
}
void reap_children() {
#ifndef _WIN32
  while (waitpid(-1, nullptr, WNOHANG) > 0) {
  }
#endif
}
void apply_resource_budget(const config &c) {
#ifdef _WIN32
  // No KILL_ON_JOB_CLOSE: a supervisor restart must preserve children.
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  require(job, "resource_limit_failed");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
  info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  info.ProcessMemoryLimit = static_cast<SIZE_T>(c.memory_mb) * 1024 * 1024;
  require(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info)) &&
              AssignProcessToJobObject(job, GetCurrentProcess()),
          "resource_limit_failed");
  // Retained for the worker lifetime; the OS closes it on process exit.
#else
  rlimit files{256, 256};
  require(setrlimit(RLIMIT_NOFILE, &files) == 0, "resource_limit_failed");
  // RSS is supervised separately. RLIMIT_AS breaks ASan's shadow reservation.
#endif
  (void)c;
}
json spawn(const fs::path &exe, const config &c, const std::string &generation) {
  int64_t pid;
#ifdef _WIN32
  auto quote = [](const std::wstring &s) {
    std::wstring out = L"\"";
    size_t slash = 0;
    for (auto ch : s) {
      if (ch == L'\\') {
        ++slash;
        continue;
      }
      out.append(ch == L'"' ? 2 * slash + 1 : slash, L'\\');
      slash = 0;
      out += ch;
    }
    out.append(2 * slash, L'\\');
    return out + L"\"";
  };
  std::wstring cmd = quote(exe.wstring()) + L" --state " + quote(c.state.wstring()) +
                     L" --generation " + std::wstring(generation.begin(), generation.end());
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  require(CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                         nullptr, nullptr, &si, &pi) != 0,
          "spawn_failed");
  pid = pi.dwProcessId;
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
#else
  auto ex = exe.string(), state = c.state.string();
  char *argv[] = {ex.data(),
                  const_cast<char *>("--state"),
                  state.data(),
                  const_cast<char *>("--generation"),
                  const_cast<char *>(generation.c_str()),
                  nullptr};
  pid_t child;
  require(posix_spawn(&child, ex.c_str(), nullptr, nullptr, argv, environ) == 0, "spawn_failed");
  pid = child;
#endif
  auto result = process_info(pid);
  result["generation"] = generation;
  return result;
}
static std::string endpoint(const config &c, const std::string &role) {
#ifdef _WIN32
  return "\\\\.\\pipe\\taucloud-" + digest(c.state.string()).substr(0, 24) + "-" + role;
#else
  return (c.state / (role + ".sock")).string();
#endif
}
channel::~channel() {
#ifdef _WIN32
  if (handle_ != -1)
    CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
  if (handle_ != -1)
    close(static_cast<int>(handle_));
#endif
}
channel::channel(channel &&o) noexcept : handle_(std::exchange(o.handle_, -1)) {}
channel &channel::operator=(channel &&o) noexcept {
  std::swap(handle_, o.handle_);
  return *this;
}
#ifdef _WIN32
static DWORD complete(HANDLE h, OVERLAPPED &ov, int64_t deadline, std::stop_token stop) {
  while (WaitForSingleObject(ov.hEvent, 20) == WAIT_TIMEOUT) {
    if (stop.stop_requested() || now() >= deadline) {
      CancelIoEx(h, &ov);
      WaitForSingleObject(ov.hEvent, INFINITE);
      throw error(stop.stop_requested() ? "cancelled" : "deadline_exceeded");
    }
  }
  DWORD n = 0;
  require(GetOverlappedResult(h, &ov, &n, FALSE) != 0, "transport_closed");
  return n;
}
#endif
void channel::transfer(void *data, size_t size, bool writing, int64_t deadline,
                       std::stop_token stop) {
  size_t off = 0;
  while (off < size) {
    require(!stop.stop_requested(), "cancelled");
    require(now() < deadline, "deadline_exceeded");
#ifdef _WIN32
    auto h = reinterpret_cast<HANDLE>(handle_);
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    require(ov.hEvent, "io_error");
    DWORD n = 0;
    BOOL ok =
        writing
            ? WriteFile(h, static_cast<char *>(data) + off, static_cast<DWORD>(size - off), &n, &ov)
            : ReadFile(h, static_cast<char *>(data) + off, static_cast<DWORD>(size - off), &n, &ov);
    try {
      if (!ok) {
        require(GetLastError() == ERROR_IO_PENDING, "transport_closed");
        n = complete(h, ov, deadline, stop);
      }
    } catch (...) {
      CloseHandle(ov.hEvent);
      throw;
    }
    CloseHandle(ov.hEvent);
    require(n > 0, "transport_closed");
    off += n;
#else
    pollfd p{static_cast<int>(handle_), static_cast<short>(writing ? POLLOUT : POLLIN), 0};
    int ready = poll(&p, 1, 20);
    if (ready < 0 && errno == EINTR)
      continue;
    require(ready >= 0, "io_error");
    if (!ready)
      continue;
    auto n = writing ? ::send(p.fd, static_cast<char *>(data) + off, size - off, MSG_NOSIGNAL)
                     : ::recv(p.fd, static_cast<char *>(data) + off, size - off, 0);
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
      continue;
    require(n > 0, "transport_closed");
    off += static_cast<size_t>(n);
#endif
  }
}
void channel::send(const json &j, int64_t d, std::stop_token s) {
  auto data = j.dump();
  require(data.size() <= ipc_frame_size, "frame_too_large");
  uint32_t n = static_cast<uint32_t>(data.size());
  unsigned char head[4] = {static_cast<unsigned char>(n >> 24), static_cast<unsigned char>(n >> 16),
                           static_cast<unsigned char>(n >> 8), static_cast<unsigned char>(n)};
  transfer(head, 4, true, d, s);
  transfer(data.data(), data.size(), true, d, s);
}
json channel::receive(int64_t d, std::stop_token s) {
  unsigned char b[4];
  transfer(b, 4, false, d, s);
  uint32_t n = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | b[3];
  require(n > 0 && n <= ipc_frame_size, "frame_too_large");
  std::string data(n, '\0');
  transfer(data.data(), n, false, d, s);
  return json::parse(data);
}
channel channel::connect(const config &c, const std::string &r, int64_t deadline) {
  auto path = endpoint(c, r);
#ifdef _WIN32
  while (now() < deadline) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                           nullptr);
    if (h != INVALID_HANDLE_VALUE)
      return channel(reinterpret_cast<intptr_t>(h));
    DWORD code = GetLastError();
    require(code == ERROR_PIPE_BUSY || code == ERROR_FILE_NOT_FOUND, "service_unavailable");
    WaitNamedPipeA(path.c_str(), 20);
  }
  throw error("deadline_exceeded");
#else
  (void)deadline;
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  require(fd >= 0, "io_error");
  channel result(fd);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  require(path.size() < sizeof(addr.sun_path), "state_path_too_long");
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  require(::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0,
          "service_unavailable");
  return result;
#endif
}
struct local_listener::impl {
  std::string path;
#ifndef _WIN32
  int fd = -1;
#endif
  explicit impl(const config &c, const std::string &r) : path(endpoint(c, r)) {
#ifndef _WIN32
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    require(fd >= 0, "io_error");
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    require(path.size() < sizeof(addr.sun_path), "state_path_too_long");
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    unlink(path.c_str());
    require(bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 &&
                listen(fd, c.ipc_queue) == 0,
            "ipc_bind_failed");
#endif
  }
  ~impl() {
#ifndef _WIN32
    if (fd >= 0)
      close(fd);
    unlink(path.c_str());
#endif
  }
};
local_listener::local_listener(const config &c, const std::string &r)
    : impl_(std::make_unique<impl>(c, r)) {}
local_listener::~local_listener() = default;
std::optional<channel> local_listener::accept(std::stop_token stop) {
#ifdef _WIN32
  // Owner Rights SID resolves to the creating account; no network clients.
  PSECURITY_DESCRIPTOR sd = nullptr;
  require(ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P(A;;GA;;;SY)(A;;GA;;;OW)",
                                                               SDDL_REVISION_1, &sd, nullptr) != 0,
          "permission_denied");
  SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
  HANDLE h =
      CreateNamedPipeA(impl_->path.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                       32, 65536, 65536, 0, &sa);
  LocalFree(sd);
  require(h != INVALID_HANDLE_VALUE, "ipc_bind_failed");
  channel result(reinterpret_cast<intptr_t>(h));
  OVERLAPPED ov{};
  ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  BOOL ok = ConnectNamedPipe(h, &ov);
  DWORD code = GetLastError();
  try {
    if (!ok && code != ERROR_PIPE_CONNECTED) {
      require(code == ERROR_IO_PENDING, "io_error");
      complete(h, ov, now() + 86400000, stop);
    }
  } catch (...) {
    CloseHandle(ov.hEvent);
    if (stop.stop_requested())
      return {};
    throw;
  }
  CloseHandle(ov.hEvent);
  return result;
#else
  while (!stop.stop_requested()) {
    pollfd p{impl_->fd, POLLIN, 0};
    if (poll(&p, 1, 20) <= 0)
      continue;
    int fd = accept4(impl_->fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (fd < 0)
      continue;
    channel result(fd);
    ucred cred{};
    socklen_t n = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &n) != 0 || cred.uid != geteuid())
      continue;
    return result;
  }
  return {};
#endif
}
} // namespace tc
