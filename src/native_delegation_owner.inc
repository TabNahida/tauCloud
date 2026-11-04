// One private owner process per client object, up to 256 descriptor capabilities.
// It never accepts a pathname, network connection, credential or data operation.
struct native_delegation_owner::impl {
  static inline std::atomic_bool entry_registered = false;
#ifdef __linux__
  struct packet {
    uint32_t magic = 0x54434432, op = 0;
    uint32_t native_flags = 0, reserved = 0;
    uint64_t id = 0;
    int64_t period = 0, remaining = 0;
  };
  static_assert(sizeof(packet) == 40);
  enum { acquire_read = 1, acquire_write, query, renew, recall, release };
  resource control;
  pid_t child = -1;
  std::mutex mutex;
  std::map<uint64_t, std::shared_ptr<resource>> owned;
  static int64_t clock() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
  }
  static json snapshot(const packet &r) {
    auto state = (r.op >> 8) & 255;
    require(state <= 4 && r.period > 0 && r.remaining >= 0, "delegation_owner_io");
    const char *names[] = {"active", "recalling", "returned", "revoked", "expired"};
    auto time = clock();
    auto until = state < 2 ? (r.remaining ? std::min(r.period, r.remaining) : r.period) : 0;
    return {{"state", names[state]}, {"held", state < 2},
        {"lease_expires_ms", r.period}, {"recall_deadline_ms", r.remaining}, {"protected_until_ms", until},
        {"lease_remaining_ms", std::max<int64_t>(0, r.period - time)},
        {"recall_remaining_ms", r.remaining ? std::max<int64_t>(0, r.remaining - time) : 0}};
  }
  static bool send(int socket, const packet &p, int descriptor = -1) {
    iovec data{const_cast<packet *>(&p), sizeof(p)};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
    msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
    if (descriptor >= 0) {
      message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
      auto c = CMSG_FIRSTHDR(&message);
      c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
      std::memcpy(CMSG_DATA(c), &descriptor, sizeof(int));
    }
    ssize_t result;
    do { result = sendmsg(socket, &message, MSG_NOSIGNAL | MSG_DONTWAIT); } while (result < 0 && errno == EINTR);
    return result == sizeof(p);
  }
  static bool receive(int socket, packet &p, resource &descriptor) {
    iovec data{&p, sizeof(p)};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(2 * sizeof(int))]{};
    msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
    ssize_t result;
    do { result = recvmsg(socket, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT); } while (result < 0 && errno == EINTR);
    unsigned count = 0; bool valid = true;
    for (auto c = CMSG_FIRSTHDR(&message); result >= 0 && c; c = CMSG_NXTHDR(&message, c)) {
      if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS || c->cmsg_len < CMSG_LEN(0)) {
        valid = false; continue;
      }
      auto size = c->cmsg_len - CMSG_LEN(0);
      for (size_t i = 0; i + sizeof(int) <= size; i += sizeof(int)) {
        int fd; std::memcpy(&fd, CMSG_DATA(c) + i, sizeof(fd));
        if (++count == 1) descriptor.handle = fd; else ::close(fd);
      }
    }
    return valid && result == sizeof(p) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) && count <= 1 && p.magic == 0x54434432;
  }
  void start() {
    int sockets[2];
    require(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) == 0, "delegation_owner_unavailable");
    resource parent, peer; parent.handle = sockets[0]; peer.handle = sockets[1];
    // Keep the spawn source distinct from stdio and the target control fd.
    resource source; source.handle = fcntl(peer.handle, F_DUPFD_CLOEXEC, 4);
    require(source.handle >= 0, "delegation_owner_unavailable");
    posix_spawn_file_actions_t actions;
    require(posix_spawn_file_actions_init(&actions) == 0, "delegation_owner_unavailable");
    posix_spawnattr_t attr;
    int rc = posix_spawnattr_init(&attr);
    if (rc) { posix_spawn_file_actions_destroy(&actions); throw error("delegation_owner_unavailable"); }
    rc = posix_spawn_file_actions_adddup2(&actions, source.handle, 3);
    // Orphan retention must not hold a service's console/logging pipes open.
    for (int fd = 0; !rc && fd < 3; ++fd)
      rc = posix_spawn_file_actions_addopen(&actions, fd, "/dev/null", fd ? O_WRONLY : O_RDONLY, 0);
    if (!rc) rc = posix_spawn_file_actions_addclosefrom_np(&actions, 4);
    // A normal service/terminal process-group shutdown must not kill retained
    // guards. Explicit owner death remains a separate failure boundary.
    if (!rc) rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
    char executable[] = "/proc/self/exe", flag[] = "--native-delegation-owner";
    char *argv[] = {executable, flag, nullptr};
    char *environment[] = {nullptr};
    if (!rc) rc = posix_spawn(&child, executable, &actions, &attr, argv, environment);
    posix_spawnattr_destroy(&attr); posix_spawn_file_actions_destroy(&actions);
    require(rc == 0, "delegation_owner_unavailable");
    control.handle = parent.handle; parent.handle = -1;
  }
  void disconnect() {
    if (control.handle >= 0) { ::close(control.handle); control.handle = -1; }
  }
  packet exchange(packet request, int fd = -1) {
    require(control.handle >= 0, "delegation_owner_lost");
    auto deadline = clock() + 1500;
    bool ok = send(control.handle, request, fd);
    packet response;
    resource unexpected;
    while (ok) {
      pollfd p{control.handle, POLLIN, 0};
      auto remaining = deadline - clock();
      if (remaining <= 0) { ok = false; break; }
      int rc = poll(&p, 1, static_cast<int>(remaining));
      if (rc < 0 && errno == EINTR) continue;
      ok = rc > 0 && receive(control.handle, response, unexpected) && unexpected.handle < 0 &&
          (response.op & 255) == request.op && (request.id == 0 || response.id == request.id);
      break;
    }
    if (!ok) { disconnect(); throw error("delegation_owner_lost"); }
    auto error_code = response.op >> 16;
    if (error_code) {
      if (error_code == 2) throw error("invalid_request");
      if (error_code == 3) throw error("stale_handle");
      if (error_code == 5) throw error("operation_limit");
      throw error("delegation_owner_io");
    }
    return response;
  }
  ~impl() {
    disconnect(); // Never send RELEASE from a destructor or transport failure.
    // Native ownership flags stay fenced on still-retained local descriptions
    // after detachment; a later open may obtain a new guard after expiry.
    if (child > 0) {
      auto pid = child;
      try { std::thread([pid] { int status; while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {} }).detach(); }
      catch (...) { int status; waitpid(pid, &status, WNOHANG); }
    }
  }
  static int run(int socket) {
    int type = 0; socklen_t size = sizeof(type); ucred peer{}; socklen_t peer_size = sizeof(peer);
    if (getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_SEQPACKET ||
        getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) || peer.uid != geteuid()) return 2;
    struct record {
      native_file file;
      std::unique_ptr<native_cache_guard> guard;
      nfs_detail::delegation_lifetime lifetime;
    };
    std::map<uint64_t, record> records;
    uint64_t next = 0;
    bool connected = true;
    for (;;) {
      bool held = false;
      for (auto &[id, r] : records) {
        if (r.guard) {
          try { if (r.guard->breaking()) r.lifetime.recall(clock()); }
          catch (...) {
            r.lifetime.recall(clock());
            // Keep the descriptor, but do not acknowledge further renewals
            // after losing the ability to observe the kernel's protection.
            if (connected) { connected = false; ::close(socket); }
          }
          r.lifetime.expire(clock());
          if (!r.lifetime.held()) { r.guard.reset(); r.file = native_file(); }
        }
        held |= r.lifetime.held();
      }
      if (!connected && !held) return 0;
      pollfd p{connected ? socket : -1, POLLIN, 0};
      int ready = poll(&p, 1, 20);
      if (ready <= 0) continue;
      packet request; resource descriptor;
      if (!receive(socket, request, descriptor)) { connected = false; ::close(socket); continue; }
      packet response = request;
      unsigned failure = 0;
      try {
        auto op = request.op;
        require(op >= acquire_read && op <= release, "invalid_request");
        bool acquiring = op == acquire_read || op == acquire_write;
        require(acquiring == (descriptor.handle >= 0), "invalid_request");
        require(!request.reserved && !(request.native_flags & ~3u) &&
            (acquiring || !request.native_flags), "invalid_request");
        if (acquiring) {
          require(!request.id && request.period >= 5000 && request.period <= 3600000 &&
              request.remaining > clock() && request.remaining <= clock() + request.period, "invalid_request");
          require(records.size() < 256 && next != UINT64_MAX, "operation_limit");
          int64_t seconds = 0; std::ifstream input("/proc/sys/fs/lease-break-time");
          if (input >> seconds && seconds * 1000 >= request.period + 5000) {
            native_file file; file.impl_->file->handle = descriptor.handle; descriptor.handle = -1;
            file.impl_->private_pin = request.native_flags & 1;
            file.impl_->allow_unlinked = request.native_flags & 2;
            auto guard = file.delegation_guard(op == acquire_write);
            auto accepted = clock();
            if (guard && request.remaining > accepted) {
              response.id = ++next;
              records.emplace(response.id, record{std::move(file), std::move(guard),
                  nfs_detail::delegation_lifetime(accepted, request.period, request.remaining - accepted)});
            }
          }
        } else {
          require(request.id && request.period == 0 && (op == renew || request.remaining == 0), "invalid_request");
          auto found = records.find(request.id);
          require(found != records.end(), "stale_handle");
          auto &r = found->second;
          r.lifetime.expire(clock());
          if (!r.lifetime.held()) { r.guard.reset(); r.file = native_file(); }
          if (op == renew) {
            auto accepted = clock();
            require(request.remaining > accepted && request.remaining <= accepted + 3600000 &&
                r.lifetime.renew(accepted, request.remaining - accepted), "stale_handle");
          }
          else if (op == recall) r.lifetime.recall(clock());
          else if (op == release) { records.erase(found); }
          if (op != release) {
            response.op |= static_cast<unsigned>(r.lifetime.status()) << 8;
            response.period = r.lifetime.expires();
            response.remaining = r.lifetime.recall_until();
          }
        }
      } catch (const error &e) {
        auto code = std::string_view(e.what());
        failure = code == "invalid_request" ? 2 : code == "stale_handle" ? 3 : code == "operation_limit" ? 5 : 4;
      } catch (...) { failure = 4; }
      response.op |= failure << 16;
      if (!send(socket, response)) { connected = false; ::close(socket); }
    }
  }
#endif
};
native_delegation_owner::native_delegation_owner() : impl_(std::make_unique<impl>()) {
#ifdef __linux__
  require(impl::entry_registered, "delegation_owner_entry_required");
  impl_->start();
#endif
}
native_delegation_owner::~native_delegation_owner() = default;
int64_t native_delegation_owner::process_id() const {
#ifdef __linux__
  return impl_->child;
#else
  return 0;
#endif
}
uint64_t native_delegation_owner::acquire(const native_file &file, int64_t period, int64_t remaining, bool write) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  require(period >= 5000 && period <= 3600000 && remaining > 0 && remaining <= period, "invalid_request");
  file.info();
  auto resource = file.impl_->file;
  if (resource->cache_owned.exchange(true)) return 0;
  impl::packet request; request.op = write ? impl::acquire_write : impl::acquire_read;
  request.period = period; request.remaining = impl::clock() + remaining;
  request.native_flags = (file.impl_->private_pin ? 1 : 0) | (file.impl_->allow_unlinked ? 2 : 0);
  bool acquired = false;
  try {
    auto response = impl_->exchange(request, resource->handle);
    if (!response.id) { resource->cache_owned = false; return 0; }
    acquired = true;
    impl_->owned.emplace(response.id, resource);
    return response.id;
  } catch (...) {
    // A dead channel may have lost a successful acquire reply. Its guard must
    // expire in the owner; never unlock the shared description speculatively.
    if (!acquired && impl_->control.handle >= 0) resource->cache_owned = false;
    throw;
  }
#else
  (void)file; (void)period; (void)remaining; (void)write;
  return 0;
#endif
}
json native_delegation_owner::inspect(uint64_t id) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  impl::packet request; request.op = impl::query; request.id = id;
  auto r = impl_->exchange(request);
  auto state = (r.op >> 8) & 255;
  require(state <= 4, "delegation_owner_io");
  if (state >= 2 && impl_->owned.contains(id)) {
    impl_->owned.at(id)->cache_owned = false;
    impl_->owned.erase(id);
  }
  return impl::snapshot(r);
#else
  (void)id; throw error("not_supported");
#endif
}
json native_delegation_owner::renew(uint64_t id, int64_t remaining) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  require(remaining > 0 && remaining <= 3600000, "invalid_request");
  impl::packet request; request.op = impl::renew; request.id = id; request.remaining = impl::clock() + remaining;
  return impl::snapshot(impl_->exchange(request));
#else
  (void)id; (void)remaining; throw error("not_supported");
#endif
}
void native_delegation_owner::recall(uint64_t id) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  impl::packet request; request.op = impl::recall; request.id = id;
  impl_->exchange(request);
#else
  (void)id; throw error("not_supported");
#endif
}
void native_delegation_owner::release(uint64_t id) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  impl::packet request; request.op = impl::release; request.id = id;
  auto found = impl_->owned.find(id);
  try { impl_->exchange(request); }
  catch (const error &e) {
    // Explicit return/expiry authorizes release after confirmed owner death.
    // SCM_RIGHTS retained the same open description in this process. Directory
    // guards also own a parent description, so they cannot use this fallback.
    // A live disconnected owner could later destroy its old guard and unlock
    // a newly acquired guard on this same description. Keep the local fence
    // until the unreaped child is known dead; do not infer death from EOF.
    struct stat info{}; siginfo_t exited{};
    if (std::string_view(e.what()) != "delegation_owner_lost" || found == impl_->owned.end() ||
        waitid(P_PID, impl_->child, &exited, WEXITED | WNOHANG | WNOWAIT) || exited.si_pid != impl_->child ||
        fstat(found->second->handle, &info) || !S_ISREG(info.st_mode)) throw;
    if (delegation_level(found->second->handle, F_UNLCK) < 0 &&
        !(errno == EAGAIN && delegation_level(found->second->handle, 0, true) == F_UNLCK))
      native_error();
  }
  if (found != impl_->owned.end()) { found->second->cache_owned = false; impl_->owned.erase(found); }
#else
  (void)id; throw error("not_supported");
#endif
}
int native_delegation_owner::entry(int argc, char **argv) {
  impl::entry_registered = true;
  if (argc != 2 || std::string_view(argv[1]) != "--native-delegation-owner") return -1;
#ifdef __linux__
  try { return impl::run(3); } catch (...) { return 2; }
#else
  return 2;
#endif
}
