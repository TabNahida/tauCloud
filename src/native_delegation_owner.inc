// Private owner process with one active controller and up to 256 descriptor capabilities.
// It never accepts a pathname, Internet connection, file credential or data operation.
struct native_delegation_owner::impl {
  static inline std::atomic_bool entry_registered = false;
#ifdef __linux__
  struct packet {
    uint32_t magic = 0x54434434, op = 0;
    uint32_t native_flags = 0, reserved = 0;
    uint64_t id = 0;
    int64_t period = 0, remaining = 0;
    uint64_t reservation = 0;
    std::array<char, 32> capability{};
  };
  static_assert(sizeof(packet) == 80);
  enum { acquire_read = 1, acquire_write, query, renew, recall, release, reserve, complete, cancel,
         export_capability, bind_channel, export_owner, bind_owner };
  static std::array<char, 32> proof(std::string_view secret, std::string_view endpoint, uint64_t id,
                                     std::string_view nonce, bool server, bool recovery = false) {
    require(secret.size() == 16 && endpoint.size() == 16 && nonce.size() == 16, "invalid_request");
    auto prefix = recovery ? (server ? "TCD4-owner-server:" : "TCD4-owner-client:") :
                             (server ? "TCD4-server:" : "TCD4-client:");
    auto message = std::string(prefix) + std::string(endpoint) +
        std::to_string(id) + ":" + std::string(nonce);
    auto tag = decode_bytes(mac(secret, message).substr(0, 32));
    std::array<char, 32> result{};
    std::copy(nonce.begin(), nonce.end(), result.begin());
    std::copy(tag.begin(), tag.end(), result.begin() + 16);
    return result;
  }
  resource control;
  pid_t child = -1;
  pid_t recovered_peer = -1;
  std::mutex mutex;
  std::map<uint64_t, std::shared_ptr<resource>> owned;
  static int64_t clock() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
  }
  static json snapshot(const packet &r) {
    auto state = (r.op >> 8) & 255;
    require(state <= 4 && r.period > 0 && r.remaining >= 0 && r.reserved <= 32, "delegation_owner_io");
    const char *names[] = {"active", "recalling", "returned", "revoked", "expired"};
    auto time = clock();
    auto expiry = r.reserved ? INT64_MAX : r.period;
    auto until = state < 2 ? (r.remaining ? std::min(expiry, r.remaining) : expiry) : 0;
    return {{"state", names[state]}, {"held", state < 2},
        {"reservations", r.reserved}, {"reservation", r.reservation},
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
    return valid && result == sizeof(p) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) && count <= 1 && p.magic == 0x54434434;
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
  packet exchange(const packet &request, int fd = -1) {
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
          (response.op & 255) == request.op && (request.id == 0 || response.id == request.id) &&
          (!request.reservation || response.reservation == request.reservation);
      break;
    }
    if (!ok) { disconnect(); throw error("delegation_owner_lost"); }
    auto error_code = response.op >> 16;
    if (error_code) {
      if (error_code == 2) throw error("invalid_request");
      if (error_code == 3) throw error("stale_handle");
      if (error_code == 5) throw error("operation_limit");
      if (error_code == 6) throw error("forbidden");
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
      std::map<uint64_t, uint64_t> reservations; // token -> controller (0 is primary)
      std::string capability;
    };
    std::map<uint64_t, record> records;
    uint64_t next = 0, next_reservation = 0;
    size_t pending = 0;
    bool connected = true, recoverable = true;
    resource listener;
    std::string endpoint;
    std::string recovery_secret;
    auto listen_for_channels = [&] {
      if (listener.handle >= 0) return;
      resource created; created.handle = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      require(created.handle >= 0, "delegation_owner_io");
      auto name = decode_bytes(random_hex(16));
      sockaddr_un address{}; address.sun_family = AF_UNIX;
      auto encoded = "taucloud-nfs-" + encode_bytes(name);
      require(encoded.size() + 1 <= sizeof(address.sun_path), "delegation_owner_io");
      std::memcpy(address.sun_path + 1, encoded.data(), encoded.size());
      require(::bind(created.handle, reinterpret_cast<sockaddr *>(&address),
          offsetof(sockaddr_un, sun_path) + 1 + encoded.size()) == 0 && listen(created.handle, 16) == 0,
          "delegation_owner_io");
      endpoint = std::move(name); listener.handle = created.handle; created.handle = -1;
    };
    struct channel {
      std::unique_ptr<resource> socket;
      uint64_t id = 0, serial = 0;
      int64_t deadline = 0;
    };
    std::map<int, channel> channels;
    uint64_t next_channel = 0;
    auto close_channel = [&](int fd) {
      auto found = channels.find(fd);
      if (found == channels.end()) return;
      auto record = records.find(found->second.id);
      if (record != records.end()) {
        auto &r = record->second;
        for (auto it = r.reservations.begin(); it != r.reservations.end();) {
          if (it->second != found->second.serial) { ++it; continue; }
          r.lifetime.complete(clock(), true);
          it = r.reservations.erase(it); --pending;
        }
      }
      channels.erase(found);
    };
    auto detach = [&](bool allow_recovery = true) {
      recoverable &= allow_recovery;
      if (!recoverable) {
        channels.clear();
        if (listener.handle >= 0) { ::close(listener.handle); listener.handle = -1; }
      }
      if (!connected) return;
      connected = false; ::close(socket);
      // EOF cannot prove whether a reply reached its client. Preserve a full
      // lease from detection, then permit autonomous expiry. Recall stays fixed.
      for (auto &[id, r] : records) {
        for (const auto &[token, controller] : r.reservations) {
          (void)token; (void)controller; r.lifetime.complete(clock(), true);
        }
        r.reservations.clear();
        r.capability.clear(); // Old protocol instances cannot rebind after recovery.
      }
      pending = 0;
      // Existing reservation channels must observe loss and fence their old
      // protocol instance. Only unbound handshakes may survive for recovery.
      std::erase_if(channels, [](const auto &entry) { return entry.second.id != 0; });
      if (recovery_secret.empty()) {
        channels.clear();
        if (listener.handle >= 0) { ::close(listener.handle); listener.handle = -1; }
      }
    };
    for (;;) {
      bool held = false;
      for (auto &[id, r] : records) {
        if (r.guard) {
          try { if (r.guard->breaking()) r.lifetime.recall(clock()); }
          catch (...) {
            r.lifetime.recall(clock());
            // Keep the descriptor, but do not acknowledge further renewals
            // after losing the ability to observe the kernel's protection.
            detach(false);
          }
          r.lifetime.expire(clock());
          if (!r.lifetime.held()) { r.guard.reset(); r.file = native_file(); }
        }
        held |= r.lifetime.held();
      }
      if (!connected && !held) return 0;
      for (auto it = channels.begin(); it != channels.end();) {
        auto fd = it->first; ++it;
        if (!channels.at(fd).id && clock() >= channels.at(fd).deadline) close_channel(fd);
      }
      std::vector<pollfd> polling{{connected ? socket : -1, POLLIN, 0}, {listener.handle, POLLIN, 0}};
      for (const auto &[fd, c] : channels) polling.push_back({fd, POLLIN, 0});
      int ready = poll(polling.data(), polling.size(), 20);
      if (ready <= 0) continue;
      if (listener.handle >= 0 && polling[1].revents) {
        // Bounded handshakes cannot starve guard maintenance or primary control.
        for (int count = 0; count < 8; ++count) {
          resource incoming; incoming.handle = accept4(listener.handle, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (incoming.handle < 0) break;
          ucred identity{}; socklen_t length = sizeof(identity);
          auto handshakes = std::count_if(channels.begin(), channels.end(), [](const auto &entry) { return !entry.second.id; });
          if (channels.size() >= 512 || handshakes >= 32 || next_channel == UINT64_MAX ||
              getsockopt(incoming.handle, SOL_SOCKET, SO_PEERCRED, &identity, &length) || identity.uid != geteuid()) continue;
          auto fd = incoming.handle;
          auto owned = std::make_unique<resource>(); owned->handle = fd; incoming.handle = -1;
          channels.emplace(fd, channel{std::move(owned), 0, ++next_channel, clock() + 1500});
        }
      }
      for (size_t index = 0; index < polling.size(); ++index) {
        if (index == 1 || !polling[index].revents) continue;
        int current = polling[index].fd;
        bool primary = index == 0;
        if (primary && !connected) continue;
        if (!primary && !channels.contains(current)) continue;
        uint64_t controller = primary ? 0 : channels.at(current).serial;
        auto abandon = [&] { if (primary) detach(); else close_channel(current); };
        packet request; resource descriptor;
        if (!receive(current, request, descriptor)) { abandon(); continue; }
        packet response = request;
        response.capability.fill(0);
        unsigned failure = 0;
        bool adopting = false;
        try {
          auto op = request.op;
          require(op >= acquire_read && op <= bind_owner, "invalid_request");
          if (primary) require(op != bind_channel && op != bind_owner &&
              request.capability == std::array<char, 32>{}, "invalid_request");
          else {
            auto &c = channels.at(current);
            if (!c.id) {
              std::string capability(request.capability.data(), request.capability.size());
              if (op == bind_owner) {
                require(!connected && recoverable && !request.id && recovery_secret.size() == 16, "forbidden");
                auto expected = proof(recovery_secret, endpoint, 0, std::string_view(capability).substr(0, 16), false, true);
                require(equal(capability, std::string_view(expected.data(), expected.size())), "forbidden");
                bool live = false;
                for (auto &[id, r] : records) {
                  r.lifetime.expire(clock());
                  if (!r.lifetime.held()) { r.guard.reset(); r.file = native_file(); }
                  live |= r.lifetime.held();
                }
                require(live, "stale_handle");
              } else {
                require(connected && op == bind_channel, "forbidden");
                auto found = records.find(request.id);
                require(found != records.end() && found->second.capability.size() == 16, "forbidden");
                auto expected = proof(found->second.capability, endpoint, request.id,
                    std::string_view(capability).substr(0, 16), false);
                require(equal(capability, std::string_view(expected.data(), expected.size())), "forbidden");
                require(found->second.lifetime.held(), "stale_handle");
              }
            } else require(connected && (op == query || op == reserve || op == complete || op == cancel) &&
                request.id == c.id && request.capability == std::array<char, 32>{}, "forbidden");
          }
          bool acquiring = op == acquire_read || op == acquire_write;
          require(acquiring == (descriptor.handle >= 0), "invalid_request");
          require(!request.reserved && !(request.native_flags & ~3u) &&
              (acquiring || !request.native_flags), "invalid_request");
          require((op == complete || op == cancel) == (request.reservation != 0), "invalid_request");
          if (op == export_owner || op == bind_owner) {
            require(!request.id && !request.period && !request.remaining, "invalid_request");
            if (op == export_owner) {
              require(primary && recoverable, "forbidden");
              listen_for_channels();
              if (recovery_secret.empty()) recovery_secret = decode_bytes(random_hex(16));
              auto capability = endpoint + recovery_secret;
              std::copy(capability.begin(), capability.end(), response.capability.begin());
            } else {
              response.capability = proof(recovery_secret, endpoint, 0,
                  std::string_view(request.capability.data(), 16), true, true);
              adopting = true;
            }
          } else if (acquiring) {
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
                    nfs_detail::delegation_lifetime(accepted, request.period, request.remaining - accepted), {}, {}});
              }
            }
          } else {
            require(request.id && request.period == 0 &&
                (op == renew || (op == recall ? request.remaining >= 0 : request.remaining == 0)), "invalid_request");
            auto found = records.find(request.id);
            require(found != records.end(), "stale_handle");
            auto &r = found->second;
            r.lifetime.expire(clock());
            if (!r.lifetime.held()) { r.guard.reset(); r.file = native_file(); }
            if (op == export_capability) {
              require(primary && r.lifetime.held(), "stale_handle");
              listen_for_channels();
              if (r.capability.empty()) r.capability = decode_bytes(random_hex(16));
              auto capability = endpoint + r.capability;
              std::copy(capability.begin(), capability.end(), response.capability.begin());
            }
            else if (op == bind_channel) {
              require(r.lifetime.held(), "stale_handle");
              response.capability = proof(r.capability, endpoint, request.id,
                  std::string_view(request.capability.data(), 16), true);
              channels.at(current).id = request.id;
            }
            else if (op == renew) {
              auto accepted = clock();
              require(request.remaining > accepted && request.remaining <= accepted + 3600000 &&
                  r.lifetime.renew(accepted, request.remaining - accepted), "stale_handle");
            }
            else if (op == recall) {
              r.lifetime.recall(clock());
              if (request.remaining) r.lifetime.constrain(r.lifetime.expires(), request.remaining);
              r.lifetime.expire(clock());
              if (!r.lifetime.held()) { r.guard.reset(); r.file = native_file(); }
            }
            else if (op == reserve) {
              require(pending < 512 && r.reservations.size() < 32 && next_reservation != UINT64_MAX,
                      "operation_limit");
              require(r.lifetime.held(), "stale_handle");
              auto token = ++next_reservation;
              r.reservations.emplace(token, controller);
              if (!r.lifetime.reserve(clock())) { r.reservations.erase(token); throw error("stale_handle"); }
              ++pending; response.reservation = token;
            }
            else if (op == complete || op == cancel) {
              auto token = r.reservations.find(request.reservation);
              require(token != r.reservations.end() && token->second == controller, "stale_handle");
              r.lifetime.complete(clock(), op == complete);
              r.reservations.erase(request.reservation); --pending;
              if (!r.lifetime.held()) { r.guard.reset(); r.file = native_file(); }
            }
            else if (op == release) {
              pending -= r.reservations.size(); records.erase(found);
              std::erase_if(channels, [&](const auto &entry) { return entry.second.id == request.id; });
            }
            if (op != release) {
              response.op |= static_cast<unsigned>(r.lifetime.status()) << 8;
              response.period = r.lifetime.expires();
              response.remaining = r.lifetime.recall_until();
              response.reserved = static_cast<uint32_t>(r.reservations.size());
            }
          }
        } catch (const error &e) {
          auto code = std::string_view(e.what());
          failure = code == "invalid_request" ? 2 : code == "stale_handle" ? 3 : code == "operation_limit" ? 5 :
              code == "forbidden" ? 6 : 4;
        } catch (...) { failure = 4; }
        response.op |= failure << 16;
        bool delivered = send(current, response);
        if (adopting && !failure && delivered) {
          socket = current; connected = true;
          channels.at(current).socket->handle = -1;
          channels.erase(current);
        } else if (!delivered || (!primary && failure && !channels.at(current).id)) abandon();
      }
    }
  }
#endif
};
struct native_delegation_reservation_channel::impl {
#ifdef __linux__
  using owner = native_delegation_owner::impl;
  owner transport;
  uint64_t id = 0;
  bool nonblocking = false;
  bool authenticated = false;
  struct exchange_state {
    owner::packet request;
    int64_t deadline;
    std::optional<std::array<char, 32>> proof;
  };
  std::optional<exchange_state> pending;
  void begin(const owner::packet &request, std::optional<std::array<char, 32>> proof = {}) {
    require(!pending, "operation_pending");
    require(transport.control.handle >= 0, "delegation_owner_lost");
    auto deadline = owner::clock() + 1500;
    if (!owner::send(transport.control.handle, request)) {
      transport.disconnect(); throw error("delegation_owner_lost");
    }
    pending = exchange_state{request, deadline, proof};
  }
  void begin(unsigned op, uint64_t token = 0) {
    require(!pending, "operation_pending");
    require(transport.control.handle >= 0, "delegation_owner_lost");
    require(authenticated, "forbidden");
    owner::packet request; request.op = op; request.id = id; request.reservation = token;
    begin(request);
  }
  [[noreturn]] void lost() {
    pending.reset(); transport.disconnect(); throw error("delegation_owner_lost");
  }
  bool alive() {
    require(nonblocking, "invalid_request");
    if (transport.control.handle < 0) return false;
    pollfd readable{transport.control.handle, POLLIN, 0};
    auto ready = ::poll(&readable, 1, 0);
    bool expired = pending && owner::clock() >= pending->deadline;
    bool bad = (ready < 0 && errno != EINTR) ||
        (readable.revents & (POLLHUP | POLLERR | POLLNVAL)) ||
        (!pending && (readable.revents & POLLIN));
    if (expired || bad) { pending.reset(); transport.disconnect(); return false; }
    return true;
  }
  std::optional<json> poll() {
    require(transport.control.handle >= 0, "delegation_owner_lost");
    require(pending.has_value(), "invalid_request");
    if (owner::clock() >= pending->deadline) lost();
    pollfd readable{transport.control.handle, POLLIN, 0};
    auto ready = ::poll(&readable, 1, 0);
    if (!ready || (ready < 0 && errno == EINTR)) return {};
    owner::packet response; resource unexpected;
    const auto &request = pending->request;
    if (ready < 0 || !owner::receive(transport.control.handle, response, unexpected) || unexpected.handle >= 0 ||
        (response.op & 255) != request.op || response.id != request.id ||
        (request.reservation && response.reservation != request.reservation)) lost();
    auto expected = pending->proof;
    pending.reset();
    if (expected && (response.op >> 16)) transport.disconnect();
    switch (response.op >> 16) {
      case 0: break;
      case 2: throw error("invalid_request");
      case 3: throw error("stale_handle");
      case 5: throw error("operation_limit");
      case 6: throw error("forbidden");
      default: lost();
    }
    if (expected && !equal(std::string_view(response.capability.data(), response.capability.size()),
                          std::string_view(expected->data(), expected->size()))) {
      transport.disconnect(); throw error("forbidden");
    }
    // A successful reserve must identify its owned token. Malformed state is
    // uncertain, so abandon the channel and let the owner retain its tokens.
    if ((response.op & 255) == owner::reserve && !response.reservation) lost();
    try {
      auto value = owner::snapshot(response);
      if (expected) authenticated = true;
      return value;
    }
    catch (...) { transport.disconnect(); throw; }
  }
  json wait() {
    for (;;) {
      if (auto response = poll()) return *response;
      pollfd readable{transport.control.handle, POLLIN, 0};
      auto remaining = pending->deadline - owner::clock();
      if (remaining <= 0) lost();
      auto ready = ::poll(&readable, 1, static_cast<int>(remaining));
      if (ready < 0 && errno != EINTR) lost();
    }
  }
  json exchange(unsigned op, uint64_t token = 0) {
    std::lock_guard lock(transport.mutex);
    require(!nonblocking, "invalid_request");
    begin(op, token);
    return wait();
  }
#endif
};
native_delegation_reservation_channel::native_delegation_reservation_channel(const json &capability, mode selected)
    : impl_(std::make_unique<impl>()) {
#ifdef __linux__
  using owner = native_delegation_owner::impl;
  require(capability.is_object() && capability.contains("id") && capability.contains("capability") &&
      capability.at("id").is_number_unsigned() && capability.at("capability").is_string(), "invalid_request");
  impl_->id = capability.at("id").get<uint64_t>();
  auto encoded = capability.at("capability").get<std::string>();
  require(impl_->id && encoded.size() == 64, "invalid_request");
  auto value = decode_bytes(encoded);
  resource socket; socket.handle = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  require(socket.handle >= 0, "delegation_owner_unavailable");
  sockaddr_un address{}; address.sun_family = AF_UNIX;
  auto name = "taucloud-nfs-" + encode_bytes(std::string_view(value).substr(0, 16));
  std::memcpy(address.sun_path + 1, name.data(), name.size());
  require(::connect(socket.handle, reinterpret_cast<sockaddr *>(&address),
      offsetof(sockaddr_un, sun_path) + 1 + name.size()) == 0, "delegation_owner_unavailable");
  ucred peer{}; socklen_t length = sizeof(peer);
  require(getsockopt(socket.handle, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 && peer.uid == geteuid(), "forbidden");
  impl_->transport.control.handle = socket.handle; socket.handle = -1;
  owner::packet request; request.op = owner::bind_channel; request.id = impl_->id;
  auto endpoint = std::string_view(value).substr(0, 16), secret = std::string_view(value).substr(16);
  auto nonce = decode_bytes(random_hex(16));
  request.capability = owner::proof(secret, endpoint, impl_->id, nonce, false);
  impl_->nonblocking = selected == mode::nonblocking;
  impl_->begin(request, owner::proof(secret, endpoint, impl_->id, nonce, true));
  if (!impl_->nonblocking) impl_->wait();
#else
  (void)capability; (void)selected; throw error("not_supported");
#endif
}
native_delegation_reservation_channel::~native_delegation_reservation_channel() = default;
json native_delegation_reservation_channel::inspect() {
#ifdef __linux__
  return impl_->exchange(native_delegation_owner::impl::query);
#else
  throw error("not_supported");
#endif
}
json native_delegation_reservation_channel::reserve() {
#ifdef __linux__
  return impl_->exchange(native_delegation_owner::impl::reserve);
#else
  throw error("not_supported");
#endif
}
json native_delegation_reservation_channel::complete(uint64_t reservation, bool renew_lease) {
#ifdef __linux__
  require(reservation, "invalid_request");
  return impl_->exchange(renew_lease ? native_delegation_owner::impl::complete : native_delegation_owner::impl::cancel, reservation);
#else
  (void)reservation; (void)renew_lease; throw error("not_supported");
#endif
}
void native_delegation_reservation_channel::begin_inspect() {
#ifdef __linux__
  std::lock_guard lock(impl_->transport.mutex);
  impl_->begin(native_delegation_owner::impl::query);
#else
  throw error("not_supported");
#endif
}
void native_delegation_reservation_channel::begin_reserve() {
#ifdef __linux__
  std::lock_guard lock(impl_->transport.mutex);
  impl_->begin(native_delegation_owner::impl::reserve);
#else
  throw error("not_supported");
#endif
}
void native_delegation_reservation_channel::begin_complete(uint64_t reservation, bool renew_lease) {
#ifdef __linux__
  require(reservation, "invalid_request");
  std::lock_guard lock(impl_->transport.mutex);
  impl_->begin(renew_lease ? native_delegation_owner::impl::complete : native_delegation_owner::impl::cancel, reservation);
#else
  (void)reservation; (void)renew_lease; throw error("not_supported");
#endif
}
std::optional<json> native_delegation_reservation_channel::poll() {
#ifdef __linux__
  std::lock_guard lock(impl_->transport.mutex);
  return impl_->poll();
#else
  throw error("not_supported");
#endif
}
bool native_delegation_reservation_channel::alive() {
#ifdef __linux__
  std::lock_guard lock(impl_->transport.mutex);
  return impl_->alive();
#else
  throw error("not_supported");
#endif
}
json native_delegation_owner::reservation_capability(uint64_t id) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  impl::packet request; request.op = impl::export_capability; request.id = id;
  auto response = impl_->exchange(request);
  return {{"id", id}, {"capability", encode_bytes(std::string_view(response.capability.data(), response.capability.size()))}};
#else
  (void)id; throw error("not_supported");
#endif
}
native_delegation_owner::native_delegation_owner() : impl_(std::make_unique<impl>()) {
#ifdef __linux__
  require(impl::entry_registered, "delegation_owner_entry_required");
  impl_->start();
#endif
}
native_delegation_owner::native_delegation_owner(const json &capability) : impl_(std::make_unique<impl>()) {
#ifdef __linux__
  require(capability.is_object() && capability.contains("type") && capability.at("type") == "owner-recovery-v1" &&
      capability.contains("capability") && capability.at("capability").is_string(), "invalid_request");
  auto encoded = capability.at("capability").get<std::string>();
  require(encoded.size() == 64, "invalid_request");
  auto value = decode_bytes(encoded);
  auto endpoint = std::string_view(value).substr(0, 16), secret = std::string_view(value).substr(16);
  resource socket; socket.handle = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  require(socket.handle >= 0, "delegation_owner_unavailable");
  sockaddr_un address{}; address.sun_family = AF_UNIX;
  auto name = "taucloud-nfs-" + encode_bytes(endpoint);
  std::memcpy(address.sun_path + 1, name.data(), name.size());
  require(::connect(socket.handle, reinterpret_cast<sockaddr *>(&address),
      offsetof(sockaddr_un, sun_path) + 1 + name.size()) == 0, "delegation_owner_unavailable");
  ucred peer{}; socklen_t length = sizeof(peer);
  require(getsockopt(socket.handle, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 && peer.uid == geteuid(), "forbidden");
  impl_->control.handle = socket.handle; socket.handle = -1;
  impl::packet request; request.op = impl::bind_owner;
  auto nonce = decode_bytes(random_hex(16));
  request.capability = impl::proof(secret, endpoint, 0, nonce, false, true);
  auto response = impl_->exchange(request);
  auto expected = impl::proof(secret, endpoint, 0, nonce, true, true);
  require(equal(std::string_view(response.capability.data(), response.capability.size()),
      std::string_view(expected.data(), expected.size())), "forbidden");
  impl_->recovered_peer = peer.pid;
#else
  (void)capability; throw error("not_supported");
#endif
}
json native_delegation_owner::recovery_capability() {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  impl::packet request; request.op = impl::export_owner;
  auto response = impl_->exchange(request);
  return {{"type", "owner-recovery-v1"},
      {"capability", encode_bytes(std::string_view(response.capability.data(), response.capability.size()))}};
#else
  throw error("not_supported");
#endif
}
native_delegation_owner::~native_delegation_owner() = default;
int64_t native_delegation_owner::process_id() const {
#ifdef __linux__
  return impl_->child > 0 ? impl_->child : impl_->recovered_peer;
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
json native_delegation_owner::reserve(uint64_t id) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  impl::packet request; request.op = impl::reserve; request.id = id;
  return impl::snapshot(impl_->exchange(request));
#else
  (void)id; throw error("not_supported");
#endif
}
json native_delegation_owner::complete(uint64_t id, uint64_t reservation, bool renew_lease) {
#ifdef __linux__
  std::lock_guard lock(impl_->mutex);
  require(reservation != 0, "invalid_request");
  impl::packet request; request.op = renew_lease ? impl::complete : impl::cancel;
  request.id = id; request.reservation = reservation;
  return impl::snapshot(impl_->exchange(request));
#else
  (void)id; (void)reservation; (void)renew_lease; throw error("not_supported");
#endif
}
json native_delegation_owner::recall(uint64_t id, int64_t deadline_ms) {
#ifdef __linux__
  require(deadline_ms >= 0, "invalid_request");
  std::lock_guard lock(impl_->mutex);
  impl::packet request; request.op = impl::recall; request.id = id; request.remaining = deadline_ms;
  return impl::snapshot(impl_->exchange(request));
#else
  (void)id; (void)deadline_ms; throw error("not_supported");
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
