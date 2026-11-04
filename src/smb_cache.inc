// File-domain cookies name native data-cache exclusion. They never appear on
// the network; the SMB FileId and owning session identify the wire oplock.
void clear_cache(opened &h, bool read_break_completed = false) {
  h.cache_cookie.clear(); h.cache_fence_at = h.cache_poll_at = 0;
  h.cache_level = h.cache_break_level = 0;
  h.cache_break_sent = false;
  h.cache_read_break_completed = read_break_completed;
  h.cache_fence_is_break = false;
}
void cache_deadline(opened &h, const json &snapshot) {
  auto remaining = h.grant.at("expires").get<int64_t>() - now();
  h.cache_fence_is_break = false;
  if (snapshot.at("breaking").get<bool>() && !snapshot.value("data_invalidated", false)) {
    auto break_remaining = snapshot.at("remaining_ms").get<int64_t>();
    h.cache_fence_is_break = break_remaining <= remaining;
    remaining = std::min(remaining, break_remaining);
  }
  if (remaining <= 200) {
    close();
    log("smb", "cache_deadline_rejected", h.cache_fence_is_break ? "break" : "authority");
    throw status_error(0xc0000128);
  }
  h.cache_fence_at = async_clock() + remaining - 100;
  h.cache_poll_at = async_clock() + 250;
}
void announce_caches() {
  for (auto sid : session_ids())
    for (auto &[fid, h] : find_session(sid)->files)
      if (!h.cache_cookie.empty()) h.cache_announced = true;
}
void wake_cache_polls() {
  // A namespace waiter can be followed immediately by other requests on the
  // same transport. Publish its break before those responses, rather than
  // leaving the holder unaware until the periodic renewal interval expires.
  for (auto *connection : s.clients)
    for (auto sid : connection->session_ids())
      for (auto &[fid, h] : connection->find_session(sid)->files)
        if (!h.cache_cookie.empty()) h.cache_poll_at = 0;
}
// This coroutine has no RPC or dispatch-gate waits. A stalled operation or
// socket write must not keep a cache-bearing transport alive beyond authority.
pace::task<void> cache_watchdog() {
  try {
    while (socket.is_open() && !ending) {
      co_await s.io->sleep_for(20ms);
      auto time = async_clock();
      for (auto sid : session_ids())
        for (const auto &[fid, h] : find_session(sid)->files)
          if (socket.is_open() && !h.cache_cookie.empty() && h.cache_fence_at <= time) {
            close();
            log("smb", "cache_watchdog_expired", h.cache_fence_is_break ? "break" : "authority");
          }
    }
  } catch (...) { close(); }
  watchdog_done = true;
}
pace::task<bytes> acknowledge_lease(bytes key, unsigned state) {
  auto source = session;
  auto guid = selected.client_info.substr(4, 16);
  std::shared_ptr<client> owner;
  uint64_t owner_session = 0;
  bytes owner_file;
  auto locate = [&](client *candidate) {
    if (owner || !candidate->socket.is_open() || candidate->ending ||
        candidate->selected.client_info.size() < 20 || candidate->selected.client_info.substr(4, 16) != guid) return;
    for (auto sid : candidate->session_ids()) {
      auto *context = candidate->find_session(sid);
      for (const auto &[fid, h] : context->files)
        if (h.lease && h.lease->key == key) {
          owner = candidate->shared_from_this(); owner_session = sid; owner_file = fid;
          return;
        }
    }
  };
  locate(this);
  for (auto *candidate : s.clients) locate(candidate);
  check(bool(owner), 0xc0000034);
  std::exception_ptr failure;
  bytes result;
  auto invoke = [&]() -> pace::task<void> {
    check(owner->select_session(owner_session), 0xc0000034);
    auto it = owner->files.find(owner_file);
    check(it != owner->files.end() && it->second.lease && it->second.lease->key == key, 0xc0000034);
    auto &h = it->second;
    json request = {{"cookie", h.cache_cookie}, {"state", state}};
    auto response = co_await owner->operation(h, "cache_ack", bool(h.access & 6), request);
    h.lease_state = response.at("state");
    owner->cache_deadline(h, response);
    check(response.at("status") == 0, response.at("status"));
    result = decode_bytes(response.at("response").get<std::string>());
  };
  if (owner.get() == this) {
    try { co_await invoke(); } catch (...) { failure = std::current_exception(); }
  } else {
    // Release our gate before waiting for a peer, including reciprocal ACKs.
    // The owner reauthorizes under its own session; the incoming authenticated
    // session/tree supplies routing, not a replacement file-access credential.
    dispatching = false;
    try {
      while (owner->dispatching && owner->socket.is_open()) co_await s.io->sleep_for(1ms);
      check(owner->socket.is_open() && !owner->ending, 0xc0000034);
      dispatch_guard guard(owner->dispatching);
      co_await invoke();
    } catch (...) { failure = std::current_exception(); }
    while (dispatching) co_await s.io->sleep_for(1ms);
    dispatching = true;
  }
  check(select_session(source), 0xc0000203);
  if (failure) std::rethrow_exception(failure);
  co_return result;
}
pace::task<bool> send_lease_notification(const bytes &packet, const bytes &guid) {
  // Lease keys belong to ClientGuid, not to the session/open which polled the
  // file worker. MS-SMB2 3.3.4.7 selects the first available connection, even
  // when that transport has no member of this lease. Keep admission order;
  // pointer order and poll scheduling must not decide the destination.
  std::vector<std::shared_ptr<client>> candidates;
  for (auto *candidate : s.clients)
    if (candidate->socket.is_open() && !candidate->ending && candidate->has_authenticated() &&
        candidate->selected.client_info.size() >= 20 &&
        candidate->selected.client_info.substr(4, 16) == guid)
      candidates.push_back(candidate->shared_from_this());
  std::sort(candidates.begin(), candidates.end(), [](const auto &a, const auto &b) {
    return a->connection_order < b->connection_order;
  });
  for (auto &target : candidates) {
    if (!socket.is_open()) co_return false;
    if (!target->socket.is_open() || target->ending || !target->has_authenticated()) continue;
    try {
      // No session selection/key access is needed for this plaintext packet.
      // The transport write gate serializes its frame without waiting for a
      // peer's command gate (which may itself be waiting for this recall).
      co_await target->send_packet(packet, false);
      co_return true;
    } catch (...) { target->close(); }
  }
  co_return false;
}
// The caller owns the connection gate, including all RPC and send suspensions.
pace::task<void> poll_caches_locked() {
  auto saved_session = session;
  for (auto sid : session_ids()) {
    if (!select_session(sid)) continue;
    std::vector<bytes> ids;
    for (const auto &[fid, h] : files)
      if (!h.cache_cookie.empty() && h.cache_poll_at <= async_clock()) ids.push_back(fid);
    for (const auto &fid : ids) {
      if (!socket.is_open()) co_return;
      try {
        auto it = files.find(fid);
        if (it == files.end() || it->second.cache_cookie.empty()) continue;
        json request = {{"cookie", it->second.cache_cookie}};
        auto state = co_await operation(it->second, "cache_poll",
                                        it->second.lease ? bool(it->second.access & 6) :
                                          it->second.cache_level == 8 ||
                                            (it->second.cache_level == 9 && (it->second.access & 6)),
                                        request);
        auto &h = files.at(fid);
        cache_deadline(h, state);
        if (h.lease) {
          h.lease_state = state.at("state");
          if (!h.cache_announced || !state.contains("notification")) continue;
          auto serial = state.at("notification").at("serial").get<uint64_t>();
          auto claim = h.lease->delivery_prefix() + h.grant.at("root").at("worker").get<std::string>() +
              ":" + h.cache_cookie;
          auto previous = s.lease_sends.find(claim);
          if (previous != s.lease_sends.end() && previous->second >= serial) continue;
          s.lease_sends[claim] = serial;
          struct delivery {
            std::map<std::string, uint64_t> &claims;
            std::string key;
            uint64_t serial;
            bool complete = false;
            ~delivery() {
              auto it = claims.find(key);
              if (!complete && it != claims.end() && it->second == serial) claims.erase(it);
            }
          } sending{s.lease_sends, claim, serial};
          auto response = sized(64, 64);
          response.replace(0, 4, "\xfeSMB", 4);
          put(response, 4, 64, 2); put(response, 12, 18, 2);
          put(response, 16, 1, 4); put(response, 24, UINT64_MAX, 8);
          // MS-SMB2 3.3.4.7: lease notifications have zero SessionId/TreeId,
          // independent of a member's session. Do not wrap one in that
          // session's transform: 3.2.5.1.1.1 requires the client to disconnect
          // when the inner and transform SessionIds differ. ACKs and ordinary
          // responses still use the authenticated session's signing/encryption.
          response += decode_bytes(state.at("notification").at("body").get<std::string>());
          if (!(co_await send_lease_notification(response, h.lease->client))) {
            close();
            co_return;
          }
          request["serial"] = serial;
          auto sent = co_await operation(h, "cache_sent", bool(h.access & 6), request);
          h.lease_state = sent.at("state");
          cache_deadline(h, sent);
          // Keep the last delivered serial: another transport may receive a
          // stale poll response after this send completed. The last lease
          // binding releases this bounded per-cookie record.
          sending.complete = true;
          continue;
        }
        if (!h.cache_announced || h.cache_break_sent || !state.at("breaking").get<bool>()) continue;
        h.cache_break_sent = true;
        h.cache_break_level = state.at("break_level");
        auto response = sized(64, 64);
        response.replace(0, 4, "\xfeSMB", 4);
        put(response, 4, 64, 2); put(response, 12, 18, 2);
        put(response, 16, 1, 4); put(response, 24, UINT64_MAX, 8);
        put(response, 40, session, 8); // TreeId and credits stay zero.
        auto body = sized(24, 24);
        body[2] = char(h.cache_break_level);
        body.replace(8, 16, fid); response += body;
        // MS-SMB2 3.3.4.6 recommends unsigned notifications. In particular,
        // never reuse the all-ones MessageId as an AES-GMAC signing nonce.
        // Encrypted opens retain authenticated encryption with fresh nonces.
        co_await send_packet(std::move(response), h.cache_encrypted);
        if (h.cache_level == 1) {
          // Level II -> NONE requires no client ACK. Keep native exclusion
          // until the notification has been sent, then release this reader's
          // participation. Other transports keep their own guard references.
          co_await operation(h, "cache_ack", false, request);
          clear_cache(files.at(fid), true);
        }
      } catch (const std::exception &e) {
        // Fence before logging: diagnostics must not delay loss of authority.
        close();
        log("smb", "cache_poll_failed", e.what());
        co_return;
      } catch (...) {
        close();
        log("smb", "cache_poll_failed", "unknown_exception");
        co_return;
      }
    }
  }
  select_session(saved_session);
}
