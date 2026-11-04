// File-domain cookies name native data-cache exclusion. They never appear on
// the network; the SMB FileId and owning session identify the wire oplock.
void clear_cache(opened &h, bool read_break_completed = false) {
  h.cache_cookie.clear(); h.cache_fence_at = h.cache_poll_at = 0;
  h.cache_level = h.cache_break_level = 0;
  h.cache_break_sent = false;
  h.cache_read_break_completed = read_break_completed;
}
void cache_deadline(opened &h, const json &snapshot) {
  auto remaining = h.grant.at("expires").get<int64_t>() - now();
  if (snapshot.at("breaking").get<bool>())
    remaining = std::min(remaining, snapshot.at("remaining_ms").get<int64_t>());
  if (remaining <= 200) { close(); throw status_error(0xc0000128); }
  h.cache_fence_at = async_clock() + remaining - 100;
  h.cache_poll_at = async_clock() + 250;
}
void announce_caches() {
  for (auto sid : session_ids())
    for (auto &[fid, h] : find_session(sid)->files)
      if (!h.cache_cookie.empty()) h.cache_announced = true;
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
          if (!h.cache_cookie.empty() && h.cache_fence_at <= time) close();
    }
  } catch (...) { close(); }
  watchdog_done = true;
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
        auto state = co_await operation(it->second, "cache_poll", it->second.cache_level == 8,
                                        request);
        auto &h = files.at(fid);
        cache_deadline(h, state);
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
      } catch (...) {
        // Expiry, policy revocation or worker recovery has fenced this open.
        // A transport still advertising cached authority cannot survive it.
        close();
        co_return;
      }
    }
  }
  select_session(saved_session);
}
