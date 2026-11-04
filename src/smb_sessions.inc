// Session IDs are global; credits, AsyncIds and the socket remain per transport.
bool session_in_use(uint64_t candidate) const {
  for (auto *connection : s.clients) {
    if (connection != this && connection->session == candidate) return true;
    if (connection->sessions.contains(candidate)) return true;
  }
  return false;
}
pace::task<void> retire_active_session() {
  co_await cleanup();
  if (!token.empty()) {
    try { co_await smb_rpc(s, "identity", "logout", auth()); } catch (...) {}
  }
  reset_context();
}
pace::task<void> replace_previous_session() {
  if (!previous_session || previous_session == session) co_return;
  auto old_id = previous_session, new_id = session;
  auto identity = username;
  // Retain transports across suspension; another read coroutine may finish
  // while we wait for its dispatch gate. Never close an unrelated session.
  std::vector<std::shared_ptr<client>> connections;
  for (auto *connection : s.clients) connections.push_back(connection->shared_from_this());
  for (auto &connection : connections) {
    if (!connection->find_session(old_id)) continue;
    if (connection.get() == this) {
      auto *old = find_session(old_id);
      if (!old || !old->authenticated || old->username != identity) continue;
      select_session(old_id);
      co_await retire_active_session();
      check(select_session(new_id));
    } else {
      // Two transports may replace each other's sessions simultaneously.
      // Hand off our gate while waiting instead of holding both gates in a
      // cycle. The completing authentication is pinned against idle pruning.
      std::exception_ptr failure;
      dispatching = false;
      try {
        while (connection->dispatching) co_await s.io->sleep_for(1ms);
        dispatch_guard guard(connection->dispatching);
        auto *old = connection->find_session(old_id);
        if (old && old->authenticated && old->username == identity) {
          connection->select_session(old_id);
          co_await connection->retire_active_session();
        }
      } catch (...) { failure = std::current_exception(); }
      while (dispatching) co_await s.io->sleep_for(1ms);
      dispatching = true;
      check(select_session(new_id));
      if (failure) std::rethrow_exception(failure);
    }
  }
}
// Interim replies for any sessions in a compound have now been transmitted.
// Send each completion under that session's own keys, preserving transport IDs.
pace::task<void> complete_frame_notifications() {
  for (auto sid : session_ids()) {
    if (!select_session(sid)) continue;
    std::vector<std::pair<uint64_t, uint32_t>> completed;
    for (auto &[id, pending] : pending_locks) {
      pending.announced = true;
      if (pending.completion) completed.emplace_back(id, *pending.completion);
    }
    for (auto [id, code] : completed) co_await finish_lock(id, code);
    completed.clear();
    for (auto &[id, pending] : pending_notifications) {
      pending.announced = true;
      if (pending.completion) completed.emplace_back(id, *pending.completion);
    }
    for (auto [id, code] : completed)
      co_await finish_notify(id, code, pending_notifications.at(id).data);
    std::vector<uint64_t> ready;
    for (const auto &[id, pending] : pending_notifications) ready.push_back(id);
    for (auto id : ready) {
      if (!socket.is_open()) break;
      co_await poll_notification(id);
    }
  }
  prune_sessions();
}
