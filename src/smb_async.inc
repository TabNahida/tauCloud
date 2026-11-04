// A related compound cannot execute past an unfinished operation. Keep only
// authenticated request bytes, with bounded memory, and give each dependent
// operation its own transport AsyncId. No credit is granted twice.
static int64_t async_clock() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}
uint64_t defer_command(const bytes &request, uint32_t tid, bool encrypted,
                       uint64_t dependency, const bytes &file) {
  size_t count = 0, size = request.size();
  for (auto sid : session_ids())
    for (const auto &[id, item] : find_session(sid)->pending_commands) {
      ++count; size += item.request.size();
    }
  check(count < 128 && size <= 1024 * 1024 && next_async_id != UINT64_MAX, 0xc000009a);
  auto id = next_async_id++;
  pending_command item{request, tid, encrypted, 0, {}, 0, false, {}, {}, 0};
  item.dependency = dependency;
  item.file = file;
  pending_commands.emplace(id, std::move(item));
  return id;
}
void complete_dependents(uint64_t id, uint32_t code, const bytes &file, uint32_t tid = 0) {
  for (auto &[other, item] : pending_commands) {
    if (item.dependency != id) continue;
    item.dependency = 0;
    item.failure = code;
    item.file = file;
    if (tid) item.tree_id = tid;
  }
}
pace::task<void> finish_command(uint64_t id, uint32_t code, bytes body = {}) {
  auto found = pending_commands.find(id);
  if (found == pending_commands.end()) co_return;
  if (!found->second.announced && socket.is_open()) {
    found->second.completion = code;
    found->second.body = std::move(body);
    co_return;
  }
  auto item = std::move(found->second);
  pending_commands.erase(found);
  complete_dependents(id, code, item.file, item.tree_id);
  if (!socket.is_open()) co_return;
  auto response = sized(64, 64);
  response.replace(0, 4, "\xfeSMB", 4);
  put(response, 4, 64, 2); put(response, 6, 1, 2); put(response, 8, code, 4);
  auto cmd = get(item.request, 12, 2);
  put(response, 12, cmd, 2); put(response, 16, 3 | (item.encrypted ? 0 : 8), 4);
  put(response, 24, get(item.request, 24, 8), 8); put(response, 32, id, 8);
  put(response, 40, session, 8);
  bool security_buffer_error = cmd == 16 && code == 0xc0000023 && !body.empty();
  if (code && code != 0x80000005 && !security_buffer_error &&
      !(cmd == 15 && (code == 0x10b || code == 0x10c)))
    body = sized(9, 9);
  response += body;
  if (!item.encrypted) response.replace(48, 16, signature(key, response, selected.signing));
  co_await send_packet(std::move(response), item.encrypted);
  announce_caches();
}
// A resumed command may itself wait for a range lock or directory event. Move
// its waiter under the already announced ID; never send a second interim.
void adopt_waiter(uint64_t id) {
  auto temporary = next_async_id - 1;
  if (auto node = pending_locks.extract(temporary); !node.empty()) {
    node.key() = id; node.mapped().announced = true;
    pending_locks.insert(std::move(node));
  } else if (auto node = pending_notifications.extract(temporary); !node.empty()) {
    node.key() = id; node.mapped().announced = true;
    pending_notifications.insert(std::move(node));
  } else throw status_error(0xc000000d);
  pending_commands.erase(id);
}
pace::task<void> pump_commands(uint64_t sid) {
  auto *context = find_session(sid);
  if (!context) co_return;
  std::vector<uint64_t> ids;
  for (const auto &[id, item] : context->pending_commands) ids.push_back(id);
  for (auto id : ids) {
    while (dispatching && socket.is_open()) co_await s.io->sleep_for(1ms);
    if (!socket.is_open()) break;
    dispatch_guard guard(dispatching);
    if (!select_session(sid)) continue;
    auto found = pending_commands.find(id);
    if (found == pending_commands.end() || !found->second.announced || found->second.dependency)
      continue;
    // Authorization may revoke the whole session and erase this entry.
    auto item = found->second;
    uint32_t code = item.failure;
    bytes body;
    related_file = item.file;
    executing_command = id;
    try {
      if (code) throw status_error(code);
      if (item.deadline && async_clock() >= item.deadline) throw status_error(0xc00000b5);
      body = co_await command(item.request, item.tree_id, code, item.encrypted);
    } catch (const status_error &e) { code = e.status; }
      catch (const error &e) {
        auto cmd = get(item.request, 12, 2);
        if ((cmd == 5 || cmd == 9 || cmd == 10 || cmd == 14 || cmd == 17) && std::string_view(e.what()) == "cache_break_pending") {
          auto current = pending_commands.find(id);
          // A sharing/namespace operation can wait for the independent RH
          // HANDLE ACK timer. Bound that wait beyond the protocol deadline;
          // retries never restart it, and native dirty-cache fencing stays 5s.
          if (current != pending_commands.end() && !current->second.deadline)
            current->second.deadline = async_clock() + lease_handle_ack_ms + 5000;
          executing_command = 0;
          continue;
        }
        code = status(e.what());
      } catch (const json::exception &) { code = 0xc000000d; }
    executing_command = 0;
    if (!pending_commands.contains(id)) continue;
    pending_commands.at(id).file = related_file;
    pending_commands.at(id).tree_id = item.tree_id;
    if (code == 0x103) adopt_waiter(id);
    else {
      co_await finish_command(id, code, std::move(body));
      auto cmd = get(item.request, 12, 2);
      if (cmd == 2 || cmd == 4 || cmd == 5 || cmd == 6 || cmd == 9 || cmd == 17) {
        co_await complete_frame_notifications();
        co_await complete_peer_notifications();
      }
    }
  }
}
// All connection state and writes stay on the reactor. The dispatcher and
// waiter pump share a cooperative gate, including their RPC suspension points.
struct dispatch_guard {
  bool &busy;
  explicit dispatch_guard(bool &value) : busy(value) { busy = true; }
  ~dispatch_guard() { busy = false; }
};
pace::task<void> send_packet(bytes output, bool encrypted) {
  trace_packet(output, true, encrypted);
  if (encrypted) {
    check(nonce_counter < 65536);
    bytes nonce = nonce_prefix.substr(0, selected.cipher == 1 || selected.cipher == 3 ? 3 : 4) + bytes(8, '\0');
    put(nonce, nonce.size() - 8, ++nonce_counter, 8);
    output = encrypt(encryption_key, selected.cipher, session, nonce, output);
  }
  bytes header(4, '\0');
  header[1] = char(output.size() >> 16);
  header[2] = char(output.size() >> 8);
  header[3] = char(output.size());
  auto timer = s.io->call_after(5s, [this] { close(); });
  co_await socket.write_all(header + output);
  last_activity = now();
}
pace::task<void> finish_lock(uint64_t async_id, uint32_t code) {
  auto found = pending_locks.find(async_id);
  if (found == pending_locks.end())
    co_return;
  auto pending = found->second;
  if (!socket.is_open()) {
    pending_locks.erase(found);
    co_return; // Connection cleanup closes the authority handle and all its waiters.
  }
  if (code) {
    auto h = files.find(pending.fid);
    if (h != files.end()) {
      json body = {
          {"grant", h->second.grant}, {"handle", h->second.handle}, {"waiter", pending.waiter}};
      try {
        co_await smb_rpc(s, h->second.grant.at("root").at("worker"), "smb_lock_cancel", body);
      } catch (const error &e) {
        // A revoked/closed handle has already lost every lock and waiter.
        if (std::string_view(e.what()) != "stale_handle" &&
            std::string_view(e.what()) != "policy_revoked") {
          close();
          throw;
        }
      }
    }
  }
  if (!pending.announced) {
    found->second.completion = code;
    co_return;
  }
  complete_dependents(async_id, code, pending.fid);
  pending_locks.erase(found);
  if (!socket.is_open())
    co_return;
  auto response = sized(64, 64);
  response.replace(0, 4, "\xfeSMB", 4);
  put(response, 4, 64, 2);
  put(response, 6, 1, 2);
  put(response, 8, code, 4);
  put(response, 12, 10, 2);
  // Credits were granted in STATUS_PENDING, never a second time here.
  put(response, 16, 3 | (pending.encrypted ? 0 : 8), 4);
  put(response, 24, pending.message_id, 8);
  put(response, 32, async_id, 8);
  put(response, 40, session, 8);
  response += code ? sized(9, 9) : sized(4, 4);
  if (!pending.encrypted)
    response.replace(48, 16, signature(key, response, selected.signing));
  co_await send_packet(std::move(response), pending.encrypted);
}
bytes notify_data(const json &result, uint32_t limit, uint32_t &code) {
  bytes data;
  if (result.at("overflow").get<bool>()) { code = 0x10c; return data; }
  for (const auto &entry : result.at("events")) {
    auto name = entry.at("name").get<std::string>();
    std::replace(name.begin(), name.end(), '/', '\\');
    auto wire = utf16(name);
    auto length = 12 + wire.size();
    auto offset = data.size();
    auto aligned = (length + 3) / 4 * 4;
    if (offset + length > limit) { code = 0x10c; data.clear(); break; }
    auto item = sized(aligned, 0);
    put(item, 0, aligned, 4); put(item, 4, entry.at("action").get<uint32_t>(), 4);
    put(item, 8, wire.size(), 4); item.replace(12, wire.size(), wire);
    data += item;
  }
  // Last record has no padding requirement and no following offset.
  if (!data.empty()) {
    size_t offset = 0;
    while (offset + get(data, offset, 4) < data.size()) offset += get(data, offset, 4);
    data.resize(offset + 12 + get(data, offset + 8, 4));
    put(data, offset, 0, 4);
  }
  return data;
}
bytes notify_body(const bytes &data) {
  auto body = sized(8, 9);
  put(body, 2, data.empty() ? 0 : 72, 2); put(body, 4, data.size(), 4);
  return body + data;
}
pace::task<void> finish_notify(uint64_t async_id, uint32_t code, bytes data = {}) {
  auto found = pending_notifications.find(async_id);
  if (found == pending_notifications.end()) co_return;
  if (!socket.is_open()) { pending_notifications.erase(found); co_return; }
  if (!found->second.announced) {
    found->second.completion = code; found->second.data = std::move(data);
    co_return;
  }
  auto pending = std::move(found->second);
  complete_dependents(async_id, code, pending.fid);
  pending_notifications.erase(found);
  auto response = sized(64, 64);
  response.replace(0, 4, "\xfeSMB", 4);
  put(response, 4, 64, 2); put(response, 6, 1, 2); put(response, 8, code, 4);
  put(response, 12, 15, 2); put(response, 16, 3 | (pending.encrypted ? 0 : 8), 4);
  put(response, 24, pending.message_id, 8); put(response, 32, async_id, 8);
  put(response, 40, session, 8);
  if (!code || code == 0x10b || code == 0x10c) {
    response += notify_body(data);
  } else response += sized(9, 9);
  if (!pending.encrypted)
    response.replace(48, 16, signature(key, response, selected.signing));
  co_await send_packet(std::move(response), pending.encrypted);
}
// Caller holds the cooperative dispatch gate across all RPC suspension points.
pace::task<void> poll_notification(uint64_t id) {
  auto found = pending_notifications.find(id);
  if (found == pending_notifications.end()) co_return;
  // Only the oldest request on a handle can consume its buffered events.
  bool first = true;
  for (const auto &[other, pending] : pending_notifications)
    if (pending.order < found->second.order && pending.fid == found->second.fid) first = false;
  if (!first) co_return;
  uint32_t code = 0;
  bool waiting = false;
  bytes data;
  auto limit = found->second.limit;
  auto fid = found->second.fid;
  try {
    auto file = files.find(fid);
    check(file != files.end(), 0xc0000128);
    limit = std::min(limit, file->second.notify_capacity.value_or(limit));
    auto result = co_await operation(file->second, "notify", false);
    waiting = result.at("pending");
    if (!waiting) data = notify_data(result, limit, code);
  } catch (const status_error &e) { waiting = false; code = e.status; }
    catch (const error &e) { waiting = false; code = status(e.what()); }
  if (!waiting) co_await finish_notify(id, code, std::move(data));
}
pace::task<void> pump_notifications(uint64_t sid) {
  auto *context = find_session(sid);
  if (!context) co_return;
  std::vector<uint64_t> ids;
  for (const auto &[id, pending] : context->pending_notifications) ids.push_back(id);
  for (auto id : ids) {
    while (dispatching && socket.is_open()) co_await s.io->sleep_for(1ms);
    if (!socket.is_open()) break;
    dispatch_guard guard(dispatching);
    if (!select_session(sid)) continue;
    co_await poll_notification(id);
  }
}
pace::task<void> pump_locks() {
  try {
    while (socket.is_open() && !ending) {
      co_await s.io->sleep_for(20ms);
      // A pending operation may outlive the read timer. Restart normal idle
      // expiry after its final reply instead of leaving an immortal connection.
      if (dispatching) continue;
      prune_sessions();
      if (has_authenticated() && !has_pending() && now() - last_activity >= 60000) {
        close();
        break;
      }
      {
        dispatch_guard guard(dispatching);
        co_await poll_caches_locked();
      }
      if (!has_pending())
        continue;
      std::vector<std::pair<uint64_t, uint64_t>> ids;
      for (auto sid : session_ids())
        for (const auto &[id, pending] : find_session(sid)->pending_locks)
          ids.emplace_back(sid, id);
      for (auto [sid, id] : ids) {
        while (dispatching && socket.is_open())
          co_await s.io->sleep_for(1ms);
        if (!socket.is_open())
          break;
        dispatch_guard guard(dispatching);
        if (!select_session(sid)) continue;
        auto it = pending_locks.find(id);
        if (it == pending_locks.end())
          continue;
        auto &pending = it->second;
        auto file = files.find(pending.fid);
        uint32_t code = 0;
        bool waiting = false;
        try {
          check(file != files.end(), 0xc0000128);
          json body = {{"locks", pending.locks}, {"waiter", pending.waiter}};
          auto result = co_await operation(file->second, "lock", false, body);
          waiting = result.value("pending", false);
        } catch (const status_error &e) {
          code = e.status;
        } catch (const error &e) {
          code = status(e.what());
        }
        if (!waiting)
          co_await finish_lock(id, code);
      }
      for (auto sid : session_ids()) co_await pump_notifications(sid);
      for (auto sid : session_ids()) co_await pump_commands(sid);
    }
  } catch (...) {
    close();
  }
  pump_done = true;
}
