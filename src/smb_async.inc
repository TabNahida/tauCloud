// All connection state and writes stay on the reactor. The dispatcher and
// waiter pump share a cooperative gate, including their RPC suspension points.
struct dispatch_guard {
  bool &busy;
  explicit dispatch_guard(bool &value) : busy(value) { busy = true; }
  ~dispatch_guard() { busy = false; }
};
pace::task<void> send_packet(bytes output, bool encrypted) {
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
pace::task<void> pump_notifications() {
  std::vector<uint64_t> ids;
  for (const auto &[id, pending] : pending_notifications) ids.push_back(id);
  for (auto id : ids) {
    while (dispatching && socket.is_open()) co_await s.io->sleep_for(1ms);
    if (!socket.is_open()) break;
    dispatch_guard guard(dispatching);
    auto found = pending_notifications.find(id);
    if (found == pending_notifications.end()) continue;
    // Only the oldest request on a handle can consume its buffered events.
    bool first = true;
    for (const auto &[other, pending] : pending_notifications)
      if (other < id && pending.fid == found->second.fid) first = false;
    if (!first) continue;
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
}
pace::task<void> pump_locks() {
  try {
    while (socket.is_open() && !ending) {
      co_await s.io->sleep_for(20ms);
      // A pending operation may outlive the read timer. Restart normal idle
      // expiry after its final reply instead of leaving an immortal connection.
      if (!dispatching && authenticated && pending_locks.empty() && pending_notifications.empty() &&
          now() - last_activity >= 60000) {
        close();
        break;
      }
      if (dispatching || (pending_locks.empty() && pending_notifications.empty()))
        continue;
      std::vector<uint64_t> ids;
      for (const auto &[id, pending] : pending_locks)
        ids.push_back(id);
      for (auto id : ids) {
        while (dispatching && socket.is_open())
          co_await s.io->sleep_for(1ms);
        if (!socket.is_open())
          break;
        dispatch_guard guard(dispatching);
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
      co_await pump_notifications();
    }
  } catch (...) {
    close();
  }
  pump_done = true;
}
