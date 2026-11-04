// The I/O thread only records completion under this small lock. It never waits
// for a file-domain RPC or the main protocol mutex after writing a frame.
struct pending_reply {
  std::string connection;
  uint64_t client = 0;
  std::optional<int64_t> completed;
};
mutable std::mutex reply_mutex;
std::map<uint64_t, pending_reply> replies;
uint64_t next_reply = 0, current_reply = 0;
struct received_request {
  std::string connection;
  int64_t received;
  bool claimed = false;
};
std::map<uint64_t, received_request> arrivals;
uint64_t next_arrival = 0;
uint64_t request_boundary() {
  std::lock_guard lock(reply_mutex);
  require(next_arrival != UINT64_MAX, "overloaded");
  return next_arrival + 1;
}
uint64_t admit_request(std::string bound) {
  std::lock_guard lock(reply_mutex);
  require(arrivals.size() < 32 && next_arrival != UINT64_MAX, "overloaded");
  auto id = ++next_arrival;
  arrivals.emplace(id, received_request{std::move(bound), now()});
  return id;
}
void cancel_request(uint64_t id) {
  if (!id) return;
  std::lock_guard lock(reply_mutex);
  arrivals.erase(id);
}
void claim_request(uint64_t id, const std::string &bound) {
  std::lock_guard lock(reply_mutex);
  auto found = arrivals.find(id);
  require(found != arrivals.end() && !found->second.claimed && found->second.connection == bound,
          "cancelled");
  found->second.claimed = true;
}
uint64_t reserve_reply() {
  std::lock_guard lock(reply_mutex);
  require(replies.size() < 512 && next_reply != UINT64_MAX, "overloaded");
  auto id = ++next_reply;
  replies.emplace(id, pending_reply{connection});
  return id;
}
void bind_reply(uint64_t client) {
  if (!current_reply) return;
  std::lock_guard lock(reply_mutex);
  replies.at(current_reply).client = client;
}
bool client_live(uint64_t id) const {
  auto client = client_ids.find(id);
  if (client == client_ids.end()) return false;
  if (client->second.expires > now()) return true;
  std::lock_guard lock(reply_mutex);
  if (std::any_of(replies.begin(), replies.end(), [&](const auto &r) { return r.second.client == id; })) return true;
  // An encrypted RPC cannot be associated with a client until authentication.
  // Defer cleanup only for records received before this client's fixed expiry;
  // later unauthenticated traffic cannot extend that eligibility window.
  return std::any_of(arrivals.begin(), arrivals.end(), [&](const auto &a) {
    return a.first >= client->second.first_arrival && a.second.received < client->second.expires;
  });
}
void complete_reply(uint64_t id) {
  if (!id) return;
  std::lock_guard lock(reply_mutex);
  auto found = replies.find(id);
  // Tokens identify transmissions, not XIDs or session slots. A duplicate
  // completion cannot extend a lease, or complete a later replay's pin.
  if (found != replies.end() && !found->second.completed) found->second.completed = now();
}
void complete_connection_replies(const std::string &bound) {
  std::lock_guard lock(reply_mutex);
  auto time = now();
  for (auto &[id, r] : replies)
    if (r.connection == bound && !r.completed) r.completed = time;
  std::erase_if(arrivals, [&](const auto &a) { return a.second.connection == bound; });
}
void finish_replies() {
  std::map<uint64_t, int64_t> renewals;
  auto time = now();
  {
    std::lock_guard lock(reply_mutex);
    for (auto it = replies.begin(); it != replies.end();) {
      // Disconnect can race a dispatch before its validated SEQUENCE binds
      // the pin. Keep that reservation until this dispatch has finished.
      if (it->first == current_reply) { ++it; continue; }
      const auto &r = it->second;
      if (r.client) renewals[r.client] = std::max(renewals[r.client], r.completed.value_or(time));
      if (r.completed) it = replies.erase(it); else ++it;
    }
  }
  for (const auto &[id, accepted] : renewals) {
    auto found = client_ids.find(id);
    if (found == client_ids.end()) continue; // Never resurrect a retired client.
    found->second.expires = std::max(found->second.expires, accepted + int64_t(cfg.nfs_lease_seconds) * 1000);
    if (client_live(id)) renew_delegations(id);
  }
}
