#include "nfs_native_reservations.inc"
using native_request_holds = std::map<std::string, std::shared_ptr<native_request_hold>>;
struct pending_reply {
  std::string connection;
  uint64_t client = 0;
  std::optional<int64_t> completed;
  native_request_holds native;
  bool native_failed = false;
  bool renewal_authorized = false;
  std::vector<native_ticket> completions;
  bool native_settled = false;
};
mutable std::mutex reply_mutex;
std::map<uint64_t, pending_reply> replies;
uint64_t next_reply = 0, current_reply = 0;
uint64_t current_arrival = 0;
std::map<std::string, std::shared_ptr<reservation_route>> reservation_routes;
struct received_request {
  std::string connection;
  int64_t received;
  bool claimed = false;
  native_request_holds native;
  uint64_t authenticated_client = 0;
  std::optional<uint32_t> response_xid;
};
std::map<uint64_t, received_request> arrivals;
uint64_t next_arrival = 0;
void poll_native_locked() {
  for (auto &[key, route] : reservation_routes) {
    route->pump();
    if (route->failed && route->published && !route->revoked && !route->retiring) native_fault = true;
  }
  for (auto &[id, reply] : replies) {
    if (!reply.completed || reply.native_settled || id == current_reply) continue;
    bool done = true;
    for (auto &ticket : reply.completions) {
      ticket.route->pump();
      done &= ticket.job->done;
      reply.native_failed |= ticket.route->failed || !ticket.job->failure.empty();
    }
    if (!done) continue;
    reply.native_settled = true; reply.completions.clear();
    if (!reply.native_failed)
      for (auto &[key, route] : reservation_routes)
        if (route->client == reply.client && !route->failed && !route->revoked)
          route->expires = std::max(route->expires, *reply.completed + int64_t(cfg.nfs_lease_seconds) * 1000);
  }
}
bool poll_native() {
  std::lock_guard lock(reply_mutex); poll_native_locked(); return !native_fault;
}
bool wait_native(const std::vector<native_ticket> &tickets) {
  for (;;) {
    bool done = true, success = true;
    {
      std::lock_guard lock(reply_mutex);
      for (const auto &ticket : tickets) {
        ticket.route->pump();
        done &= ticket.job->done;
        success &= !ticket.route->failed && ticket.job->failure.empty();
      }
      if (done) return success;
    }
    std::this_thread::sleep_for(1ms);
  }
}
void drain_native() {
  for (;;) {
    bool done = true;
    {
      std::lock_guard lock(reply_mutex); poll_native_locked();
      for (const auto &[key, route] : reservation_routes)
        done &= route->queued.empty() && !route->active;
    }
    if (done) return;
    std::this_thread::sleep_for(1ms);
  }
}
uint64_t request_boundary() {
  std::lock_guard lock(reply_mutex);
  require(next_arrival != UINT64_MAX, "overloaded");
  return next_arrival + 1;
}
uint64_t begin_request(std::string bound, std::string_view packet = {}) {
  std::lock_guard lock(reply_mutex);
  require(!native_fault, "delegation_owner_lost");
  require(arrivals.size() < 32 && next_arrival != UINT64_MAX, "overloaded");
  auto id = ++next_arrival;
  received_request request{std::move(bound), now()};
  if (packet.size() >= 8) {
    reader header(packet); auto xid = header.u32();
    if (header.u32() == 1) request.response_xid = xid;
  }
  // Unauthenticated/encrypted records cannot yet be associated with a client.
  // Cover each currently eligible delegation, then cancel unrelated holds once
  // SEQUENCE identifies the client. Late records cannot revive an old lease.
  for (auto &[key, route] : reservation_routes)
    if (!route->revoked && request.received < route->expires)
      request.native.emplace(key, std::make_shared<native_request_hold>(route));
  arrivals.emplace(id, std::move(request));
  return id;
}
bool request_ready(uint64_t id) {
  std::lock_guard lock(reply_mutex); poll_native_locked();
  require(!native_fault, "delegation_owner_lost");
  auto found = arrivals.find(id);
  require(found != arrivals.end(), "cancelled");
  bool ready = true;
  for (const auto &[key, hold] : found->second.native) {
    const auto &ticket = hold->initial;
    require(!ticket.route->failed, "delegation_owner_lost");
    if (!ticket.job->failure.empty()) throw error(ticket.job->failure);
    ready &= ticket.job->done;
  }
  return ready;
}
void await_request(uint64_t id) {
  while (!request_ready(id)) std::this_thread::sleep_for(1ms);
}
uint64_t admit_request(std::string bound, std::string_view packet = {}) {
  auto id = begin_request(std::move(bound), packet);
  try { await_request(id); }
  catch (...) { cancel_request(id); throw; }
  return id;
}
bool timely_callback_receipt(uint32_t xid, const std::string &bound, uint64_t first,
                             int64_t deadline, bool current_only = false) const {
  std::lock_guard lock(reply_mutex);
  return std::any_of(arrivals.begin(), arrivals.end(), [&](const auto &entry) {
    const auto &[id, request] = entry;
    return id >= first && request.connection == bound && request.received < deadline &&
        (current_only ? id == current_arrival : request.response_xid == xid);
  });
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
uint64_t reserve_reply(uint64_t admission) {
  std::lock_guard lock(reply_mutex);
  require(replies.size() < 512 && next_reply != UINT64_MAX, "overloaded");
  auto id = ++next_reply;
  replies.emplace(id, pending_reply{connection});
  current_reply = id; current_arrival = admission;
  return id;
}
void bind_reply(uint64_t client) {
  if (!current_reply) return;
  std::lock_guard lock(reply_mutex);
  auto &reply = replies.at(current_reply);
  check(!reply.client || reply.client == client, 10008);
  auto arrival = arrivals.find(current_arrival);
  for (const auto &[key, route] : reservation_routes) {
    if (route->client != client || route->revoked) continue;
    check(!route->failed, 10008);
    if (reply.native.contains(key)) continue;
    check(arrival != arrivals.end(), 10008);
    auto node = arrival->second.native.extract(key);
    check(!node.empty(), 10008);
    reply.native.insert(std::move(node));
  }
  reply.client = client;
  if (arrival != arrivals.end()) {
    arrival->second.authenticated_client = client;
    arrival->second.native.clear();
  }
}
void publish_reservation_route(const std::string &key, uint64_t client, const json &capability) {
  auto route = std::make_shared<reservation_route>(client, client_ids.at(client).expires, capability);
  std::vector<native_ticket> tickets;
  {
    std::lock_guard lock(reply_mutex);
    require(!reservation_routes.contains(key), "invalid_request");
    require(current_reply && replies.at(current_reply).client == client &&
        !replies.at(current_reply).completed, "cancelled");
    reservation_routes.emplace(key, route);
    try {
      for (auto &[id, arrival] : arrivals)
        if (!arrival.claimed && id >= client_ids.at(client).first_arrival && arrival.received < route->expires) {
          auto hold = std::make_shared<native_request_hold>(route);
          tickets.push_back(hold->initial); arrival.native.emplace(key, std::move(hold));
        }
      for (auto &[id, reply] : replies)
        if (reply.client == client && !reply.completed) {
          auto hold = std::make_shared<native_request_hold>(route);
          tickets.push_back(hold->initial); reply.native.emplace(key, std::move(hold));
        }
    } catch (...) {
      reservation_routes.erase(key);
      for (auto &[id, arrival] : arrivals) arrival.native.erase(key);
      for (auto &[id, reply] : replies) reply.native.erase(key);
      throw;
    }
  }
  // Publishing before waiting also covers records received during the handshake.
  // Failed ACKs decline handout; callers remove the route and return its guard.
  require(wait_native(tickets), "delegation_owner_lost");
  std::lock_guard lock(reply_mutex);
  require(!route->revoked && !route->failed, "stale_handle");
  route->published = true;
}
void unpublish_reservation_route(const std::string &key) {
  std::lock_guard lock(reply_mutex);
  reservation_routes.erase(key);
  for (auto &[id, arrival] : arrivals) arrival.native.erase(key);
  for (auto &[id, reply] : replies) reply.native.erase(key);
}
void retiring_reservation_route(const std::string &key, bool retiring) {
  std::lock_guard lock(reply_mutex);
  auto found = reservation_routes.find(key);
  if (found != reservation_routes.end()) found->second->retiring = retiring;
}
void reservation_client_expiry(uint64_t client, int64_t expires) {
  std::lock_guard lock(reply_mutex);
  for (auto &[key, route] : reservation_routes)
    if (route->client == client && !route->failed && !route->revoked)
      route->expires = std::max(route->expires, expires);
}
void observe_native_revocations() {
  std::map<std::string, uint32_t> revoked;
  {
    std::lock_guard lock(reply_mutex);
    for (const auto &[key, route] : reservation_routes)
      if (route->revoked) revoked[key] = route->revoked;
  }
  for (const auto &[cookie, status] : revoked) {
    for (auto &[id, delegation] : delegations) if (delegation.cookie == cookie) {
      delegation.revoked = status;
      remove_recovery(delegation.recovery);
    }
    unpublish_reservation_route(cookie);
  }
}
void acknowledge_native_renewal() {
  std::vector<native_ticket> tickets;
  uint64_t id;
  {
    std::lock_guard lock(reply_mutex);
    id = current_reply; if (!id) return;
    auto &reply = replies.at(id);
    if (reply.renewal_authorized) return;
    for (auto &[key, hold] : reply.native) tickets.push_back(hold->refresh());
  }
  auto success = wait_native(tickets);
  {
    std::lock_guard lock(reply_mutex);
    auto &reply = replies.at(id);
    reply.native_failed |= !success;
    check(!reply.native_failed, 10008);
    reply.renewal_authorized = true;
  }
  observe_native_revocations();
}
void finish_native_reply(pending_reply &reply, int64_t) {
  for (auto &[key, hold] : reply.native) {
    auto ticket = hold->finish(true);
    if (ticket.job) reply.completions.push_back(std::move(ticket));
    else reply.native_failed = true;
  }
  reply.native.clear();
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
    return (!a.second.authenticated_client || a.second.authenticated_client == id) &&
        a.first >= client->second.first_arrival && a.second.received < client->second.expires;
  });
}
void complete_reply(uint64_t id) {
  if (!id) return;
  std::lock_guard lock(reply_mutex);
  auto found = replies.find(id);
  // Tokens identify transmissions, not XIDs or session slots. A duplicate
  // completion cannot extend a lease, or complete a later replay's pin.
  if (found != replies.end() && !found->second.completed) {
    auto time = now();
    finish_native_reply(found->second, time);
    found->second.completed = time;
  }
}
void complete_connection_replies(const std::string &bound) {
  std::lock_guard lock(reply_mutex);
  auto time = now();
  for (auto &[id, r] : replies)
    if (r.connection == bound && !r.completed) {
      // An executing dispatch may still bind its authenticated client. Its
      // reservations must survive until dispatch has actually finished.
      if (id != current_reply) finish_native_reply(r, time);
      r.completed = time;
    }
  std::erase_if(arrivals, [&](const auto &a) { return a.second.connection == bound; });
}
std::set<std::string> disconnected_transports;
bool disconnect_all_transports = false;
void transport_disconnected(const std::string &bound) {
  complete_connection_replies(bound);
  std::lock_guard lock(reply_mutex);
  if (disconnected_transports.size() == 512) {
    disconnected_transports.clear(); disconnect_all_transports = true;
  }
  if (!disconnect_all_transports) disconnected_transports.insert(bound);
}
void finish_disconnections() {
  std::set<std::string> disconnected; bool all;
  {
    std::lock_guard lock(reply_mutex);
    disconnected.swap(disconnected_transports);
    all = std::exchange(disconnect_all_transports, false);
  }
  if (all) {
    for (const auto &[id, session] : sessions)
      for (const auto &bound : session.connections) disconnected.insert(bound);
    for (const auto &[id, session] : sessions)
      for (const auto &bound : session.back_connections) disconnected.insert(bound);
    if (close_backchannel) for (const auto &bound : disconnected) close_backchannel(bound);
  }
  for (auto &[id, session] : sessions) for (const auto &bound : disconnected) {
    session.connections.erase(bound); session.back_connections.erase(bound);
    session.callback_up.erase(bound); session.callback_ready.erase(bound);
  }
  std::erase_if(callback_probes, [&](const auto &p) { return all || disconnected.contains(p.second.connection); });
  for (const auto &bound : disconnected) callback_closing.erase(bound);
  if (all) callback_closing.clear();
}
void finish_replies() {
  finish_disconnections();
  std::vector<native_ticket> tickets;
  {
    std::lock_guard lock(reply_mutex);
    for (auto &[id, r] : replies) {
      if (id == current_reply) continue;
      if (r.completed) tickets.insert(tickets.end(), r.completions.begin(), r.completions.end());
      else for (auto &[key, hold] : r.native) {
        try { tickets.push_back(hold->refresh()); }
        catch (...) { r.native_failed = true; }
      }
    }
  }
  wait_native(tickets);
  std::map<uint64_t, int64_t> renewals;
  auto time = now();
  {
    std::lock_guard lock(reply_mutex); poll_native_locked();
    for (auto it = replies.begin(); it != replies.end();) {
      if (it->first == current_reply) { ++it; continue; }
      auto &r = it->second;
      for (const auto &[key, hold] : r.native) r.native_failed |= hold->route->failed;
      if (r.client && r.renewal_authorized && !r.native_failed && (!r.completed || r.native_settled))
        renewals[r.client] = std::max(renewals[r.client], r.completed.value_or(time));
      if (r.completed && r.native_settled) it = replies.erase(it); else ++it;
    }
  }
  for (const auto &[id, accepted] : renewals) {
    auto found = client_ids.find(id);
    if (found == client_ids.end()) continue;
    found->second.expires = std::max(found->second.expires, accepted + int64_t(cfg.nfs_lease_seconds) * 1000);
    reservation_client_expiry(id, found->second.expires);
    if (client_live(id)) renew_delegations(id);
  }
}
