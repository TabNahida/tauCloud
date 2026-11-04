// Backchannel requests use only bound TCP transports, never client addresses.
struct callback_probe {
  std::string session, connection;
  int64_t deadline;
  bool compound = false;
  uint32_t sequence = 0;
  uint64_t generation = 0;
};
std::map<uint32_t, callback_probe> callback_probes;
std::set<std::string> callback_closing;
uint32_t callback_xid = static_cast<uint32_t>(hex64(random_hex(8)));
void configure_callback(session &s, const json &a) {
  s.callback_flavor = UINT32_MAX;
  s.callback_credential.clear();
  if (a.contains("callback_auth")) {
    s.callback_flavor = a.at("callback_auth").at("flavor");
    s.callback_credential = decode_bytes(a.at("callback_auth").at("credential").get<std::string>());
  }
}
bool callback_available(const session &s) const {
  // RPC header plus a solo CB_SEQUENCE, including the exact AUTH_SYS body.
  return send_backchannel && s.callback_flavor <= 1 && s.callback_slots &&
         s.callback_request_limit >= 96 + s.callback_credential.size() &&
         s.callback_response_limit >= 76;
}
bool callback_path_up(uint64_t client) const {
  for (const auto &[id, s] : sessions)
    if (s.client == client && !s.callback_up.empty()) return true;
  return false;
}
void send_callback_probe(const std::string &id, const std::string &bound, bool compound) {
  auto &s = sessions.at(id);
  do { ++callback_xid; } while (callback_probes.contains(callback_xid));
  // RFC 5662 NFS4_CALLBACK XDR assigns RPC version 1 (not NFS version 4).
  writer call;
  call.u32(callback_xid).u32(0).u32(2).u32(s.callback_program).u32(1).u32(compound ? 1 : 0)
      .u32(s.callback_flavor).opaque(s.callback_credential).u32(0).opaque("");
  if (compound) {
    s.callback_unresolved = true;
    // One bounded slot suffices even when the client offers UINT32_MAX slots.
    // A solo SEQUENCE reply is cached independently of cachethis. Keep these
    // bytes/sequence unchanged after uncertain completion, including rebinds.
    call.opaque("").u32(1).u32(0).u32(s.callback_extra.empty() ? 1 : 2)
        .u32(11).fixed(decode_bytes(id)).u32(s.callback_sequence).u32(0).u32(0).boolean(false);
    if (s.callback_references.empty()) call.u32(0);
    else call.fixed(s.callback_references);
    call.fixed(s.callback_extra);
  }
  callback_probes.emplace(callback_xid, callback_probe{id, bound, now() + 5000, compound,
                                                     s.callback_sequence, s.callback_generation});
  send_backchannel(bound, std::move(call.data));
}
void sequence_callback(const std::string &id) {
  auto &s = sessions.at(id);
  auto client = client_ids.find(s.client);
  if (s.expires <= now() || client == client_ids.end() || client->second.expires <= now()) return;
  if (!callback_available(s) || callback_probes.size() >= 128) return;
  // Only one CB_COMPOUND may own slot zero. Other validated NULL paths wait
  // for its result; a retry on another path uses the same unresolved sequence.
  for (const auto &[xid, p] : callback_probes)
    if (p.session == id && p.compound) return;
  for (const auto &bound : s.callback_ready) {
    if ((!s.callback_up.contains(bound) || !s.callback_extra.empty()) && !callback_closing.contains(bound)) {
      if (96 + s.callback_credential.size() + s.callback_extra.size() +
              (s.callback_references.empty() ? 0 : s.callback_references.size() - 4) > s.callback_request_limit)
        return;
      send_callback_probe(id, bound, true);
      return;
    }
  }
}
void disconnect_callback(const std::string &bound) {
  for (auto &[id, s] : sessions) {
    s.callback_up.erase(bound);
    s.callback_ready.erase(bound);
  }
  if (callback_closing.insert(bound).second && close_backchannel) close_backchannel(bound);
}
void expire_callback_probes() {
  std::erase_if(callback_probes, [&](const auto &item) {
    const auto &probe = item.second;
    auto found = sessions.find(probe.session);
    if (found == sessions.end()) return true;
    auto client = client_ids.find(found->second.client);
    if (found->second.expires <= now() || client == client_ids.end() || client->second.expires <= now()) return true;
    if (probe.deadline > now()) return false;
    if (probe.compound) {
      // RFC 8881 2.10.6.2 prohibits retry on a live original transport.
      // Keep the slot occupied until disconnect() confirms that it is gone.
      disconnect_callback(probe.connection);
      return false;
    }
    found->second.callback_up.erase(probe.connection);
    found->second.callback_ready.erase(probe.connection);
    return true;
  });
  for (const auto &[id, s] : sessions) sequence_callback(id);
}
void probe_callback(const std::string &id, const std::string &bound) {
  auto &s = sessions.at(id);
  // CB_NULL has no session slot. It can be replaced, but an outstanding
  // CB_COMPOUND must finish (or its transport disconnect) before slot reuse.
  std::erase_if(callback_probes, [&](const auto &p) {
    return !p.second.compound && p.second.session == id && p.second.connection == bound;
  });
  s.callback_up.erase(bound);
  s.callback_ready.erase(bound);
  if (!callback_available(s) || callback_probes.size() >= 128 || callback_closing.contains(bound)) return;
  send_callback_probe(id, bound, false);
}
void callback_reply(uint32_t xid, reader &r) {
  auto found = callback_probes.find(xid);
  // Unknown, late, duplicate and wrong-transport replies have no effect.
  if (found == callback_probes.end() || found->second.connection != connection) return;
  auto probe = found->second;
  auto current = sessions.find(probe.session);
  if (current == sessions.end() || !current->second.back_connections.contains(connection)) {
    callback_probes.erase(found);
    return;
  }
  if (callback_closing.contains(connection)) return;
  auto &s = current->second;
  auto client = client_ids.find(s.client);
  if (s.expires <= now() || client == client_ids.end() || client->second.expires <= now()) {
    callback_probes.erase(found);
    return; // A callback must not revive expired client/session authority.
  }
  bool current_config = probe.generation == s.callback_generation;
  if (current_config) {
    s.callback_up.erase(connection);
    s.callback_ready.erase(connection);
  }
  bool valid = false;
  try {
    if (probe.deadline > now() && r.data.size() <= s.callback_response_limit &&
        r.u32() == 0 && r.u32() == 0 && r.opaque(400).empty() && r.u32() == 0) {
      if (probe.compound) {
        // Validate the complete result before committing sequence/lease state.
        auto status = r.u32();
        bool notification = !s.callback_extra.empty();
        if (!r.opaque().empty() || r.u32() != (notification ? 2u : 1u) || r.u32() != 11 ||
            r.u32() != 0 || r.fixed(16) != decode_bytes(probe.session) ||
            r.u32() != probe.sequence || r.u32() != 0)
          throw xdr_error();
        // The peer may grow/shrink its slot table after CREATE_SESSION
        // (RFC 8881 2.10.6.1). Slot zero fits every advertised maximum; no
        // allocation or concurrency increase is needed to honor either value.
        r.u32(); // csr_highest_slotid
        r.u32(); // csr_target_highest_slotid
        // CB_NOTIFY_LOCK is an optional hint. Even NOTSUPP or an uncached
        // replay result consumes the sequence; no lock authority is granted.
        if (notification) {
          if (r.u32() != 13 || r.u32() != status) throw xdr_error();
        } else if (status != 0) throw xdr_error();
      }
      r.end();
      valid = true;
    }
  } catch (const xdr_error &) { }
  if (!valid && probe.compound) {
    // An invalid result leaves execution uncertain. Disconnect before any
    // retry, preserving the exact sequence even if BIND/BACKCHANNEL_CTL races.
    disconnect_callback(connection);
    return;
  }
  callback_probes.erase(found);
  if (valid) {
    if (current_config) s.callback_ready.insert(connection);
    if (probe.compound) {
      ++s.callback_sequence; // Unsigned wraparound is part of the protocol.
      s.callback_unresolved = false;
      s.callback_extra.clear();
      s.callback_references.clear();
      if (current_config) s.callback_up.insert(connection);
      s.expires = now() + 60000;
      client_ids.at(s.client).expires = s.expires;
    }
  }
  sequence_callback(probe.session);
}
