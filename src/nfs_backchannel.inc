// Backchannel requests use only bound TCP transports, never client addresses.
struct callback_probe {
  std::string session, connection;
  int64_t deadline;
  bool compound = false;
  uint32_t sequence = 0;
  uint64_t generation = 0;
  std::string gss_handle;
  uint32_t gss_sequence = 0, gss_service = 0;
};
std::map<uint32_t, callback_probe> callback_probes;
std::set<std::string> callback_closing;
uint32_t callback_xid = static_cast<uint32_t>(hex64(random_hex(8)));
void configure_callback(session &s, const json &a) {
  auto contexts = s.callback_contexts;
  std::erase_if(contexts, [&](const auto &c) { return !callback_context(c); });
  // BACKCHANNEL_CTL adds handles; it must not revoke earlier usable handles.
  // Validate the entire offer before changing the session or callback program.
  if (a.contains("callback_gss")) for (const auto &offer : a.at("callback_gss")) {
    callback_gss c{decode_bytes(offer.at("server").get<std::string>()),
                   decode_bytes(offer.at("client").get<std::string>()), offer.at("service")};
    check(c.service >= 1 && c.service <= 3 && c.client_handle.size() <= 380);
    check(callback_context(c) != nullptr, 2);
    if (std::find(contexts.begin(), contexts.end(), c) == contexts.end()) contexts.push_back(std::move(c));
  }
  check(contexts.size() <= 16, 10018);
  s.callback_contexts = std::move(contexts);
  s.callback_gss_configured |= a.contains("callback_gss");
  s.callback_flavor = UINT32_MAX;
  s.callback_credential.clear();
  if (a.contains("callback_auth")) {
    s.callback_flavor = a.at("callback_auth").at("flavor");
    s.callback_credential = decode_bytes(a.at("callback_auth").at("credential").get<std::string>());
  }
}
const gss_session *callback_context(const callback_gss &c) const {
  auto found = gss_sessions.find(c.server_handle);
  if (found == gss_sessions.end()) return nullptr;
  const auto &g = found->second;
  if (g.principal.empty() || g.program != 100003 || g.version != 4 ||
      g.expires <= std::chrono::steady_clock::now() || g.callback_sequence >= 0x7fffffffu) return nullptr;
  return &g;
}
uint32_t callback_gss_flags(const session &s) const {
  if (!s.callback_gss_configured) return 0;
  bool live = false;
  for (const auto &c : s.callback_contexts) if (auto g = callback_context(c)) {
    live = true;
    if (g->expires > std::chrono::steady_clock::now() + 60s) return 0;
  }
  return live ? 2 : 4;
}
bool callback_gss_fits(const session &s, const callback_gss &c, size_t extra, size_t response_extra) const {
  auto g = callback_context(c);
  if (!g) return false;
  auto pad = [](size_t n) { return (n + 3) & ~size_t(3); };
  auto fits = [&](size_t header, size_t body, uint32_t limit) {
    if (header > limit) return false;
    if (c.service == 1) return body <= limit - header;
    if (c.service == 2) return 8 + 4 + pad(body) + pad(g->mic_size) <= limit - header;
    if (limit - header < 4) return false;
    try { return body + 4 <= g->context->wrap_size_limit((limit - header - 4) & ~3u); }
    catch (...) { return false; }
  };
  return fits(60 + pad(c.client_handle.size()) + pad(g->mic_size), 56 + extra, s.callback_request_limit) &&
         fits(24 + pad(g->mic_size), 52 + response_extra, s.callback_response_limit);
}
const callback_gss *select_callback_gss(const session &s, size_t extra = 0, size_t response_extra = 0) const {
  for (const auto &c : s.callback_contexts)
    if (callback_gss_fits(s, c, extra, response_extra)) return &c;
  return nullptr;
}
bool callback_fits(const session &s, size_t extra = 0, size_t response_extra = 0) const {
  return select_callback_gss(s, extra, response_extra) ||
         (s.callback_flavor <= 1 && s.callback_request_limit >= 96 + s.callback_credential.size() + extra &&
          s.callback_response_limit >= 76 + response_extra);
}
bool callback_available(const session &s) const {
  // RPC header plus a solo CB_SEQUENCE, including the exact AUTH_SYS body.
  return send_backchannel && s.callback_slots && callback_fits(s);
}
bool callback_path_up(uint64_t client) const {
  for (const auto &[id, s] : sessions)
    if (s.client == client && callback_available(s) && !s.callback_up.empty()) return true;
  return false;
}
void send_callback_probe(const std::string &id, const std::string &bound, bool compound) {
  auto &s = sessions.at(id);
  do { ++callback_xid; } while (callback_probes.contains(callback_xid));
  // RFC 5662 NFS4_CALLBACK XDR assigns RPC version 1 (not NFS version 4).
  writer body;
  if (compound) {
    // One bounded slot; keep the plaintext/sequence stable on uncertain retry.
    body.opaque("").u32(1).u32(0).u32(s.callback_extra.empty() ? 1 : 2)
        .u32(11).fixed(decode_bytes(id)).u32(s.callback_sequence).u32(0).u32(0).boolean(false);
    if (s.callback_references.empty()) body.u32(0);
    else body.fixed(s.callback_references);
    body.fixed(s.callback_extra);
  }
  callback_probe probe{id, bound, now() + 5000, compound, s.callback_sequence, s.callback_generation};
  writer call;
  call.u32(callback_xid).u32(0).u32(2).u32(s.callback_program).u32(1).u32(compound ? 1 : 0);
  auto extra = compound ? body.data.size() - 56 : 0;
  if (auto c = select_callback_gss(s, extra, compound && !s.callback_extra.empty() ? 8 : 0)) {
    auto &g = gss_sessions.at(c->server_handle);
    // A context can serve several sessions/transports. Do not advance beyond
    // the peer's 64-entry RPC window while an older request is outstanding.
    for (const auto &[xid, pending] : callback_probes)
      if (pending.gss_handle == c->server_handle && g.callback_sequence - pending.gss_sequence >= 63)
        return;
    probe.gss_handle = c->server_handle;
    probe.gss_sequence = ++g.callback_sequence;
    probe.gss_service = c->service;
    auto credential = writer().u32(1).u32(0).u32(probe.gss_sequence).u32(c->service).opaque(c->client_handle).data;
    try {
      call.u32(6).opaque(credential);
      auto verifier = g.context->sign(call.data);
      if (verifier.size() > 400) return;
      call.u32(6).opaque(verifier);
      if (c->service == 1) call.fixed(body.data);
      else {
        auto clear = writer().u32(probe.gss_sequence).fixed(body.data).data;
        if (c->service == 2) call.opaque(clear).opaque(g.context->sign(clear));
        else call.opaque(g.context->wrap(clear));
      }
    } catch (...) { return; } // Never silently downgrade a failed GSS operation.
  } else {
    if (s.callback_flavor > 1) return;
    call.u32(s.callback_flavor).opaque(s.callback_credential).u32(0).opaque("").fixed(body.data);
  }
  if (call.data.size() > s.callback_request_limit) return;
  if (compound) s.callback_unresolved = true;
  callback_probes.emplace(callback_xid, std::move(probe));
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
      if (!callback_fits(s, s.callback_extra.size() +
              (s.callback_references.empty() ? 0 : s.callback_references.size() - 4),
              s.callback_extra.empty() ? 0 : 8))
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
  std::string clear;
  try {
    if (probe.deadline > now() && r.data.size() <= s.callback_response_limit && r.u32() == 0) {
      auto flavor = r.u32();
      auto verifier = r.opaque(400);
      auto accepted = r.u32();
      if (!probe.gss_handle.empty()) {
        auto found_gss = gss_sessions.find(probe.gss_handle);
        if (found_gss == gss_sessions.end() || found_gss->second.expires <= std::chrono::steady_clock::now())
          throw xdr_error();
        auto &g = found_gss->second;
        if (flavor != 6 || !g.context->verify(writer().u32(probe.gss_sequence).data, verifier) || accepted)
          throw xdr_error();
        if (probe.gss_service != 1) {
          auto token = r.opaque(max_record);
          if (probe.gss_service == 2) {
            if (!g.context->verify(token, r.opaque(400))) throw xdr_error();
            clear = std::move(token);
          } else clear = g.context->unwrap(token);
          r.end();
          r = reader(clear);
          if (r.u32() != probe.gss_sequence) throw xdr_error();
        }
      } else if (flavor || !verifier.empty() || accepted) throw xdr_error();
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
    catch (const error &) { }
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
