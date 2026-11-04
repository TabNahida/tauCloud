// Backchannel probes use the bound TCP connection and client-selected program.
// No name resolution or separate connection to a client-supplied target occurs.
struct callback_probe {
  std::string session, connection;
  int64_t deadline;
};
std::map<uint32_t, callback_probe> callback_probes;
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
  return send_backchannel && s.callback_flavor <= 1 &&
         s.callback_request_limit >= 40 + s.callback_credential.size();
}
bool callback_path_up(uint64_t client) const {
  for (const auto &[id, s] : sessions)
    if (s.client == client && !s.callback_up.empty()) return true;
  return false;
}
void expire_callback_probes() {
  std::erase_if(callback_probes, [&](const auto &item) {
    const auto &probe = item.second;
    auto found = sessions.find(probe.session);
    if (found == sessions.end()) return true;
    if (probe.deadline > now()) return false;
    found->second.callback_up.erase(probe.connection);
    return true;
  });
}
void probe_callback(const std::string &id, const std::string &bound) {
  auto &s = sessions.at(id);
  expire_callback_probes();
  // BACKCHANNEL_CTL replaces the program/security, so an older response must
  // never validate the new configuration. There is at most one probe per path.
  std::erase_if(callback_probes, [&](const auto &p) {
    return p.second.session == id && p.second.connection == bound;
  });
  s.callback_up.erase(bound);
  if (!callback_available(s) || callback_probes.size() >= 128) return;
  do { ++callback_xid; } while (callback_probes.contains(callback_xid));
  // RFC 5662 NFS4_CALLBACK XDR assigns RPC version 1 (not NFS version 4).
  writer call;
  call.u32(callback_xid).u32(0).u32(2).u32(s.callback_program).u32(1).u32(0)
      .u32(s.callback_flavor).opaque(s.callback_credential).u32(0).opaque("");
  callback_probes.emplace(callback_xid, callback_probe{id, bound, now() + 5000});
  send_backchannel(bound, std::move(call.data));
}
void callback_reply(uint32_t xid, reader &r) {
  auto found = callback_probes.find(xid);
  // Unknown, late, duplicate and wrong-transport replies have no effect.
  if (found == callback_probes.end() || found->second.connection != connection) return;
  auto probe = found->second;
  callback_probes.erase(found);
  auto session = sessions.find(probe.session);
  if (session == sessions.end() || !session->second.back_connections.contains(connection)) return;
  auto &s = session->second;
  s.callback_up.erase(connection);
  try {
    if (probe.deadline <= now() || r.u32() != 0 || r.u32() != 0 || !r.opaque(400).empty() || r.u32() != 0)
      return;
    r.end();
    s.callback_up.insert(connection);
  } catch (const xdr_error &) { }
}
