// RFC 2203 authentication envelope. The ordinary NFS dispatcher sees verified
// plaintext only; every accepted reply (including RPC errors) is authenticated.
struct gss_session {
  std::unique_ptr<gss_context> context;
  std::string principal;
  uint32_t program = 0, version = 0, highest = 0;
  uint64_t seen = 0;
  std::chrono::steady_clock::time_point expires;
};
std::map<std::string, gss_session> gss_sessions;
void gss_expire() {
  auto time = std::chrono::steady_clock::now();
  std::erase_if(gss_sessions, [&](const auto &entry) { return entry.second.expires <= time; });
}
std::string dispatch(std::string_view packet, std::string connection_id) {
  std::lock_guard guard(mutex);
  connection = std::move(connection_id);
  reader r(packet);
  uint32_t xid = r.u32();
  auto denied = [&](uint32_t code) {
    return writer().u32(xid).u32(1).u32(1).u32(1).u32(code).data;
  };
  try {
    if (r.u32() != 0 || r.u32() != 2) return dispatch_plain(packet);
    auto program = r.u32(), version = r.u32(), procedure = r.u32();
    if (r.u32() != 6) return dispatch_plain(packet);
    if (cfg.nfs_gss_service.empty()) return denied(2);
    auto credential = r.opaque(400);
    auto header_end = r.pos;
    auto vf = r.u32();
    auto verifier = r.opaque(400);
    auto arguments = r.pos;
    reader cred(credential);
    if (cred.u32() != 1) return denied(2);
    auto control = cred.u32(), sequence = cred.u32(), service = cred.u32();
    auto handle = cred.opaque(128);
    cred.end();
    if (control > 3 || (control && procedure)) return denied(1);
    if (!((program == 100003 && (version == 3 || version == 4)) ||
          (program == 100005 && version == 3))) return denied(2);
    gss_expire();
    if (control == 1 || control == 2) {
      if (vf || !verifier.empty() || (control == 1 && !handle.empty())) return denied(1);
      auto token = r.opaque(65536);
      r.end();
      if (control == 1) {
        if (gss_sessions.size() >= 128) return denied(2);
        handle = decode_bytes(random_hex(32));
        gss_session entry;
        try { entry.context = std::make_unique<gss_context>(cfg.nfs_gss_service, cfg.nfs_gss_keytab); }
        catch (...) { return denied(2); }
        entry.program = program;
        entry.version = version;
        entry.expires = std::chrono::steady_clock::now() + 60s;
        gss_sessions.emplace(handle, std::move(entry));
      }
      auto found = gss_sessions.find(handle);
      if (found == gss_sessions.end() || !found->second.principal.empty() ||
          found->second.program != program || found->second.version != version) return denied(2);
      auto &entry = found->second;
      gss_context::result accepted;
      try { accepted = entry.context->accept(token); }
      catch (...) { gss_sessions.erase(found); return denied(2); }
      writer reply;
      reply.u32(xid).u32(1).u32(0);
      if (accepted.major == 0) {
        entry.principal = accepted.principal;
        entry.expires = std::chrono::steady_clock::now() +
            std::chrono::seconds(std::min(accepted.lifetime, 3600u));
        reply.u32(6).opaque(entry.context->sign(writer().u32(64).data));
      } else reply.u32(0).opaque("");
      if (accepted.major != 0 && accepted.major != 1) {
        gss_sessions.erase(found);
        handle.clear();
        accepted.token.clear();
      }
      return reply.u32(0).opaque(handle).u32(accepted.major).u32(accepted.minor)
          .u32(64).opaque(accepted.token).data;
    }
    if (service < 1 || service > 3 || vf != 6) return denied(1);
    auto found = gss_sessions.find(handle);
    if (found == gss_sessions.end() || found->second.principal.empty() ||
        found->second.program != program || found->second.version != version) return denied(13);
    auto &entry = found->second;
    if (!entry.context->verify(packet.substr(0, header_end), verifier)) return denied(13);
    if (sequence >= 0x80000000u) return denied(14);
    // Verify the header before advancing the window: a forged high sequence
    // cannot evict outstanding legitimate requests. GSS sequence flags are
    // deliberately not the RPC replay mechanism (requests may arrive unordered).
    if (sequence > entry.highest) {
      auto shift = sequence - entry.highest;
      entry.seen = shift >= 64 ? 0 : entry.seen << shift;
      entry.highest = sequence;
    }
    auto distance = entry.highest - sequence;
    if (distance >= 64 || (entry.seen & (uint64_t(1) << distance))) return "";
    entry.seen |= uint64_t(1) << distance;
    auto protect = [&](uint32_t status, std::string_view body) {
      writer out;
      out.u32(xid).u32(1).u32(0).u32(6)
          .opaque(entry.context->sign(writer().u32(sequence).data)).u32(status);
      if (status || service == 1) return out.fixed(body).data;
      auto data = writer().u32(sequence).fixed(body).data;
      if (service == 2) return out.opaque(data).opaque(entry.context->sign(data)).data;
      return out.opaque(entry.context->wrap(data)).data;
    };
    std::string clear;
    try {
      if (service == 1) clear = std::string(packet.substr(arguments));
      else {
        auto token = r.opaque(max_record);
        if (service == 2) {
          auto mic = r.opaque(400);
          require(entry.context->verify(token, mic), "gss_context");
          clear = std::move(token);
        } else clear = entry.context->unwrap(token);
        r.end();
        reader data(clear);
        if (data.u32() != sequence) return protect(4, "");
        clear.erase(0, 4);
      }
    } catch (...) { return protect(4, ""); }
    if (control == 3) {
      if (!clear.empty()) return protect(4, "");
      auto response = protect(0, "");
      gss_sessions.erase(found);
      return response;
    }
    identity who;
    who.credential = {{"auth", "rpcsec-gss"}, {"principal", entry.principal}, {"service", service}};
    who.key = digest("rpcsec-gss:krb5:" + entry.principal);
    auto plaintext = std::string(packet.substr(0, arguments)) + clear;
    auto result = dispatch_plain(plaintext, &who);
    reader reply(result);
    reply.u32(); reply.u32();
    if (reply.u32() != 0 || reply.u32() != 0 || !reply.opaque(400).empty()) return "";
    auto status = reply.u32();
    return protect(status, std::string_view(result).substr(reply.pos));
  } catch (const xdr_error &) {
    return denied(1);
  } catch (...) {
    // In particular, never downgrade a failed reply MIC/wrap to AUTH_NONE.
    return "";
  }
}
