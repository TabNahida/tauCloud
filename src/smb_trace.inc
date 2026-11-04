// Opt-in protocol metadata only: never log payloads, names, credentials,
// session keys, security descriptors or raw lease/file identifiers. Outbound
// records describe packets before encryption/write, not successful delivery.
void trace_packet(std::string_view packet, bool outbound, bool encrypted) noexcept {
  if (trace_id.empty()) return;
  try {
    size_t offset = 0;
    for (unsigned count = 0; count < 16 && packet.size() - offset >= 64; ++count) {
      auto p = packet.substr(offset);
      if (!p.starts_with(std::string_view("\xfeSMB", 4))) return;
      auto next = get(p, 20, 4);
      if (next && (next < 64 || next > p.size())) return;
      if (next) p = p.substr(0, next);
      auto cmd = get(p, 12, 2), flags = get(p, 16, 4);
      json entry = {{"connection", trace_id}, {"outbound", outbound}, {"encrypted", encrypted},
          {"command", cmd}, {"message", get(p, 24, 8)}, {"flags", flags},
          {"session", get(p, 40, 8)}, {"size", p.size()}};
      if (flags & 2) entry["async"] = get(p, 32, 8);
      else entry["tree"] = get(p, 36, 4);
      if (outbound) entry["status"] = get(p, 8, 4);
      auto fingerprint = [&](size_t at) { return digest(slice(p, at, 16, 64)).substr(0, 16); };
      if (cmd == 5 && p.size() >= (outbound ? 152u : 120u) && (!outbound || get(p, 8, 4) == 0)) {
        entry["oplock"] = get(p, outbound ? 66 : 67, 1);
        if (outbound) entry["file"] = fingerprint(128);
        else {
          entry["access"] = get(p, 88, 4); entry["share"] = get(p, 96, 4);
          entry["disposition"] = get(p, 100, 4); entry["options"] = get(p, 104, 4);
        }
        auto contexts = slice(p, get(p, outbound ? 144 : 112, 4), get(p, outbound ? 148 : 116, 4), 0);
        size_t pos = 0;
        for (unsigned n = 0; n < 16 && contexts.size() - pos >= 16; ++n) {
          auto item = std::string_view(contexts).substr(pos);
          auto step = get(item, 0, 4);
          if (step && (step < 16 || step > item.size())) break;
          if (step) item = item.substr(0, step);
          auto tag = slice(item, get(item, 4, 2), get(item, 6, 2), 16);
          if (tag == "RqLs") {
            auto data = slice(item, get(item, 10, 2), get(item, 12, 4), 16);
            if (data.size() == 32 || data.size() == 52) {
              entry["lease"] = {{"key", digest(data.substr(0, 16)).substr(0, 16)},
                  {"state", get(data, 16, 4)}, {"flags", get(data, 20, 4)},
                  {"version", data.size() == 52 ? 2 : 1}};
              if (data.size() == 52) entry["lease"]["epoch"] = get(data, 48, 2);
            }
          }
          if (!step) break;
          pos += step;
        }
      } else if (cmd == 18 && p.size() >= 88) {
        auto size = get(p, 64, 2);
        entry["structure"] = size;
        if (size == 44 && p.size() >= 108) {
          entry["lease_key"] = fingerprint(72); entry["epoch"] = get(p, 66, 2);
          entry["ack_required"] = get(p, 68, 4); entry["current"] = get(p, 88, 4);
          entry["target"] = get(p, 92, 4);
        } else if (size == 36 && p.size() >= 100) {
          entry["lease_key"] = fingerprint(72); entry["state"] = get(p, 88, 4);
        } else if (size == 24) {
          entry["file"] = fingerprint(72); entry["oplock"] = get(p, 66, 1);
        }
      } else if (!outbound) {
        if ((cmd == 6 || cmd == 7 || cmd == 10 || cmd == 14) && p.size() >= 88)
          entry["file"] = fingerprint(72);
        if ((cmd == 8 || cmd == 9 || cmd == 17) && p.size() >= 96)
          entry["file"] = fingerprint(80);
        if (cmd == 16 && p.size() >= 104) entry["file"] = fingerprint(88);
        if ((cmd == 16 || cmd == 17) && p.size() >= 96) {
          entry["info_type"] = get(p, 66, 1); entry["info_class"] = get(p, 67, 1);
          if (cmd == 17) entry["security_information"] = get(p, 76, 4);
        }
      }
      log("smb", "protocol_trace", entry.dump());
      if (!next) return;
      offset += next;
    }
  } catch (...) { /* Diagnostics never change protocol results. */ }
}
