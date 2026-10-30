pace::task<bytes> pipe_request(opened &h, std::string_view request) {
  check(h.pipe && request.size() >= 16 && request.size() <= 65536 && get(request, 0, 1) == 5 &&
        get(request, 1, 1) == 0 && get(request, 3, 1) == 3 && get(request, 4, 4) == 0x10 &&
        get(request, 8, 2) == request.size() && get(request, 10, 2) == 0);
  json auth_request = {{"auth", auth()}, {"resource", "shares"}};
  auto visible = co_await smb_rpc(s, "identity", "policy_list", auth_request);
  auto pdu = [&](unsigned type, bytes body) {
    bytes out(16, '\0');
    out[0] = 5;
    out[2] = char(type);
    out[3] = 3;
    out[4] = 0x10;
    put(out, 8, 16 + body.size(), 2);
    put(out, 12, get(request, 12, 4), 4);
    return out + body;
  };
  const auto ndr = decode_bytes("045d888aeb1cc9119fe808002b10486002000000");
  if (get(request, 2, 1) == 11) {
    check(request.size() >= 28);
    auto count = get(request, 24, 1);
    check(count > 0 && count <= 4);
    size_t pos = 28;
    bytes results;
    h.contexts.clear();
    for (size_t i = 0; i < count; ++i) {
      auto id = get(request, pos, 2), transfers = get(request, pos + 2, 1);
      check(transfers > 0 && transfers <= 4 && pos + 24 + 20 * transfers <= request.size());
      bool accepted = false;
      auto abstract = request.substr(pos + 4, 20);
      for (size_t n = 0; n < transfers; ++n)
        if (request.substr(pos + 24 + 20 * n, 20) == ndr &&
            abstract == decode_bytes("c84f324b7016d30112785a47bf6ee18803000000"))
          accepted = true;
      bytes result(24, '\0');
      put(result, 0, accepted ? 0 : 2, 2);
      put(result, 2, accepted ? 0 : 2, 2);
      result.replace(4, 20, ndr);
      results += result;
      if (accepted)
        h.contexts.insert(static_cast<uint16_t>(id));
      pos += 24 + 20 * transfers;
    }
    check(pos == request.size());
    bytes body(10, '\0');
    put(body, 0, 65535, 2);
    put(body, 2, 65535, 2);
    put(body, 4, 1, 4);
    bytes address("\\PIPE\\srvsvc\0", 13);
    put(body, 8, address.size(), 2);
    body += address;
    body.resize((body.size() + 3) / 4 * 4, '\0');
    body += bytes(4, '\0');
    body[body.size() - 4] = char(count);
    co_return pdu(12, body + results);
  }
  check(get(request, 2, 1) == 0 && request.size() >= 24 &&
        h.contexts.contains(static_cast<uint16_t>(get(request, 20, 2))));
  auto reply = [&](bytes stub) {
    bytes body(8, '\0');
    put(body, 0, stub.size(), 4);
    put(body, 4, get(request, 20, 2), 2);
    return pdu(2, body + stub);
  };
  if (get(request, 22, 2) != 15) {
    bytes body(16, '\0');
    put(body, 4, get(request, 20, 2), 2);
    put(body, 8, 0x1c010002, 4);
    co_return pdu(3, body);
  }
  auto data = request.substr(24);
  size_t pos = 4;
  if (get(data, 0, 4)) {
    auto maximum = get(data, pos, 4), offset = get(data, pos + 4, 4), count = get(data, pos + 8, 4);
    check(maximum <= 256 && offset == 0 && count > 0 && count <= maximum);
    pos += 12;
    check(pos + 2 * count <= data.size() && get(data, pos + 2 * count - 2, 2) == 0);
    pos += 2 * count;
    pos = (pos + 3) / 4 * 4;
  }
  check(get(data, pos, 4) == 1 && get(data, pos + 4, 4) == 1 && get(data, pos + 8, 4) != 0,
        0xc00000bb);
  pos += 12;
  check(get(data, pos, 4) == 0);
  bool buffer = get(data, pos + 4, 4) != 0;
  pos += 8;
  if (buffer) {
    check(get(data, pos, 4) == 0);
    pos += 4;
  }
  auto preferred = get(data, pos, 4);
  pos += 4;
  auto resume = get(data, pos, 4);
  pos += 4;
  uint64_t start = 0;
  if (resume) {
    start = get(data, pos, 4);
    pos += 4;
  }
  check(pos == data.size());
  std::vector<std::string> shares;
  for (auto item : visible) {
    if (item.at("exposures").value("smb", "").empty())
      continue;
    json q = {{"auth", auth()},
              {"protocol", "smb"},
              {"share", item.at("id")},
              {"path", ""},
              {"write", false}};
    bool allowed = false;
    try {
      co_await smb_rpc(s, "identity", "authorize", q);
      allowed = true;
    } catch (...) {
    }
    if (allowed) {
      check(shares.size() < 64, 0xc000009a);
      shares.push_back(item.at("id"));
    }
  }
  check(start <= shares.size());
  std::vector<std::string> page;
  size_t cost = 36;
  for (size_t i = static_cast<size_t>(start); i < shares.size(); ++i) {
    auto next = 12 + 12 + (utf16(shares[i]).size() + 2 + 3) / 4 * 4 + 12 + 20;
    if (cost + next > preferred)
      break;
    page.push_back(shares[i]);
    cost += next;
  }
  auto append32 = [](bytes &b, uint32_t v) {
    auto o = b.size();
    b.resize(o + 4);
    put(b, o, v, 4);
  };
  auto ndr_string = [&](bytes &b, const std::string &value) {
    auto encoded = utf16(value) + bytes(2, '\0');
    append32(b, static_cast<uint32_t>(encoded.size() / 2));
    append32(b, 0);
    append32(b, static_cast<uint32_t>(encoded.size() / 2));
    b += encoded;
    b.resize((b.size() + 3) / 4 * 4, '\0');
  };
  bytes stub;
  append32(stub, 1);
  append32(stub, 1);
  append32(stub, 0x20000);
  append32(stub, static_cast<uint32_t>(page.size()));
  append32(stub, page.empty() ? 0 : 0x20004);
  if (!page.empty()) {
    append32(stub, static_cast<uint32_t>(page.size()));
    uint32_t ref = 0x20008;
    for (auto &share : page) {
      (void)share;
      append32(stub, ref);
      append32(stub, 0);
      append32(stub, ref + 4);
      ref += 8;
    }
    for (auto &share : page) {
      ndr_string(stub, share);
      ndr_string(stub, "tauCloud");
    }
  }
  append32(stub, static_cast<uint32_t>(shares.size()));
  bool more = start + page.size() < shares.size();
  append32(stub, more ? 0x30000 : 0);
  if (more)
    append32(stub, static_cast<uint32_t>(start + page.size()));
  append32(stub, more ? 234 : 0);
  co_return reply(stub);
}
