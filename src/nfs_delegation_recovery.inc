// Protocol recovery owns durable intents; the file domain owns the original
// native incarnation and the monotonic binding generation. Never reopen a path
// or acquire a replacement guard to satisfy a delegation reclaim.
void save_delegation_recovery(const std::string &id, const json &record) {
  statement q(db, "INSERT OR REPLACE INTO recovery VALUES(?,?)");
  q.bind(1, id); q.bind(2, record.dump()); q.row();
}
json recovering_delegation_call(const json &record, const std::string &op, int64_t remaining = 0,
                                bool destination = false) {
  const auto &b = record.at("binding");
  json request = {{"op", op}, {"grant", b.at("grant")}, {"cookie", b.at("cookie")},
      {"handle", record.at("handle")},
      {"client", destination ? record.at("adoption").at("to") : b.at("client")}};
  if (remaining) request["remaining_ms"] = remaining;
  return call(b.at("worker"), "nfs_delegation", request);
}
// A destination poll can settle an uncertain adoption without new authority:
// it observes the exact generation, but never authorizes data or a new stateid.
void reconcile_delegation_destination(const std::string &id, json &record) {
  if (!record.contains("adoption")) return;
  const auto &intent = record.at("adoption");
  auto generation = record.at("binding").at("generation").get<uint64_t>();
  require(generation != UINT64_MAX && intent.at("from") == record.at("binding").at("client") &&
      intent.at("generation") == generation, "database_corrupt");
  try {
    auto result = recovering_delegation_call(record, "poll", 0, true);
    require(result.at("binding_generation") == generation + 1, "delegation_recovery_failed");
    record["binding"]["client"] = intent.at("to");
    record["binding"]["generation"] = generation + 1;
    record.erase("adoption"); save_delegation_recovery(id, record);
  } catch (const error &e) {
    if (std::string_view(e.what()) != "forbidden") throw;
    // The original operation could still execute. Keep the intent until a
    // fresh-authority idempotent adoption completes it, never discard it here.
  }
}
void retain_recovering_delegations() {
  for (auto &[id, record] : reclaim) {
    if (record.value("kind", "") != "delegation") continue;
    if (!record.contains("binding") || record.at("binding").value("provider", "") != "independent-owner") {
      record["recovery_denied"] = true; save_delegation_recovery(id, record); continue;
    }
    try {
      reconcile_delegation_destination(id, record);
      auto snapshot = recovering_delegation_call(record, "poll");
      require(snapshot.at("binding_generation") == record.at("binding").at("generation"),
          "delegation_recovery_failed");
      require(snapshot.at("lease_period_ms") == record.at("binding").at("period_ms"),
          "delegation_recovery_failed");
      auto state = snapshot.at("state").get<std::string>();
      if (state == "active" || state == "recalling") {
        // Cleanup authority may preserve coherence but cannot restore data
        // authority. Retain starts recall and cannot postpone an earlier one.
        auto period = record.at("binding").at("period_ms").get<int64_t>();
        require(period >= 5000 && period <= 3600000, "database_corrupt");
        snapshot = recovering_delegation_call(record, "retain", period);
        state = snapshot.at("state");
      }
      if (state != "active" && state != "recalling") {
        record["recovery_denied"] = true; save_delegation_recovery(id, record);
      }
    } catch (const error &e) {
      if (std::string_view(e.what()) != "stale_handle") throw;
      record["recovery_denied"] = true; save_delegation_recovery(id, record);
    }
  }
}
void release_recovering_delegation(json &record) {
  if (record.value("kind", "") != "delegation" || !record.contains("binding")) return;
  auto release = [&](bool destination) {
    try {
      recovering_delegation_call(record, "return", 0, destination);
      recovering_delegation_call(record, "forget", 0, destination);
    } catch (const error &e) { if (std::string_view(e.what()) != "stale_handle") throw; }
  };
  if (record.contains("adoption")) {
    // An uncertain late adopt cannot run after successful return: the file
    // domain serializes both, and adoption cannot resurrect terminal records.
    try { release(true); return; }
    catch (const error &e) { if (std::string_view(e.what()) != "forbidden") throw; }
  }
  release(false);
}
void emit_reclaimed_delegation(writer &body, const std::string &stateid) {
  // Reclaim must work before the backchannel has proven usable.
  body.u32(1).fixed(decode_bytes(stateid)).boolean(true)
      .u32(1).u32(0).u32(0x1f01ff).opaque("EVERYONE@");
}
void reclaim_delegation4(writer &body, const identity &who, const std::string &sid,
                          const std::string &fh, const json &metadata, uint32_t type) {
  auto client = sessions.at(sid).client;
  auto &owner = client_ids.at(client);
  check(type == 1, 10034);
  check(!owner.reclaimed_filesystems.contains(metadata.at("fsid").get<std::string>()), 10033);
  check(!metadata.at("directory").get<bool>(), 21);
  check((metadata.at("security_access").get<uint32_t>() & 1) != 0, 13);
  for (auto &[id, d] : delegations) if (d.client == client && d.fh == fh && d.principal == who.key) {
    check(!d.revoked, 10033); recall_delegation(d); check(!d.revoked, 10033);
    emit_reclaimed_delegation(body, id); return;
  }
  json key = {{"kind", "delegation"}, {"client", owner.owner}, {"principal", who.key}, {"handle", fh}, {"type", type}};
  auto rid = digest(key.dump());
  auto found = reclaim.find(rid);
  check(found != reclaim.end(), 10034);
  auto &record = found->second;
  check(record.value("owner_principal", "") == owner.principal, 10034);
  check(!record.value("recovery_denied", false) && record.contains("binding"), 10033);
  check(record.at("verifier") == owner.verifier, 10034);
  check(delegations.size() < 32, 10018);
  auto grant = authorize({{"peer", "127.0.0.1"}, {"credential", who.credential},
      {"uuid", encode_bytes(decode_bytes(fh).substr(2, 16))}, {"write", false}});
  check(grant_scope(grant) == grant_scope(record.at("binding").at("grant")) &&
      record.at("binding").at("object") == metadata.at("object"), 13);
  const auto cookie = record.at("binding").at("cookie").get<std::string>();
  auto adopt = [&] {
    const auto &intent = record.at("adoption");
    auto remaining = owner.expires - now(); check(remaining > 0, 10011);
    // An earlier SQL failure may have left an intent only in memory. Retry
    // durability before every native mutation, including redriving that intent.
    save_delegation_recovery(rid, record);
    json result;
    try {
      result = call(record.at("binding").at("worker"), "nfs_delegation",
          {{"op", "adopt"}, {"grant", grant}, {"cookie", cookie}, {"handle", fh},
           {"client", intent.at("from")}, {"next_client", intent.at("to")},
           {"binding_generation", intent.at("generation")}, {"adoption", intent.at("id")},
           {"remaining_ms", remaining}});
    } catch (const error &e) {
      if (std::string_view(e.what()) != "stale_handle") throw;
      record["recovery_denied"] = true; save_delegation_recovery(rid, record);
      check(false, 10033);
    }
    auto generation = intent.at("generation").get<uint64_t>();
    check(result.at("granted").get<bool>(), 10033);
    require(generation != UINT64_MAX && result.at("binding_generation") == generation + 1,
        "delegation_recovery_failed");
    record["binding"]["client"] = intent.at("to");
    record["binding"]["generation"] = generation + 1;
    record["binding"]["grant"] = grant;
    record.erase("adoption"); save_delegation_recovery(rid, record);
  };
  if (record.contains("adoption")) adopt(); // Settle any earlier uncertain call first.
  auto generation = record.at("binding").at("generation").get<uint64_t>();
  check(generation != UINT64_MAX, 10018);
  auto native_client = std::to_string(client) + ":" + random_hex(16);
  record["adoption"] = {{"from", record.at("binding").at("client")}, {"to", native_client},
      {"generation", generation}, {"id", random_hex(16)}};
  save_delegation_recovery(rid, record); // Intent precedes the file-domain mutation.
  adopt();
  delegation_state d{client, fh, metadata.at("object"), who.key, cookie,
      record.at("binding").at("worker"), rid, who.credential, grant};
  d.native_client = native_client; d.recalling = true;
  auto recalled = delegation_control(d, "recall");
  check(recalled.at("granted").get<bool>() && recalled.at("state") == "recalling", 10033);
  auto stateid = encode_bytes(writer().u32(1).fixed(decode_bytes(random_hex(12))).data);
  try {
    publish_reservation_route(cookie, client, delegation_control(d, "channel").at("reservation_capability"));
    delegations.emplace(stateid, std::move(d));
  } catch (...) { unpublish_reservation_route(cookie); throw; }
  reclaim.erase(found);
  emit_reclaimed_delegation(body, stateid);
}
