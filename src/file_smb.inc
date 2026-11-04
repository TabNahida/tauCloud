// SMB sharing/locking is owned by the file service, including other protocols' opens.
static unsigned smb_categories(uint32_t access) {
  return ((access & (1u | 0x20u)) ? 1u : 0u) | ((access & 6u) ? 2u : 0u) |
         ((access & 0x10000u) ? 4u : 0u);
}
void smb_sharing(const std::string &space, const std::string &path, uint32_t access,
                 unsigned share) {
  statement pending_delete(db, "SELECT 1 FROM smb_pending WHERE space=? AND path=?");
  pending_delete.bind(1, space);
  pending_delete.bind(2, path);
  require(!pending_delete.row(), "delete_pending");
  auto parent = path;
  while (parent.find('/') != std::string::npos) {
    parent = parent.substr(0, parent.rfind('/'));
    statement ancestor(db, "SELECT 1 FROM smb_pending WHERE space=? AND path=?");
    ancestor.bind(1, space);
    ancestor.bind(2, parent);
    require(!ancestor.row(), "delete_pending");
  }
  for (auto &[id, h] : handles)
    if (h.space == space && h.path == path) {
      auto existing = h.protocol == "smb" ? smb_categories(h.access) : (h.writable ? 3u : 1u);
      auto sharing = h.protocol == "smb" ? h.sharing : 3u;
      // Metadata-only opens do not participate in data/delete sharing checks.
      if (!existing || !smb_categories(access))
        continue;
      require((smb_categories(access) & ~sharing) == 0 && (existing & ~share) == 0,
              "sharing_violation");
    }
}
void smb_reap(space_state &s) {
  smb_reap_times(s);
  auto space = s.data.at("space").at("id").get<std::string>();
  // CREATE's DELETE_ON_CLOSE is an open mode, not Link.IsDeleted. Only a
  // closed (or lost) open activates it; a nonempty directory is left intact.
  // The durable intent is removed atomically with publishing pending deletion.
  statement intents(db, "SELECT handle,path,native,directory,target FROM smb_close_delete WHERE space=?");
  intents.bind(1, space);
  std::vector<json> closing;
  while (intents.row())
    if (!handles.contains(intents.text(0)))
      closing.push_back({{"handle", intents.text(0)}, {"path", intents.text(1)},
                         {"native", intents.text(2)}, {"directory", bool(intents.integer(3))},
                         {"target", intents.text(4)}});
  for (const auto &intent : closing) {
    std::string matched;
    for (const auto &field : {"path", "target"}) {
      auto path = intent.at(field).get<std::string>();
      if (path.empty()) continue;
      auto current = stat_path(s.directory, path, intent.at("directory"));
      if (!current || current->at("object") != intent.at("native")) continue;
      if (!intent.at("directory").get<bool>() || s.directory.open(path, true).list(true).empty())
        matched = path;
      break;
    }
    transaction tx(db);
    if (!matched.empty()) {
      statement mark(db, "INSERT OR IGNORE INTO smb_pending VALUES(?,?,?,?)");
      mark.bind(1, space); mark.bind(2, matched); mark.bind(3, intent.at("native"));
      mark.bind(4, int64_t(intent.at("directory").get<bool>())); mark.row();
    }
    statement done(db, "DELETE FROM smb_close_delete WHERE handle=?");
    done.bind(1, intent.at("handle")); done.row();
    tx.commit();
  }
  statement q(db, "SELECT path,native,directory FROM smb_pending WHERE space=?");
  q.bind(1, space);
  std::vector<json> rows;
  while (q.row())
    rows.push_back({{"path", q.text(0)}, {"native", q.text(1)}, {"directory", bool(q.integer(2))}});
  for (auto row : rows) {
    auto path = row.at("path").get<std::string>();
    bool busy = false;
    for (auto &[id, h] : handles)
      if (h.space == space && h.path == path)
        busy = true;
    if (busy)
      continue;
    auto current = stat_path(s.directory, path, row.at("directory"));
    if (current) {
      require(current->at("object") == row.at("native"), "object_replaced");
      s.directory.remove(path, row.at("directory"));
      s.directory.flush();
    }
    transaction tx(db);
    erase(space, path);
    statement del(db, "DELETE FROM smb_pending WHERE space=? AND path=?");
    del.bind(1, space);
    del.bind(2, path);
    del.row();
    tx.commit();
  }
}
json smb_eas(const json &info) {
  statement q(db, "SELECT body FROM smb_eas WHERE native=?");
  q.bind(1, info.at("object"));
  return q.row() ? json::parse(q.text(0)) : json::object();
}
json smb_merge_eas(json values, const json &input) {
  require(input.is_array() && input.size() <= 256, "invalid_request");
  for (auto ea : input) {
    auto name = ea.at("name").get<std::string>(), key = name;
    require(!name.empty() && name.size() <= 255, "invalid_ea_name");
    for (auto &c : key) {
      require(uint8_t(c) >= 32 && uint8_t(c) < 127 &&
                  std::string_view("\\/:*?\"<>|,+=[];").find(c) == std::string_view::npos,
              "invalid_ea_name");
      if (c >= 'a' && c <= 'z')
        c -= 'a' - 'A';
    }
    require(ea.at("flags") == 0 || ea.at("flags") == 128, "invalid_request");
    auto bytes = decode_bytes(ea.at("value").get<std::string>());
    require(bytes.size() <= 65535, "invalid_request");
    if (bytes.empty())
      values.erase(key);
    else {
      ea["name"] = key;
      values[key] = ea;
    }
  }
  size_t total = 0;
  for (auto &[key, ea] : values.items())
    total += 5 + key.size() + ea.at("value").get<std::string>().size() / 2;
  require(values.size() <= 256 && total <= 65531, "ea_too_large");
  return values;
}
void smb_update_eas(const json &info, const json &input) {
  auto values = smb_merge_eas(smb_eas(info), input);
  statement q(
      db, "INSERT INTO smb_eas VALUES(?,?) ON CONFLICT(native) DO UPDATE SET body=excluded.body");
  q.bind(1, info.at("object"));
  q.bind(2, values.dump());
  q.row();
  notify_metadata(info.at("object"), 0x80);
}
uint32_t smb_ea_size(const json &info) {
  uint32_t size = 0;
  auto values = smb_eas(info);
  for (auto &[name, ea] : values.items())
    size += uint32_t(5 + name.size() + ea.at("value").get<std::string>().size() / 2);
  return size;
}
// Persist portable DOS metadata by native incarnation, never by a reusable name.
uint32_t smb_attributes(const json &info) {
  statement q(db, "SELECT attributes FROM smb_attributes WHERE native=?");
  q.bind(1, info.at("object"));
  return q.row() ? static_cast<uint32_t>(q.integer(0))
                 : (info.at("directory").get<bool>() ? 0x10u : 0x20u);
}
uint32_t smb_attribute_value(uint32_t value, bool directory) {
  // Sparse/compressed/reparse/encrypted flags require their own filesystem ops.
  require(!(value & ~0x31b7u), "not_supported");
  require(!directory || !(value & 0x100), "invalid_request");
  value &= ~(0x10u | 0x80u);
  if (directory)
    value |= 0x10;
  return value ? value : 0x80u;
}
void smb_save_attributes(const json &info, uint32_t attributes) {
  if (smb_attributes(info) == attributes) return;
  statement q(db, "INSERT INTO smb_attributes VALUES(?,?) ON CONFLICT(native) DO UPDATE SET "
                  "attributes=excluded.attributes");
  q.bind(1, info.at("object"));
  q.bind(2, int64_t(attributes));
  q.row();
  notify_metadata(info.at("object"), 4);
}
static uint64_t smb_ticks(const json &info, const char *field) {
  return uint64_t(info.at(field).get<int64_t>() / 100 + int64_t(116444736000000000));
}
json smb_times(const json &info) {
  json result = json::array({smb_ticks(info, "created_ns"), smb_ticks(info, "accessed_ns"),
                             smb_ticks(info, "modified_ns"), smb_ticks(info, "changed_ns")});
  statement q(db, "SELECT body FROM smb_times WHERE native=?");
  q.bind(1, info.at("object"));
  if (q.row()) {
    auto stored = json::parse(q.text(0));
    result[0] = stored.at("times").at(0);
    size_t i = 1;
    for (auto field : {"accessed_ns", "modified_ns", "changed_ns"}) {
      if (stored.at(field) == info.at(field))
        result[i] = stored.at("times").at(i);
      ++i;
    }
  }
  return result;
}
json smb_time_record(const std::string &native) {
  statement q(db, "SELECT body FROM smb_times WHERE native=?");
  q.bind(1, native);
  return q.row() ? json::parse(q.text(0)) : json::object();
}
void smb_save_time_record(const std::string &native, const json &value) {
  statement q(db, "INSERT INTO smb_times VALUES(?,?) ON CONFLICT(native) DO UPDATE SET body=excluded.body");
  q.bind(1, native); q.bind(2, value.dump()); q.row();
}
void smb_save_times(const json &info, const json &times) {
  auto native = info.at("object").get<std::string>();
  auto value = smb_time_record(native);
  value["times"] = times;
  for (const auto *field : {"accessed_ns", "modified_ns", "changed_ns"}) value[field] = info.at(field);
  smb_save_time_record(native, value);
}
void smb_reap_times(space_state &s, const std::string &closing = "") {
  auto space = s.data.at("space").at("id").get<std::string>();
  for (auto it = smb_deferred_times.begin(); it != smb_deferred_times.end();) {
    auto native = *it;
    auto value = smb_time_record(native);
    auto pending = value.value("rename_pending", json::object());
    if (pending.empty()) { it = smb_deferred_times.erase(it); continue; }
    statement object_path(db, "SELECT space,path,directory FROM objects WHERE native=?");
    object_path.bind(1, native);
    if (!object_path.row()) {
      value.erase("rename_pending"); smb_save_time_record(native, value);
      it = smb_deferred_times.erase(it); continue;
    }
    if (object_path.text(0) != space) { ++it; continue; }
    bool change = false, notify = false, completed = false;
    auto closer = handles.find(closing);
    bool flush_notifications = closer != handles.end() && closer->second.space == space &&
                               closer->second.path == object_path.text(1);
    for (auto p = pending.begin(); p != pending.end();) {
      // PendingNotifications belongs to the file; any close of this file
      // flushes it. The deferred timestamp belongs to its originating open.
      if (flush_notifications && p.value().at("notify").get<bool>()) {
        notify = true; completed = true; p.value()["notify"] = false; p.value()["archive"] = false;
      }
      if (p.key() != closing && handles.contains(p.key())) { ++p; continue; }
      change |= p.value().at("change").get<bool>();
      notify |= p.value().at("notify").get<bool>();
      completed = true; p = pending.erase(p);
    }
    if (!completed) { ++it; continue; }
    auto current = stat_path(s.directory, object_path.text(1), bool(object_path.integer(2)), true);
    if (current && current->at("object") == native) {
      auto times = smb_times(*current);
      if (change) times[3] = uint64_t(now()) * 10000 + 116444736000000000ull;
      value["times"] = times;
      for (const auto *field : {"accessed_ns", "modified_ns", "changed_ns"}) value[field] = current->at(field);
    } else notify = false; // Never update or notify a replacement incarnation.
    if (pending.empty()) value.erase("rename_pending");
    else value["rename_pending"] = std::move(pending);
    smb_save_time_record(native, value);
    if (notify) notify_metadata(native, 4);
    if (!value.contains("rename_pending")) it = smb_deferred_times.erase(it);
    else ++it;
  }
}
static uint64_t smb_nanoseconds(uint64_t ticks) {
  constexpr uint64_t epoch = 116444736000000000;
  require(ticks >= epoch && ticks - epoch <= uint64_t(INT64_MAX) / 100, "invalid_timestamp");
  return (ticks - epoch) * 100;
}
void smb_preserve_times(native_file &file, const opened &h, const json &before) {
  if (!h.user_access_time && !h.user_write_time && !h.user_change_time)
    return;
  const auto &times = before.at("times");
  auto info = file.info(true);
  auto accessed = h.user_access_time && smb_ticks(info, "accessed_ns") != times[1]
                      ? std::optional(smb_nanoseconds(times[1]))
                      : std::nullopt;
  auto modified = h.user_write_time && smb_ticks(info, "modified_ns") != times[2]
                      ? std::optional(smb_nanoseconds(times[2]))
                      : std::nullopt;
  if (accessed || modified) {
    file.set_times(accessed, modified);
    info = file.info(true);
  }
  auto after = smb_times(info);
  if (h.user_access_time)
    after[1] = times[1];
  if (h.user_write_time)
    after[2] = times[2];
  if (h.user_change_time)
    after[3] = times[3];
  smb_save_times(info, after);
}
json smb_meta(space_state &s, const opened &h) {
  auto info = h.directory ? (h.path.empty() ? s.directory.info(true)
                                            : s.directory.open(h.path, true).info(true))
                          : h.file.info(true);
  if (!h.path.empty())
    require(info.at("object") == object(h.space, h.path).at("native"), "object_replaced");
  statement q(db, "SELECT 1 FROM smb_pending WHERE space=? AND path=?");
  q.bind(1, h.space);
  q.bind(2, h.path);
  return {{"path", h.path},
          {"directory", h.directory},
          {"size", h.directory ? json(0) : info.at("size")},
          {"allocated", info.at("allocated")},
          {"modified_ns", info.at("modified_ns")},
          {"object", info.at("object")},
          {"delete_pending", q.row()},
          {"access", h.access},
          {"attributes", smb_attributes(info)},
          {"times", smb_times(info)},
          {"ea_size", smb_ea_size(info)}};
}
json smb_dispatch(const std::string &op, const json &body, const call_context &ctx) {
  require(ctx.caller == "smb", "forbidden");
  if (op == "smb_recover") {
    std::erase_if(handles, [](const auto &entry) { return entry.second.protocol == "smb"; });
    std::erase_if(locks, [&](const auto &entry) { return !handles.contains(entry.handle); });
    smb_waiters.clear();
    statement q(db, "SELECT body FROM spaces");
    std::vector<json> owned;
    while (q.row())
      owned.push_back(json::parse(q.text(0)));
    for (auto value : owned) {
      auto &s = attach(value, ctx);
      smb_reap(s);
    }
    return {{"recovered", true}};
  }
  bool cleanup = op == "smb_close" || op == "smb_lock_cancel";
  bool writing = op == "smb_write" || op == "smb_resize" || op == "smb_allocation" ||
                 op == "smb_rename" || op == "smb_disposition" || op == "smb_attributes" ||
                 op == "smb_set_eas" || op == "smb_set_security";
  if (op == "smb_open")
    writing = body.value("write", false);
  auto grant = verify(body.at("grant"), writing, cleanup);
  require(grant.at("protocol") == "smb", "forbidden");
  auto owner_authority = grant.value("owner_authority", "none");
  bool restore_owner = owner_authority == "restore" && grant.at("write").get<bool>();
  auto space = grant.at("space").at("id").get<std::string>(),
       path = grant.at("path").get<std::string>(), actor = grant.at("actor").get<std::string>();
  auto &s = attach(grant, ctx);
  if (!cleanup)
    lease(grant, ctx);
  if (op == "smb_path_stat") {
    auto f = path.empty() ? native_file() : s.directory.open(path, true);
    auto info = path.empty() ? s.directory.info() : f.info();
    info["size"] = 0;
    return info;
  }
  if (op == "smb_open") {
    // An EXCLUSIVE oplock does not relax sharing. Reject an incompatible
    // ordinary open before recalling dirty data that it cannot access anyway.
    if (!body.value("maximum", false)) {
      auto requested = smb_categories(body.at("access").get<uint32_t>());
      auto share = body.at("sharing").get<unsigned>();
      for (const auto &[other, held] : handles)
        if (held.cache && held.space == space && held.path == path && requested) {
          auto existing = smb_categories(held.access);
          require((requested & ~held.sharing) == 0 && (existing & ~share) == 0,
                  "sharing_violation");
        }
    }
    require(handles.size() < 128, "handle_limit");
    if (!path.empty())
      portable_path(path);
    uint32_t access = body.at("access");
    unsigned sharing = body.at("sharing"), disposition = body.at("disposition"),
             options = body.at("options");
    require(sharing <= 7 && disposition <= 5, "invalid_request");
    require(!(options & 0x200) || !body.contains("eas"), "forbidden");
    // Standard file rights are valid even when an optional SET_INFO operation
    // is unavailable. Granting them never bypasses the space's write policy.
    // ACCESS_SYSTEM_SECURITY is privilege-gated, not an unknown DACL right.
    // Native ACL editors use PRIVILEGE_NOT_HELD to retry without audit changes.
    require(!(access & 0x01000000u), "privilege_not_held");
    require((access & ~0x001f01ffu) == 0, "forbidden");
    require(!(access & (0xd0000u | 0x156u)) || grant.at("write").get<bool>(), "forbidden");
    // Attribute-only OPEN/OPEN_IF does not consume cached data. Retain the
    // already pinned native object instead of opening its pathname for read,
    // which would itself break the kernel lease. The new SMB handle still has
    // its own granted rights; a later metadata mutation recalls before acting.
    std::optional<json> cached_info;
    native_file cached_file;
    std::string cache_owner;
    if (!body.value("maximum", false) && !(access & ~0x00100180u) &&
        (disposition == 1 || disposition == 3) && !(options & 0x1000)) {
      for (const auto &[id, held] : handles)
        if (held.cache && held.space == space && held.path == path && !held.directory) {
          cached_info = held.file.info(true);
          require(cached_info->at("object") == object(space, path).at("native"),
                  "object_replaced");
          cached_file = held.file.retain();
          cache_owner = id;
          break;
        }
    }
    cache_conflict(space, path, cache_owner);
    smb_reap(s);
    auto existing = cached_info ? cached_info : dav_exists(s, path);
    require(!existing || disposition != 2, "already_exists");
    bool directory = existing ? existing->at("directory").get<bool>() : bool(options & 1);
    require(!(options & 1) || directory, "not_directory");
    require(!(options & 0x40) || !directory, "is_directory");
    require(existing || disposition == 0 || disposition == 2 || disposition == 3 ||
                disposition == 5,
            "not_found");
    require(!existing || disposition != 2, "already_exists");
    uint32_t requested_attributes = body.value("attributes", uint32_t(0));
    auto normalized_attributes = smb_attribute_value(requested_attributes, directory);
    if (existing) {
      auto existing_file = path.empty() || cached_info ? native_file()
                                                       : s.directory.open(path, directory);
      auto info = cached_info ? *cached_info
                              : path.empty() ? s.directory.info() : existing_file.info();
      auto attributes = smb_attributes(info);
      if (options & 0x200) {
        auto values = smb_eas(info);
        for (auto &[name, ea] : values.items())
          require(ea.at("flags") == 0, "forbidden");
      }
      if (!directory && (attributes & 1)) {
        if (body.value("maximum", false)) {
          require(!(body.value("explicit_access", uint32_t(0)) & 6), "forbidden");
          access &= ~6u;
        }
        require(!(access & 6), "forbidden");
        require(!(options & 0x1000), "cannot_delete");
      }
    }
    auto descriptor = existing ? security_get(s, cached_info ? *cached_info : security_info(s, path))
                               : security_new(s, grant, path, directory);
    if (!existing) {
      security_add(s, grant, path, directory);
      if (body.contains("security")) {
        auto supplied = security::decode(decode_bytes(body.at("security").get<std::string>()));
        auto owner = security::principal(actor);
        require(supplied.at("owner") == "" || supplied.at("owner") == owner || restore_owner,
                "invalid_owner");
        if (supplied.at("owner") != "") {
          owner = supplied.at("owner");
          descriptor["owner"] = owner;
        }
        if (supplied.at("group") != "") {
          bool valid_group = supplied.at("group") == descriptor.at("group");
          for (const auto &group : grant.value("groups", json::array()))
            valid_group |=
                supplied.at("group") == security::principal(group.get<std::string>(), true);
          require(valid_group || restore_owner, "invalid_owner");
          descriptor["group"] = supplied.at("group");
        }
        auto parent_sd = security_get(s, security_info(s, security_parent(path)));
        // Resolve CREATOR OWNER/GROUP using the restored creation identities,
        // including a SecD that supplies ownership without an explicit DACL.
        if (supplied.at("group") != "")
          parent_sd["group"] = descriptor.at("group");
        descriptor = security::inherit(parent_sd, owner, descriptor.at("group"), directory);
        auto control = supplied.at("control").get<uint32_t>();
        if (control & 4) {
          descriptor["dacl"] = supplied.at("dacl");
          descriptor["control"] = (control & 0x100c) | 0x8000;
          if (!(control & 0x1000) && !supplied.at("dacl").is_null()) {
            auto inherited =
                security::inherit(parent_sd, owner, descriptor.at("group"), directory, false);
            for (const auto &entry : inherited.at("dacl"))
              descriptor["dacl"].push_back(entry);
            descriptor["control"] = descriptor.at("control").get<uint32_t>() |
                                    (inherited.at("control").get<uint32_t>() & 0x400);
          }
        }
        require(descriptor.at("dacl").size() <= 1024 &&
                    security::encode(descriptor, 7).size() <= 65536,
                "invalid_security_descriptor");
      }
    }
    auto permitted = security::allowed(descriptor, security::token(grant));
    // Taking ownership overrides WRITE_OWNER. Restoration bypasses this DACL
    // right only on backup-intent opens; ordinary MAXIMUM_ALLOWED/MxAc must
    // still reflect the DACL. Neither mode grants data, WRITE_DAC or SACL access.
    if (grant.at("write").get<bool>() &&
        (owner_authority == "take" || (restore_owner && (options & 0x4000))))
      permitted |= 0x80000;
    if (existing && !path.empty()) {
      auto parent_access = security_allowed(s, grant, security_info(s, security_parent(path)));
      if (parent_access & 0x40)
        permitted |= 0x10000;
      if (parent_access & 1)
        permitted |= 0x80;
    }
    // Once the parent permits creation, the creating open receives its requested
    // rights; the inherited DACL controls subsequent opens (MS-FSA 2.1.5.1.1).
    auto open_permissions = existing ? permitted : 0x1f01ffu;
    if (body.value("maximum", false)) {
      require((body.value("explicit_access", uint32_t(0)) & ~open_permissions) == 0, "forbidden");
      access &= open_permissions;
      require(access != 0, "forbidden");
    } else
      require((access & ~open_permissions) == 0, "forbidden");
    smb_sharing(space, path, access, sharing);
    bool truncate = existing && (disposition == 0 || disposition == 4 || disposition == 5);
    // Validate all initial metadata and quota before creating or truncating a file.
    if (!existing && body.contains("eas"))
      smb_merge_eas(json::object(), body.at("eas"));
    auto allocation = body.contains("allocation") ? number(body, "allocation") : 0;
    bool allocating = !directory && (!existing || truncate) && body.contains("allocation");
    if (allocating)
      quota(s, existing ? growth(s.directory.open(path, false).info(), allocation) : allocation);
    require(!truncate || (!directory && (access & 2)), "forbidden");
    require(disposition != 0 || (access & 0x10000), "forbidden");
    require(!(options & 0x1000) || (!path.empty() && (access & 0x10000)), "forbidden");
    if ((options & 0x1000) && existing)
      security_sticky(s, grant, path);
    if (!existing || truncate) {
      require(!path.empty() && grant.at("write").get<bool>(), "forbidden");
      dav_guard(s, path, actor, body, false, !existing);
      case_check(s.directory, path);
    }
    native_file file;
    if (!existing) {
      file = s.directory.open(path, directory, true, !directory);
      security_save(file.info(), descriptor);
      file.flush();
      s.directory.flush();
      index(space, path, file.info());
    } else if (!directory)
      file = cached_info ? std::move(cached_file)
                         : s.directory.open(path, false, false, bool(access & 6));
    if (truncate) {
      auto before = file.info();
      security_data_changed(s, before);
      if (allocating && allocation) {
        auto native = before.at("object").get<std::string>();
        allocation_reservation(native, std::max(allocation_reservation(native), allocation));
        // Establish capacity before destroying the old contents. The final
        // allocation below is still needed because native truncation can free
        // preallocated extents; an overwrite is not an atomic replacement.
        // Native allocation only shrinks EOF after successfully reserving the
        // requested extent. Allocating the old EOF would materialize a sparse
        // file and could reject a small overwrite for lack of disk space.
        file.allocate(allocation);
      }
      file.truncate(0);
      file.flush();
      index(space, path, file.info());
      allocation_reservation(before.at("object"), 0);
    }
    if (allocating) {
      auto info = file.info();
      auto native = info.at("object").get<std::string>();
      allocation_reservation(native, allocation);
      try {
        file.allocate(allocation);
        file.flush();
        index(space, path, file.info());
      } catch (...) {
        // A failed new CREATE must not leave a file or charge quota. Never
        // remove an unrelated object that replaced the newly created name.
        if (!existing) {
          file = native_file();
          auto current = stat_path(s.directory, path);
          if (current && current->at("object") == native) {
            s.directory.remove(path, false, native);
            s.directory.flush();
            erase(space, path);
            allocation_reservation(native, 0);
          }
        } else
          index(space, path, file.info());
        throw;
      }
    }
    if (!existing || truncate) {
      auto info = file.info();
      auto attributes = normalized_attributes;
      if (!directory)
        attributes = (attributes & ~0x80u) | 0x20u;
      smb_save_attributes(info, attributes);
      if (!existing && body.contains("eas"))
        smb_update_eas(info, body.at("eas"));
      // Initial metadata is part of the added object, not a later mutation.
      // Keep native CREATE visible but do not emit synthetic MODIFIED events
      // for the descriptor, attributes or EAs assigned by this same CREATE.
      if (!existing) pending_metadata.erase(info.at("object").get<std::string>());
    }
    if (directory)
      file = native_file();
    auto id = generation + ":" + random_hex(16);
    opened h{std::move(file), actor, space, path, bool(access & 6), grant.at("epoch"), "smb"};
    h.access = access;
    h.sharing = sharing;
    h.directory = directory;
    auto meta = smb_meta(s, h);
    if (options & 0x1000) {
      statement intent(db, "INSERT INTO smb_close_delete VALUES(?,?,?,?,?,?)");
      intent.bind(1, id); intent.bind(2, space); intent.bind(3, path);
      intent.bind(4, meta.at("object")); intent.bind(5, int64_t(directory));
      intent.bind(6, std::string()); intent.row();
    }
    handles.emplace(id, std::move(h));
    meta["maximal_access"] = permitted;
    meta["handle"] = id;
    meta["action"] = !existing ? 2 : truncate ? (disposition == 0 ? 0 : 3) : 1;
    return meta;
  }
  if (op == "smb_quota") {
    scan(s, ctx);
    return {{"used", used(space)},
            {"reserved", reserved(space)},
            {"limit", s.data.at("space").at("quota")}};
  }
  auto id = body.at("handle").get<std::string>();
  auto it = handles.find(id);
  if (cleanup && it == handles.end())
    return {{"closed", true}};
  require(it != handles.end() && id.starts_with(generation + ":"), "stale_handle");
  auto &h = it->second;
  require(h.protocol == "smb" && h.space == space && h.actor == actor &&
              (cleanup || h.path == path),
          "forbidden");
  if (op.starts_with("smb_cache_")) {
    if (op == "smb_cache_acquire" && smb_meta(s, h).at("delete_pending").get<bool>())
      return {{"granted", false}, {"cookie", ""}, {"breaking", false}, {"remaining_ms", 0}};
    return cache_dispatch(op, body, grant, h);
  }
  // Recall before any namespace/metadata mutation. Repeating a deferred SMB
  // request is safe only when no mutation has happened before this boundary.
  if (op == "smb_rename" || op == "smb_disposition" || op == "smb_attributes" ||
      op == "smb_set_eas" || op == "smb_set_security" || op == "smb_resize" ||
      op == "smb_allocation" || op == "smb_list") {
    cache_conflict(space, path);
    if (op == "smb_rename") {
      auto target = verify(body.at("target"), true);
      require(target.at("space").at("id") == space && target.at("actor") == actor &&
              target.at("protocol") == "smb", "forbidden");
      cache_conflict(space, target.at("path"));
    }
  }
  if (op == "smb_lock_cancel") {
    const auto token = body.at("waiter").get<std::string>();
    std::erase_if(smb_waiters,
                  [&](const auto &w) { return w.token == token && w.range.handle == id; });
    return {{"cancelled", true}};
  }
  if (cleanup) {
    if (h.cache) {
      h.file.flush();
      h.cache.reset(); h.cache_cookie.clear();
      h.cache_authority_until = h.cache_break_until = 0;
    }
    smb_reap_times(s, id);
    auto meta = smb_meta(s, h);
    handles.erase(it);
    std::erase_if(locks, [&](const auto &v) { return v.handle == id; });
    std::erase_if(smb_waiters, [&](const auto &w) { return w.range.handle == id; });
    smb_reap(s);
    return meta;
  }
  auto meta = smb_meta(s, h);
  if (op == "smb_notify") {
    require(!meta.at("delete_pending").get<bool>(), "delete_pending");
    require(h.directory, "invalid_request");
    require(h.access & 1, "forbidden");
    if (!h.notification) {
      h.notify_filter = body.at("filter").get<uint32_t>() & 0xfff;
      h.notify_recursive = body.at("recursive");
      auto directory = path.empty() ? s.directory.retain() : s.directory.open(path, true);
      h.notification = directory.watch(h.notify_recursive, h.notify_filter);
    }
    if (body.value("register", false)) return {{"pending", true}};
    collect_notifications(h);
    require(!h.notify_deleted, "notify_cleanup");
    bool overflow = h.notify_overflow;
    auto events = std::move(h.notify_events);
    h.notify_events = json::array(); h.notify_overflow = false; h.notify_bytes = 0;
    return {{"pending", !overflow && events.empty()}, {"overflow", overflow}, {"events", events}};
  }
  if (op == "smb_security" || op == "smb_set_security") {
    uint32_t information = body.at("information");
    require(!(information & 8), "forbidden");
    require((information & 7) && !(information & ~0xa0000007u), "not_supported");
    require(!((information & 0x80000000) && (information & 0x20000000)), "invalid_request");
    auto descriptor = security_get(s, meta);
    if (op == "smb_security") {
      require(h.access & 0x20000, "forbidden");
      return {{"data", encode_bytes(security::encode(descriptor, information))}};
    }
    require(!(information & 4) || (h.access & 0x40000), "forbidden");
    require(!(information & 3) || (h.access & 0x80000), "forbidden");
    require(!(information & 0xa0000000) || (information & 4), "invalid_request");
    auto replacement = security::decode(decode_bytes(body.at("data").get<std::string>()));
    if (!h.directory && (information & 3))
      descriptor["mode_special"] = descriptor.value("mode_special", 0u) & ~06000u;
    auto subjects = security::token(grant);
    if (information & 1) {
      require(replacement.at("owner") != "" &&
                  (replacement.at("owner") == subjects.at(0) || restore_owner), "invalid_owner");
      descriptor["owner"] = replacement.at("owner");
    }
    if (information & 2) {
      auto group = replacement.at("group");
      bool valid_group = false;
      for (const auto &name : grant.value("groups", json::array()))
        valid_group |= group == security::principal(name.get<std::string>(), true);
      // The primary group of an existing descriptor may be retained.
      require(group != "" && (valid_group || group == descriptor.at("group") || restore_owner),
              "invalid_owner");
      descriptor["group"] = group;
      if (!descriptor.at("dacl").is_null())
        for (auto &entry : descriptor["dacl"])
          if (entry.value("nfs_who", "") == "GROUP@")
            entry["sid"] = group;
    }
    if (information & 4) {
      descriptor["dacl"] = replacement.at("dacl");
      auto control = descriptor.at("control").get<uint32_t>();
      auto supplied = replacement.at("control").get<uint32_t>();
      control = (control & ~0x150cu) | (supplied & 0x100c);
      if ((supplied & 0x500) == 0x500)
        control |= 0x400;
      if (information & 0x80000000)
        control |= 0x1000;
      if (information & 0x20000000)
        control &= ~0x1000u;
      descriptor["control"] = control;
    }
    lease(grant, ctx);
    transaction tx(db);
    security_save(meta, descriptor);
    auto times = meta.at("times");
    times[3] = uint64_t(now()) * 10000 + 116444736000000000ULL;
    auto info = h.directory ? security_info(s, path) : h.file.info(true);
    smb_save_times(info, times);
    audit(actor, "smb_set_security", path);
    tx.commit();
    return {{"updated", true}};
  }
  if (op == "smb_stat")
    return meta;
  if (op == "smb_list") {
    require(h.directory && (h.access & 1), "forbidden");
    json entries = json::array();
    auto dir = path.empty() ? native_file() : s.directory.open(path, true);
    auto &root = path.empty() ? s.directory : dir;
    size_t total = 0;
    for (auto value : root.list()) {
      auto name = value.at("name").get<std::string>();
      if (name.starts_with(".tc-"))
        continue;
      portable_path(name);
      auto child = path.empty() ? name : path + "/" + name;
      auto info = s.directory.open(child, value.at("directory")).info(true);
      if (grant.value("access_based_enumeration", false) &&
          (security_allowed(s, grant, info) & 0x20089) != 0x20089)
        continue;
      index(space, child, info);
      auto item = dav_meta(s, child);
      item["name"] = name;
      item["object"] = info.at("object");
      item["attributes"] = smb_attributes(info);
      item["times"] = smb_times(info);
      item["ea_size"] = smb_ea_size(info);
      item["allocated"] = info.at("allocated");
      total += item.dump().size();
      require(entries.size() < 1024 && total <= 256 * 1024, "directory_limit");
      entries.push_back(item);
    }
    return entries;
  }
  if (op == "smb_eas" || op == "smb_set_eas") {
    require(h.access & (op == "smb_eas" ? 8 : 16), "forbidden");
    if (op == "smb_set_eas") {
      dav_guard(s, path, actor, body);
      lease(grant, ctx);
      auto directory = h.directory ? (path.empty() ? native_file() : s.directory.open(path, true))
                                   : native_file();
      auto &file = h.directory ? (path.empty() ? s.directory : directory) : h.file;
      auto info = file.info(true);
      require(info.at("object") == meta.at("object"), "object_replaced");
      transaction tx(db);
      smb_update_eas(meta, body.at("eas"));
      auto times = meta.at("times");
      if (!h.user_change_time)
        times[3] = uint64_t(now()) * 10000 + 116444736000000000ull;
      smb_save_times(info, times);
      smb_save_attributes(info, (meta.at("attributes").get<uint32_t>() & ~0x80u) | 0x20u);
      audit(actor, "smb_extended_attributes", path);
      tx.commit();
    }
    return smb_eas(meta);
  }
  if (op == "smb_attributes") {
    require(h.access & 0x100, "forbidden");
    uint32_t requested = body.at("attributes");
    require(h.directory || !(requested & 0x10), "invalid_request");
    require(!h.directory || !(requested & 0x100), "invalid_request");
    auto value = requested ? smb_attribute_value(requested & 0x31b7u, h.directory)
                           : meta.at("attributes").get<uint32_t>();
    if (path.empty())
      value = (value & ~6u) | (meta.at("attributes").get<uint32_t>() & 6u);
    auto input = body.value("times", json::array({0, 0, 0, 0}));
    require(input.is_array() && input.size() == 4, "invalid_request");
    auto times = meta.at("times");
    bool user_access = h.user_access_time, user_write = h.user_write_time,
         user_change = h.user_change_time;
    bool changed = value != meta.at("attributes");
    std::optional<uint64_t> access_time, write_time;
    for (size_t i = 0; i < 4; ++i) {
      require(input[i].is_number_unsigned() ||
                  (input[i].is_number_integer() && input[i].get<int64_t>() >= 0),
              "invalid_timestamp");
      auto t = input[i].get<uint64_t>();
      require(t <= uint64_t(INT64_MAX) || t >= UINT64_MAX - 1, "invalid_timestamp");
      if (!t)
        continue;
      if (i == 1)
        user_access = t != UINT64_MAX - 1;
      if (i == 2)
        user_write = t != UINT64_MAX - 1;
      if (i == 3)
        user_change = t != UINT64_MAX - 1;
      if (t >= UINT64_MAX - 1)
        continue;
      changed = changed || times[i] != t;
      times[i] = t;
      if (i == 1)
        access_time = smb_nanoseconds(t);
      if (i == 2)
        write_time = smb_nanoseconds(t);
    }
    if (changed && !user_change)
      times[3] = uint64_t(now()) * 10000 + 116444736000000000ull;
    dav_guard(s, path, actor, body);
    lease(grant, ctx);
    auto directory =
        h.directory ? (path.empty() ? native_file() : s.directory.open(path, true)) : native_file();
    auto &file = h.directory ? (path.empty() ? s.directory : directory) : h.file;
    if (access_time || write_time)
      file.set_times(access_time, write_time);
    auto info = file.info(true);
    transaction tx(db);
    smb_save_attributes(info, value);
    smb_save_times(info, times);
    auto saved = smb_time_record(info.at("object"));
    if (saved.contains("rename_pending") && saved["rename_pending"].contains(id)) {
      auto &pending = saved["rename_pending"][id];
      pending["change"] = !user_change;
      pending["notify"] = !h.directory && (!user_change || pending.value("archive", false));
      smb_save_time_record(info.at("object"), saved);
    }
    audit(actor, "smb_basic_information", path);
    tx.commit();
    if (times[0] != meta.at("times")[0]) notify_metadata(info.at("object"), 64);
    h.user_access_time = user_access;
    h.user_write_time = user_write;
    h.user_change_time = user_change;
    return smb_meta(s, h);
  }
  if (op == "smb_flush") {
    if (!h.directory)
      h.file.flush();
    return {{"flushed", true}};
  }
  if (op == "smb_lock") {
    require(!h.directory, "invalid_request");
    require(h.access & 0x27, "forbidden");
    auto requested = body.at("locks");
    require(requested.is_array() && !requested.empty() && requested.size() <= 64,
            "invalid_request");
    auto candidate = locks;
    const bool unlocking = requested.front().at("flags") == 4;
    for (auto v : requested) {
      auto lock_number = [&](const char *key) {
        const auto &n = v.at(key);
        require(n.is_number_unsigned() || (n.is_number_integer() && n.get<int64_t>() >= 0),
                "invalid_offset");
        return n.get<uint64_t>();
      };
      auto start = lock_number("offset"), length = lock_number("length");
      unsigned flags = v.at("flags");
      require(!length || length - 1 <= UINT64_MAX - start, "invalid_lock_range");
      const bool through_max = length && start + length == 0;
      if (unlocking) {
        require(flags == 4, "invalid_request");
        auto matches = [&](const auto &l) {
          return l.handle == id && l.start == start && l.end == start + length && l.through_max == through_max;
        };
        // Exclusive entries precede stacked shared entries on exact unlock.
        auto found = std::find_if(candidate.begin(), candidate.end(), [&](const auto &l) { return matches(l) && l.exclusive; });
        if (found == candidate.end()) found = std::find_if(candidate.begin(), candidate.end(), matches);
        require(found != candidate.end(), "range_not_locked");
        candidate.erase(found);
        locks = candidate; // Unlocks commit individually; later failure preserves earlier unlocks.
      } else {
        require(flags == 1 || flags == 2 || flags == 0x11 || flags == 0x12,
                "invalid_request");
        require(requested.size() == 1 || (flags & 0x10), "invalid_request");
        bool exclusive = (flags & 2) != 0;
        const auto token = body.value("waiter", std::string());
        require(token.empty() || (token.size() == 32 && requested.size() == 1 && !(flags & 0x10)),
                "invalid_request");
        byte_lock range{id, meta.at("object"), start, start + length, exclusive, through_max};
        auto conflicts = [&](const byte_lock &l) {
          return l.object == range.object && (l.through_max || start < l.end) &&
                 (through_max || start + length > l.start) &&
                 (exclusive || (l.exclusive && l.handle != id));
        };
        bool blocked = std::any_of(candidate.begin(), candidate.end(), conflicts);
        // Preserve arrival order for conflicting waiters in the authority shared
        // by every connection. Disjoint ranges and compatible readers proceed.
        for (const auto &w : smb_waiters) {
          if (!token.empty() && w.token == token) {
            require(w.range.handle == id && w.range.object == range.object &&
                        w.range.start == start && w.range.end == range.end &&
                        w.range.exclusive == exclusive && w.range.through_max == through_max,
                    "invalid_request");
            break;
          }
          blocked |= conflicts(w.range);
        }
        if (blocked) {
          require(!(flags & 0x10), "lock_not_granted");
          require(!token.empty(), "invalid_request");
          if (std::none_of(smb_waiters.begin(), smb_waiters.end(),
                           [&](const auto &w) { return w.token == token; })) {
            require(smb_waiters.size() < 256, "lock_limit");
            smb_waiters.push_back({token, range});
          }
          return {{"pending", true}};
        }
        require(candidate.size() < 256, "lock_limit");
        candidate.push_back(std::move(range));
        if (!token.empty())
          std::erase_if(smb_waiters,
                        [&](const auto &w) { return w.token == token && w.range.handle == id; });
      }
    }
    locks = std::move(candidate);
    return {{"locked", true}};
  }
  if (op == "smb_disposition") {
    require(!path.empty() && (h.access & 0x10000), "forbidden");
    if (body.at("delete").get<bool>()) {
      security_sticky(s, grant, path);
      require(h.directory || !(meta.at("attributes").get<uint32_t>() & 1), "cannot_delete");
      for (auto &[other, x] : handles)
        if (other != id && x.space == space && x.path == path)
          require(x.protocol == "smb" && (x.sharing & 4), "sharing_violation");
      if (h.directory) {
        auto dir = s.directory.open(path, true);
        require(dir.list(true).empty(), "directory_not_empty");
      }
      dav_guard(s, path, actor, body);
      statement mark(db, "INSERT OR REPLACE INTO smb_pending VALUES(?,?,?,?)");
      mark.bind(1, space);
      mark.bind(2, path);
      mark.bind(3, meta.at("object"));
      mark.bind(4, int64_t(h.directory));
      mark.row();
    } else {
      statement del(db, "DELETE FROM smb_pending WHERE space=? AND path=?");
      del.bind(1, space);
      del.bind(2, path);
      del.row();
    }
    return {{"updated", true}};
  }
  if (op == "smb_rename") {
    require(!path.empty() && (h.access & 0x10000) && !meta.at("delete_pending").get<bool>(),
            "forbidden");
    security_sticky(s, grant, path);
    auto target = verify(body.at("target"), true);
    require(target.at("protocol") == "smb" && target.at("space").at("id") == space &&
                target.at("actor") == actor && target.at("share") == grant.at("share"),
            "forbidden");
    auto to = target.at("path").get<std::string>();
    portable_path(to);
    security_add(s, target, to, h.directory);
    if (dav_exists(s, to))
      security_delete(s, target, to);
    if (to == path) return {{"from", path}, {"path", to}, {"space", space}};
    require(!beneath(to, path), "invalid_path");
    case_check(s.directory, to);
    dav_guard(s, path, actor, body, h.directory, true);
    dav_guard(s, to, actor, body, h.directory, true);
    auto parent = [](const std::string &p) {
      auto slash = p.rfind('/');
      return slash == std::string::npos ? std::string() : p.substr(0, slash);
    };
    // MS-FSA 2.1.5.15.12 opens the destination directory for ADD_FILE or
    // ADD_SUBDIRECTORY with READ|WRITE|DELETE sharing. A source-directory
    // open is not that destination open. Older Windows versions omitted
    // SHARE_DELETE here (product note 185); do not impose that old restriction.
    smb_sharing(space, parent(to), h.directory ? 4u : 2u, 7);
    if (h.directory)
      for (const auto &[other, x] : handles)
        require(x.space != space || x.path == path || !beneath(x.path, path), "forbidden");
    for (auto &[other, x] : handles)
      if (other != id && x.space == space && beneath(x.path, path))
        require(x.protocol == "smb" && (!smb_categories(x.access) || (x.sharing & 4)), "sharing_violation");
    auto dest = dav_exists(s, to);
    if (dest) {
      require(body.value("replace", false), "already_exists");
      require(!dest->at("directory").get<bool>() && !h.directory, "not_supported");
      unlocked(space, to);
    }
    statement pending_tree(db, "SELECT path FROM smb_pending WHERE space=?");
    pending_tree.bind(1, space);
    while (pending_tree.row())
      require(!beneath(pending_tree.text(0), path) && !beneath(pending_tree.text(0), to),
              "delete_pending");
    lease(target, ctx);
    // Record both possible names before the native rename. Recovery checks
    // native incarnation at either name and never deletes a replacement.
    statement intent_target(db, "UPDATE smb_close_delete SET target=? WHERE space=? AND path=?");
    intent_target.bind(1, to); intent_target.bind(2, space); intent_target.bind(3, path);
    intent_target.row();
    // On failure keep both names: flush can fail after a successful rename.
    s.directory.rename(path, to, body.value("replace", false), h.directory);
    s.directory.flush();
    statement intent_moved(db, "UPDATE smb_close_delete SET path=?,target='' WHERE space=? AND path=?");
    intent_moved.bind(1, to); intent_moved.bind(2, space); intent_moved.bind(3, path);
    intent_moved.row();
    // A native rename is atomic. Rescan reconciles the path index after a crash in the SQL gap.
    for (auto &[other, x] : handles)
      if (x.space == space && beneath(x.path, path))
        x.path = to + x.path.substr(path.size());
    // Preserve the basic times until CLOSE (MS-FSA product note 187).
    // Archive and the deferred change/notification survive loss of the SMB
    // process; record them by native incarnation and originating open.
    scan(s, ctx);
    auto moved = h.directory ? s.directory.open(to, true) : native_file();
    auto info = h.directory ? moved.info(true) : h.file.info(true);
    auto native = info.at("object").get<std::string>();
    transaction tx(db);
    smb_save_times(info, meta.at("times"));
    auto value = smb_time_record(native);
    auto attributes = meta.at("attributes").get<uint32_t>();
    bool archive_changed = !h.directory && !(attributes & 0x20);
    if (!h.directory) {
      statement archive(db, "INSERT INTO smb_attributes VALUES(?,?) ON CONFLICT(native) DO UPDATE SET attributes=excluded.attributes");
      archive.bind(1, native); archive.bind(2, int64_t((attributes & ~0x80u) | 0x20u)); archive.row();
    }
    if (value.contains("rename_pending") && value["rename_pending"].contains(id))
      archive_changed |= value["rename_pending"][id].value("archive", false);
    value["rename_pending"][id] = {{"change", !h.user_change_time}, {"archive", archive_changed},
                                   {"notify", !h.directory && (!h.user_change_time || archive_changed)}};
    smb_save_time_record(native, value);
    tx.commit();
    smb_deferred_times.insert(native);
    return {{"from", path}, {"path", to}, {"space", space}};
  }
  require(!h.directory, op == "smb_read" ? "invalid_device_request" : "is_directory");
  if (op == "smb_read") {
    require(h.access & 0x21, "forbidden");
    auto offset = number(body, "offset"), count = number(body, "count");
    require(count <= 65536 && offset <= uint64_t(INT64_MAX) - count, "invalid_offset");
    for (auto &l : locks)
      require(!count || !l.exclusive || l.handle == id || l.object != meta.at("object").get<std::string>() ||
                  (!l.through_max && offset >= l.end) || offset + count <= l.start,
              "locked");
    auto data = h.file.read(offset, static_cast<size_t>(count));
    smb_preserve_times(h.file, h, meta);
    return {{"data", encode_bytes(data)}, {"read", data.size()}};
  }
  if (op == "smb_resize" || op == "smb_allocation") {
    require(h.access & 2, "forbidden");
    auto size = number(body, "size");
    auto native = meta.at("object").get<std::string>();
    auto reservation = allocation_reservation(native);
    quota(s, growth(meta, size));
    dav_guard(s, path, actor, body);
    lease(grant, ctx);
    try {
      if (op == "smb_resize" || size < meta.at("size").get<uint64_t>())
        security_data_changed(s, meta);
      if (op == "smb_allocation") {
        // Reserve before touching storage. Failure/crash retains the higher
        // bound until a successful retry/shrink or object deletion releases it.
        allocation_reservation(native, std::max(reservation, size));
        h.file.allocate(size);
      } else
        h.file.truncate(size);
      smb_preserve_times(h.file, h, meta);
      h.file.flush();
    } catch (...) {
      index(space, path, h.file.info());
      throw;
    }
    auto current = h.file.info();
    index(space, path, current);
    if (op == "smb_allocation")
      allocation_reservation(native, size);
    else
      shrink_reservation(meta, size);
    return {{"size", current.at("size")}, {"allocated", current.at("allocated")}};
  }
  if (op == "smb_write") {
    require(h.access & 6, "forbidden");
    auto offset = number(body, "offset");
    auto data = decode_bytes(body.at("data").get<std::string>());
    require(data.size() <= 65536 && offset <= uint64_t(INT64_MAX) - data.size(), "invalid_offset");
    auto previous = meta.at("size").get<uint64_t>();
    require((h.access & 2) || offset == previous, "forbidden");
    if (data.empty()) return {{"written", 0}};
    range_unlocked(id, meta.at("object"), offset, offset + data.size());
    quota(s, growth(meta, offset + data.size()));
    dav_guard(s, path, actor, body);
    lease(grant, ctx);
    auto request = body.at("request_id").get<std::string>(),
         hash = digest(
             json::array({actor, space, path, meta.at("object"), offset, body.at("data")}).dump());
    if (auto result = replay(request, hash))
      return *result;
    pending(request, hash);
    try {
      security_data_changed(s, meta);
      auto written = h.file.write(offset, data);
      smb_preserve_times(h.file, h, meta);
      smb_save_attributes(meta, (meta.at("attributes").get<uint32_t>() & ~0x80u) | 0x20u);
      if (body.value("flush", false))
        h.file.flush();
      transaction tx(db);
      index(space, path, h.file.info());
      json result = {{"written", written}};
      complete(request, result);
      audit(actor, "smb_write", path);
      tx.commit();
      return result;
    } catch (...) {
      index(space, path, h.file.info());
      throw;
    }
  }
  throw error("not_supported");
}
