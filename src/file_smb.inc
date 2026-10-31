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
  auto space = s.data.at("space").at("id").get<std::string>();
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
void smb_update_eas(const json &info, const json &input) {
  require(input.is_array() && input.size() <= 256, "invalid_request");
  auto values = smb_eas(info);
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
  statement q(
      db, "INSERT INTO smb_eas VALUES(?,?) ON CONFLICT(native) DO UPDATE SET body=excluded.body");
  q.bind(1, info.at("object"));
  q.bind(2, values.dump());
  q.row();
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
  statement q(db, "INSERT INTO smb_attributes VALUES(?,?) ON CONFLICT(native) DO UPDATE SET "
                  "attributes=excluded.attributes");
  q.bind(1, info.at("object"));
  q.bind(2, int64_t(attributes));
  q.row();
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
void smb_save_times(const json &info, const json &times) {
  json value = {{"times", times},
                {"accessed_ns", info.at("accessed_ns")},
                {"modified_ns", info.at("modified_ns")},
                {"changed_ns", info.at("changed_ns")}};
  statement q(
      db, "INSERT INTO smb_times VALUES(?,?) ON CONFLICT(native) DO UPDATE SET body=excluded.body");
  q.bind(1, info.at("object"));
  q.bind(2, value.dump());
  q.row();
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
  bool cleanup = op == "smb_close";
  bool writing = op == "smb_write" || op == "smb_resize" || op == "smb_allocation" ||
                 op == "smb_rename" || op == "smb_disposition" || op == "smb_attributes" ||
                 op == "smb_set_eas";
  if (op == "smb_open")
    writing = body.value("write", false);
  auto grant = verify(body.at("grant"), writing, cleanup);
  require(grant.at("protocol") == "smb", "forbidden");
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
    smb_reap(s);
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
    require((access & ~0x001f01ffu) == 0, "not_supported");
    require(!(access & (0xd0000u | 0x156u)) || grant.at("write").get<bool>(), "forbidden");
    auto existing = dav_exists(s, path);
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
      auto existing_file = path.empty() ? native_file() : s.directory.open(path, directory);
      auto info = path.empty() ? s.directory.info() : existing_file.info();
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
    smb_sharing(space, path, access, sharing);
    bool truncate = existing && (disposition == 0 || disposition == 4 || disposition == 5);
    require(!truncate || (!directory && (access & 2)), "forbidden");
    require(disposition != 0 || (access & 0x10000), "forbidden");
    require(!(options & 0x1000) || (!path.empty() && (access & 0x10000)), "forbidden");
    if ((options & 0x1000) && directory && existing) {
      auto dir = s.directory.open(path, true);
      require(dir.list().empty(), "directory_not_empty");
    }
    if (!existing || truncate) {
      require(!path.empty() && grant.at("write").get<bool>(), "forbidden");
      dav_guard(s, path, actor, body, false, !existing);
      case_check(s.directory, path);
    }
    native_file file;
    if (!existing) {
      file = s.directory.open(path, directory, true, !directory);
      file.flush();
      s.directory.flush();
      index(space, path, file.info());
    } else if (!directory)
      file = s.directory.open(path, false, false, bool(access & 6));
    if (truncate) {
      file.truncate(0);
      file.flush();
      index(space, path, file.info());
    }
    if (!existing || truncate) {
      auto info = file.info();
      auto attributes = normalized_attributes;
      if (!directory)
        attributes = (attributes & ~0x80u) | 0x20u;
      smb_save_attributes(info, attributes);
      if (!existing && body.contains("eas"))
        smb_update_eas(info, body.at("eas"));
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
      statement mark(db, "INSERT OR REPLACE INTO smb_pending VALUES(?,?,?,?)");
      mark.bind(1, space);
      mark.bind(2, path);
      mark.bind(3, meta.at("object"));
      mark.bind(4, int64_t(directory));
      mark.row();
    }
    handles.emplace(id, std::move(h));
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
  if (cleanup) {
    auto meta = smb_meta(s, h);
    handles.erase(it);
    std::erase_if(locks, [&](const auto &v) { return v.handle == id; });
    smb_reap(s);
    return meta;
  }
  auto meta = smb_meta(s, h);
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
    audit(actor, "smb_basic_information", path);
    tx.commit();
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
        for (const auto &l : candidate)
          require(l.object != meta.at("object").get<std::string>() ||
                      (!l.through_max && start >= l.end) ||
                      (!through_max && start + length <= l.start) ||
                      (!exclusive && (!l.exclusive || l.handle == id)),
                  (flags & 0x10) ? "lock_not_granted" : "not_supported");
        require(candidate.size() < 256, "lock_limit");
        candidate.push_back({id, meta.at("object"), start, start + length, exclusive, through_max});
      }
    }
    locks = std::move(candidate);
    return {{"locked", true}};
  }
  if (op == "smb_disposition") {
    require(!path.empty() && (h.access & 0x10000), "forbidden");
    if (body.at("delete").get<bool>()) {
      require(h.directory || !(meta.at("attributes").get<uint32_t>() & 1), "cannot_delete");
      for (auto &[other, x] : handles)
        if (other != id && x.space == space && x.path == path)
          require(x.protocol == "smb" && (x.sharing & 4), "sharing_violation");
      if (h.directory) {
        auto dir = s.directory.open(path, true);
        require(dir.list().empty(), "directory_not_empty");
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
    auto target = verify(body.at("target"), true);
    require(target.at("protocol") == "smb" && target.at("space").at("id") == space &&
                target.at("actor") == actor && target.at("share") == grant.at("share"),
            "forbidden");
    auto to = target.at("path").get<std::string>();
    portable_path(to);
    if (to == path) return {{"from", path}, {"path", to}, {"space", space}};
    require(!beneath(to, path), "invalid_path");
    case_check(s.directory, to);
    dav_guard(s, path, actor, body, h.directory, true);
    dav_guard(s, to, actor, body, h.directory, true);
    auto parent = [](const std::string &p) {
      auto slash = p.rfind('/');
      return slash == std::string::npos ? std::string() : p.substr(0, slash);
    };
    for (const auto &[other, x] : handles)
      if (other != id && x.space == space && x.directory &&
          (x.path == parent(path) || x.path == parent(to)))
        require(x.protocol == "smb" && (!smb_categories(x.access) ||
            (!(x.access & 0x10000) && (x.sharing & 4))), "sharing_violation");
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
    s.directory.rename(path, to, body.value("replace", false), h.directory);
    s.directory.flush();
    // A native rename is atomic. Rescan reconciles the path index after a crash in the SQL gap.
    for (auto &[other, x] : handles)
      if (x.space == space && beneath(x.path, path))
        x.path = to + x.path.substr(path.size());
    // A same-volume Windows rename preserves the file's basic timestamps;
    // Linux ctime still changes, so anchor the SMB values to the new native stamp.
    auto moved = h.directory ? s.directory.open(to, true) : native_file();
    smb_save_times(h.directory ? moved.info(true) : h.file.info(true), meta.at("times"));
    scan(s, ctx);
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
