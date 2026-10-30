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
json smb_meta(space_state &s, const opened &h) {
  auto info = h.directory
                  ? (h.path.empty() ? s.directory.info() : s.directory.open(h.path, true).info())
                  : h.file.info();
  if (!h.path.empty())
    require(info.at("object") == object(h.space, h.path).at("native"), "object_replaced");
  statement q(db, "SELECT 1 FROM smb_pending WHERE space=? AND path=?");
  q.bind(1, h.space);
  q.bind(2, h.path);
  return {{"path", h.path},
          {"directory", h.directory},
          {"size", h.directory ? json(0) : info.at("size")},
          {"modified_ns", info.at("modified_ns")},
          {"object", info.at("object")},
          {"delete_pending", q.row()},
          {"access", h.access}};
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
  bool writing =
      op == "smb_write" || op == "smb_resize" || op == "smb_allocation" ||
      op == "smb_rename" || op == "smb_disposition";
  if (op == "smb_open")
    writing = body.value("write", false);
  auto grant = verify(body.at("grant"), writing, cleanup);
  require(grant.at("protocol") == "smb", "forbidden");
  auto space = grant.at("space").at("id").get<std::string>(),
       path = grant.at("path").get<std::string>(), actor = grant.at("actor").get<std::string>();
  auto &s = attach(grant, ctx);
  if (!cleanup)
    lease(grant, ctx);
  if (op == "smb_open") {
    smb_reap(s);
    require(handles.size() < 128, "handle_limit");
    if (!path.empty())
      portable_path(path);
    uint32_t access = body.at("access");
    unsigned sharing = body.at("sharing"), disposition = body.at("disposition"),
             options = body.at("options");
    require(sharing <= 7 && disposition <= 5, "invalid_request");
    // Attribute/security mutations have no portable implementation in this profile.
    require((access & ~0x001301bfu) == 0, "not_supported");
    require(!(access & (0x10000u | 0x116u)) || grant.at("write").get<bool>(), "forbidden");
    smb_sharing(space, path, access, sharing);
    auto existing = dav_exists(s, path);
    bool directory = existing ? existing->at("directory").get<bool>() : bool(options & 1);
    require(!(options & 1) || directory, "not_directory");
    require(!(options & 0x40) || !directory, "is_directory");
    require(existing || disposition == 0 || disposition == 2 || disposition == 3 ||
                disposition == 5,
            "not_found");
    require(!existing || disposition != 2, "already_exists");
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
      range_unlocked("", file.info().at("object"), 0, UINT64_MAX);
      file.truncate(0);
      file.flush();
      index(space, path, file.info());
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
      auto info = s.directory.open(child, value.at("directory")).info();
      index(space, child, info);
      auto item = dav_meta(s, child);
      item["name"] = name;
      item["object"] = info.at("object");
      total += item.dump().size();
      require(entries.size() < 1024 && total <= 256 * 1024, "directory_limit");
      entries.push_back(item);
    }
    return entries;
  }
  if (op == "smb_flush") {
    if (!h.directory)
      h.file.flush();
    return {{"flushed", true}};
  }
  if (op == "smb_lock") {
    require(!h.directory && (h.access & 7), "forbidden");
    auto requested = body.at("locks");
    require(requested.is_array() && !requested.empty() && requested.size() <= 64,
            "invalid_request");
    auto candidate = locks;
    for (auto v : requested) {
      auto start = number(v, "offset"), length = number(v, "length");
      unsigned flags = v.at("flags");
      require(length > 0 && start <= uint64_t(INT64_MAX) - length, "invalid_offset");
      if (flags == 4) {
        auto found = std::find_if(candidate.begin(), candidate.end(), [&](const auto &l) {
          return l.handle == id && l.start == start && l.end == start + length;
        });
        require(found != candidate.end(), "range_not_locked");
        candidate.erase(found);
      } else {
        require(flags == 0x11 || flags == 0x12, "not_supported");
        bool exclusive = flags == 0x12;
        for (const auto &l : candidate)
          require(l.object != meta.at("object").get<std::string>() || start >= l.end ||
                      start + length <= l.start || (!exclusive && !l.exclusive),
                  "locked");
        require(candidate.size() < 256, "lock_limit");
        candidate.push_back({id, meta.at("object"), start, start + length, exclusive});
      }
    }
    locks = std::move(candidate);
    return {{"locked", true}};
  }
  if (op == "smb_disposition") {
    require(!path.empty() && (h.access & 0x10000), "forbidden");
    if (body.at("delete").get<bool>()) {
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
    require(to != path && !beneath(to, path), "invalid_path");
    case_check(s.directory, to);
    dav_guard(s, path, actor, body, h.directory, true);
    dav_guard(s, to, actor, body, h.directory, true);
    for (auto &[other, x] : handles)
      if (x.space == space && beneath(x.path, path))
        require(x.protocol == "smb" && (x.sharing & 4), "sharing_violation");
    auto dest = dav_exists(s, to);
    if (dest) {
      require(body.value("replace", false), "already_exists");
      require(!dest->at("directory").get<bool>() && !h.directory, "not_supported");
      unlocked(space, to);
    }
    // Pinned Windows parent handles forbid moving an ancestor of a live file.
    // Use the same explicit sharing violation on both platforms.
    if (h.directory)
      for (auto &[other, x] : handles)
        require(x.space != space || x.path == path || !beneath(x.path, path), "sharing_violation");
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
    scan(s, ctx);
    return {{"from", path}, {"path", to}, {"space", space}};
  }
  require(!h.directory, "is_directory");
  if (op == "smb_read") {
    require(h.access & 1, "forbidden");
    auto offset = number(body, "offset"), count = number(body, "count");
    require(count <= 65536 && offset <= uint64_t(INT64_MAX) - count, "invalid_offset");
    for (auto &l : locks)
      require(!l.exclusive || l.handle == id || l.object != meta.at("object").get<std::string>() ||
                  offset >= l.end || offset + count <= l.start,
              "locked");
    auto data = h.file.read(offset, static_cast<size_t>(count));
    return {{"data", encode_bytes(data)}, {"read", data.size()}};
  }
  if (op == "smb_resize" || op == "smb_allocation") {
    require(h.access & 2, "forbidden");
    auto size = number(body, "size"), previous = meta.at("size").get<uint64_t>();
    if (op == "smb_allocation") {
      // Support truncation and the native Windows SetEndOfFile follow-up.
      // Growing preallocation needs separate quota accounting; never claim it.
      require(size <= (previous + 4095) / 4096 * 4096, "not_supported");
      if (size >= previous)
        return {{"size", previous}};
    }
    range_unlocked(id, meta.at("object"), std::min(size, previous), UINT64_MAX);
    quota(s, size > previous ? size - previous : 0);
    dav_guard(s, path, actor, body);
    lease(grant, ctx);
    try {
      h.file.truncate(size);
      h.file.flush();
    } catch (...) {
      index(space, path, h.file.info());
      throw;
    }
    index(space, path, h.file.info());
    return {{"size", size}};
  }
  if (op == "smb_write") {
    require(h.access & 6, "forbidden");
    auto offset = number(body, "offset");
    auto data = decode_bytes(body.at("data").get<std::string>());
    require(data.size() <= 65536 && offset <= uint64_t(INT64_MAX) - data.size(), "invalid_offset");
    auto previous = meta.at("size").get<uint64_t>();
    require((h.access & 2) || offset == previous, "forbidden");
    range_unlocked(id, meta.at("object"), offset, offset + data.size());
    quota(s, offset + data.size() > previous ? offset + data.size() - previous : 0);
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
