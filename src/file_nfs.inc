// NFS owns wire state; this file-domain adapter alone owns native identity and I/O.
std::unique_ptr<database> nfs_db;
std::string nfs_key;
void nfs_init() {
  if (nfs_db)
    return;
  nfs_db = std::make_unique<database>(cfg.state / (role + ".nfs.db"));
  sql(*nfs_db,
      "CREATE TABLE IF NOT EXISTS secret(value TEXT NOT NULL);"
      "CREATE TABLE IF NOT EXISTS objects(id TEXT PRIMARY KEY,export TEXT NOT NULL,"
      "token TEXT NOT NULL,path TEXT NOT NULL,directory INTEGER NOT NULL,dead INTEGER NOT NULL);"
      "CREATE INDEX IF NOT EXISTS native ON objects(export,token,dead);"
      "CREATE TABLE IF NOT EXISTS attributes(id TEXT PRIMARY KEY,mode INTEGER NOT NULL);"
      "CREATE TABLE IF NOT EXISTS ownership(id TEXT PRIMARY KEY,uid INTEGER,gid INTEGER);"
      "CREATE TABLE IF NOT EXISTS metadata_times(token TEXT PRIMARY KEY,changed_ns INTEGER NOT NULL);"
      "CREATE TABLE IF NOT EXISTS exclusive_create(id TEXT PRIMARY KEY,verifier TEXT NOT NULL);"
      "CREATE TABLE IF NOT EXISTS change_clock(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);"
      "INSERT OR IGNORE INTO change_clock VALUES(1,0);"
      "CREATE TABLE IF NOT EXISTS changes(token TEXT PRIMARY KEY,signature TEXT NOT NULL,value INTEGER NOT NULL);");
  sql(*nfs_db, "CREATE TABLE IF NOT EXISTS retained(token TEXT PRIMARY KEY,body TEXT NOT NULL);");
  // Earlier previews keyed projections by export handles. Metadata belongs to
  // the native incarnation, so aliases must observe the same attributes.
  {
    transaction tx(*nfs_db);
    sql(*nfs_db,
        "INSERT OR IGNORE INTO attributes SELECT o.token,a.mode FROM attributes a "
        "JOIN objects o ON a.id=o.id ORDER BY o.id;"
        "INSERT OR IGNORE INTO ownership SELECT o.token,a.uid,a.gid FROM ownership a "
        "JOIN objects o ON a.id=o.id ORDER BY o.id;"
        "DELETE FROM attributes WHERE id IN (SELECT id FROM objects);"
        "DELETE FROM ownership WHERE id IN (SELECT id FROM objects);");
    tx.commit();
  }
  statement q(*nfs_db, "SELECT value FROM secret");
  if (q.row())
    nfs_key = q.text(0);
  else {
    nfs_key = random_hex();
    statement add(*nfs_db, "INSERT INTO secret VALUES(?)");
    add.bind(1, nfs_key);
    add.row();
  }
}
void nfs_forget_pin(const std::string &token) {
  statement q(*nfs_db, "DELETE FROM retained WHERE token=?");
  q.bind(1, token); q.row();
  nfs_retained.erase(token);
}
void nfs_restore_pins(space_state &s) {
  nfs_init();
  auto space = s.data.at("space").at("id").get<std::string>();
  std::vector<std::pair<std::string, json>> records;
  {
    statement q(*nfs_db, "SELECT token,body FROM retained");
    while (q.row()) {
      auto body = json::parse(q.text(1));
      if (body.at("space") == space) records.emplace_back(q.text(0), std::move(body));
    }
  }
  for (const auto &[token, record] : records) {
    require(record.at("root") == s.data.at("root") &&
        record.at("space_object") == s.data.at("space").at("object"), "space_replaced");
    auto path = record.at("path").get<std::string>();
    auto pin = record.at("pin").get<std::string>();
    auto object = record.at("object").get<std::string>();
    if (record.value("reaping", false)) {
      try { s.directory.remove(pin, false, object); }
      catch (const error &e) { if (std::string_view(e.what()) != "not_found") throw; }
      s.directory.flush();
      statement dead(*nfs_db, "UPDATE objects SET dead=1 WHERE token=?");
      dead.bind(1, token); dead.row();
      nfs_forget_pin(token);
      continue;
    }
    bool original = s.directory.matches_pin(path, object);
    try {
      auto file = s.directory.open_pin(pin, object);
      require(file.stable_identity() == token, "object_replaced");
      if (original) {
        // Crash before the unlink/atomic replacement: discard only our private
        // link. The original name and its old NFS handle remain valid.
        file = native_file();
        s.directory.remove(pin, false, object);
        s.directory.flush();
        nfs_forget_pin(token);
      } else {
        require(nfs_retained.size() < 128 || nfs_retained.contains(token), "handle_limit");
        nfs_retained.insert_or_assign(token, retained_nfs_file{space, path,
            s.data.at("root").dump(), pin, object, std::move(file)});
      }
    } catch (const error &e) {
      if (std::string_view(e.what()) != "not_found" || !original) throw;
      // The durable journal precedes link creation. No user data was removed.
      nfs_forget_pin(token);
    }
  }
}
void nfs_pin(space_state &s, const json &grant, const std::string &path,
             native_file &file, const std::string &token) {
  require(nfs_retained.size() < 128 && !nfs_retained.contains(token), "handle_limit");
  auto space = grant.at("space").at("id").get<std::string>();
  auto object = file.info().at("object").get<std::string>();
  auto pin = ".tc-nfs-" + random_hex(16);
  json record = {{"space", space}, {"path", path}, {"root", grant.at("root")},
      {"space_object", grant.at("space").at("object")}, {"pin", pin}, {"object", object}};
  statement q(*nfs_db, "INSERT INTO retained VALUES(?,?)");
  q.bind(1, token); q.bind(2, record.dump()); q.row();
  try {
    auto held = file.pin(s.directory, pin);
    nfs_retained.emplace(token, retained_nfs_file{space, path, grant.at("root").dump(),
        pin, object, std::move(held)});
  } catch (...) {
    nfs_restore_pins(s);
    throw;
  }
}
native_file nfs_open(space_state &s, const std::string &path, bool dir, bool write = false) {
  if (path.empty())
    return s.root.open(s.data.at("space").at("path"), true);
  return s.directory.open(path, dir, false, write);
}
std::string nfs_handle(const std::string &export_id, const std::string &id) {
  auto it = std::find(file_roles().begin(), file_roles().end(), role);
  std::string wire(1, 1);
  wire += char(it - file_roles().begin());
  wire += decode_bytes(export_id) + decode_bytes(id);
  wire += decode_bytes(mac(nfs_key, wire).substr(0, 32));
  return encode_bytes(wire); // 50 bytes; UUIDs are never reused.
}
json nfs_meta(space_state &s, const json &g, const std::string &path, native_file &f) {
  auto info = f.info(true);
  std::string token;
  for (const auto &[key, retained] : nfs_retained)
    if (retained.space == g.at("space").at("id").get<std::string>() &&
        retained.file.info().at("object") == info.at("object")) {
      token = key;
      break;
    }
  bool unlinked = !token.empty();
  if (!unlinked) token = f.stable_identity();
  auto export_id = g.at("export").at("uuid").get<std::string>();
  std::string id;
  {
    statement q(*nfs_db, "SELECT id FROM objects WHERE export=? AND token=? AND dead=0");
    q.bind(1, export_id);
    q.bind(2, token);
    if (q.row())
      id = q.text(0);
  }
  {
    statement time(*nfs_db, "SELECT changed_ns FROM metadata_times WHERE token=?");
    time.bind(1, token);
    if (time.row()) info["changed_ns"] = std::max(info.at("changed_ns").get<int64_t>(), time.integer(0));
  }
  auto stamp = info;
  stamp.erase("accessed_ns"); // Reading a file must not invalidate its data cache.
  if (id.empty()) {
    statement count(*nfs_db, "SELECT count(*) FROM objects");
    count.row();
    require(count.integer(0) < 100000, "operation_limit");
    id = random_hex(16);
    statement q(*nfs_db, "INSERT INTO objects VALUES(?,?,?,?,?,0)");
    q.bind(1, id);
    q.bind(2, export_id);
    q.bind(3, token);
    q.bind(4, path);
    q.bind(5, int64_t(info.at("directory").get<bool>()));
    q.row();
  } else {
    statement q(*nfs_db, "UPDATE objects SET path=? WHERE id=?");
    q.bind(1, path);
    q.bind(2, id);
    q.row();
  }
  if (!path.empty() && !unlinked)
    index(g.at("space").at("id"), path, info);
  info["handle"] = nfs_handle(export_id, id);
  info["fileid"] = id.substr(0, 16);
  info["fsid"] = export_id.substr(0, 16);
  info["quota"] = g.at("space").at("quota");
  info["used"] = used(g.at("space").at("id"));
  info["path"] = path;
  info["uid"] = 65534;
  info["gid"] = 65534;
  if (g.at("export").contains("uids"))
    for (const auto &[uid, user] : g.at("export").at("uids").items())
      if (user == g.at("space").at("owner")) {
        info["uid"] = std::stoull(uid);
        break;
      }
  statement attrs(*nfs_db, "SELECT mode FROM attributes WHERE id=?");
  attrs.bind(1, token);
  info["mode"] = attrs.row() ? attrs.integer(0) : (info.at("directory").get<bool>() ? 0700 : 0600);
  stamp["mode"] = info["mode"];
  statement owner(*nfs_db, "SELECT uid,gid FROM ownership WHERE id=?");
  owner.bind(1, token);
  if (owner.row()) {
    info["uid"] = owner.integer(0); info["gid"] = owner.integer(1);
    stamp["uid"] = info["uid"]; stamp["gid"] = info["gid"];
  }
  auto signature = digest(stamp.dump());
  int64_t change = 0;
  {
    statement q(*nfs_db, "SELECT signature,value FROM changes WHERE token=?");
    q.bind(1, token);
    if (q.row() && q.text(0) == signature)
      change = q.integer(1);
  }
  if (!change) {
    transaction tx(*nfs_db);
    statement q(*nfs_db, "SELECT value FROM change_clock WHERE id=1");
    require(q.row() && q.integer(0) < INT64_MAX, "operation_limit");
    change = q.integer(0) + 1;
    statement clock(*nfs_db, "UPDATE change_clock SET value=? WHERE id=1");
    clock.bind(1, change);clock.row();
    statement update(*nfs_db, "INSERT OR REPLACE INTO changes VALUES(?,?,?)");
    update.bind(1, token);update.bind(2, signature);update.bind(3, change);update.row();
    tx.commit();
  }
  info["change"] = change;
  (void)s;
  return info;
}
void nfs_apply_attrs(space_state &s, const json &g, const std::string &path, native_file &f,
                     const json &attrs) {
  auto meta = nfs_meta(s, g, path, f);
  auto raw = decode_bytes(meta.at("handle").get<std::string>());
  statement native(*nfs_db, "SELECT token FROM objects WHERE id=?");
  native.bind(1, encode_bytes(raw.substr(18, 16)));
  require(native.row(), "stale_handle");
  auto id = native.text(0);
  if (attrs.contains("atime_ns") || attrs.contains("mtime_ns"))
    f.set_times(attrs.contains("atime_ns") ? std::optional<uint64_t>(number(attrs, "atime_ns")) : std::nullopt,
                attrs.contains("mtime_ns") ? std::optional<uint64_t>(number(attrs, "mtime_ns")) : std::nullopt);
  if (attrs.contains("mode")) {
    statement q(*nfs_db, "INSERT OR REPLACE INTO attributes VALUES(?,?)");
    q.bind(1, id); q.bind(2, int64_t(number(attrs, "mode"))); q.row();
  }
  if (attrs.contains("uid") || attrs.contains("gid")) {
    statement q(*nfs_db, "INSERT OR REPLACE INTO ownership VALUES(?,?,?)");
    q.bind(1, id); q.bind(2, int64_t(attrs.value("uid", meta.at("uid").get<uint64_t>())));
    q.bind(3, int64_t(attrs.value("gid", meta.at("gid").get<uint64_t>()))); q.row();
  }
  if (attrs.contains("mode") || attrs.contains("uid") || attrs.contains("gid") ||
      attrs.contains("atime_ns") || attrs.contains("mtime_ns")) {
    statement q(*nfs_db, "INSERT INTO metadata_times VALUES(?,?) ON CONFLICT(token) DO UPDATE SET changed_ns=MAX(changed_ns,excluded.changed_ns)");
    q.bind(1, id);q.bind(2, now() * int64_t(1000000));q.row();
  }
}
struct nfs_object {
  std::string path;
  native_file file;
  bool unlinked = false;
};
json nfs_reap(const json &body, const call_context &ctx) {
  require(ctx.caller == "nfs", "forbidden");
  const auto &live = body.at("handles");
  require(live.is_array() && live.size() <= 4096, "invalid_request");
  nfs_init();
  // File-domain restart loses descriptors but not the private links/journal.
  // Reattach every affected registered space before applying the live set.
  std::set<std::string> affected;
  {
    statement q(*nfs_db, "SELECT body FROM retained");
    while (q.row()) affected.insert(json::parse(q.text(0)).at("space"));
  }
  for (const auto &space : affected) {
    statement q(db, "SELECT body FROM spaces WHERE id=?");
    q.bind(1, space); require(q.row(), "space_unavailable");
    attach(json::parse(q.text(0)), ctx);
  }
  std::set<std::string> tokens;
  for (const auto &encoded : live) {
    auto h = decode_bytes(encoded.get<std::string>());
    require(h.size() == 50, "invalid_request");
    // The authenticated NFS worker supplies the complete live/reclaim set.
    statement q(*nfs_db, "SELECT token FROM objects WHERE id=?");
    q.bind(1, encode_bytes(h.substr(18, 16)));
    if (q.row()) tokens.insert(q.text(0));
  }
  for (auto it = nfs_retained.begin(); it != nfs_retained.end();)
    if (!tokens.contains(it->first)) {
      auto &held = it->second;
      auto &s = *spaces.at(held.space);
      {
        statement q(*nfs_db, "SELECT body FROM retained WHERE token=?");
        q.bind(1, it->first); require(q.row(), "internal_error");
        auto record = json::parse(q.text(0)); record["reaping"] = true;
        statement mark(*nfs_db, "UPDATE retained SET body=? WHERE token=?");
        mark.bind(1, record.dump()); mark.bind(2, it->first); mark.row();
      }
      held.file = native_file();
      try { s.directory.remove(held.pin, false, held.object); }
      catch (const error &e) {
        if (std::string_view(e.what()) != "not_found") {
          held.file = s.directory.open_pin(held.pin, held.object);
          throw;
        }
      }
      s.directory.flush();
      statement q(*nfs_db, "UPDATE objects SET dead=1 WHERE token=?");
      q.bind(1, it->first); q.row();
      statement drop(*nfs_db, "DELETE FROM retained WHERE token=?");
      drop.bind(1, it->first); drop.row();
      it = nfs_retained.erase(it);
    } else ++it;
  return {{"retained", nfs_retained.size()}};
}
nfs_object nfs_resolve(space_state &s, const json &g, const std::string &encoded, bool write,
                       const call_context &ctx) {
  auto h = decode_bytes(encoded);
  require(h.size() == 50 && h[0] == 1 &&
              h[1] == char(std::find(file_roles().begin(), file_roles().end(), role) -
                           file_roles().begin()) &&
              equal(h.substr(34), decode_bytes(mac(nfs_key, h.substr(0, 34)).substr(0, 32))) &&
              encode_bytes(h.substr(2, 16)) == g.at("export").at("uuid").get<std::string>(),
          "stale_handle");
  auto id = encode_bytes(h.substr(18, 16));
  std::string path, token;
  bool dir;
  {
    statement q(*nfs_db, "SELECT path,token,directory,dead FROM objects WHERE id=?");
    q.bind(1, id);
    require(q.row(), "stale_handle");
    path = q.text(0);
    token = q.text(1);
    dir = q.integer(2) != 0;
    require(!q.integer(3) || nfs_retained.contains(token), "stale_handle");
  }
  auto prefix = g.at("path").get<std::string>();
  if (auto retained = nfs_retained.find(token); retained != nfs_retained.end()) {
    require(retained->second.space == g.at("space").at("id").get<std::string>() &&
                retained->second.root == g.at("root").dump() &&
                beneath(retained->second.path, prefix), "stale_handle");
    return {retained->second.path, retained->second.file.retain(), true};
  }
  auto attempt = [&](const std::string &p) -> std::optional<native_file> {
    if (!beneath(p, prefix))
      return {};
    try {
      auto f = nfs_open(s, p, dir, write && !dir);
      if (f.stable_identity() == token)
        return f;
    } catch (const error &e) {
      auto code = std::string_view(e.what());
      if (code != "not_found" && code != "unsafe_path" && code != "hardlink_denied" &&
          code != "is_directory")
        throw;
    }
    return {};
  };
  if (auto f = attempt(path))
    return {path, std::move(*f)};
  // The path is only a search hint. Match the kernel incarnation token on the
  // exact confined handle before using it. Exhaustion never tombstones a handle.
  std::vector<std::string> queue{prefix};
  size_t visited = 0;
  for (size_t i = 0; i < queue.size(); ++i) {
    ctx.check();
    require(++visited <= 4096, "directory_limit");
    auto p = queue[i];
    auto d = nfs_open(s, p, true);
    if (dir && d.stable_identity() == token) {
      scan(s, ctx);
      return {p, std::move(d)};
    }
    for (const auto &entry : d.list()) {
      require(++visited <= 4096, "directory_limit");
      auto name = entry.at("name").get<std::string>();
      if (name.starts_with(".tc-"))
        continue;
      auto child = p.empty() ? name : p + "/" + name;
      auto isdir = entry.at("directory").get<bool>();
      if (isdir)
        queue.push_back(child);
      else if (!dir)
        if (auto f = attempt(child)) {
          scan(s, ctx);
          return {child, std::move(*f)};
        }
    }
  }
  // Absence can race an external rename; do not permanently tombstone on a scan.
  // A later retry can find the same incarnation, never a reused inode.
  throw error("stale_handle");
}
json nfs_dispatch(const json &body, const call_context &ctx) {
  require(ctx.caller == "nfs", "forbidden");
  auto op = body.at("op").get<std::string>();
  bool mutation = op == "write" || op == "resize" || op == "create" || op == "mkdir" ||
                  op == "remove" || op == "rename" || op == "setattr";
  if (body.contains("mode")) require(number(body, "mode") <= 0777, "not_supported");
  auto g = verify(body.at("grant"), mutation);
  require(g.at("protocol") == "nfs" && g.contains("export"), "forbidden");
  auto &s = attach(g, ctx);
  nfs_init();
  auto space = g.at("space").at("id").get<std::string>(), actor = g.at("actor").get<std::string>();
  if (op == "root") {
    auto p = g.at("path").get<std::string>();
    auto f = nfs_open(s, p, true);
    return nfs_meta(s, g, p, f);
  }
  auto o = nfs_resolve(s, g, body.at("handle"), mutation || op == "commit", ctx);
  if (op == "lookup" || op == "list" || op == "create" || op == "mkdir" || op == "remove" ||
      op == "rename")
    scan(s, ctx); // Reconcile host changes before consulting the shared namespace index.
  auto before = o.file.info();
  auto p = o.path;
  bool dir = before.at("directory");
  std::string request, hash;
  if (mutation) {
    request = body.at("request_id");
    auto stable = body;
    stable.erase("grant");
    hash = digest(stable.dump() + actor + g.at("export").dump());
    if (auto saved = replay(request, hash))
      return *saved;
    if (!o.unlinked) {
      dav_guard(s, p, actor, body, dir, op == "remove" || op == "rename");
      smb_sharing(space, p, op == "remove" || op == "rename" ? 0x10000 : 2, 7);
    }
    range_unlocked("", before.at("object"), 0, UINT64_MAX);
  } else if (!o.unlinked)
    smb_sharing(space, p, 1, 7);
  lease(g, ctx);
  auto change_before = mutation && dir ? nfs_meta(s, g, p, o.file).at("change").get<uint64_t>() : 0;
  auto finish = [&](json result) {
    if (mutation) {
      if (dir) {
        result["change_before"] = change_before;
        result["change_after"] = nfs_meta(s, g, p, o.file).at("change");
      }
      transaction tx(db);
      complete(request, result);
      audit(actor, "nfs_" + op, p);
      tx.commit();
    }
    return result;
  };
  auto name = [&](const char *field) {
    auto n = body.at(field).get<std::string>();
    portable_path(n);
    require(n.find('/') == std::string::npos, "invalid_path");
    return n;
  };
  if (op == "stat")
    return nfs_meta(s, g, p, o.file);
  if (op == "parent") {
    require(dir, "not_directory");
    auto prefix = g.at("path").get<std::string>();
    if (p == prefix)
      return {{"export_root", true}};
    auto slash = p.rfind('/');
    auto parent = slash == std::string::npos ? std::string() : p.substr(0, slash);
    require(beneath(parent, prefix), "forbidden");
    auto f = nfs_open(s, parent, true);
    return nfs_meta(s, g, parent, f);
  }
  if (op == "lookup") {
    require(dir, "not_directory");
    auto n = name("name");
    auto child = p.empty() ? n : p + "/" + n;
    auto meta = dav_exists(s, child);
    require(meta.has_value(), "not_found");
    auto f = nfs_open(s, child, meta->at("directory"));
    return nfs_meta(s, g, child, f);
  }
  if (op == "list") {
    require(dir, "not_directory");
    json entries = json::array();
    size_t bytes = 0;
    for (const auto &e : o.file.list()) {
      ctx.check();
      auto n = e.at("name").get<std::string>();
      if (n.starts_with(".tc-"))
        continue;
      auto child = p.empty() ? n : p + "/" + n;
      auto f = nfs_open(s, child, e.at("directory"));
      auto entry = nfs_meta(s, g, child, f);
      entry["name"] = n;
      bytes += entry.dump().size();
      require(entries.size() < 1024 && bytes < 200 * 1024, "directory_limit");
      entries.push_back(entry);
    }
    return {{"entries", entries}, {"verifier", digest(entries.dump()).substr(0, 16)}};
  }
  if (op == "read") {
    require(!dir, "is_directory");
    auto off = number(body, "offset"), count = number(body, "count");
    require(count <= 65536 && off <= uint64_t(INT64_MAX) - count, "invalid_offset");
    for (const auto &l : locks)
      require(!count || !l.exclusive || l.object != before.at("object").get<std::string>() || (!l.through_max && off >= l.end) ||
                  off + count <= l.start,
              "locked");
    auto data = o.file.read(off, count);
    auto meta = nfs_meta(s, g, p, o.file);
    meta["data"] = encode_bytes(data);
    meta["eof"] = off + data.size() >= meta.at("size").get<uint64_t>();
    return meta;
  }
  if (op == "commit") {
    require(!dir, "is_directory");
    o.file.flush();
    return nfs_meta(s, g, p, o.file);
  }
  if (op == "write" || op == "resize" || op == "setattr") {
    require(!dir || (op == "setattr" && !body.contains("size")), "is_directory");
    auto off = op == "write" ? number(body, "offset") : body.value("size", uint64_t(0));
    auto data = op == "write" ? decode_bytes(body.at("data").get<std::string>()) : std::string();
    require(data.size() <= 65536 && off <= uint64_t(INT64_MAX) - data.size(), "invalid_offset");
    auto end = off + data.size();
    quota(s, growth(before, end));
    pending(request, hash);
    try {
      if (op == "write") {
        size_t written = 0;
        while (written < data.size()) {
          lease(g, ctx);
          auto n = o.file.write(off + written, std::string_view(data).substr(written));
          require(n > 0 && n <= data.size() - written, "io_error");
          written += n;
        }
      } else if (body.contains("size")) {
        o.file.truncate(off);
        shrink_reservation(before, off);
      }
      if (op == "setattr") nfs_apply_attrs(s, g, p, o.file, body);
      o.file.flush(); // All acknowledgements are FILE_SYNC, even for UNSTABLE requests.
    } catch (...) {
      if (!o.unlinked) index(space, p, o.file.info());
      throw;
    }
    auto meta = nfs_meta(s, g, p, o.file);
    meta["count"] = data.size();
    return finish(meta);
  }
  if (op == "create" || op == "mkdir") {
    require(dir, "not_directory");
    auto n = name("name"), child = p.empty() ? n : p + "/" + n;
    auto mode = body.value("create_mode", 1u);
    require(mode <= 3, "invalid_request");
    if (body.contains("mode")) require(number(body, "mode") <= 0777, "not_supported");
    if (auto existing = dav_exists(s, child)) {
      require(op == "create" && !existing->at("directory").get<bool>() && mode != 1, "already_exists");
      auto f = nfs_open(s, child, false);
      auto result = nfs_meta(s, g, child, f);
      if (mode >= 2) {
        auto raw = decode_bytes(result.at("handle").get<std::string>());
        statement q(*nfs_db, "SELECT verifier FROM exclusive_create WHERE id=?");
        q.bind(1, encode_bytes(raw.substr(18, 16)));
        require(q.row() && q.text(0) == body.at("verifier").get<std::string>(), "already_exists");
      }
      pending(request, hash);
      result["created"] = false;
      return finish(result);
    }
    case_check(s.directory, child);
    if (body.contains("size")) quota(s, number(body, "size"));
    pending(request, hash);
    auto f = s.directory.open(child, op == "mkdir", true, op == "create");
    if (body.contains("size")) {
      require(op == "create", "is_directory");
      f.truncate(number(body, "size"));
    }
    f.flush();
    o.file.flush();
    nfs_apply_attrs(s, g, child, f, body);
    f.flush();
    auto result = nfs_meta(s, g, child, f);
    result["created"] = true;
    if (mode >= 2) {
      auto raw = decode_bytes(result.at("handle").get<std::string>());
      statement q(*nfs_db, "INSERT INTO exclusive_create VALUES(?,?)");
      q.bind(1, encode_bytes(raw.substr(18, 16)));
      q.bind(2, body.at("verifier")); q.row();
    }
    return finish(result);
  }
  if (op == "remove") {
    require(dir, "not_directory");
    auto n = name("name"), child = p.empty() ? n : p + "/" + n;
    auto meta = dav_exists(s, child);
    require(meta.has_value(), "not_found");
    if (body.contains("directory"))
      require(meta->at("directory") == body.at("directory"),
              meta->at("directory").get<bool>() ? "is_directory" : "not_directory");
    unlocked(space, child);
    smb_sharing(space, child, 0x10000, 7);
    dav_guard(s, child, actor, body, meta->at("directory"), true);
    bool retain = body.value("retain", false) && !meta->at("directory").get<bool>();
    require(!retain || nfs_retained.size() < 128, "handle_limit");
    auto f = nfs_open(s, child, meta->at("directory"), retain);
    auto token = f.stable_identity();
    auto native_object = f.info().at("object").get<std::string>();
    pending(request, hash);
    if (retain) nfs_pin(s, g, child, f, token);
    f = native_file();
    try {
      s.directory.remove(child, meta->at("directory"), retain ? native_object : "");
    } catch (...) {
      if (retain) nfs_restore_pins(s);
      throw;
    }
    o.file.flush();
    erase(space, child);
    if (!retain) {
      statement dead(*nfs_db, "UPDATE objects SET dead=1 WHERE token=?");
      dead.bind(1, token); dead.row();
    }
    return finish(json::object());
  }
  if (op == "rename") {
    require(dir, "not_directory");
    auto target = nfs_resolve(s, g, body.at("target"), false, ctx);
    require(target.file.info().at("directory"), "not_directory");
    auto target_before = nfs_meta(s, g, target.path, target.file).at("change");
    auto n = name("name"), t = name("to");
    auto from = p.empty() ? n : p + "/" + n;
    auto to = target.path.empty() ? t : target.path + "/" + t;
    auto meta = dav_exists(s, from);
    require(meta.has_value(), "not_found");
    if (from == to) {
      pending(request, hash);
      return finish({{"target_before", target_before}, {"target_after", target_before}});
    }
    require(!beneath(to, from), "invalid_path");
    case_check(s.directory, to);
    auto destination = dav_exists(s, to);
    std::string replaced;
    native_file pin_source;
    bool retain = false;
    if (destination) {
      require(destination->at("directory") == meta->at("directory"),
              destination->at("directory").get<bool>() ? "is_directory" : "not_directory");
      retain = body.value("retain", false) && !destination->at("directory").get<bool>();
      require(!retain || nfs_retained.size() < 128, "handle_limit");
      auto f = nfs_open(s, to, destination->at("directory"), retain);
      if (destination->at("directory")) require(f.list().empty(), "directory_not_empty");
      replaced = f.stable_identity();
      if (retain) pin_source = std::move(f);
      unlocked(space, to);
      smb_sharing(space, to, 0x10000, 7);
    }
    unlocked(space, from);
    smb_sharing(space, from, 0x10000, 7);
    dav_guard(s, from, actor, body, meta->at("directory"), true);
    dav_guard(s, to, actor, body);
    pending(request, hash);
    if (retain) nfs_pin(s, g, to, pin_source, replaced);
    pin_source = native_file();
    try {
      s.directory.rename(from, to, bool(destination), meta->at("directory"));
    } catch (...) {
      if (retain) nfs_restore_pins(s);
      throw;
    }
    o.file.flush();
    target.file.flush();
    if (!replaced.empty() && !retain) {
      statement dead(*nfs_db, "UPDATE objects SET dead=1 WHERE token=?");
      dead.bind(1, replaced); dead.row();
    }
    scan(s, ctx);
    return finish({{"target_before", target_before},
                   {"target_after", nfs_meta(s, g, target.path, target.file).at("change")}});
  }
  throw error("not_supported");
}
