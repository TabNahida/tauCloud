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
      "CREATE INDEX IF NOT EXISTS native ON objects(export,token,dead);");
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
  auto token = f.stable_identity();
  auto export_id = g.at("export").at("uuid").get<std::string>();
  std::string id;
  {
    statement q(*nfs_db, "SELECT id FROM objects WHERE export=? AND token=? AND dead=0");
    q.bind(1, export_id);
    q.bind(2, token);
    if (q.row())
      id = q.text(0);
  }
  auto info = f.info();
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
  if (!path.empty())
    index(g.at("space").at("id"), path, info);
  info["handle"] = nfs_handle(export_id, id);
  info["fileid"] = id.substr(0, 16);
  info["fsid"] = export_id.substr(0, 16);
  info["quota"] = g.at("space").at("quota");
  info["used"] = used(g.at("space").at("id"));
  info["path"] = path;
  (void)s;
  return info;
}
struct nfs_object {
  std::string path;
  native_file file;
};
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
    require(q.row() && !q.integer(3), "stale_handle");
    path = q.text(0);
    token = q.text(1);
    dir = q.integer(2) != 0;
  }
  auto prefix = g.at("path").get<std::string>();
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
      if (name == ".tc-stages")
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
                  op == "remove" || op == "rename";
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
    dav_guard(s, p, actor, body, dir, op == "remove" || op == "rename");
    smb_sharing(space, p, op == "remove" || op == "rename" ? 0x10000 : 2, 7);
    range_unlocked("", before.at("object"), 0, UINT64_MAX);
  } else
    smb_sharing(space, p, 1, 7);
  lease(g, ctx);
  auto finish = [&](json result) {
    if (mutation) {
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
      if (n == ".tc-stages")
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
      require(!l.exclusive || l.object != before.at("object").get<std::string>() || off >= l.end ||
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
  if (op == "write" || op == "resize") {
    require(!dir, "is_directory");
    auto off = op == "write" ? number(body, "offset") : number(body, "size");
    auto data = op == "write" ? decode_bytes(body.at("data").get<std::string>()) : std::string();
    require(data.size() <= 65536 && off <= uint64_t(INT64_MAX) - data.size(), "invalid_offset");
    auto end = off + data.size(), old = before.at("size").get<uint64_t>();
    quota(s, end > old ? end - old : 0);
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
      } else
        o.file.truncate(off);
      o.file.flush(); // All acknowledgements are FILE_SYNC, even for UNSTABLE requests.
    } catch (...) {
      index(space, p, o.file.info());
      throw;
    }
    auto meta = nfs_meta(s, g, p, o.file);
    meta["count"] = data.size();
    return finish(meta);
  }
  if (op == "create" || op == "mkdir") {
    require(dir, "not_directory");
    auto n = name("name"), child = p.empty() ? n : p + "/" + n;
    case_check(s.directory, child);
    require(!dav_exists(s, child), "already_exists");
    pending(request, hash);
    auto f = s.directory.open(child, op == "mkdir", true, op == "create");
    f.flush();
    o.file.flush();
    return finish(nfs_meta(s, g, child, f));
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
    auto f = nfs_open(s, child, meta->at("directory"));
    auto token = f.stable_identity();
    f = native_file();
    pending(request, hash);
    s.directory.remove(child, meta->at("directory"));
    o.file.flush();
    erase(space, child);
    statement dead(*nfs_db, "UPDATE objects SET dead=1 WHERE export=? AND token=?");
    dead.bind(1, g.at("export").at("uuid"));
    dead.bind(2, token);
    dead.row();
    return finish(json::object());
  }
  if (op == "rename") {
    require(dir, "not_directory");
    auto target = nfs_resolve(s, g, body.at("target"), false, ctx);
    require(target.file.info().at("directory"), "not_directory");
    auto n = name("name"), t = name("to");
    auto from = p.empty() ? n : p + "/" + n;
    auto to = target.path.empty() ? t : target.path + "/" + t;
    require(!beneath(to, from), "invalid_path");
    case_check(s.directory, to);
    auto meta = dav_exists(s, from);
    require(meta.has_value(), "not_found");
    // Replacing a live destination requires unlink/open-state coordination: reject explicitly.
    require(!dav_exists(s, to), "already_exists");
    unlocked(space, from);
    smb_sharing(space, from, 0x10000, 7);
    dav_guard(s, from, actor, body, meta->at("directory"), true);
    dav_guard(s, to, actor, body);
    pending(request, hash);
    s.directory.rename(from, to, false, meta->at("directory"));
    o.file.flush();
    target.file.flush();
    scan(s, ctx);
    return finish(json::object());
  }
  throw error("not_supported");
}
