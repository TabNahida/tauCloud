void dav_cancel_upload(space_state &s, json j) {
  auto stage = stat_path(s.directory, j.at("stage"));
  if (stage) {
    require(stage->at("object") == j.at("native"), "object_replaced");
    s.directory.remove(j.at("stage"));
  }
  j["status"] = "cancelled";
  j["reserved"] = 0;
  save_job(j);
}
json dav_meta(space_state &s, const std::string &path) {
  auto space = s.data.at("space").at("id").get<std::string>();
  native_file file;
  json info;
  if (path.empty())
    info = s.directory.info();
  else {
    auto value = object(space, path);
    file = s.directory.open(path, value.at("directory"));
    info = file.info();
    require(info.at("object") == value.at("native"), "object_replaced");
  }
  // Reads and directory enumeration can update atime without changing the
  // representation. Including it would invalidate our own conditional writes.
  info.erase("accessed_ns");
  return {{"path", path},
          {"directory", info.at("directory")},
          {"size", info.at("directory").get<bool>() ? json(0) : info.at("size")},
          {"modified_ns", info.at("modified_ns")},
          {"etag", "\"" + digest(info.dump()).substr(0, 32) + "\""}};
}
std::optional<json> dav_exists(space_state &s, const std::string &path) {
  try {
    return dav_meta(s, path);
  } catch (const error &e) {
    if (std::string_view(e.what()) == "not_found")
      return {};
    throw;
  }
}
json dav_properties(const std::string &space, const std::string &path) {
  statement q(db, "SELECT name,value FROM dav_properties WHERE space=? AND path=?");
  q.bind(1, space);
  q.bind(2, path);
  json out = json::object();
  while (q.row())
    out[q.text(0)] = json::parse(q.text(1));
  return out;
}
json dav_locks(const std::string &space) {
  statement prune(db, "DELETE FROM dav_locks WHERE expires<=?");
  prune.bind(1, now());
  prune.row();
  statement q(db, "SELECT body FROM dav_locks WHERE space=?");
  q.bind(1, space);
  json out = json::array();
  while (q.row())
    out.push_back(json::parse(q.text(0)));
  return out;
}
static bool dav_covers(const json &lock, const std::string &path) {
  auto base = lock.at("path").get<std::string>();
  return base == path || (lock.at("depth") == "infinity" && beneath(path, base));
}
std::vector<std::string> dav_conditions(space_state &s, const std::string &path, const json &body) {
  auto space = s.data.at("space").at("id").get<std::string>();
  auto locks = dav_locks(space);
  auto current = dav_exists(s, path);
  auto etag = current ? current->at("etag").get<std::string>() : "";
  auto matches = [&](const std::string &v, bool weak = false) {
    return http_stream::etag_matches(v, etag, bool(current), weak);
  };
  if (body.contains("if_match"))
    require(matches(body.at("if_match")), "precondition_failed");
  if (body.contains("if_none_match"))
    require(!matches(body.at("if_none_match"), true), "precondition_failed");
  if (current && body.contains("unmodified_since"))
    require(current->at("modified_ns").get<int64_t>() / 1000000000 <=
                body.at("unmodified_since").get<int64_t>() / 1000000000,
            "precondition_failed");
  std::vector<std::string> tokens;
  for (auto group : body.value("dav_if", json::array())) {
    auto p = group.value("path", path);
    auto value = dav_exists(s, p);
    bool passed = false;
    for (auto list : group.at("lists")) {
      bool ok = true;
      std::vector<std::string> selected;
      for (auto c : list) {
        bool found = false;
        auto text = c.at("value").get<std::string>();
        if (c.at("kind") == "etag")
          found = value && value->at("etag") == text;
        else
          for (auto lock : locks)
            if (lock.at("token") == text && dav_covers(lock, p)) {
              found = true;
              if (!c.at("not").get<bool>())
                selected.push_back(text);
            }
        if (c.at("not").get<bool>())
          found = !found;
        ok = ok && found;
      }
      if (ok) {
        passed = true;
        tokens.insert(tokens.end(), selected.begin(), selected.end());
      }
    }
    require(passed, "precondition_failed");
  }
  return tokens;
}
void dav_guard(space_state &s, const std::string &path, const std::string &actor, const json &body,
               bool subtree = false, bool membership = false) {
  auto tokens = dav_conditions(s, path, body);
  auto locks = dav_locks(s.data.at("space").at("id"));
  auto slash = path.rfind('/');
  auto parent = slash == std::string::npos ? "" : path.substr(0, slash);
  for (auto lock : locks) {
    bool affects = dav_covers(lock, path) || (subtree && beneath(lock.at("path"), path)) ||
                   (membership && dav_covers(lock, parent));
    if (!affects)
      continue;
    bool allowed = false;
    for (auto candidate : locks)
      if (candidate.at("path") == lock.at("path") && candidate.at("actor") == actor &&
          std::find(tokens.begin(), tokens.end(), candidate.at("token").get<std::string>()) !=
              tokens.end())
        allowed = true;
    require(allowed, "dav_locked");
  }
}
json dav_tree(space_state &s, const std::string &path, bool recursive = true) {
  json result = json::array();
  std::vector<std::string> pending{path};
  while (!pending.empty()) {
    auto current = pending.back();
    pending.pop_back();
    auto item = dav_meta(s, current);
    result.push_back(item);
    require(result.size() <= 256, "tree_limit");
    if (item.at("directory") && recursive) {
      native_file directory;
      native_file *dir = &s.directory;
      if (!current.empty()) {
        directory = s.directory.open(current, true);
        dir = &directory;
      }
      for (auto entry : dir->list()) {
        auto name = entry.at("name").get<std::string>();
        if (name.starts_with(".tc-"))
          continue;
        portable_path(name);
        pending.push_back(current.empty() ? name : current + "/" + name);
      }
    }
  }
  return result;
}
void dav_remove_native(space_state &s, const std::string &path, bool directory) {
  if (directory) {
    auto dir = s.directory.open(path, true);
    auto entries = dir.list();
    dir = native_file();
    for (auto entry : entries)
      dav_remove_native(s, path + "/" + entry.at("name").get<std::string>(), entry.at("directory"));
  }
  s.directory.remove(path, directory);
}
void dav_erase_prefix(const std::string &space, const std::string &path) {
  for (auto table : {"objects", "dav_properties", "dav_locks"}) {
    std::string query =
        "DELETE FROM " + std::string(table) + " WHERE space=? AND (path=? OR substr(path,1,?)=?)";
    statement q(db, query.c_str());
    q.bind(1, space);
    q.bind(2, path);
    q.bind(3, int64_t(path.size() + 1));
    q.bind(4, path + "/");
    q.row();
  }
}
void dav_recover(space_state &s, json j) {
  auto space = j.at("space").get<std::string>(), path = j.at("path").get<std::string>(),
       action = j.at("action").get<std::string>();
  auto native_stat = [&](const std::string &p, bool dir) -> std::optional<json> {
    return stat_path(s.directory, p, dir);
  };
  bool directory = j.at("directory");
  if (action == "dav_delete") {
    auto existing = native_stat(path, directory);
    if (existing) {
      require(existing->at("object") == j.at("native"), "conflict");
      dav_remove_native(s, path, directory);
    }
    transaction tx(db);
    dav_erase_prefix(space, path);
    j["status"] = "completed";
    save_job(j);
    audit(j.at("actor"), action, path);
    tx.commit();
    return;
  }
  auto to = j.at("to").get<std::string>(),
       source = action == "dav_copy" ? j.at("stage").get<std::string>() : path;
  std::optional<json> target;
  auto slash = to.rfind('/');
  auto parent = slash == std::string::npos ? "" : to.substr(0, slash);
  auto leaf = slash == std::string::npos ? to : to.substr(slash + 1);
  native_file parent_dir;
  native_file *p = &s.directory;
  if (!parent.empty()) {
    parent_dir = s.directory.open(parent, true);
    p = &parent_dir;
  }
  for (auto entry : p->list())
    if (entry.at("name") == leaf)
      target = native_stat(to, entry.at("directory"));
  parent_dir = native_file();
  if (!target || target->at("object") != j.at("native")) {
    auto from = native_stat(source, directory);
    require(from && from->at("object") == j.at("native"), "uncertain_write");
    if (target) {
      require(!j.at("previous").is_null() && target->at("object") == j.at("previous"), "conflict");
      dav_remove_native(s, to, target->at("directory"));
    }
    s.directory.rename(source, to, false, directory);
  }
  transaction tx(db);
  dav_erase_prefix(space, to);
  if (action == "dav_move")
    dav_erase_prefix(space, path);
  for (auto entry : j.at("entries")) {
    auto dest = to + entry.at("suffix").get<std::string>();
    auto info = s.directory.open(dest, entry.at("directory")).info();
    index(space, dest, info, entry.at("object"));
    for (auto &[name, value] : entry.at("properties").items()) {
      statement put(db, "INSERT INTO dav_properties VALUES(?,?,?,?)");
      put.bind(1, space);
      put.bind(2, dest);
      put.bind(3, name);
      put.bind(4, value.dump());
      put.row();
    }
  }
  j["status"] = "completed";
  j["reserved"] = 0;
  save_job(j);
  audit(j.at("actor"), action, to);
  tx.commit();
}
json dav_dispatch(const std::string &op, const json &body, const json &grant, space_state &s,
                  const call_context &ctx) {
  auto space = grant.at("space").at("id").get<std::string>(),
       path = grant.at("path").get<std::string>(), actor = grant.at("actor").get<std::string>();
  if (op == "dav_stat" || op == "dav_list") {
    auto value = dav_meta(s, path);
    auto decorate = [&](json item) {
      auto p = item.at("path").get<std::string>();
      item["properties"] = dav_properties(space, p);
      item["locks"] = json::array();
      for (auto lock : dav_locks(space))
        if (dav_covers(lock, p))
          item["locks"].push_back(lock);
      return item;
    };
    if (op == "dav_stat")
      return decorate(value);
    json result = json::array({decorate(value)});
    if (value.at("directory") && body.value("depth", 1) != 0) {
      native_file dir;
      native_file *folder = &s.directory;
      if (!path.empty()) {
        dir = s.directory.open(path, true);
        folder = &dir;
      }
      for (auto entry : folder->list()) {
        auto name = entry.at("name").get<std::string>();
        if (name.starts_with(".tc-"))
          continue;
        auto p = path.empty() ? name : path + "/" + name;
        result.push_back(decorate(dav_meta(s, p)));
        require(result.size() <= 256 && result.dump().size() <= 256 * 1024, "tree_limit");
      }
    }
    return result;
  }
  if (op == "dav_props") {
    dav_meta(s, path);
    dav_guard(s, path, actor, body);
    auto edits = body.at("properties");
    require(edits.size() <= 128 && edits.dump().size() <= 65536, "invalid_request");
    for (auto item : edits)
      require(!item.value("protected", false), "protected_property");
    transaction tx(db);
    for (auto item : edits) {
      auto name = item.at("key").get<std::string>();
      statement q(db, item.at("remove").get<bool>()
                          ? "DELETE FROM dav_properties WHERE space=? AND path=? AND name=?"
                          : "INSERT INTO dav_properties VALUES(?,?,?,?) ON "
                            "CONFLICT(space,path,name) DO UPDATE SET value=excluded.value");
      q.bind(1, space);
      q.bind(2, path);
      q.bind(3, name);
      if (!item.at("remove").get<bool>())
        q.bind(4, item.dump());
      q.row();
    }
    require(dav_properties(space, path).dump().size() <= 65536, "property_limit");
    audit(actor, "proppatch", path);
    tx.commit();
    return {{"updated", true}};
  }
  if (op == "dav_lock") {
    auto current = dav_exists(s, path);
    auto locks = dav_locks(space);
    auto token = body.value("token", "");
    auto lifetime = std::clamp(body.value("timeout", int64_t(3600)), int64_t(1), int64_t(3600));
    dav_conditions(s, path, body);
    if (!token.empty()) {
      for (auto lock : locks)
        if (lock.at("token") == token && dav_covers(lock, path) && lock.at("actor") == actor) {
          lock["expires"] = now() + lifetime * 1000;
          statement q(db, "UPDATE dav_locks SET expires=?,body=? WHERE token=?");
          q.bind(1, lock.at("expires"));
          q.bind(2, lock.dump());
          q.bind(3, token);
          q.row();
          return lock;
        }
      throw error("precondition_failed");
    }
    require(locks.size() < 256, "lock_limit");
    auto depth = body.value("depth", "infinity"), scope = body.value("scope", "exclusive");
    require((depth == "0" || depth == "infinity") && (scope == "exclusive" || scope == "shared"),
            "invalid_request");
    for (auto lock : locks)
      if (dav_covers(lock, path) || (depth == "infinity" && beneath(lock.at("path"), path)))
        require(scope == "shared" && lock.at("scope") == "shared", "dav_locked");
    if (!current) {
      require(!path.empty(), "not_found");
      dav_guard(s, path, actor, body, false, true);
      case_check(s.directory, path);
      auto f = s.directory.open(path, false, true, true);
      f.flush();
      index(space, path, f.info());
    }
    json lock = {{"token", "opaquelocktoken:" + random_hex(16)},
                 {"path", path},
                 {"actor", actor},
                 {"space", space},
                 {"depth", depth},
                 {"scope", scope},
                 {"owner", body.value("owner", "")},
                 {"expires", now() + lifetime * 1000},
                 {"created", !current}};
    statement q(db, "INSERT INTO dav_locks VALUES(?,?,?,?,?)");
    q.bind(1, lock.at("token"));
    q.bind(2, space);
    q.bind(3, path);
    q.bind(4, lock.at("expires"));
    q.bind(5, lock.dump());
    q.row();
    audit(actor, "lock", path);
    return lock;
  }
  if (op == "dav_unlock") {
    for (auto lock : dav_locks(space))
      if (lock.at("token") == body.at("token") && lock.at("path") == path) {
        require(lock.at("actor") == actor, "forbidden");
        statement q(db, "DELETE FROM dav_locks WHERE token=?");
        q.bind(1, body.at("token"));
        q.row();
        audit(actor, "unlock", path);
        return {{"unlocked", true}};
      }
    throw error("lock_mismatch");
  }
  require(op == "dav_delete" || op == "dav_copy" || op == "dav_move", "not_supported");
  require(!path.empty(), "forbidden");
  auto list = dav_tree(s, path, op != "dav_copy" || body.value("depth", "infinity") != "0");
  auto info = list.at(0);
  bool dir = info.at("directory");
  if (op != "dav_copy")
    dav_guard(s, path, actor, body, true, true);
  else
    dav_conditions(s, path, body);
  for (auto &[id, h] : handles)
    require(h.space != space || !beneath(h.path, path), "locked");
  std::string to;
  json target;
  std::optional<json> previous;
  if (op != "dav_delete") {
    target = verify(body.at("target_grant"), true);
    require(target.at("actor") == actor && target.at("space").at("id") == space,
            "cross_volume_move_requires_copy");
    to = target.at("path");
    portable_path(to);
    require(!beneath(to, path) && !beneath(path, to), "forbidden");
    try {
      case_check(s.directory, to);
    } catch (const error &e) {
      if (std::string_view(e.what()) == "not_found")
        throw error("parent_missing");
      throw;
    }
    previous = dav_exists(s, to);
    require(!previous || body.value("overwrite", true), "precondition_failed");
    auto target_conditions = body;
    target_conditions.erase("if_match");
    target_conditions.erase("if_none_match");
    target_conditions.erase("unmodified_since");
    dav_guard(s, to, actor, target_conditions, true, true);
    if (previous && previous->at("directory"))
      dav_tree(s, to);
    for (auto &[id, h] : handles)
      require(h.space != space || !beneath(h.path, to), "locked");
  }
  uint64_t bytes = 0;
  json entries = json::array();
  for (auto item : list) {
    auto p = item.at("path").get<std::string>();
    bytes += item.at("size").get<uint64_t>();
    entries.push_back(
        {{"suffix", p.substr(path.size())},
         {"directory", item.at("directory")},
         {"object",
          op == "dav_copy" ? random_hex(16) : object(space, p).at("object").get<std::string>()},
         {"properties", dav_properties(space, p)}});
  }
  require(op != "dav_copy" || bytes <= 16 * 1024 * 1024, "copy_limit");
  if (op == "dav_copy")
    quota(s, bytes);
  require(jobs(space).size() < 4096, "job_limit");
  json j = {{"id", body.at("request_id")},
            {"space", space},
            {"actor", actor},
            {"action", op},
            {"path", path},
            {"to", to},
            {"directory", dir},
            {"entries", entries},
            {"status", "committing"},
            {"reserved", op == "dav_copy" ? bytes : 0},
            {"previous", previous
                             ? s.directory.open(to, previous->at("directory")).info().at("object")
                             : json(nullptr)}};
  if (op == "dav_copy") {
    auto stage = ".tc-stage-" + random_hex(16);
    auto root = s.directory.open(stage, dir, true, true);
    j["stage"] = stage;
    j["native"] = root.info().at("object");
    root = native_file();
    j["status"] = "staging";
    save_job(j);
    try {
      for (auto item : list) {
        ctx.check();
        auto p = item.at("path").get<std::string>(), dest = stage + p.substr(path.size());
        bool folder = item.at("directory");
        auto output = s.directory.open(dest, folder, p != path, true);
        if (!folder) {
          auto input = s.directory.open(p);
          uint64_t offset = 0;
          while (offset < item.at("size").get<uint64_t>()) {
            ctx.check();
            auto data = input.read(offset, file_chunk_size);
            require(!data.empty(), "object_replaced");
            size_t written = 0;
            while (written < data.size())
              written += output.write(offset + written, std::string_view(data).substr(written));
            offset += data.size();
          }
          output.flush();
        }
      }
      lease(grant, ctx);
      lease(target, ctx);
      j["status"] = "committing";
      save_job(j);
    } catch (...) {
      dav_remove_native(s, stage, dir);
      j["status"] = "cancelled";
      j["reserved"] = 0;
      save_job(j);
      throw;
    }
  } else {
    j["native"] = s.directory.open(path, dir).info().at("object");
    lease(grant, ctx);
    save_job(j);
  }
  dav_recover(s, j);
  return {{"status", "completed"}, {"created", !previous}, {"id", j.at("id")}};
}
