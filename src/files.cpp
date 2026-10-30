#include <taucloud/files.hpp>
#include <taucloud/http_stream.hpp>
#include <taucloud/database.hpp>
#include <algorithm>
#include <map>
#include <set>
namespace tc {
namespace {
std::string lower(std::string value) { return path_fold(value); }
bool beneath(const std::string &path, const std::string &prefix) {
  return prefix.empty() || path == prefix || path.starts_with(prefix + "/");
}
uint64_t number(const json &data, const char *key) {
  require(data.at(key).is_number_integer(), "invalid_offset");
  auto value = data.at(key).get<int64_t>();
  require(value >= 0, "invalid_offset");
  return static_cast<uint64_t>(value);
}
std::optional<json> stat_path(native_file &root, const std::string &path, bool directory = false) {
  try {
    return root.open(path, directory).info();
  } catch (const error &e) {
    if (std::string_view(e.what()) == "not_found")
      return {};
    throw;
  }
}
void case_check(native_file &root, const std::string &path) {
  size_t start = 0;
  native_file parent;
  native_file *current = &root;
  for (;;) {
    auto end = path.find('/', start);
    auto name = path.substr(start, end - start);
    for (auto item : current->list())
      require(lower(item.at("name").get<std::string>()) != lower(name) || item.at("name") == name,
              "case_collision");
    if (end == std::string::npos)
      break;
    parent = root.open(path.substr(0, end), true);
    current = &parent;
    start = end + 1;
  }
}
} // namespace
struct file_store::impl {
  config cfg;
  std::string role, generation, key;
  database db;
  std::mutex mutex;
  int64_t minimum_epoch = 0;
  struct space_state {
    json data;
    native_file root;
    native_file directory;
  };
  struct opened {
    native_file file;
    std::string actor, space, path;
    bool writable;
    int64_t epoch;
    std::string protocol;
    uint32_t access = 0;
    unsigned sharing = 7;
    bool directory = false;
  };
  struct byte_lock {
    std::string handle, object;
    uint64_t start, end;
    bool exclusive = true;
    bool through_max = false;
  };
  std::map<std::string, std::unique_ptr<space_state>> spaces;
  std::map<std::string, opened> handles;
  std::vector<byte_lock> locks;
  struct retained_nfs_file {
    std::string space, path, root, pin, object;
    native_file file;
  };
  std::map<std::string, retained_nfs_file> nfs_retained;
  impl(const config &c, std::string r, std::string g)
      : cfg(c), role(std::move(r)), generation(std::move(g)),
        key(read_json(c.state / "ipc-keys.json").at("identity")), db(c.state / (role + ".db")) {
    int64_t version;
    {
      statement q(db, "PRAGMA user_version");
      q.row();
      version = q.integer(0);
    }
    require(version <= 3, "schema_too_new");
    if (version > 0 && version < 3)
      backup_database(db, c.state / (role + (version == 1 ? ".pre-v2.db" : ".pre-v3.db")));
    transaction migration(db);
    sql(db, "CREATE TABLE IF NOT EXISTS spaces(id TEXT PRIMARY KEY,request TEXT NOT NULL,body TEXT "
            "NOT NULL);"
            "CREATE TABLE IF NOT EXISTS objects(space TEXT NOT NULL,path TEXT COLLATE NOCASE NOT "
            "NULL,native TEXT NOT NULL,object TEXT NOT NULL,size INTEGER NOT NULL,directory "
            "INTEGER NOT NULL,PRIMARY KEY(space,path));"
            "CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,space TEXT NOT NULL,actor TEXT "
            "NOT NULL,body TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,hash TEXT NOT NULL,state "
            "TEXT NOT NULL,result TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,time INTEGER NOT NULL,actor "
            "TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL); PRAGMA user_version=1;"
            "UPDATE operations SET state='uncertain' WHERE state='pending';");
    sql(db, "CREATE TABLE IF NOT EXISTS dav_properties(space TEXT NOT NULL,path TEXT NOT NULL,name "
            "TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(space,path,name)); CREATE TABLE IF NOT "
            "EXISTS dav_locks(token TEXT PRIMARY KEY,space TEXT NOT NULL,path TEXT NOT "
            "NULL,expires INTEGER NOT NULL,body TEXT NOT NULL); PRAGMA user_version=2;");
    sql(db,
        "CREATE TABLE IF NOT EXISTS smb_pending(space TEXT NOT NULL,path TEXT NOT NULL,native TEXT "
        "NOT NULL,directory INTEGER NOT NULL,PRIMARY KEY(space,path)); PRAGMA user_version=3;");
    migration.commit();
  }
  void audit(const std::string &actor, const std::string &action, const std::string &resource) {
    statement q(db, "INSERT INTO audit(time,actor,action,resource) VALUES(?,?,?,?)");
    q.bind(1, now());
    q.bind(2, actor);
    q.bind(3, action);
    q.bind(4, resource);
    q.row();
  }
  json verify(json grant, bool writing, bool cleanup = false) {
    auto signature = grant.at("signature").get<std::string>();
    grant.erase("signature");
    require(equal(signature, mac(key, grant.dump())), "grant_denied");
    if (!cleanup) {
      require(grant.at("expires").get<int64_t>() > now() &&
                  grant.at("expires").get<int64_t>() <= now() + 2500,
              "lease_expired");
      require(grant.at("epoch").get<int64_t>() >= minimum_epoch, "policy_revoked");
    }
    require(grant.at("root").at("worker") == role, "wrong_domain");
    require(!writing || grant.at("write").get<bool>(), "forbidden");
    return grant;
  }
  void lease(const json &grant, const call_context &ctx) {
    ctx.check();
    require(grant.at("expires").get<int64_t>() > now() &&
                grant.at("epoch").get<int64_t>() >= minimum_epoch,
            "lease_expired");
  }
  json object(const std::string &space, const std::string &path) {
    statement q(db,
                "SELECT native,object,size,directory,path FROM objects WHERE space=? AND path=?");
    q.bind(1, space);
    q.bind(2, path);
    require(q.row(), "not_found");
    require(q.text(4) == path, "case_collision");
    return {{"native", q.text(0)},
            {"object", q.text(1)},
            {"size", q.integer(2)},
            {"directory", bool(q.integer(3))}};
  }
  void index(const std::string &space, const std::string &path, const json &info,
             std::string object_id = "") {
    if (object_id.empty()) {
      try {
        auto old = object(space, path);
        if (old.at("native") == info.at("object"))
          object_id = old.at("object");
      } catch (const error &e) {
        if (std::string_view(e.what()) != "not_found")
          throw;
      }
    }
    if (object_id.empty())
      object_id = random_hex(16);
    statement q(db, "INSERT INTO objects VALUES(?,?,?,?,?,?) ON CONFLICT(space,path) DO UPDATE SET "
                    "native=excluded.native,object=excluded.object,size=excluded.size,directory="
                    "excluded.directory");
    q.bind(1, space);
    q.bind(2, path);
    q.bind(3, info.at("object"));
    q.bind(4, object_id);
    q.bind(5, info.at("directory").get<bool>() ? int64_t(0) : info.at("size").get<int64_t>());
    q.bind(6, int64_t(info.at("directory").get<bool>()));
    q.row();
  }
  void erase(const std::string &space, const std::string &path) {
    statement q(db, "DELETE FROM objects WHERE space=? AND path=?");
    q.bind(1, space);
    q.bind(2, path);
    q.row();
  }
  json job(const std::string &id) {
    statement q(db, "SELECT body FROM jobs WHERE id=?");
    q.bind(1, id);
    require(q.row(), "not_found");
    return json::parse(q.text(0));
  }
  void save_job(const json &j) {
    statement q(
        db, "INSERT INTO jobs VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body");
    q.bind(1, j.at("id"));
    q.bind(2, j.at("space"));
    q.bind(3, j.at("actor"));
    q.bind(4, j.dump());
    q.row();
  }
  json jobs(const std::string &space) {
    statement q(db, "SELECT body FROM jobs WHERE space=?");
    q.bind(1, space);
    json values = json::array();
    while (q.row())
      values.push_back(json::parse(q.text(0)));
    return values;
  }
  uint64_t used(const std::string &space) {
    statement q(db, "SELECT COALESCE(SUM(size),0) FROM objects WHERE space=?");
    q.bind(1, space);
    q.row();
    auto total = static_cast<uint64_t>(q.integer(0));
    for (const auto &[token, retained] : nfs_retained)
      if (retained.space == space)
        total += retained.file.info().at("size").get<uint64_t>();
    return total;
  }
  uint64_t reserved(const std::string &space) {
    uint64_t total = 0;
    for (auto j : jobs(space))
      if (j.at("status") == "staging" || j.at("status") == "committing" ||
          j.at("status") == "uncertain")
        total += j.value("reserved", uint64_t(0));
    return total;
  }
  void quota(const space_state &s, uint64_t extra) {
    auto limit = s.data.at("space").at("quota").get<uint64_t>();
    auto charged = used(s.data.at("space").at("id")) + reserved(s.data.at("space").at("id"));
    require(extra <= limit && charged <= limit - extra, "quota_exceeded");
  }
  void scan(space_state &s, const call_context &ctx) {
    auto id = s.data.at("space").at("id").get<std::string>();
    std::vector<std::string> pending{""};
    std::map<std::string, json> found;
    size_t count = 0;
    std::set<std::string> stages;
    for (auto j : jobs(id))
      if (j.contains("stage"))
        stages.insert(j.at("stage").get<std::string>());
    while (!pending.empty()) {
      ctx.check();
      auto path = pending.back();
      pending.pop_back();
      native_file child;
      native_file *dir = &s.directory;
      if (!path.empty()) {
        child = s.directory.open(path, true);
        dir = &child;
      }
      for (auto entry : dir->list()) {
        auto name = entry.at("name").get<std::string>();
        if (path.empty() && name.starts_with(".tc-nfs-")) {
          require(std::any_of(nfs_retained.begin(), nfs_retained.end(), [&](const auto &item) {
            return item.second.space == id && item.second.pin == name;
          }), "orphan_nfs_pin");
          continue;
        }
        if (path.empty() && name.starts_with(".tc-stage-")) {
          require(stages.contains(name), "orphan_stage");
          continue;
        }
        portable_path(name);
        require(++count <= 10000, "reconcile_limit");
        auto relative = path.empty() ? name : path + "/" + name;
        auto native = s.directory.open(relative, entry.at("directory"));
        auto info = native.info();
        require(found.emplace(lower(relative), json{{"path", relative}, {"info", info}}).second,
                "case_collision");
        if (info.at("directory"))
          pending.push_back(relative);
      }
    }
    transaction tx(db);
    std::vector<std::string> stale;
    {
      statement q(db, "SELECT path FROM objects WHERE space=?");
      q.bind(1, id);
      while (q.row())
        if (!found.contains(lower(q.text(0))))
          stale.push_back(q.text(0));
    }
    for (auto path : stale)
      erase(id, path);
    for (auto &[fold, item] : found)
      index(id, item.at("path"), item.at("info"));
    tx.commit();
  }
  void reconcile_job(space_state &s, json j) {
    if (j.at("status") != "committing")
      return;
    if (j.at("action").get<std::string>().starts_with("dav_")) {
      dav_recover(s, j);
      return;
    }
    auto path = j.at("path").get<std::string>(), space = j.at("space").get<std::string>();
    try {
      auto target = stat_path(s.directory, path);
      std::string action = j.at("action");
      if (action == "upload") {
        auto stage = stat_path(s.directory, j.at("stage"));
        if (!target || target->at("object") != j.at("native")) {
          require(stage && stage->at("object") == j.at("native"), "uncertain_write");
          require(j.at("previous").is_null() ? !target
                                             : (target && target->at("object") == j.at("previous")),
                  "conflict");
          s.directory.rename(j.at("stage"), path, !j.at("previous").is_null());
          target = stat_path(s.directory, path);
        }
        transaction tx(db);
        index(space, path, *target, j.at("object"));
        j["status"] = "completed";
        j["reserved"] = 0;
        save_job(j);
        audit(j.at("actor"), "upload_committed", path);
        tx.commit();
      } else if (action == "remove") {
        if (target) {
          require(target->at("object") == j.at("native"), "conflict");
          s.directory.remove(path);
        }
        transaction tx(db);
        erase(space, path);
        j["status"] = "completed";
        save_job(j);
        audit(j.at("actor"), "removed", path);
        tx.commit();
      } else if (action == "rename") {
        auto to = j.at("to").get<std::string>();
        auto moved = stat_path(s.directory, to);
        if (!moved || moved->at("object") != j.at("native")) {
          require(target && target->at("object") == j.at("native") && !moved, "conflict");
          s.directory.rename(path, to);
          moved = stat_path(s.directory, to);
        }
        transaction tx(db);
        erase(space, path);
        index(space, to, *moved, j.at("object"));
        j["status"] = "completed";
        save_job(j);
        audit(j.at("actor"), "renamed", path);
        tx.commit();
        for (auto &[key, h] : handles)
          if (h.space == space && h.path == path)
            h.path = to;
      }
    } catch (const error &e) {
      j["status"] = "uncertain";
      j["error"] = e.what();
      save_job(j);
      throw;
    }
  }
  space_state &attach(const json &grant, const call_context &ctx) {
    auto id = grant.at("space").at("id").get<std::string>();
    auto expected = grant.at("root");
    auto live = inspect_root(expected.at("path").get<std::string>());
    require(live.at("object") == expected.at("object"), "root_replaced");
    if (!spaces.contains(id)) {
      statement q(db, "SELECT body FROM spaces WHERE id=?");
      q.bind(1, id);
      require(q.row(), "space_unavailable");
      auto data = json::parse(q.text(0));
      require(data.at("root") == expected &&
                  data.at("space").at("object") == grant.at("space").at("object"),
              "space_replaced");
      auto state = std::make_unique<space_state>();
      state->data = data;
      state->root = native_file::root(expected.at("path").get<std::string>());
      state->directory = state->root.open(data.at("space").at("path"), true);
      require(state->directory.info().at("object") == data.at("space").at("object"),
              "space_replaced");
      for (auto j : jobs(id)) {
        if (j.at("status") == "committing")
          reconcile_job(*state, j);
        else if (j.at("status") == "staging" && j.at("action") == "dav_copy") {
          dav_remove_native(*state, j.at("stage"), j.at("directory"));
          j["status"] = "cancelled";
          j["reserved"] = 0;
          save_job(j);
        } else if (j.at("status") == "staging" &&
                   (j.value("protocol", "") == "webdav" || j.value("protocol", "") == "ftp")) {
          dav_cancel_upload(*state, j);
        } else if (j.at("status") == "staging") {
          auto actual = stat_path(state->directory, j.at("stage"));
          if (!actual || actual->at("object") != j.at("native") ||
              actual->at("size") != j.at("progress")) {
            j["status"] = "uncertain";
            j["error"] = "uncertain_write";
            save_job(j);
          }
        }
      }
      nfs_restore_pins(*state);
      scan(*state, ctx);
      spaces[id] = std::move(state);
    }
    auto &s = *spaces.at(id);
    require(s.root.open(grant.at("space").at("path"), true).info().at("object") ==
                s.directory.info().at("object"),
            "space_replaced");
    return s;
  }
  void unlocked(const std::string &space, const std::string &path) {
    for (auto &[id, h] : handles)
      require(h.space != space || h.path != path, "locked");
  }
  void range_unlocked(const std::string &handle, const std::string &object, uint64_t start,
                      uint64_t end) {
    if (start == end) return;
    for (auto &l : locks)
      require((l.handle == handle && l.exclusive) || l.object != object || (!l.through_max && start >= l.end) ||
                  end <= l.start,
              "locked");
  }
  std::optional<json> replay(const std::string &id, const std::string &hash) {
    statement q(db, "SELECT hash,state,result FROM operations WHERE id=?");
    q.bind(1, id);
    if (!q.row())
      return {};
    require(q.text(0) == hash, "idempotency_conflict");
    require(q.text(1) == "done", "uncertain_write");
    return json::parse(q.text(2));
  }
  void pending(const std::string &id, const std::string &hash) {
    require(id.size() >= 16 && id.size() <= 64, "invalid_request");
    statement count(db, "SELECT count(*) FROM operations");
    count.row();
    require(count.integer(0) < 100000, "operation_limit");
    statement q(db, "INSERT INTO operations VALUES(?,?,'pending','{}')");
    q.bind(1, id);
    q.bind(2, hash);
    q.row();
  }
  void complete(const std::string &id, const json &result) {
    statement q(db, "UPDATE operations SET state='done',result=? WHERE id=?");
    q.bind(1, result.dump());
    q.bind(2, id);
    q.row();
  }
#include "file_dav.inc"
#include "file_smb.inc"
#include "file_nfs.inc"
  json dispatch(const std::string &op, const json &body, const call_context &ctx) {
    std::lock_guard guard(mutex);
    ctx.check();
    if (op == "nfs_file") return nfs_dispatch(body, ctx);
    if (op == "nfs_reap") return nfs_reap(body, ctx);
    if (op.starts_with("smb_"))
      return smb_dispatch(op, body, ctx);
    if (op == "inspect") {
      require(ctx.caller == "identity", "forbidden");
      return inspect_root(body.at("path").get<std::string>());
    }
    if (op == "ftp_recover") {
      require(ctx.caller == "ftp", "forbidden");
      std::erase_if(handles, [](const auto &entry) { return entry.second.protocol == "ftp"; });
      std::erase_if(locks, [&](const auto &entry) { return !handles.contains(entry.handle); });
      statement q(db, "SELECT body FROM spaces");
      std::vector<json> owned;
      while (q.row())
        owned.push_back(json::parse(q.text(0)));
      for (auto value : owned) {
        auto &s = attach(value, ctx);
        for (auto j : jobs(value.at("space").at("id")))
          if (j.value("protocol", "") == "ftp" && j.at("status") == "staging")
            dav_cancel_upload(s, j);
      }
      return {{"recovered", true}};
    }
    if (op == "revoke") {
      require(ctx.caller == "identity", "forbidden");
      minimum_epoch = std::max(minimum_epoch, body.at("epoch").get<int64_t>());
      handles.clear();
      locks.clear();
      for (auto &[id, s] : spaces)
        smb_reap(*s);
      return {{"epoch", minimum_epoch}, {"drained", true}};
    }
    if (op == "provision") {
      require(ctx.caller == "identity", "forbidden");
      auto root = body.at("root"), space = body.at("space");
      require(root.at("worker") == role, "wrong_domain");
      auto id = space.at("id").get<std::string>();
      auto fingerprint = digest(root.dump() + space.dump());
      {
        statement q(db, "SELECT request,body FROM spaces WHERE id=?");
        q.bind(1, id);
        if (q.row()) {
          require(q.text(0) == fingerprint, "idempotency_conflict");
          auto saved = json::parse(q.text(1));
          require(saved.at("space").contains("object"), "uncertain_provision");
          return saved.at("space");
        }
      }
      auto directory = native_file::root(root.at("path").get<std::string>());
      require(directory.info().at("object") == root.at("object"), "root_replaced");
      case_check(directory, space.at("path"));
      // Record ownership intent before creating anything. A crash in the native/SQL gap
      // remains explicitly uncertain; an existing directory is never silently adopted.
      {
        statement q(db, "INSERT INTO spaces VALUES(?,?,?)");
        q.bind(1, id);
        q.bind(2, fingerprint);
        q.bind(3, json{{"root", root}, {"space", space}}.dump());
        q.row();
      }
      auto created = directory.open(space.at("path"), true, true);
      space["object"] = created.info().at("object");
      directory.flush();
      json record = {{"root", root}, {"space", space}};
      statement q(db, "UPDATE spaces SET body=? WHERE id=?");
      q.bind(1, record.dump());
      q.bind(2, id);
      q.row();
      return space;
    }
    if (op == "dav_abort" || op == "dav_close" || op == "ftp_abort" || op == "ftp_close") {
      const auto profile = op.starts_with("ftp_") ? "ftp" : "webdav";
      require(ctx.caller == profile, "forbidden");
      auto g = verify(body.at("grant"), op.ends_with("_abort"), true);
      require(g.at("protocol") == profile, "forbidden");
      auto actor = g.at("actor").get<std::string>(), path = g.at("path").get<std::string>(),
           space = g.at("space").at("id").get<std::string>();
      if (op.ends_with("_close")) {
        auto it = handles.find(body.at("handle"));
        if (it != handles.end()) {
          require(it->second.actor == actor && it->second.space == space &&
                      it->second.path == path && it->second.protocol == profile,
                  "forbidden");
          const auto id = it->first;
          handles.erase(it);
          std::erase_if(locks, [&](const auto &entry) { return entry.handle == id; });
        }
      } else {
        auto j = job(body.at("job"));
        require(j.at("actor") == actor && j.at("path") == path && j.at("space") == space &&
                    j.value("protocol", "") == profile,
                "forbidden");
        if (j.at("status") == "staging" || j.at("status") == "uncertain") {
          auto &state = attach(g, ctx);
          dav_cancel_upload(state, j);
        }
      }
      return {{"cleaned", true}};
    }
    bool writing = op != "dav_copy" && op != "dav_stat" && op != "dav_list" && op != "stat" &&
                   op != "list" && op != "read" && op != "jobs" && op != "quota" && op != "close";
    if (op == "open")
      writing = body.value("write", false);
    auto grant = verify(body.at("grant"), writing);
    auto &s = attach(grant, ctx);
    auto space = grant.at("space").at("id").get<std::string>(),
         path = grant.at("path").get<std::string>(), actor = grant.at("actor").get<std::string>();
    lease(grant, ctx);
    for (auto j : jobs(space))
      if ((j.value("protocol", "") == "webdav" || j.value("protocol", "") == "ftp") &&
          j.at("status") == "staging" && j.value("active_until", int64_t(0)) < now())
        dav_cancel_upload(s, j);
    if (op == "ftp_rmdir") {
      require(ctx.caller == "ftp" && !path.empty(), "forbidden");
      auto dir = s.directory.open(path, true);
      require(dir.list().empty(), "directory_not_empty");
      dir = native_file();
      return dav_dispatch("dav_delete", body, grant, s, ctx);
    }
    if (op.starts_with("dav_"))
      return dav_dispatch(op, body, grant, s, ctx);
    if (op == "quota") {
      scan(s, ctx);
      return {{"used", used(space)},
              {"reserved", reserved(space)},
              {"limit", s.data.at("space").at("quota")},
              {"enforcement", "service_enforced"},
              {"external_writers", "bypass_possible"}};
    }
    if (op == "list") {
      json values = json::array();
      native_file directory;
      native_file *dir = &s.directory;
      if (!path.empty()) {
        directory = s.directory.open(path, true);
        dir = &directory;
      }
      for (auto item : dir->list()) {
        auto name = item.at("name").get<std::string>();
        if (name.starts_with(".tc-"))
          continue;
        portable_path(name);
        auto relative = path.empty() ? name : path + "/" + name;
        auto native = s.directory.open(relative, item.at("directory"));
        index(space, relative, native.info());
        auto value = object(space, relative);
        value.erase("native");
        value["path"] = relative;
        values.push_back(value);
      }
      return values;
    }
    if (op == "jobs") {
      json values = json::array();
      for (auto j : jobs(space))
        if (j.at("actor") == actor && beneath(j.at("path"), path)) {
          j.erase("stage");
          j.erase("native");
          j.erase("previous");
          j.erase("entries");
          j.erase("conditions");
          values.push_back(j);
        }
      return values;
    }
    if (op == "stat") {
      auto info = object(space, path);
      auto native = s.directory.open(path, info.at("directory")).info();
      require(native.at("object") == info.at("native"), "object_replaced");
      info.erase("native");
      return info;
    }
    if (op == "open") {
      require(handles.size() < 128, "handle_limit");
      portable_path(path);
      smb_sharing(space, path, writing ? 3 : 1, 7);
      auto metadata = object(space, path);
      require(!metadata.at("directory").get<bool>(), "invalid_path");
      auto file = s.directory.open(path, false, false, writing);
      require(file.info().at("object") == metadata.at("native"), "object_replaced");
      auto handle = generation + ":" + random_hex(16);
      handles.emplace(handle, opened{std::move(file), actor, space, path, writing,
                                     grant.at("epoch"), grant.at("protocol")});
      return {{"handle", handle},
              {"object", metadata.at("object")},
              {"generation", generation},
              {"size", metadata.at("size")}};
    }
    if (op == "read" || op == "write" || op == "flush" || op == "close" || op == "lock" ||
        op == "unlock") {
      auto id = body.at("handle").get<std::string>();
      require(id.starts_with(generation + ":"), "stale_handle");
      auto it = handles.find(id);
      require(it != handles.end(), "stale_handle");
      auto &h = it->second;
      require(h.actor == actor && h.space == space && h.path == path, "forbidden");
      require(!writing || h.writable, "forbidden");
      if (op == "close") {
        handles.erase(it);
        std::erase_if(locks, [&](auto &l) { return l.handle == id; });
        return {{"closed", true}};
      }
      auto info = h.file.info();
      require(info.at("object") == object(space, path).at("native"), "object_replaced");
      if (op == "flush") {
        h.file.flush();
        return {{"flushed", true}};
      }
      if (op == "unlock") {
        std::erase_if(locks, [&](auto &l) { return l.handle == id; });
        return {{"unlocked", true}};
      }
      auto offset = number(body, "offset");
      if (op == "lock") {
        auto length = number(body, "length");
        require(offset <= uint64_t(INT64_MAX) - length && locks.size() < 256, "invalid_offset");
        auto end = length ? offset + length : uint64_t(INT64_MAX);
        range_unlocked(id, info.at("object"), offset, end);
        locks.push_back({id, info.at("object"), offset, end});
        return {{"locked", true}};
      }
      if (op == "read") {
        auto count = number(body, "count");
        require(count <= file_chunk_size && offset <= uint64_t(INT64_MAX) - count,
                "invalid_request");
        for (auto &l : locks)
          require(!count || !l.exclusive || l.handle == id ||
                      l.object != info.at("object").get<std::string>() || (!l.through_max && offset >= l.end) ||
                      offset + count <= l.start,
                  "locked");
        auto bytes = h.file.read(offset, static_cast<size_t>(count));
        return {{"data", encode_bytes(bytes)}, {"read", bytes.size()}, {"offset", offset}};
      }
      dav_guard(s, path, actor, body);
      auto data = decode_bytes(body.at("data").get<std::string>());
      require(offset <= uint64_t(INT64_MAX) - data.size(), "invalid_offset");
      range_unlocked(id, info.at("object"), offset, offset + data.size());
      auto request = body.at("request_id").get<std::string>(),
           hash = digest(json::array({actor, space, path, info.at("object"), offset,
                                      body.value("flush", false), body.at("data")})
                             .dump());
      if (auto previous = replay(request, hash))
        return *previous;
      auto size = info.at("size").get<uint64_t>();
      quota(s, offset + data.size() > size ? offset + data.size() - size : 0);
      pending(request, hash);
      lease(grant, ctx);
      try {
        auto written = h.file.write(offset, data);
        if (body.value("flush", false))
          h.file.flush();
        auto updated = h.file.info();
        transaction tx(db);
        index(space, path, updated);
        json result = {{"written", written},
                       {"offset", offset},
                       {"size", updated.at("size")},
                       {"durable", body.value("flush", false)}};
        complete(request, result);
        audit(actor, "write", path);
        tx.commit();
        return result;
      } catch (...) {
        index(space, path, h.file.info());
        throw;
      }
    }
    if (op == "begin") {
      dav_guard(s, path, actor, body, false, !dav_exists(s, path));
      portable_path(path);
      case_check(s.directory, path);
      unlocked(space, path);
      auto id = body.at("request_id").get<std::string>();
      require(id.size() >= 16 && id.size() <= 64 &&
                  id.find_first_not_of(
                      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") ==
                      std::string::npos,
              "invalid_request");
      auto size = number(body, "size");
      auto source = body.value("source_sha256", "");
      require(source.empty() || source.size() == 64, "invalid_request");
      try {
        auto previous = job(id);
        require(previous.at("action") == "upload" && previous.at("space") == space &&
                    previous.at("path") == path && previous.at("actor") == actor &&
                    previous.at("total") == size && previous.value("source_sha256", "") == source,
                "idempotency_conflict");
        return previous;
      } catch (const error &e) {
        if (std::string_view(e.what()) != "not_found")
          throw;
      }
      require(jobs(space).size() < 4096, "job_limit");
      quota(s, size);
      auto previous = stat_path(s.directory, path);
      auto stage = ".tc-stage-" + random_hex(16);
      auto file = s.directory.open(stage, false, true, true);
      file.flush();
      auto info = file.info();
      json j = {{"id", id},
                {"space", space},
                {"actor", actor},
                {"action", "upload"},
                {"path", path},
                {"stage", stage},
                {"native", info.at("object")},
                {"object", random_hex(16)},
                {"previous", previous ? previous->at("object") : json(nullptr)},
                {"total", size},
                {"source_sha256", source},
                {"conditions", body.value("conditions", json::object())},
                {"protocol", grant.at("protocol")},
                {"active_until", now() + 15000},
                {"progress", 0},
                {"reserved", size},
                {"status", "staging"}};
      save_job(j);
      audit(actor, "upload_started", path);
      return j;
    }
    if (op == "chunk" || op == "commit" || op == "seal" || op == "cancel_job") {
      auto j = job(body.at("job"));
      require(j.at("action") == "upload", "invalid_request");
      require(j.at("space") == space && j.at("path") == path && j.at("actor") == actor,
              "forbidden");
      if (op == "cancel_job") {
        require(j.at("status") == "staging" || j.at("status") == "uncertain" ||
                    j.at("status") == "cancelled",
                "not_cancellable");
        if (j.at("action") == "upload") {
          auto stage = stat_path(s.directory, j.at("stage"));
          if (stage) {
            require(stage->at("object") == j.at("native"), "object_replaced");
            s.directory.remove(j.at("stage"));
          }
        }
        j["status"] = "cancelled";
        j["reserved"] = 0;
        save_job(j);
        audit(actor, "job_cancelled", path);
        return j;
      }
      if (op == "commit" && j.at("status") == "completed")
        return j;
      require(j.at("status") == "staging", "uncertain_write");
      auto file = s.directory.open(j.at("stage"), false, false, true);
      require(file.info().at("object") == j.at("native"), "object_replaced");
      require(file.info().at("size") == j.at("progress"), "uncertain_write");
      if (op == "chunk") {
        auto offset = number(body, "offset");
        auto data = decode_bytes(body.at("data").get<std::string>());
        auto total = j.at("total").get<uint64_t>();
        require(offset <= total && data.size() <= total - offset, "invalid_offset");
        if (offset < j.at("progress").get<uint64_t>()) {
          require(offset + data.size() <= j.at("progress").get<uint64_t>() &&
                      file.read(offset, data.size()) == data,
                  "uncertain_write");
          return {{"written", data.size()}, {"progress", j.at("progress")}, {"replayed", true}};
        }
        require(offset == j.at("progress"), "invalid_offset");
        lease(grant, ctx);
        auto count = file.write(offset, data);
        file.flush();
        j["progress"] = offset + count;
        j["active_until"] = now() + 15000;
        save_job(j);
        return {{"written", count}, {"progress", j.at("progress")}};
      }
      if (op == "seal") {
        j["total"] = j.at("progress");
        j["reserved"] = j.at("progress");
        save_job(j);
        return j;
      }
      dav_guard(s, path, actor, j.value("conditions", json::object()), false, !dav_exists(s, path));
      require(j.at("progress") == j.at("total"), "incomplete_upload");
      unlocked(space, path);
      file.flush();
      lease(grant, ctx);
      j["status"] = "committing";
      save_job(j);
      file = native_file();
      reconcile_job(s, j);
      return job(j.at("id"));
    }
    if (op == "mkdir") {
      dav_guard(s, path, actor, body, false, true);
      portable_path(path);
      case_check(s.directory, path);
      auto dir = s.directory.open(path, true, true);
      s.directory.flush();
      index(space, path, dir.info());
      audit(actor, "mkdir", path);
      return object(space, path);
    }
    if (op == "rename" || op == "remove") {
      dav_guard(s, path, actor, body, true, true);
      portable_path(path);
      auto id = body.at("request_id").get<std::string>();
      require(id.size() >= 16 && id.size() <= 64, "invalid_request");
      std::string to;
      if (op == "rename") {
        auto target = verify(body.at("target_grant"), true);
        require(target.at("actor") == actor, "forbidden");
        require(target.at("space").at("id") == space, "cross_volume_move_requires_copy");
        to = target.at("path");
        portable_path(to);
        dav_guard(s, to, actor, body, true, true);
      }
      try {
        auto previous = job(id);
        require(previous.at("action") == op && previous.at("actor") == actor &&
                    previous.at("space") == space && previous.at("path") == path &&
                    previous.at("to") == to,
                "idempotency_conflict");
        require(previous.at("status") != "uncertain", "uncertain_write");
        return previous;
      } catch (const error &e) {
        if (std::string_view(e.what()) != "not_found")
          throw;
      }
      require(jobs(space).size() < 4096, "job_limit");
      auto info = object(space, path);
      require(!info.at("directory").get<bool>(), "directory_mutation_unavailable");
      require(s.directory.open(path).info().at("object") == info.at("native"), "object_replaced");
      if (op == "remove")
        unlocked(space, path);
      else {
        case_check(s.directory, to);
        require(!stat_path(s.directory, to), "already_exists");
      }
      json j = {{"id", id},
                {"space", space},
                {"actor", actor},
                {"action", op},
                {"path", path},
                {"to", to},
                {"native", info.at("native")},
                {"object", info.at("object")},
                {"status", "committing"}};
      lease(grant, ctx);
      save_job(j);
      reconcile_job(s, j);
      return job(id);
    }
    throw error("not_supported");
  }
};
file_store::file_store(const config &c, std::string role, std::string generation)
    : impl_(std::make_unique<impl>(c, std::move(role), std::move(generation))) {}
file_store::~file_store() = default;
json file_store::dispatch(const std::string &op, const json &body, const call_context &ctx) {
  return impl_->dispatch(op, body, ctx);
}
} // namespace tc
