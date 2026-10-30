#include <taucloud/policy.hpp>
#include <taucloud/files.hpp>
#include <algorithm>
namespace tc {
namespace {
void identifier(const std::string &id) {
  require(!id.empty() && id.size() <= 48 &&
              id.find_first_not_of(
                  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.") ==
                  std::string::npos &&
              id != "." && id != "..",
          "invalid_identifier");
}
json record(sqlite3 *db, const std::string &kind, const std::string &id) {
  statement q(db, "SELECT body FROM records WHERE kind=? AND id=?");
  q.bind(1, kind);
  q.bind(2, id);
  require(q.row(), "not_found");
  return json::parse(q.text(0));
}
json records(sqlite3 *db, const std::string &kind) {
  statement q(db, "SELECT body FROM records WHERE kind=? ORDER BY id");
  q.bind(1, kind);
  json values = json::array();
  while (q.row())
    values.push_back(json::parse(q.text(0)));
  return values;
}
void put(sqlite3 *db, const std::string &kind, const std::string &id, const json &body,
         bool update = false) {
  statement count(db, "SELECT count(*) FROM records");
  count.row();
  require(count.integer(0) < 1024, "record_limit");
  if (!update) {
    statement exists(db, "SELECT 1 FROM records WHERE kind=? AND id=?");
    exists.bind(1, kind);
    exists.bind(2, id);
    require(!exists.row(), "already_exists");
  }
  statement q(
      db,
      "INSERT INTO records VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body");
  q.bind(1, kind);
  q.bind(2, id);
  q.bind(3, body.dump());
  q.row();
}
bool exists_user(sqlite3 *db, const std::string &user) {
  statement q(db, "SELECT 1 FROM users WHERE name=? AND enabled=1");
  q.bind(1, user);
  return q.row();
}
bool member(sqlite3 *db, const std::string &user, const std::string &group) {
  statement q(db, "SELECT 1 FROM memberships WHERE username=? AND groupname=?");
  q.bind(1, user);
  q.bind(2, group);
  return q.row();
}
std::string access(sqlite3 *db, const json &space, const std::string &user) {
  if (space.value("owner", "") == user)
    return "rw";
  std::string rights =
      (!space.value("group", "").empty() && member(db, user, space.at("group"))) ? "rw" : "";
  statement q(db, "SELECT kind,subject,rights FROM grants WHERE space=?");
  q.bind(1, space.at("id"));
  while (q.row())
    if ((q.text(0) == "user" && q.text(1) == user) ||
        (q.text(0) == "group" && member(db, user, q.text(1)))) {
      if (q.text(2) == "rw")
        return "rw";
      if (q.text(2) == "r" && rights != "rw")
        rights = "r";
    }
  return rights;
}
json subject(sqlite3 *db, const json &body) {
  auto auth = body.at("auth");
  statement q(db, "SELECT u.name,u.role,s.scope,s.expires FROM sessions s JOIN users u ON "
                  "u.name=s.name WHERE s.hash=? AND s.kind=? AND u.enabled=1");
  q.bind(1, digest(auth.at("token").get<std::string>()));
  q.bind(2, auth.at("kind"));
  require(q.row() && q.integer(3) > now(), "unauthorized");
  return {{"username", q.text(0)},
          {"role", q.text(1)},
          {"scope", q.text(2)},
          {"expires", q.integer(3)}};
}
int64_t epoch(sqlite3 *db) {
  statement q(db, "SELECT value FROM policy_state WHERE id=1");
  q.row();
  return q.integer(0);
}
void audit(sqlite3 *db, const std::string &actor, const std::string &action,
           const std::string &resource) {
  statement q(db, "INSERT INTO policy_audit(time,actor,action,resource) VALUES(?,?,?,?)");
  q.bind(1, now());
  q.bind(2, actor);
  q.bind(3, action);
  q.bind(4, resource);
  q.row();
}
bool overlap(const std::string &a, const std::string &b) {
  return a == b || a.starts_with(b + "/") || b.starts_with(a + "/");
}
json push_revocation(const config &c, json result) {
  auto revision = result.at("policy_epoch").get<int64_t>();
  json acknowledgements = json::object();
  auto effective_by = now() + 2000;
  for (auto &worker : file_roles()) {
    try {
      auto ack = rpc(c, "identity", worker, "revoke", {{"epoch", revision}}, "", {}, "", 250);
      acknowledgements[worker] = ack.at("epoch");
    } catch (...) {
      acknowledgements[worker] = "pending";
    }
  }
  result["revocation"] = {{"acknowledgements", acknowledgements}, {"effective_by", effective_by}};
  return result;
}
} // namespace
void migrate_policy(sqlite3 *db) {
  sql(db, "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'; ALTER TABLE users ADD "
          "COLUMN enabled INTEGER NOT NULL DEFAULT 1; UPDATE users SET role='admin';"
          "CREATE TABLE records(kind TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY "
          "KEY(kind,id));"
          "CREATE TABLE memberships(username TEXT NOT NULL REFERENCES users(name),groupname TEXT "
          "NOT NULL,PRIMARY KEY(username,groupname));"
          "CREATE TABLE grants(space TEXT NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,rights "
          "TEXT NOT NULL,PRIMARY KEY(space,kind,subject));"
          "CREATE TABLE policy_state(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);INSERT INTO "
          "policy_state VALUES(1,1);"
          "CREATE TABLE policy_audit(id INTEGER PRIMARY KEY,time INTEGER NOT NULL,actor TEXT NOT "
          "NULL,action TEXT NOT NULL,resource TEXT NOT NULL);"
          "CREATE TABLE policy_requests(id TEXT PRIMARY KEY,hash TEXT NOT NULL,result TEXT NOT "
          "NULL); PRAGMA user_version=3;");
}
json policy_dispatch(sqlite3 *db, const config &c, const std::string &operation, const json &body,
                     const call_context &ctx) {
  ctx.check();
  json who;
  json nfs_export;
  if (operation == "nfs_authorize") {
    require(ctx.caller == "nfs" && body.value("peer", "") == "127.0.0.1", "forbidden");
    for (const auto &e : records(db, "nfs-exports"))
      if (e.at("id") == body.value("export", "") || e.at("uuid") == body.value("uuid", ""))
        nfs_export = e;
    require(!nfs_export.is_null() && nfs_export.at("enabled").get<bool>() &&
                nfs_export.at("trust") == "loopback-auth-sys", "forbidden");
    const auto &cred = body.at("credential");
    auto uid = cred.at("uid").get<uint32_t>();
    auto gid = cred.at("gid").get<uint32_t>();
    require(cred.at("groups").is_array() && cred.at("groups").size() <= 16, "forbidden");
    std::string user;
    if (uid == 0)
      user = nfs_export.at("anonymous"); // Root squash is mandatory, including all groups.
    else {
      user = nfs_export.at("uids").value(std::to_string(uid), "");
      require(!user.empty(), "forbidden");
      auto check_group = [&](uint32_t id) {
        auto g = nfs_export.at("gids").value(std::to_string(id), "");
        require(!g.empty() && member(db, user, g), "forbidden");
      };
      check_group(gid);
      for (auto g : cred.at("groups")) check_group(g.get<uint32_t>());
    }
    require(exists_user(db, user), "forbidden");
    who = {{"username", user}, {"role", "member"}, {"scope", "files"}, {"expires", now()+2000}};
  } else
    who = subject(db, body);
  auto actor = who.at("username").get<std::string>();
  if (operation == "authorize" || operation == "nfs_authorize") {
    json space;
    std::string relative = body.value("path", "");
    if (!relative.empty())
      portable_path(relative);
    std::string share_id = nfs_export.is_null() ? body.value("share", "") : nfs_export.at("id").get<std::string>();
    auto profile = nfs_export.is_null() ? body.value("protocol", "core") : "nfs";
    require(profile == "core" ||
                ((profile == "webdav" || profile == "ftp" || profile == "smb" || (profile == "nfs" && operation == "nfs_authorize")) && ctx.caller == profile),
            "protocol_unavailable");
    require(profile == "core" || !share_id.empty(), "forbidden");
    std::string exposed = "rw";
    if (!share_id.empty()) {
      auto share = record(db, "shares", share_id);
      space = record(db, "spaces", share.at("space"));
      exposed = share.at("exposures").value(profile, "");
      auto sub = share.value("path", "");
      if (!sub.empty())
        relative = sub + (relative.empty() ? "" : "/" + relative);
    } else
      space = record(db, "spaces", body.at("space"));
    auto rights = access(db, space, actor);
    require(!rights.empty() && !exposed.empty(), "forbidden");
    bool write = body.value("write", false);
    if (write) {
      require(rights == "rw" && exposed == "rw" &&
                  (who.at("scope") == "files" || who.at("scope") == "admin"),
              "forbidden");
      for (auto share : records(db, "shares"))
        if (share.at("space") == space.at("id"))
          for (auto &[protocol, mode] : share.at("exposures").items())
            require(mode != "rw" || protocol == profile ||
                        ((protocol == "core" || protocol == "webdav") &&
                         (profile == "core" || profile == "webdav")),
                    "mixed_writers_disabled");
    }
    auto root = record(db, "storage-roots", space.at("root"));
    json grant = {
        {"actor", actor},     {"space", space},
        {"root", root},       {"path", relative},
        {"write", write},     {"share", share_id},
        {"epoch", epoch(db)}, {"expires", std::min<int64_t>(now() + 2000, who.at("expires"))},
        {"protocol", profile}};
    if (!nfs_export.is_null()) grant["export"] = nfs_export;
    auto key = read_json(c.state / "ipc-keys.json").at("identity").get<std::string>();
    grant["signature"] = mac(key, grant.dump());
    return grant;
  }
  auto kind = body.at("resource").get<std::string>();
  if (operation == "policy_list") {
    if (kind == "spaces" || kind == "shares") {
      json visible = json::array();
      for (auto value : records(db, kind)) {
        auto space = kind == "spaces" ? value : record(db, "spaces", value.at("space"));
        if (who.at("role") == "admin" || !access(db, space, actor).empty())
          visible.push_back(value);
      }
      return visible;
    }
    require(who.at("role") == "admin", "forbidden");
    if (kind == "users") {
      statement q(db, "SELECT name,role,enabled FROM users ORDER BY name");
      json users = json::array();
      while (q.row())
        users.push_back(
            {{"username", q.text(0)}, {"role", q.text(1)}, {"enabled", q.integer(2) != 0}});
      return users;
    }
    if (kind == "memberships") {
      statement q(db, "SELECT username,groupname FROM memberships ORDER BY groupname,username");
      json rows = json::array();
      while (q.row())
        rows.push_back({{"username", q.text(0)}, {"group", q.text(1)}});
      return rows;
    }
    if (kind == "grants") {
      statement q(db, "SELECT space,kind,subject,rights FROM grants ORDER BY space,subject");
      json rows = json::array();
      while (q.row())
        rows.push_back({{"space", q.text(0)},
                        {"subject_type", q.text(1)},
                        {"subject", q.text(2)},
                        {"rights", q.text(3)}});
      return rows;
    }
    if (kind == "audit") {
      statement q(
          db, "SELECT id,time,actor,action,resource FROM policy_audit ORDER BY id DESC LIMIT 100");
      json rows = json::array();
      while (q.row())
        rows.push_back({{"id", q.integer(0)},
                        {"time", q.integer(1)},
                        {"actor", q.text(2)},
                        {"action", q.text(3)},
                        {"resource", q.text(4)}});
      return rows;
    }
    require(kind == "storage-roots" || kind == "groups" || kind == "nfs-exports", "invalid_request");
    return records(db, kind);
  }
  require(operation == "policy_write" && who.at("role") == "admin" && who.at("scope") == "admin",
          "forbidden");
  auto data = body.at("data");
  auto request_id = body.at("request_id").get<std::string>();
  require(request_id.size() >= 16 && request_id.size() <= 64, "invalid_request");
  auto request_hash = mac(read_json(c.state / "ipc-keys.json").at("identity").get<std::string>(),
                          actor + kind + data.dump());
  {
    statement q(db, "SELECT hash,result FROM policy_requests WHERE id=?");
    q.bind(1, request_id);
    if (q.row()) {
      require(q.text(0) == request_hash, "idempotency_conflict");
      return push_revocation(c, json::parse(q.text(1)));
    }
  }
  transaction tx(db);
  statement history(db, "SELECT count(*) FROM policy_requests");
  history.row();
  require(history.integer(0) < 10000, "operation_limit");
  json result;
  std::string id = data.value("id", data.value("username", data.value("name", kind)));
  if (kind == "users") {
    auto name = data.at("username").get<std::string>();
    identifier(name);
    auto role = data.value("role", "member");
    require(role == "admin" || role == "member", "invalid_request");
    bool update = data.value("update", false);
    if (update) {
      require(name != actor, "self_change_denied");
      statement existing(db, "SELECT role,enabled FROM users WHERE name=?");
      existing.bind(1, name);
      require(existing.row(), "not_found");
      role = data.value("role", existing.text(0));
      bool enabled = data.value("enabled", bool(existing.integer(1)));
      statement q(db, "UPDATE users SET role=?,enabled=? WHERE name=?");
      q.bind(1, role);
      q.bind(2, int64_t(enabled));
      q.bind(3, name);
      q.row();
      statement revoke(db, "DELETE FROM sessions WHERE name=?");
      revoke.bind(1, name);
      revoke.row();
      result = {{"username", name}, {"role", role}, {"enabled", enabled}};
    } else {
      require(!exists_user(db, name), "already_exists");
      statement count(db, "SELECT count(*) FROM users");
      count.row();
      require(count.integer(0) < 1024, "record_limit");
      auto password = data.at("password").get<std::string>();
      require(password.size() >= 12 && password.size() <= 1024, "invalid_credentials_format");
      auto salt = random_hex(16), verifier = password_hash(password, salt);
      ctx.check();
      statement q(db, "INSERT INTO users(name,salt,verifier,role,enabled) VALUES(?,?,?,?,1)");
      q.bind(1, name);
      q.bind(2, salt);
      q.bind(3, verifier);
      q.bind(4, role);
      q.row();
      result = {{"username", name}, {"role", role}};
    }
  } else if (kind == "nfs-exports") {
    identifier(id);
    auto share = record(db, "shares", id);
    require(share.at("exposures").contains("nfs"), "protocol_unavailable");
    require(data.at("trust") == "loopback-auth-sys", "invalid_request");
    auto anon = data.at("anonymous").get<std::string>();
    require(exists_user(db, anon), "not_found");
    auto uids = data.at("uids"), gids = data.at("gids");
    require(uids.is_object() && gids.is_object() && uids.size() <= 128 && gids.size() <= 128,
            "invalid_request");
    for (const auto *mapping : {&uids, &gids})
      for (const auto &[number, name] : mapping->items()) {
        require(!number.empty() && number.size() <= 10 &&
                    number.find_first_not_of("0123456789") == std::string::npos &&
                    std::stoull(number) <= UINT32_MAX && std::to_string(std::stoull(number)) == number &&
                    name.is_string(), "invalid_request");
        if (mapping == &uids)
          require(number != "0" && exists_user(db, name), "invalid_request");
        else record(db, "groups", name);
      }
    auto uuid = random_hex(16);
    if (data.value("update", false)) uuid = record(db, kind, id).at("uuid");
    result = {{"id", id}, {"uuid", uuid}, {"trust", "loopback-auth-sys"},
              {"root_squash", true}, {"anonymous", anon}, {"uids", uids}, {"gids", gids},
              {"enabled", data.value("enabled", true)}};
    put(db, kind, id, result, data.value("update", false));
  } else if (kind == "groups") {
    id = data.at("name");
    identifier(id);
    result = {{"id", id}};
    put(db, kind, id, result);
  } else if (kind == "memberships") {
    auto group = data.at("group").get<std::string>(), user = data.at("username").get<std::string>();
    record(db, "groups", group);
    require(exists_user(db, user), "not_found");
    statement q(db, data.value("enabled", true)
                        ? "INSERT OR IGNORE INTO memberships VALUES(?,?)"
                        : "DELETE FROM memberships WHERE username=? AND groupname=?");
    q.bind(1, user);
    q.bind(2, group);
    q.row();
    result = {{"group", group}, {"username", user}, {"enabled", data.value("enabled", true)}};
  } else if (kind == "storage-roots") {
    identifier(id);
    auto path = fs::path(data.at("path").get<std::string>());
    auto info = rpc(c, "identity", "file", "inspect", {{"path", path.string()}});
    auto canonical = fs::path(info.at("path").get<std::string>());
    auto state = c.state.lexically_normal();
    auto relative = state.lexically_relative(canonical);
    require(relative.empty() || relative.begin()->string() == "..", "unsafe_alias");
    relative = canonical.lexically_relative(state);
    require(relative.empty() || relative.begin()->string() == "..", "unsafe_alias");
    require(canonical != canonical.root_path(), "unsafe_root");
    auto roots = records(db, kind);
    require(roots.size() < file_roles().size(), "domain_limit");
    for (auto r : roots)
      require(r.at("volume") != info.at("volume"), "volume_already_registered");
    result = info;
    result["id"] = id;
    result["worker"] = file_roles().at(roots.size());
    put(db, kind, id, result);
  } else if (kind == "spaces") {
    identifier(id);
    auto root = record(db, "storage-roots", data.at("root"));
    auto path = data.at("path").get<std::string>();
    portable_path(path);
    auto owner = data.value("owner", ""), group = data.value("group", "");
    require(owner.empty() != group.empty(), "invalid_owner");
    if (!owner.empty())
      require(exists_user(db, owner), "not_found");
    else
      record(db, "groups", group);
    int64_t quota = data.at("quota");
    require(quota >= 0 && quota <= INT64_MAX / 2, "invalid_quota");
    for (auto s : records(db, kind))
      if (s.at("root") == root.at("id")) {
        auto a = s.at("path").get<std::string>(), b = path;
        a = path_fold(a);
        b = path_fold(b);
        require(!overlap(a, b), "overlapping_space");
      }
    result = {{"id", id},
              {"root", root.at("id")},
              {"path", path},
              {"owner", owner},
              {"group", group},
              {"quota", quota},
              {"quota_enforcement", "service_enforced"}};
    // File provisioning is idempotent and journalled by its own owner before policy publication.
    auto prepared = rpc(c, "identity", root.at("worker"), "provision",
                        {{"root", root}, {"space", result}, {"request_id", request_id}});
    result["object"] = prepared.at("object");
    put(db, kind, id, result);
  } else if (kind == "shares") {
    identifier(id);
    auto space = record(db, "spaces", data.at("space"));
    auto path = data.value("path", "");
    if (!path.empty())
      portable_path(path);
    auto exposures = data.value("exposures", json{{"core", "rw"}});
    require(exposures.is_object(), "invalid_request");
    int writers = 0;
    for (auto &[protocol, mode] : exposures.items()) {
      require(protocol == "core" || protocol == "webdav" || protocol == "smb" ||
                  protocol == "ftp" || protocol == "nfs",
              "protocol_unavailable");
      require(mode == "r" || mode == "rw", "invalid_request");
      if (mode == "rw")
        ++writers;
    }
    require(writers <= 1 || (writers == 2 && exposures.value("core", "") == "rw" &&
                             exposures.value("webdav", "") == "rw"),
            "mixed_writers_disabled");
    for (auto s : records(db, kind))
      if (s.at("space") == space.at("id") && s.at("id") != id)
        for (auto &[p, m] : s.at("exposures").items())
          if (m == "rw")
            for (auto &[p2, m2] : exposures.items())
              require(m2 != "rw" || p == p2 ||
                          ((p == "core" || p == "webdav") && (p2 == "core" || p2 == "webdav")),
                      "mixed_writers_disabled");
    result = {{"id", id}, {"space", space.at("id")}, {"path", path}, {"exposures", exposures}};
    if (data.value("update", false))
      record(db, kind, id);
    put(db, kind, id, result, data.value("update", false));
  } else if (kind == "grants") {
    auto space = record(db, "spaces", data.at("space"));
    auto type = data.at("subject_type").get<std::string>(),
         name = data.at("subject").get<std::string>(),
         rights = data.at("rights").get<std::string>();
    require(type == "user" || type == "group", "invalid_request");
    if (type == "user")
      require(exists_user(db, name), "not_found");
    else
      record(db, "groups", name);
    require(rights.empty() || rights == "r" || rights == "rw", "invalid_request");
    statement q(db, "INSERT INTO grants VALUES(?,?,?,?) ON CONFLICT(space,kind,subject) DO UPDATE "
                    "SET rights=excluded.rights");
    q.bind(1, space.at("id"));
    q.bind(2, type);
    q.bind(3, name);
    q.bind(4, rights);
    q.row();
    result = data;
  } else
    throw error("invalid_request");
  ctx.check();
  sql(db, "UPDATE policy_state SET value=value+1 WHERE id=1");
  auto revision = epoch(db);
  audit(db, actor, kind, id);
  result["policy_epoch"] = revision;
  statement store(db, "INSERT INTO policy_requests VALUES(?,?,?)");
  store.bind(1, request_id);
  store.bind(2, request_hash);
  store.bind(3, result.dump());
  store.row();
  tx.commit();
  return push_revocation(c, result);
}
} // namespace tc
