// The file worker owns DACLs for every protocol. Identity grants carry the
// authenticated group set; no native host identity or client SID is trusted.
json security_get(space_state &s, const json &info) {
  statement q(db, "SELECT body FROM security_descriptors WHERE native=?");
  q.bind(1, info.at("object"));
  if (q.row())
    return json::parse(q.text(0));
  auto space = s.data.at("space");
  return security::defaults(security::principal(space.at("owner")),
                            security::principal(space.value("group", ""), true));
}
void security_save(const json &info, const json &descriptor) {
  statement q(db, "INSERT INTO security_descriptors VALUES(?,?) ON CONFLICT(native) "
                  "DO UPDATE SET body=excluded.body");
  q.bind(1, info.at("object"));
  q.bind(2, descriptor.dump());
  q.row();
  notify_metadata(info.at("object"), 0x100);
}
void security_data_changed(space_state &s, const json &info) {
  if (info.at("directory").get<bool>())
    return;
  auto descriptor = security_get(s, info);
  if (descriptor.value("mode_special", 0u) & 06000) {
    descriptor["mode_special"] = descriptor.value("mode_special", 0u) & ~06000u;
    security_save(info, descriptor);
  }
}
static std::string security_parent(const std::string &path) {
  auto slash = path.rfind('/');
  return slash == std::string::npos ? "" : path.substr(0, slash);
}
json security_info(space_state &s, const std::string &path) {
  if (path.empty())
    return s.directory.info(true);
  auto found = dav_exists(s, path);
  require(found.has_value(), "not_found");
  return s.directory.open(path, found->at("directory")).info(true);
}
uint32_t security_allowed(space_state &s, const json &grant, const json &info) {
  return security::allowed(security_get(s, info), security::token(grant));
}
void security_check(space_state &s, const json &grant, const json &info, uint32_t mask) {
  require((mask & ~security_allowed(s, grant, info)) == 0, "forbidden");
}
void security_path(space_state &s, const json &grant, const std::string &path, uint32_t mask) {
  security_check(s, grant, security_info(s, path), mask);
}
json security_new(space_state &s, const json &grant, const std::string &path, bool directory) {
  // Staged DAV copies are deliberately absent from the public namespace index.
  // Read the pinned native parent so children inherit its already-stored ACL.
  auto parent_path = security_parent(path);
  auto parent =
      parent_path.empty() ? s.directory.info(true) : s.directory.open(parent_path, true).info(true);
  auto result =
      security::inherit(security_get(s, parent), security::principal(grant.at("actor")),
                        security::principal(grant.at("space").value("group", ""), true), directory);
  require(result.at("dacl").size() <= 1024 && security::encode(result, 7).size() <= 65536,
          "invalid_security_descriptor");
  return result;
}
void security_add(space_state &s, const json &grant, const std::string &path, bool directory) {
  security_path(s, grant, security_parent(path), directory ? 4 : 2);
}
void security_sticky(space_state &s, const json &grant, const std::string &path) {
  require(!path.empty(), "forbidden");
  auto parent = security_get(s, security_info(s, security_parent(path)));
  if (!(parent.value("mode_special", 0u) & 01000))
    return;
  auto actor = security::principal(grant.at("actor"));
  auto child = security_get(s, security_info(s, path));
  require(parent.at("owner") == actor || child.at("owner") == actor, "forbidden");
}
void security_delete(space_state &s, const json &grant, const std::string &path) {
  security_sticky(s, grant, path);
  auto info = security_info(s, path);
  auto parent = security_info(s, security_parent(path));
  require((security_allowed(s, grant, info) & 0x10000) ||
              (security_allowed(s, grant, parent) & 0x40),
          "forbidden");
}
// Non-SMB protocols do not cache Windows handle rights. Recheck on each data
// operation and before publishing a staged replacement, including after restart.
void security_preflight(space_state &s, const json &grant, const std::string &op) {
  auto path = grant.at("path").get<std::string>();
  if (op == "close" || op == "cancel_job" || op == "unlock" || op == "jobs" || op == "quota")
    return;
  if (op == "begin" || op == "commit" || op == "chunk" || op == "seal") {
    if (dav_exists(s, path))
      security_path(s, grant, path, 2);
    else
      security_add(s, grant, path, false);
  } else if (op == "mkdir")
    security_add(s, grant, path, true);
  else if (op == "remove" || op == "rename" || op == "ftp_rmdir")
    security_delete(s, grant, path);
  else if (op == "open" || op == "read")
    security_path(s, grant, path, 1);
  else if (op == "write")
    security_path(s, grant, path, 2);
  else if (op == "list" || op == "dav_list")
    security_path(s, grant, path, 1);
  else if (op == "stat" || op == "dav_stat")
    security_path(s, grant, path, 0x80);
  else if (op == "dav_lock" && !dav_exists(s, path))
    security_add(s, grant, path, false);
  else if (op == "dav_props" || op == "dav_lock")
    security_path(s, grant, path, 0x100);
}
