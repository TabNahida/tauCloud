// NFSv4 ACLs and SMB DACLs are two encodings of the same authority descriptor.
// The export maps identify ordinary service principals; opaque SIDs preserve
// trustees that another protocol installed and this export cannot name.
static constexpr auto nfs_everyone = "010100000000000100000000";
static constexpr auto nfs_owner_rights = "010100000000000304000000";
json nfs_decode_acl(const json &g, json descriptor, const json &acl, bool directory) {
  require(acl.is_array() && acl.size() <= 1024, "invalid_acl");
  json entries = json::array();
  for (const auto &ace : acl) {
    auto type = ace.at("type").get<uint32_t>(), flags = ace.at("flags").get<uint32_t>(),
         mask = ace.at("mask").get<uint32_t>();
    require(type <= 1, "not_supported");
    require(!(flags & ~0xcfu) && !(mask & ~0x1f01ffu), "invalid_acl");
    require(directory || !(flags & 0x0f), "invalid_acl");
    require(!(flags & 0x0c) || (flags & 3), "invalid_acl");
    auto who = ace.at("who").get<std::string>();
    bool group = flags & 0x40;
    std::string sid;
    if (who == "OWNER@") {
      group = false; // IDENTIFIER_GROUP is ignored on special identifiers.
      sid = nfs_owner_rights;
    } else if (who == "GROUP@") {
      group = false;
      sid = descriptor.at("group");
    } else if (who == "EVERYONE@") {
      group = false;
      sid = nfs_everyone;
    } else {
      require(who.ends_with("@taucloud"), "invalid_owner");
      auto name = who.substr(0, who.size() - 9);
      bool known = !group && name == g.at("actor").get<std::string>();
      for (const auto &[id, value] : g.at("export").at(group ? "gids" : "uids").items())
        known |= value == name;
      if (known)
        sid = security::principal(name, group);
      else {
        require(name.starts_with("sid-") && name.size() <= 140, "invalid_owner");
        sid = name.substr(4);
        require(sid.size() % 2 == 0 &&
                    sid.find_first_not_of("0123456789abcdef") == std::string::npos,
                "invalid_owner");
        auto raw = decode_bytes(sid);
        require(raw.size() >= 8 && uint8_t(raw[0]) == 1 && uint8_t(raw[1]) <= 15 &&
                    raw.size() == 8u + 4u * uint8_t(raw[1]),
                "invalid_owner");
      }
    }
    entries.push_back({{"sid", sid},
                       {"type", type},
                       {"mask", mask},
                       {"flags", flags & 15}, // INHERITED_ACE is only valid in dacl/sacl.
                       {"nfs_who", who},
                       {"nfs_group", group}});
  }
  descriptor["dacl"] = std::move(entries);
  descriptor["control"] = 0x8404;
  require(security::encode(descriptor, 7).size() <= 65536, "invalid_acl");
  return descriptor;
}
json nfs_encode_acl(const json &g, const json &descriptor) {
  std::map<std::string, std::pair<std::string, bool>> names;
  for (auto [kind, group] : {std::pair{"uids", false}, {"gids", true}})
    for (const auto &[id, name] : g.at("export").at(kind).items())
      names[security::principal(name, group)] = {name.get<std::string>() + "@taucloud", group};
  auto entries = descriptor.at("dacl");
  if (entries.is_null())
    entries = json::array({{{"sid", nfs_everyone}, {"type", 0}, {"mask", 0x1f01ff}, {"flags", 0}}});
  json acl = json::array();
  for (const auto &entry : entries) {
    auto sid = entry.at("sid").get<std::string>();
    auto flags = entry.at("flags").get<unsigned>();
    auto special = entry.value("nfs_who", "");
    bool group = entry.value("nfs_group", false);
    std::string who;
    if (sid == nfs_everyone)
      who = "EVERYONE@";
    else if (sid == nfs_owner_rights ||
             (special.empty() && sid == descriptor.at("owner").get<std::string>()))
      who = "OWNER@";
    else if (special == "GROUP@" ||
             (special.empty() && sid == descriptor.at("group").get<std::string>()))
      who = "GROUP@";
    else {
      if (auto found = names.find(sid); found != names.end()) {
        who = found->second.first;
        group = found->second.second;
      }
      if (who.empty())
        who = "sid-" + sid + "@taucloud";
    }
    if (who == "OWNER@" || who == "GROUP@" || who == "EVERYONE@")
      group = false;
    acl.push_back({{"type", entry.at("type")},
                   {"mask", entry.at("mask")},
                   {"who", who},
                   {"flags", (flags & 15) | (group ? 0x40 : 0)}});
  }
  return acl;
}
