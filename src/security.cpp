#include <taucloud/security.hpp>
#include <taucloud/files.hpp>
#include <taucloud/smb.hpp>
#include <algorithm>
namespace tc::security {
using smb_detail::get;
using smb_detail::put;
namespace {
constexpr uint32_t full = 0x1f01ff;
const std::string everyone = "010100000000000100000000";
const std::string authenticated = "01010000000000050b000000";
const std::string creator_owner = "010100000000000300000000";
const std::string creator_group = "010100000000000301000000";
const std::string owner_rights = "010100000000000304000000";
void valid(bool condition) { require(condition, "invalid_security_descriptor"); }
std::string sid(std::string_view wire, size_t offset, size_t end) {
  valid(offset <= end && end <= wire.size() && end - offset >= 8);
  valid(get(wire, offset, 1) == 1 && get(wire, offset + 1, 1) <= 15);
  size_t size = 8 + 4 * get(wire, offset + 1, 1);
  valid(size <= end - offset);
  return encode_bytes(wire.substr(offset, size));
}
bool contains(const json &values, const std::string &value) {
  return std::find(values.begin(), values.end(), json(value)) != values.end();
}
} // namespace
std::string principal(const std::string &name, bool group) {
  auto hash =
      decode_bytes(digest(std::string(group ? "tauCloud/group/" : "tauCloud/user/") + name));
  std::string wire(28, '\0');
  put(wire, 0, 1, 1);
  put(wire, 1, 5, 1);
  put(wire, 7, 5, 1);
  put(wire, 8, 21, 4);
  wire.replace(12, 16, hash.substr(0, 16));
  return encode_bytes(wire);
}
json token(const json &grant) {
  json result = json::array({principal(grant.at("actor")), everyone, authenticated});
  for (const auto &group : grant.value("groups", json::array()))
    result.push_back(principal(group.get<std::string>(), true));
  return result;
}
uint32_t map_mask(uint32_t mask) {
  if (mask & 0x80000000)
    mask |= 0x120089;
  if (mask & 0x40000000)
    mask |= 0x120116;
  if (mask & 0x20000000)
    mask |= 0x1200a0;
  if (mask & 0x10000000)
    mask |= full;
  return mask & 0x0fffffff;
}
json decode(std::string_view wire) {
  valid(wire.size() >= 20 && wire.size() <= 65536 && get(wire, 0, 1) == 1);
  auto control = uint32_t(get(wire, 2, 2));
  valid(control & 0x8000);
  // Audit, mandatory labels and conditional/object ACEs need their own authority.
  require(!(control & 0x10) && get(wire, 12, 4) == 0, "privilege_not_held");
  json result = {{"owner", ""}, {"group", ""}, {"control", control}, {"dacl", nullptr}};
  std::vector<std::pair<size_t, size_t>> regions{{0, 20}};
  auto region = [&](size_t start, size_t size, bool shared_sid = false) {
    valid(start % 4 == 0 && start <= wire.size() && size <= wire.size() - start);
    for (const auto &[a, b] : regions)
      valid(start >= b || start + size <= a || (shared_sid && start == a && start + size == b));
    regions.emplace_back(start, start + size);
  };
  for (auto [name, offset] : {std::pair{"owner", 4}, {"group", 8}}) {
    auto start = size_t(get(wire, offset, 4));
    if (start) {
      auto value = sid(wire, start, wire.size());
      region(start, value.size() / 2, true);
      result[name] = value;
    }
  }
  size_t start = get(wire, 16, 4);
  valid((control & 4) || start == 0);
  if (start) {
    valid(start <= wire.size() && wire.size() - start >= 8);
    auto revision = get(wire, start, 1), size = get(wire, start + 2, 2),
         count = get(wire, start + 4, 2);
    valid((revision == 2 || revision == 4) && size >= 8 && size % 4 == 0 && count <= 1024);
    region(start, size);
    size_t pos = start + 8, end = start + size;
    result["dacl"] = json::array();
    for (size_t i = 0; i < count; ++i) {
      valid(pos <= end && end - pos >= 8);
      auto type = get(wire, pos, 1), flags = get(wire, pos + 1, 1), length = get(wire, pos + 2, 2);
      valid(length >= 16 && length % 4 == 0 && length <= end - pos);
      require(type <= 1 && !(flags & ~0x1fu), "not_supported");
      auto trustee = sid(wire, pos + 8, pos + length);
      valid(length == 8 + trustee.size() / 2);
      auto mask = map_mask(uint32_t(get(wire, pos + 4, 4)));
      require(!(mask & ~full), "not_supported");
      result["dacl"].push_back(
          {{"type", type}, {"flags", flags}, {"mask", mask}, {"sid", trustee}});
      pos += length;
    }
  }
  return result;
}
std::string encode(const json &descriptor, uint32_t information) {
  std::string wire(20, '\0');
  put(wire, 0, 1, 1);
  uint32_t control = descriptor.at("control").get<uint32_t>() | 0x8000;
  if (!(information & 4))
    control &= ~0x150c;
  put(wire, 2, control, 2);
  for (auto [name, offset, bit] : {std::tuple{"owner", 4, 1}, {"group", 8, 2}}) {
    if ((information & bit) && !descriptor.at(name).get<std::string>().empty()) {
      put(wire, offset, wire.size(), 4);
      wire += decode_bytes(descriptor.at(name).get<std::string>());
    }
  }
  if ((information & 4) && !descriptor.at("dacl").is_null()) {
    put(wire, 16, wire.size(), 4);
    std::string acl(8, '\0');
    put(acl, 0, 2, 1);
    for (const auto &entry : descriptor.at("dacl")) {
      auto trustee = decode_bytes(entry.at("sid").get<std::string>());
      std::string ace(8, '\0');
      put(ace, 0, entry.at("type"), 1);
      put(ace, 1, entry.at("flags"), 1);
      put(ace, 2, 8 + trustee.size(), 2);
      put(ace, 4, entry.at("mask"), 4);
      acl += ace + trustee;
    }
    require(acl.size() <= 65535, "invalid_security_descriptor");
    put(acl, 2, acl.size(), 2);
    put(acl, 4, descriptor.at("dacl").size(), 2);
    wire += acl;
  }
  return wire;
}
json defaults(const std::string &owner, const std::string &group) {
  return {{"owner", owner},
          {"group", group},
          {"control", 0x8004},
          {"dacl", json::array({{{"type", 0}, {"flags", 3}, {"mask", full}, {"sid", everyone}}})}};
}
json inherit(const json &parent, const std::string &owner, const std::string &group, bool directory,
             bool fallback) {
  bool setgid = parent.value("mode_special", 0u) & 02000;
  auto inherited_group = setgid ? parent.at("group").get<std::string>() : group;
  auto result = defaults(owner, inherited_group);
  if (setgid && directory)
    result["mode_special"] = 02000;
  if (parent.at("dacl").is_null()) {
    result["dacl"] = nullptr;
    return result;
  }
  json inherited = json::array();
  unsigned inherited_flag = (parent.at("control").get<unsigned>() & 0x400) ? 16 : 0;
  for (auto entry : parent.at("dacl")) {
    auto flags = entry.at("flags").get<unsigned>();
    if (directory ? !(flags & 3) : !(flags & 1))
      continue;
    unsigned next = directory ? ((flags & ~0x18u) | inherited_flag) : inherited_flag;
    if (directory && !(flags & 2))
      next |= 8;
    if (flags & 4) {
      next &= ~7u;
      if (next & 8)
        continue;
    }
    entry["flags"] = next;
    if (entry.value("nfs_who", "") == "GROUP@")
      entry["sid"] = inherited_group;
    auto trustee = entry.at("sid").get<std::string>();
    if (!(next & 8) && (trustee == creator_owner || trustee == creator_group)) {
      auto effective = entry;
      effective["sid"] = trustee == creator_owner ? owner : inherited_group;
      effective["flags"] = inherited_flag;
      inherited.push_back(effective);
      if (!(next & 3))
        continue;
      entry["flags"] = next | 8;
    }
    inherited.push_back(entry);
  }
  if (!inherited.empty() || !fallback) {
    result["dacl"] = inherited;
    result["control"] = inherited_flag ? 0x8404 : 0x8004;
  }
  return result;
}
uint32_t allowed(const json &descriptor, const json &subjects) {
  if (descriptor.at("dacl").is_null())
    return full;
  bool owner = subjects.at(0) == descriptor.at("owner"), explicit_owner = false;
  for (const auto &entry : descriptor.at("dacl"))
    if (!(entry.at("flags").get<unsigned>() & 8) && entry.at("sid") == owner_rights)
      explicit_owner = true;
  uint32_t granted = owner && !explicit_owner ? 0x60000 : 0, remaining = full & ~granted;
  for (const auto &entry : descriptor.at("dacl")) {
    if (entry.at("flags").get<unsigned>() & 8)
      continue;
    auto trustee = entry.at("sid").get<std::string>();
    if (!contains(subjects, trustee) && !(owner && trustee == owner_rights))
      continue;
    auto bits = entry.at("mask").get<uint32_t>() & remaining;
    if (entry.at("type") == 0)
      granted |= bits;
    remaining &= ~bits; // Preserve ACE order: a later deny cannot undo an earlier allow.
  }
  return granted;
}
unsigned mode(const json &descriptor) {
  auto projected = descriptor;
  if (!projected.at("dacl").is_null())
    std::erase_if(projected["dacl"].get_ref<json::array_t &>(), [&](const auto &entry) {
      auto who = entry.value("nfs_who", "");
      return !who.empty() && who != "OWNER@" && who != "GROUP@" && who != "EVERYONE@";
    });
  unsigned result = descriptor.value("mode_special", 0u) & 07000;
  for (unsigned category = 0; category < 3; ++category) {
    json subjects = json::array(
        {category == 0 ? descriptor.at("owner").get<std::string>() : std::string("mode-non-owner"),
         everyone});
    if (category == 1)
      subjects.push_back(descriptor.at("group"));
    auto access = allowed(projected, subjects);
    unsigned bits =
        ((access & 1) ? 4u : 0u) | ((access & 6) == 6 ? 2u : 0u) | ((access & 0x20) ? 1u : 0u);
    result |= bits << (6 - 3 * category);
  }
  return result;
}
json chmod(json descriptor, unsigned value, bool directory) {
  require(value <= 07777, "invalid_mode");
  descriptor["mode_special"] = value & 07000;
  const uint32_t data = directory ? 0x67 : 0x27;
  auto rights = [directory](unsigned bits) {
    return ((bits & 4) ? 1u : 0u) | ((bits & 2) ? (directory ? 0x46u : 6u) : 0u) |
           ((bits & 1) ? 0x20u : 0u);
  };
  auto owner = rights(value >> 6), group = rights(value >> 3), other = rights(value);
  json acl = json::array();
  auto add = [&](const std::string &sid, uint32_t mask, unsigned type,
                 const std::string &who = "") {
    if (mask)
      acl.push_back({{"sid", sid},
                     {"mask", mask},
                     {"type", type},
                     {"flags", 0},
                     {"nfs_who", who},
                     {"mode_generated", true}});
  };
  // An owner/group class decision must precede EVERYONE, otherwise a more
  // permissive other class can silently widen an owner's requested mode.
  add(owner_rights, owner | 0xe0188, 0, "OWNER@");
  add(owner_rights, data & ~owner, 1, "OWNER@");
  add(descriptor.at("group"), group, 0, "GROUP@");
  add(descriptor.at("group"), data & ~group, 1, "GROUP@");
  if (!descriptor.at("dacl").is_null())
    for (auto entry : descriptor.at("dacl")) {
      if (entry.value("mode_generated", false))
        continue;
      auto flags = entry.at("flags").get<unsigned>();
      if (flags & 8) {
        acl.push_back(entry);
        continue;
      }
      auto sid = entry.at("sid").get<std::string>();
      auto mask = entry.at("mask").get<uint32_t>();
      bool standard = sid == everyone || sid == owner_rights ||
                      sid == descriptor.at("owner").get<std::string>() ||
                      sid == descriptor.at("group").get<std::string>();
      auto effective = entry;
      effective["flags"] = flags & ~7u;
      // Keep unrelated permissions and bounded named-principal grants. Keep a
      // separate inherit-only ACE so chmod does not erase child inheritance.
      auto preserved = mask & ~data;
      if (sid == everyone || sid == descriptor.at("group").get<std::string>())
        preserved &= ~0xc0000u;
      effective["mask"] =
          preserved | (standard ? 0u : mask & data & (entry.at("type") == 0 ? group : data));
      if (effective.at("mask") != 0)
        acl.push_back(effective);
      if (flags & 3) {
        entry["flags"] = flags | 8;
        acl.push_back(entry);
      }
    }
  add(everyone, other | 0x120088, 0, "EVERYONE@");
  add(everyone, data & ~other, 1, "EVERYONE@");
  descriptor["dacl"] = std::move(acl);
  descriptor["control"] = descriptor.at("control").get<unsigned>() | 4;
  require(descriptor.at("dacl").size() <= 1024 && encode(descriptor, 7).size() <= 65536,
          "invalid_security_descriptor");
  return descriptor;
}
} // namespace tc::security
