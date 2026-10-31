#include <taucloud/plugins.hpp>
#include <taucloud/files.hpp>
#include <algorithm>
#include <array>
#include <fstream>
#include <regex>
#include <set>
#include <openssl/evp.h>
namespace tc {
namespace {
void only(const json &j, std::initializer_list<const char *> keys) {
  require(j.is_object(), "invalid_request");
  for (auto &[k, v] : j.items())
    require(std::any_of(keys.begin(), keys.end(), [&](auto p) { return k == p; }),
            "invalid_request");
}
std::string component(const json &v) {
  auto s = v.get<std::string>();
  require(std::regex_match(s, std::regex("[a-z][a-z0-9-]{0,47}")), "invalid_identifier");
  return s;
}
std::string version(const json &v) {
  auto s = v.get<std::string>();
  require(
      s.size() <= 32 &&
          std::regex_match(s, std::regex("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)")),
      "invalid_manifest");
  return s;
}
std::string file_hash(native_file &file, native_file *destination = nullptr,
                      const call_context *ctx = nullptr) {
  auto info = file.info();
  uint64_t size = info.at("size");
  require(size <= 64 * 1024 * 1024, "package_limit");
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  require(hash && EVP_DigestInit_ex(hash.get(), EVP_sha256(), nullptr) == 1, "crypto_failed");
  for (uint64_t off = 0; off < size;) {
    if (ctx)
      ctx->check();
    auto bytes = file.read(off, std::min<uint64_t>(65536, size - off));
    require(!bytes.empty(), "package_changed");
    require(EVP_DigestUpdate(hash.get(), bytes.data(), bytes.size()) == 1, "crypto_failed");
    if (destination)
      require(destination->write(off, bytes) == bytes.size(), "io_error");
    off += bytes.size();
  }
  require(file.info().at("size") == size, "package_changed");
  std::array<unsigned char, 32> bytes{};
  unsigned count = 0;
  require(EVP_DigestFinal_ex(hash.get(), bytes.data(), &count) == 1 && count == 32,
          "crypto_failed");
  if (destination)
    destination->flush();
  return encode_bytes(std::string_view(reinterpret_cast<char *>(bytes.data()), bytes.size()));
}
json manifest(const fs::path &source, const call_context &ctx) {
  auto root = native_file::root(source);
  auto f = root.open("manifest.json");
  require(f.info().at("size").get<uint64_t>() <= 65536, "invalid_manifest");
  json m;
  try {
    m = json::parse(f.read(0, 65536), [](int depth, json::parse_event_t, json &) {
      require(depth <= 8, "invalid_manifest");
      return true;
    });
  } catch (...) {
    throw error("invalid_manifest");
  }
  only(m, {"schema", "id", "version", "ipc_version", "kind", "entry", "files", "capabilities"});
  require(m.at("schema") == 1 && m.at("ipc_version") == 1, "plugin_version_unsupported");
  component(m.at("id"));
  version(m.at("version"));
  require(m.at("kind") == "generic" || m.at("kind") == "docker", "invalid_manifest");
  auto entry = m.at("entry").get<std::string>();
  portable_path(entry);
  require(!entry.empty() && entry != "manifest.json", "invalid_manifest");
  auto &files = m.at("files");
  require(files.is_object() && !files.empty() && files.size() <= 32 && files.contains(entry),
          "invalid_manifest");
  require(m.at("capabilities").is_array() && m.at("capabilities").size() <= 4, "invalid_manifest");
  std::set<std::string> caps;
  for (auto &v : m.at("capabilities")) {
    auto cap = v.get<std::string>();
    require(caps.insert(cap).second, "invalid_manifest");
    require(cap == "plugin.invoke" ||
                (m.at("kind") == "docker" &&
                 (cap == "docker.read" || cap == "docker.logs" || cap == "docker.control")),
            "invalid_capability");
  }
  require(caps.contains("plugin.invoke"), "invalid_capability");
  if (m.at("kind") == "docker")
    require(caps.contains("docker.read"), "invalid_capability");
  uint64_t total = 0;
  std::set<std::string> names;
  for (auto &[name, want] : files.items()) {
    portable_path(name);
    require(!name.empty() && name != "manifest.json" && names.insert(path_fold(name)).second,
            "invalid_manifest");
    require(want.is_string() &&
                std::regex_match(want.get<std::string>(), std::regex("[0-9a-f]{64}")),
            "invalid_manifest");
    auto file = root.open(name);
    total += file.info().at("size").get<uint64_t>();
    require(total <= 128 * 1024 * 1024, "package_limit");
    require(file_hash(file, nullptr, &ctx) == want.get<std::string>(), "package_hash_mismatch");
  }
  if (m.at("kind") == "docker") {
    auto binary = fs::path(process_info(own_pid()).at("exe").get<std::string>()).parent_path();
    auto name = std::string("taucloud_docker") +
#ifdef _WIN32
                ".exe";
#else
                "";
#endif
    auto root_bin = native_file::root(binary);
    auto bundled = root_bin.open(name);
    require(m.at("files").at(entry).get<std::string>() == file_hash(bundled, nullptr, &ctx),
            "docker_worker_not_bundled");
  }
  return m;
}
struct manager {
  config cfg;
  fs::path base;
  json registry;
  std::mutex mutex;
  explicit manager(const config &c) : cfg(c), base(c.state / "plugins") {
    secure_directory(base);
    secure_directory(base / "packages");
    secure_directory(base / "state");
    registry = fs::exists(base / "registry.json")
                   ? read_json(base / "registry.json")
                   : json{{"schema", 1}, {"plugins", json::object()}, {"engines", json::object()}};
    require(registry.at("schema") == 1, "schema_too_new");
    for (auto &[id, p] : registry["plugins"].items()) {
      // Preserve the native spawn identity across a manager crash, including
      // the interval before the child publishes plugin.instance.json.
      if (!p.contains("identity"))
        p["identity"] = nullptr;
      if (!p.contains("failures"))
        p["failures"] = json::array();
    }
  }
  void save() { write_json(base / "registry.json", registry); }
  fs::path state(const std::string &id) { return base / "state" / id; }
  config private_config(const std::string &id) {
    auto c = cfg;
    c.state = state(id);
    c.ipc_queue = 4;
    c.memory_mb = 256;
    return c;
  }
  fs::path package(const std::string &id, const std::string &v) {
    return base / "packages" / id / v;
  }
  void runtime(const std::string &id, json &p) {
    auto s = state(id);
    secure_directory(s);
    secure_directory(s / "data");
    secure_directory(s / "configuration");
    if (!fs::exists(s / "ipc-keys.json"))
      write_json(s / "ipc-keys.json", {{"plugins", random_hex()}, {"plugin", random_hex()}});
    auto c = read_json(cfg.state / "config.json");
    c["ipc_queue"] = 4;
    c["memory_mb"] = 256;
    for (auto key : {"dav_port", "ftp_port", "smb_port", "nfs_port"})
      c[key] = 0;
    write_json(s / "config.json", c);
    json settings = {{"schema", 1},
                     {"id", id},
                     {"capabilities", p.at("manifest").at("capabilities")},
                     {"configuration_directory", (s / "configuration").string()},
                     {"data_directory", (s / "data").string()},
                     {"trust_mode", "trusted-code-only"},
                     {"engines", json::object()}};
    if (p.at("manifest").at("kind") == "docker")
      settings["engines"] = registry.at("engines");
    write_json(s / "plugin.json", settings);
  }
  void stop(const std::string &id, json &p) {
    auto identity = p.value("identity", json());
    auto path = state(id) / "plugin.instance.json";
    if (identity.is_null() && fs::exists(path))
      identity = read_json(path);
    if (!identity.is_null() && verified_alive(identity)) {
      auto exe = package(id, p.at("version")) / p.at("manifest").at("entry").get<std::string>();
      require(fs::equivalent(identity.at("exe").get<std::string>(), exe), "adoption_refused");
      try {
        rpc(private_config(id), "plugins", "plugin", "stop", json::object(),
            identity.at("generation"), {}, "", 500);
      } catch (...) {
      }
      auto deadline = now() + 500;
      while (verified_alive(identity) && now() < deadline)
        std::this_thread::sleep_for(10ms);
      if (verified_alive(identity))
        terminate_verified(identity);
      // Do not replace/delete running code on Windows or race a delayed exit.
      deadline = now() + 500;
      while (verified_alive(identity) && now() < deadline)
        std::this_thread::sleep_for(10ms);
      require(!verified_alive(identity), "plugin_stop_pending");
    }
    p["identity"] = nullptr;
    p["status"] = "disabled";
  }
  json plan(const fs::path &source, const call_context &ctx) {
    auto m = manifest(source, ctx);
    auto id = m.at("id").get<std::string>();
    json added = json::array(), old = json::array();
    if (registry["plugins"].contains(id))
      old = registry["plugins"][id]["manifest"]["capabilities"];
    for (auto &cap : m["capabilities"])
      if (std::find(old.begin(), old.end(), cap) == old.end())
        added.push_back(cap);
    return {{"manifest", m},
            {"digest", digest(m.dump())},
            {"added_permissions", added},
            {"trust_mode", "trusted-code-only"},
            {"os_confinement_verified", false},
            {"approval_required", true}};
  }
  void approve(const json &b, const json &m) {
    require(b.value("trusted_code", false) && b.value("approved_digest", "") == digest(m.dump()),
            "approval_required");
    require(b.contains("approved_permissions") &&
                b.at("approved_permissions") == m.at("capabilities"),
            "approval_required");
  }
  json dispatch(const std::string &op, const json &b, const call_context &ctx) {
    std::lock_guard guard(mutex);
    ctx.check();
    if (op == "list") {
      json list = json::array();
      for (auto &[id, p] : registry["plugins"].items())
        list.push_back({{"id", id},
                        {"version", p["version"]},
                        {"enabled", p["enabled"]},
                        {"status", p["status"]},
                        {"manifest", p["manifest"]},
                        {"previous", p["previous"]},
                        {"failures", p["failures"].size()}});
      json engines = json::array();
      for (auto &[id, e] : registry["engines"].items())
        engines.push_back({{"id", id},
                           {"transport", e["transport"]},
                           {"platform", e["platform"]},
                           {"permissions", e["permissions"]}});
      return {{"plugins", list},
              {"engines", engines},
              {"trust_mode", "trusted-code-only"},
              {"os_confinement_verified", false}};
    }
    if (op == "plan" || op == "install") {
      only(b, op == "plan"
                  ? std::initializer_list<const char *>{"source"}
                  : std::initializer_list<const char *>{"source", "approved_digest",
                                                        "approved_permissions", "trusted_code"});
      auto source = fs::path(b.at("source").get<std::string>());
      require(source.is_absolute(), "invalid_path");
      auto result = plan(source, ctx);
      if (op == "plan")
        return result;
      auto m = result.at("manifest");
      approve(b, m);
      auto id = m.at("id").get<std::string>(), v = m.at("version").get<std::string>();
      auto &all = registry["plugins"];
      require(all.contains(id) || all.size() < 8, "plugin_limit");
      if (all.contains(id))
        require(all[id].at("version").get<std::string>() != v, "already_exists");
      auto parent = base / "packages" / id;
      size_t identities = 0;
      for (auto &unused : fs::directory_iterator(base / "packages")) {
        (void)unused;
        ++identities;
      }
      require(fs::exists(parent) || identities < 8, "plugin_limit");
      secure_directory(parent);
      auto target = package(id, v);
      size_t versions = 0;
      for (auto &unused : fs::directory_iterator(parent)) {
        (void)unused;
        ++versions;
      }
      require(fs::exists(target) || versions < 4, "package_limit");
      if (fs::exists(target))
        require(manifest(target, ctx) == m, "package_changed");
      else {
        auto stage = parent / ("stage-" + random_hex(8));
        secure_directory(stage);
        try {
          auto input = native_file::root(source), output = native_file::root(stage);
          for (auto &[name, want] : m["files"].items()) {
            auto relative = fs::path(name).parent_path();
            fs::path current = stage;
            for (auto &part : relative) {
              current /= part;
              secure_directory(current);
            }
            auto in = input.open(name), out = output.open(name, false, true, true);
            require(file_hash(in, &out, &ctx) == want.get<std::string>(), "package_changed");
          }
          write_json(stage / "manifest.json", m);
#ifndef _WIN32
          fs::permissions(stage / m.at("entry").get<std::string>(), fs::perms::owner_exec,
                          fs::perm_options::add);
#endif
          fs::rename(stage, target);
        } catch (...) {
          std::error_code ignored;
          fs::remove_all(stage, ignored);
          throw;
        }
      }
      // A crash before registry publication leaves an inert, validated package;
      // it cannot execute without a durable explicit activation record.
      json previous = nullptr;
      if (all.contains(id)) {
        auto &old = all[id];
        old["enabled"] = false;
        save();
        stop(id, old);
        previous = {{"version", old["version"]}, {"manifest", old["manifest"]}};
      }
      all[id] = {{"version", v},
                 {"manifest", m},
                 {"previous", previous},
                 {"enabled", false},
                 {"generation", random_hex(16)},
                 {"identity", nullptr},
                 {"status", "disabled"},
                 {"failures", json::array()},
                 {"next", 0}};
      runtime(id, all[id]);
      save();
      return {{"installed", true}, {"id", id}, {"version", v}, {"enabled", false}};
    }
    if (op == "engine-plan" || op == "engine-approve") {
      only(b, op == "engine-plan"
                  ? std::initializer_list<const char *>{"endpoint"}
                  : std::initializer_list<const char *>{"endpoint", "approved_digest"});
      auto e = docker_endpoint(b.at("endpoint"));
      auto hash = digest(e.dump());
      if (op == "engine-plan")
        return {{"digest", hash},
                {"endpoint", e},
                {"approval_required", true},
                {"authority", "daemon-management"}};
      require(b.value("approved_digest", "") == hash, "approval_required");
      auto id = e.at("id").get<std::string>();
      require(registry["engines"].contains(id) || registry["engines"].size() < 8, "engine_limit");
      registry["engines"][id] = e;
      save();
      for (auto &[pid, p] : registry["plugins"].items())
        runtime(pid, p);
      return {{"approved", true}, {"id", id}};
    }
    if (op == "engine-remove") {
      only(b, {"id"});
      auto id = component(b.at("id"));
      registry["engines"].erase(id);
      save();
      for (auto &[pid, p] : registry["plugins"].items())
        runtime(pid, p);
      return {{"removed", true}};
    }
    auto id = component(b.at("id"));
    require(registry["plugins"].contains(id), "not_found");
    auto &p = registry["plugins"][id];
    if (op == "invoke") {
      only(b, {"id", "request"});
      require(p.at("enabled") == true && p.at("status") == "running", "plugin_unavailable");
      require(b.at("request").is_object() && b.at("request").dump().size() <= 65536,
              "invalid_request");
      require(std::find(p["manifest"]["capabilities"].begin(), p["manifest"]["capabilities"].end(),
                        "plugin.invoke") != p["manifest"]["capabilities"].end(),
              "forbidden");
      if (p["manifest"]["kind"] == "docker") {
        auto engine = b["request"].at("engine").get<std::string>();
        require(registry["engines"].contains(engine), "forbidden");
        auto operation = b["request"].at("operation").get<std::string>();
        auto cap = operation == "logs"        ? "docker.logs"
                   : operation == "lifecycle" ? "docker.control"
                                              : "docker.read";
        for (const auto &grants :
             {p["manifest"]["capabilities"], registry["engines"][engine]["permissions"]})
          require(std::find(grants.begin(), grants.end(), cap) != grants.end(), "forbidden");
      }
      return rpc(private_config(id), "plugins", "plugin", "invoke", b.at("request"),
                 p.at("generation"), ctx.cancellation, "",
                 static_cast<int>(
                     std::max<int64_t>(1, std::min<int64_t>(3000, ctx.deadline - now() - 100))));
    }
    if (op == "rollback-plan") {
      only(b, {"id"});
      require(!p.at("previous").is_null(), "not_found");
      auto m = p["previous"]["manifest"];
      return {{"manifest", m},
              {"digest", digest(m.dump())},
              {"approval_required", true},
              {"trust_mode", "trusted-code-only"}};
    }
    if (op == "rollback") {
      only(b, {"id", "approved_digest", "approved_permissions", "trusted_code"});
      require(!p.at("previous").is_null(), "not_found");
      auto prior = p["previous"];
      approve(b, prior.at("manifest"));
      require(manifest(package(id, prior.at("version")), ctx) == prior.at("manifest"),
              "package_changed");
      p["enabled"] = false;
      save();
      stop(id, p);
      auto current = json{{"version", p["version"]}, {"manifest", p["manifest"]}};
      p["manifest"] = prior["manifest"];
      p["version"] = prior["version"];
      p["previous"] = current;
      p["generation"] = random_hex(16);
      p["failures"] = json::array();
      p["next"] = 0;
      runtime(id, p);
      save();
      return {{"rolled_back", true}, {"enabled", false}};
    }
    only(b, {"id"});
    if (op == "enable") {
      require(manifest(package(id, p.at("version")), ctx) == p.at("manifest"), "package_changed");
      p["enabled"] = true;
      p["failures"] = json::array();
      p["next"] = 0;
      runtime(id, p);
      save();
      return {{"enabled", true}};
    }
    if (op == "disable" || op == "uninstall") {
      p["enabled"] = false;
      save();
      stop(id, p);
      save();
      if (op == "uninstall") {
        // Retain configuration/data (and inert versioned packages) deliberately.
        // No recursive deletion of paths writable by trusted plugin code.
        registry["plugins"].erase(id);
        save();
      }
      return {{"enabled", false}, {"uninstalled", op == "uninstall"}, {"data_preserved", true}};
    }
    throw error("not_supported");
  }
  void tick() {
    std::lock_guard guard(mutex);
    reap_children();
    for (auto &[id, p] : registry["plugins"].items()) {
      if (!p.at("enabled").get<bool>()) {
        try {
          stop(id, p);
        } catch (...) {
          p["status"] = "stop_pending";
        }
        continue;
      }
      try {
        auto exe = package(id, p.at("version")) / p.at("manifest").at("entry").get<std::string>();
        auto instance = state(id) / "plugin.instance.json";
        if (p.at("status") == "starting" && now() < p.value("started", int64_t(0)) + 2000)
          continue;
        if (p["identity"].is_null() && fs::exists(instance)) {
          auto candidate = read_json(instance);
          if (verified_alive(candidate)) {
            require(fs::equivalent(candidate.at("exe").get<std::string>(), exe) &&
                        candidate.at("generation") == p.at("generation"),
                    "adoption_refused");
            auto hello = rpc(private_config(id), "plugins", "plugin", "ping", json::object(),
                             p.at("generation"), {}, "", 300);
            require(hello.at("pid") == candidate.at("pid") &&
                        hello.at("birth") == candidate.at("birth") && hello.at("ipc_version") == 1,
                    "adoption_refused");
            p["identity"] = candidate;
          }
        }
        if (!p["identity"].is_null()) {
          if (verified_alive(p["identity"])) {
            require(fs::equivalent(p["identity"].at("exe").get<std::string>(), exe),
                    "adoption_refused");
            auto hello = rpc(private_config(id), "plugins", "plugin", "ping", json::object(),
                             p.at("generation"), {}, "", 300);
            require(hello.at("pid") == p["identity"].at("pid") &&
                        hello.at("birth") == p["identity"].at("birth") &&
                        hello.at("ipc_version") == 1,
                    "adoption_refused");
            require(process_info(hello.at("pid")).at("rss").get<uint64_t>() < 256 * 1024 * 1024,
                    "resource_exhausted");
            p["status"] = "running";
            continue;
          }
          throw error("plugin_exited");
        }
        auto &failures = p["failures"];
        while (!failures.empty() && failures[0].get<int64_t>() < now() - 60000)
          failures.erase(failures.begin());
        if (failures.size() >= 5) {
          p["status"] = "crash_loop";
          continue;
        }
        if (p.at("next").get<int64_t>() > now())
          continue;
        call_context check{"plugins", random_hex(16), now() + 3000, {}};
        require(manifest(package(id, p.at("version")), check) == p.at("manifest"),
                "package_changed");
        runtime(id, p);
        p["status"] = "starting";
        p["started"] = now();
        save();
        p["identity"] = spawn(exe, private_config(id), p.at("generation"));
        save();
      } catch (const std::exception &e) {
        if (!p["identity"].is_null() && verified_alive(p["identity"]))
          terminate_verified(p["identity"]);
        p["identity"] = nullptr;
        p["failures"].push_back(now());
        while (p["failures"].size() > 5)
          p["failures"].erase(p["failures"].begin());
        p["next"] = now() + std::min<int64_t>(5000, 200LL << p["failures"].size());
        p["status"] = "backoff";
        p["generation"] = random_hex(16);
        log("plugins", "worker_failed", e.what());
        save();
      }
    }
    save();
  }
  void shutdown() {
    std::lock_guard guard(mutex);
    for (auto &[id, p] : registry["plugins"].items())
      try {
        stop(id, p);
      } catch (...) {
        log("plugins", "stop_failed");
      }
    save();
  }
};
} // namespace
int plugins(const config &c, const std::string &generation, std::atomic_bool &stopping) {
  file_lock lock(c.state / "plugins.lock");
  apply_resource_budget(c);
  manager m(c);
  rpc_server server(c, "plugins", generation,
                    [&](const std::string &op, const json &body, const call_context &ctx) -> json {
                      if (op == "ping") {
                        auto p = process_info(own_pid());
                        p["generation"] = generation;
                        return p;
                      }
                      if (op == "stop") {
                        stopping = true;
                        return {{"stopping", true}};
                      }
                      return m.dispatch(op, body, ctx);
                    });
  auto p = process_info(own_pid());
  p["generation"] = generation;
  write_json(c.state / "plugins.instance.json", p);
  auto next = now();
  while (!stopping) {
    if (now() >= next) {
      m.tick();
      next = now() + 1000;
    }
    std::this_thread::sleep_for(20ms);
  }
  server.stop();
  m.shutdown();
  return 0;
}
} // namespace tc
