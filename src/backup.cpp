#include <taucloud/core.hpp>
#include <taucloud/database.hpp>
#include <taucloud/files.hpp>
#include <openssl/evp.h>
#include <array>
#include <fstream>
namespace tc {
namespace {
std::string hash_file(const fs::path &path) {
  require(fs::is_regular_file(fs::symlink_status(path)) &&
              fs::file_size(path) <= 1024ull * 1024 * 1024,
          "invalid_backup");
  std::ifstream in(path, std::ios::binary);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  require(hash && EVP_DigestInit_ex(hash.get(), EVP_sha256(), nullptr) == 1, "crypto_error");
  std::array<char, 65536> buffer;
  while (in) {
    in.read(buffer.data(), buffer.size());
    require(EVP_DigestUpdate(hash.get(), buffer.data(), in.gcount()) == 1, "crypto_error");
  }
  require(in.eof(), "io_error");
  unsigned char result[32];
  unsigned n = 0;
  require(EVP_DigestFinal_ex(hash.get(), result, &n) == 1 && n == 32, "crypto_error");
  return encode_bytes(std::string_view(reinterpret_cast<char *>(result), 32));
}
std::vector<std::string> backup_names() {
  std::vector<std::string> out{"identity.db"};
  for (auto &role : file_roles())
    out.push_back(role + ".db");
  out.push_back("config.json");
  return out;
}
void scrub(const fs::path &path, const std::string &name) {
  database db(path);
  {
    statement version(db, "PRAGMA user_version");
    require(version.row() && version.integer(0) == (name == "identity.db" ? 4 : 3),
            "unsupported_backup_schema");
  }
  if (name == "identity.db") {
    sql(db, "PRAGMA secure_delete=ON; DELETE FROM smb_credentials; DELETE FROM sessions; DELETE "
            "FROM attempts; DELETE FROM records WHERE kind='nfs-exports'; UPDATE "
            "bootstrap SET used=1; UPDATE "
            "policy_state SET value=value+1 WHERE id=1;");
  } else {
    statement jobs(db, "SELECT body FROM jobs");
    while (jobs.row()) {
      auto status = json::parse(jobs.text(0)).at("status");
      require(status == "completed" || status == "cancelled", "unfinished_jobs");
    }
    statement pending(db, "SELECT count(*) FROM smb_pending");
    require(pending.row() && pending.integer(0) == 0, "unfinished_jobs");
    sql(db, "DELETE FROM dav_locks;");
  }
  sql(db, "PRAGMA wal_checkpoint(TRUNCATE)");
}
} // namespace
json metadata_backup(const config &c, const fs::path &destination) {
  std::vector<std::unique_ptr<file_lock>> locks;
  locks.push_back(std::make_unique<file_lock>(c.state / "supervisor.lock"));
  for (auto role : roles())
    locks.push_back(std::make_unique<file_lock>(c.state / (role + ".lock")));
  require(!fs::exists(destination), "already_exists");
  secure_directory(destination);
  try {
    json manifest = {{"schema", 1},
                     {"created", now()},
                     {"files", json::object()},
                     {"file_data", false},
                     {"private_keys", false},
                     {"password_verifiers", true},
                     {"smb_credentials", false}, {"nfs_exports", false}, {"nfs_handles_and_state", false}};
    for (auto name : backup_names()) {
      auto path = c.state / name;
      require(fs::is_regular_file(fs::symlink_status(path)), "invalid_backup");
      if (name == "config.json")
        write_json(destination / name, read_json(path));
      else {
        database source(path);
        backup_database(source, destination / name);
        scrub(destination / name, name);
      }
      manifest["files"][name] = hash_file(destination / name);
    }
    write_json(destination / "manifest.json", manifest);
    return {{"status", "completed"},
            {"output", fs::absolute(destination).string()},
            {"file_data", false}};
  } catch (...) {
    std::error_code ignored;
    fs::remove_all(destination, ignored);
    throw;
  }
}
json metadata_restore(const fs::path &destination, const fs::path &source) {
  require(!fs::exists(destination), "already_exists");
  auto manifest = read_json(source / "manifest.json");
  auto names = backup_names();
  require(manifest.at("schema") == 1 && manifest.at("files").size() == names.size(),
          "invalid_backup");
  for (auto name : names)
    require(manifest.at("files").at(name) == hash_file(source / name), "backup_checksum");
  auto settings = read_json(source / "config.json");
  // All validation occurs in a fresh private sibling; destination never contains a partial restore.
  auto staging = destination;
  staging += ".restore-" + random_hex(16);
  require(!fs::exists(staging), "already_exists");
  try {
    initialize(staging, settings.at("port"));
    write_json(staging / "config.json", settings);
    config::load(staging);
    for (auto name : names)
      if (name != "config.json") {
        fs::copy_file(source / name, staging / name);
        scrub(staging / name, name);
      }
    fs::remove(staging / "bootstrap.json");
    // Never overwrite a concurrently-created destination.
    require(!fs::exists(destination), "already_exists");
    fs::rename(staging, destination);
    return {{"status", "completed"},
            {"state", fs::absolute(destination).string()},
            {"new_tls_identity", true},
            {"sessions_revoked", true}};
  } catch (...) {
    std::error_code ignored;
    fs::remove_all(staging, ignored);
    throw;
  }
}
} // namespace tc
