#include <fstream>
#include <iostream>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <taucloud/core.hpp>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace tc {
void require(bool v, const char *code) {
  if (!v)
    throw error(code);
}
int64_t now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
static std::string hex(const unsigned char *data, size_t n) {
  std::string out;
  out.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    out += "0123456789abcdef"[data[i] >> 4];
    out += "0123456789abcdef"[data[i] & 15];
  }
  return out;
}
std::string random_hex(size_t bytes) {
  std::vector<unsigned char> b(bytes);
  require(RAND_bytes(b.data(), static_cast<int>(bytes)) == 1, "crypto_failed");
  return hex(b.data(), b.size());
}
std::string digest(std::string_view v) {
  unsigned char out[32];
  unsigned n = 0;
  require(EVP_Digest(v.data(), v.size(), out, &n, EVP_sha256(), nullptr) == 1, "crypto_failed");
  return hex(out, n);
}
std::string mac(std::string_view k, std::string_view v) {
  unsigned char out[32];
  unsigned n = 0;
  require(HMAC(EVP_sha256(), k.data(), static_cast<int>(k.size()),
               reinterpret_cast<const unsigned char *>(v.data()), v.size(), out, &n) != nullptr,
          "crypto_failed");
  return hex(out, n);
}
bool equal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
std::string password_hash(std::string_view pass, std::string_view salt) {
  auto *kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  require(kdf, "crypto_failed");
  auto *ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  require(ctx, "crypto_failed");
  uint32_t lanes = 1, memory = 65536, iterations = 3, threads = 1;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string("pass", const_cast<char *>(pass.data()), pass.size()),
      OSSL_PARAM_construct_octet_string("salt", const_cast<char *>(salt.data()), salt.size()),
      OSSL_PARAM_construct_uint32("lanes", &lanes),
      OSSL_PARAM_construct_uint32("memcost", &memory),
      OSSL_PARAM_construct_uint32("iter", &iterations),
      OSSL_PARAM_construct_uint32("threads", &threads),
      OSSL_PARAM_construct_end()};
  unsigned char out[32];
  int ok = EVP_KDF_derive(ctx, out, sizeof(out), params);
  EVP_KDF_CTX_free(ctx);
  require(ok == 1, "crypto_failed");
  return hex(out, sizeof(out));
}
json read_json(const fs::path &p) {
  require(fs::file_size(p) <= 1024 * 1024, "file_too_large");
  std::ifstream f(p);
  require(bool(f), "io_error");
  return json::parse(f);
}
void secure_directory(const fs::path &p) {
  fs::create_directories(p);
#ifdef _WIN32
  HANDLE token;
  require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != 0, "permission_denied");
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<char> buffer(size);
  bool ok = GetTokenInformation(token, TokenUser, buffer.data(), size, &size) != 0;
  CloseHandle(token);
  require(ok, "permission_denied");
  LPWSTR sid = nullptr;
  require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &sid) !=
              0,
          "permission_denied");
  std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;";
  sddl += sid;
  sddl += L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR sd = nullptr;
  require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd,
                                                               nullptr) != 0,
          "permission_denied");
  ok = SetFileSecurityW(p.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        sd) != 0;
  LocalFree(sd);
  require(ok, "permission_denied");
#else
  struct stat st {};
  require(lstat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid(),
          "unsafe_state_directory");
  require(chmod(p.c_str(), 0700) == 0, "permission_denied");
#endif
}
void write_json(const fs::path &p, const json &v) {
  auto tmp = p;
  tmp += ".tmp-" + random_hex(8);
  auto data = v.dump(2) + "\n";
#ifdef _WIN32
  HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                         nullptr);
  require(h != INVALID_HANDLE_VALUE, "io_error");
  DWORD n = 0;
  bool ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &n, nullptr) &&
            n == data.size() && FlushFileBuffers(h);
  CloseHandle(h);
  require(ok, "io_error");
  require(MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) !=
              0,
          "io_error");
#else
  int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  require(fd >= 0, "io_error");
  size_t off = 0;
  while (off < data.size()) {
    auto n = write(fd, data.data() + off, data.size() - off);
    if (n <= 0) {
      close(fd);
      throw error("io_error");
    }
    off += static_cast<size_t>(n);
  }
  bool ok = fsync(fd) == 0;
  close(fd);
  require(ok, "io_error");
  fs::rename(tmp, p);
  fd = open(p.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(fd >= 0, "io_error");
  ok = fsync(fd) == 0;
  close(fd);
  require(ok, "io_error");
#endif
}
static fs::path log_directory;
void set_log_directory(const fs::path &directory) {
  secure_directory(directory);
  log_directory = directory;
}
void log(std::string_view role, std::string_view event, std::string_view code) {
  static std::mutex m;
  std::lock_guard l(m);
  auto line = json{{"time", now()}, {"role", role}, {"event", event}, {"code", code}}.dump();
  std::cerr << line << std::endl;
  if (!log_directory.empty()) {
    try {
      auto path = log_directory / (std::string(role) + ".jsonl");
      if (fs::exists(path) && fs::file_size(path) >= 1024 * 1024) {
        auto previous = path;
        previous += ".1";
        std::error_code ignored;
        fs::remove(previous, ignored);
        fs::rename(path, previous);
      }
      std::ofstream output(path, std::ios::app);
      output << line << '\n';
    } catch (...) { /* Logging failure cannot interrupt shutdown/recovery. */
    }
  }
}
const std::vector<std::string> &roles() {
  static const std::vector<std::string> r = {
      "identity", "file",          "file_1", "file_2", "file_3", "protocol", "monitor",
      "updater",  "storage_admin", "helper", "webdav", "ftp",    "smb",      "nfs", "api"};
  return r;
}
std::string config::origin() const { return "https://127.0.0.1:" + std::to_string(port); }
config config::load(const fs::path &path) {
  config c;
  c.state = fs::canonical(path);
  secure_directory(c.state);
  auto j = read_json(c.state / "config.json");
  for (auto &[key, value] : j.items())
    require(key == "schema" || key == "listen" || key == "port" || key == "connections" ||
                key == "ipc_queue" || key == "restart_limit" || key == "memory_mb" ||
                key == "nfs_port" || key == "smb_port" || key == "dav_port" || key == "ftp_port" ||
                key == "ftp_plaintext" || key == "ftp_passive_first" || key == "ftp_passive_last",
            "invalid_config");
  require(j.is_object() && j.at("schema") == 1 && j.at("listen") == "127.0.0.1", "invalid_config");
  for (auto key : {"port", "connections", "ipc_queue", "restart_limit", "memory_mb"}) {
    require(j.at(key).is_number_integer(), "invalid_config");
    const auto value = j.at(key).get<int64_t>();
    require(value >= 0 && value <= 65535, "invalid_config");
  }
  int port = j.at("port");
  require(port >= 1024 && port <= 65535, "invalid_config");
  c.port = static_cast<uint16_t>(port);
  require(!j.contains("dav_port") || j.at("dav_port").is_number_integer(), "invalid_config");
  auto dav = j.value("dav_port", int64_t(0));
  require(dav == 0 || (dav >= 1024 && dav <= 65535 && dav != port), "invalid_config");
  c.dav_port = static_cast<uint16_t>(dav);
  for (auto key : {"ftp_port", "ftp_passive_first", "ftp_passive_last"})
    require(!j.contains(key) || j.at(key).is_number_integer(), "invalid_config");
  auto ftp = j.value("ftp_port", int64_t(0));
  auto first = j.value("ftp_passive_first", int64_t(50000));
  auto last = j.value("ftp_passive_last", int64_t(50031));
  require(ftp == 0 || (ftp >= 1024 && ftp <= 65535 && ftp != port && ftp != dav), "invalid_config");
  require(first >= 1024 && last <= 65535 && first <= last && last - first < 128 &&
              (ftp == 0 || (!(port >= first && port <= last) && !(dav >= first && dav <= last) &&
                            !(ftp >= first && ftp <= last))),
          "invalid_config");
  require(!j.contains("ftp_plaintext") || j.at("ftp_plaintext").is_boolean(), "invalid_config");
  require(!j.contains("smb_port") || j.at("smb_port").is_number_integer(), "invalid_config");
  auto smb = j.value("smb_port", int64_t(0));
  require(smb == 0 || (smb >= 1024 && smb <= 65535 && smb != port && smb != dav && smb != ftp &&
                       (!ftp || smb < first || smb > last)),
          "invalid_config");
  require(!j.contains("nfs_port") || j.at("nfs_port").is_number_integer(), "invalid_config");
  auto nfs = j.value("nfs_port", int64_t(0));
  require(nfs == 0 || (nfs >= 1024 && nfs <= 65535 && nfs != port && nfs != dav &&
                      nfs != ftp && nfs != smb && (!ftp || nfs < first || nfs > last)),
          "invalid_config");
  c.nfs_port = static_cast<uint16_t>(nfs);
  c.smb_port = static_cast<uint16_t>(smb);
  c.ftp_port = static_cast<uint16_t>(ftp);
  c.ftp_passive_first = static_cast<uint16_t>(first);
  c.ftp_passive_last = static_cast<uint16_t>(last);
  c.ftp_plaintext = j.value("ftp_plaintext", false);
  c.connections = j.at("connections");
  c.ipc_queue = j.at("ipc_queue");
  c.restart_limit = j.at("restart_limit");
  c.memory_mb = j.at("memory_mb");
  require(c.connections >= 1 && c.connections <= 128 && c.ipc_queue >= 2 && c.ipc_queue <= 64 &&
              c.restart_limit >= 1 && c.restart_limit <= 20 && c.memory_mb >= 256 &&
              c.memory_mb <= 4096,
          "invalid_config");
  return c;
}
void initialize(const fs::path &state, int port) {
  require(port >= 1024 && port <= 65535, "invalid_config");
  secure_directory(state);
  file_lock lock(state / "init.lock");
  require(!fs::exists(state / "config.json"), "already_initialized");
  json keys;
  for (auto r : roles())
    keys[r] = random_hex();
  keys["supervisor"] = random_hex();
  keys["ctl"] = random_hex();
  write_json(state / "ipc-keys.json", keys);
  write_json(state / "bootstrap.json", {{"token", random_hex()}, {"expires", now() + 600000}});
  EVP_PKEY *key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
  require(key, "crypto_failed");
  X509 *cert = X509_new();
  require(cert, "crypto_failed");
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_getm_notBefore(cert), -60);
  X509_gmtime_adj(X509_getm_notAfter(cert), 86400 * 30);
  X509_set_pubkey(cert, key);
  auto *name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char *>("tauCloud local management"),
                             -1, -1, 0);
  X509_set_issuer_name(cert, name);
  X509V3_CTX ctx{};
  X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
  for (auto entry : {std::pair{NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1"},
                     std::pair{NID_basic_constraints, "critical,CA:TRUE"},
                     std::pair{NID_key_usage, "critical,digitalSignature,keyCertSign"}}) {
    auto *ext = X509V3_EXT_conf_nid(nullptr, &ctx, entry.first, const_cast<char *>(entry.second));
    require(ext, "crypto_failed");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
  }
  require(X509_sign(cert, key, EVP_sha256()) > 0, "crypto_failed");
  auto keypath = (state / "tls-key.pem").string(), certpath = (state / "tls-cert.pem").string();
  BIO *out = BIO_new_file(keypath.c_str(), "w");
  require(out, "io_error");
  int ok = PEM_write_bio_PrivateKey(out, key, nullptr, nullptr, 0, nullptr, nullptr);
  BIO_free(out);
  require(ok == 1, "io_error");
  out = BIO_new_file(certpath.c_str(), "w");
  require(out, "io_error");
  ok = PEM_write_bio_X509(out, cert);
  BIO_free(out);
  X509_free(cert);
  EVP_PKEY_free(key);
  require(ok == 1, "io_error");
#ifndef _WIN32
  require(chmod(keypath.c_str(), 0600) == 0, "permission_denied");
#endif
  // Publish the ready marker last; interrupted initialization can be retried.
  write_json(state / "config.json", {{"schema", 1},
                                     {"listen", "127.0.0.1"},
                                     {"port", port},
                                     {"connections", 32},
                                     {"ipc_queue", 16},
                                     {"restart_limit", 5},
                                     {"memory_mb", 512}});
}
void call_context::check() const {
  require(!cancellation.stop_requested(), "cancelled");
  require(now() < deadline, "deadline_exceeded");
}
} // namespace tc
