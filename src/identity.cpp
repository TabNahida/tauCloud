#include <sqlite3.h>
#include <taucloud/core.hpp>
#include <taucloud/policy.hpp>
#include <taucloud/smb.hpp>
#include <taucloud/files.hpp>
#include <openssl/crypto.h>
#include <map>
namespace tc {
struct identity_store::impl {
  config cfg;
  sqlite3 *db = nullptr;
  std::mutex mutex;
  std::map<std::string, smb_detail::ntlm_exchange> exchanges;
  std::string vault;
  explicit impl(const config &c) : cfg(c) {
    require(sqlite3_open_v2((c.state / "identity.db").string().c_str(), &db,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                            nullptr) == SQLITE_OK,
            "database_error");
    sqlite3_busy_timeout(db, 2000);
    sql(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA "
            "foreign_keys=ON");
    statement check(db, "PRAGMA quick_check");
    require(check.row() && check.text(0) == "ok", "database_corrupt");
    int64_t version = 0;
    {
      statement v(db, "PRAGMA user_version");
      v.row();
      version = v.integer(0);
    }
    require(version <= 4, "schema_too_new");
    if (version > 0 && version < 4) {
      sqlite3 *backup = nullptr;
      require(sqlite3_open((c.state / (version < 2   ? "identity.pre-v2.db"
                                       : version < 3 ? "identity.pre-v3.db"
                                                     : "identity.pre-v4.db"))
                               .string()
                               .c_str(),
                           &backup) == SQLITE_OK,
              "backup_failed");
      auto b = sqlite3_backup_init(backup, "main", db, "main");
      int status = b ? sqlite3_backup_step(b, -1) : SQLITE_ERROR;
      if (b)
        sqlite3_backup_finish(b);
      sqlite3_close(backup);
      require(status == SQLITE_DONE, "backup_failed");
    }
    transaction tx(db);
    if (version < 1)
      sql(db, "CREATE TABLE users(name TEXT PRIMARY KEY,salt TEXT NOT "
              "NULL,verifier TEXT NOT NULL); CREATE TABLE bootstrap(id INTEGER "
              "PRIMARY KEY CHECK(id=1),hash TEXT NOT NULL,expires INTEGER NOT "
              "NULL,used INTEGER NOT NULL DEFAULT 0); PRAGMA user_version=1");
    if (version < 2)
      sql(db, "CREATE TABLE sessions(hash TEXT PRIMARY KEY,name TEXT NOT NULL "
              "REFERENCES users(name),kind TEXT NOT NULL,scope TEXT NOT "
              "NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL); CREATE TABLE "
              "attempts(key TEXT PRIMARY KEY,count INTEGER NOT NULL,reset "
              "INTEGER NOT NULL); PRAGMA user_version=2");
    if (version < 3)
      migrate_policy(db);
    if (version < 4)
      sql(db, "CREATE TABLE IF NOT EXISTS smb_credentials(name TEXT PRIMARY KEY REFERENCES "
              "users(name),cipher TEXT NOT NULL); PRAGMA user_version=4;");
    {
      statement exists(db, "SELECT count(*) FROM bootstrap");
      exists.row();
      if (exists.integer(0) == 0 && fs::exists(c.state / "bootstrap.json")) {
        auto token = read_json(c.state / "bootstrap.json");
        statement insert(db, "INSERT INTO bootstrap(id,hash,expires) VALUES(1,?,?)");
        insert.bind(1, digest(token.at("token").get<std::string>()));
        insert.bind(2, token.at("expires").get<int64_t>());
        insert.row();
      }
    }
    tx.commit();
    vault = smb_detail::vault_key(c);
  }
  ~impl() {
    OPENSSL_cleanse(vault.data(), vault.size());
    if (db)
      sqlite3_close(db);
  }
  void throttle(const std::string &name) {
    transaction tx(db);
    statement prune(db, "DELETE FROM attempts WHERE reset<=?");
    prune.bind(1, now());
    prune.row();
    statement count(db, "SELECT count(*) FROM attempts");
    count.row();
    require(count.integer(0) < 2048, "rate_limited");
    for (const auto &key : std::vector<std::string>{"global", digest(name)}) {
      statement get(db, "SELECT count FROM attempts WHERE key=?");
      get.bind(1, key);
      int max = key == "global" ? 30 : 5;
      if (get.row())
        require(get.integer(0) < max, "rate_limited");
      statement update(db, "INSERT INTO attempts(key,count,reset) VALUES(?,1,?) ON "
                           "CONFLICT(key) DO UPDATE SET count=count+1");
      update.bind(1, key);
      update.bind(2, now() + 60000);
      update.row();
    }
    tx.commit();
  }
  void authenticated_attempt(const std::string &name) {
    // Verified logins do not consume the failed-attempt budget. Preserve prior
    // failures, including the global budget, rather than resetting either.
    transaction tx(db);
    for (const auto &key : std::vector<std::string>{"global", digest(name)}) {
      statement q(db, "UPDATE attempts SET count=max(0,count-1) WHERE key=?");
      q.bind(1, key);
      q.row();
    }
    tx.commit();
  }
  json smb_dispatch(const std::string &op, const json &body, const call_context &ctx) {
    using namespace smb_detail;
    if (op == "smb_enroll") {
      require(ctx.caller == "api", "forbidden");
      const auto &auth = body.at("auth");
      statement user(
          db, "SELECT u.name FROM users u JOIN sessions s ON s.name=u.name WHERE s.hash=? AND "
              "s.kind=? AND s.scope='admin' AND u.role='admin' AND u.enabled=1 AND s.expires>?");
      user.bind(1, digest(auth.at("token").get<std::string>()));
      user.bind(2, auth.at("kind"));
      user.bind(3, now());
      require(user.row(), "forbidden");
      auto name = body.at("username").get<std::string>();
      statement exists(db, "SELECT name FROM users WHERE name=? AND enabled=1");
      exists.bind(1, name);
      require(exists.row(), "not_found");
      bool enabled = body.value("enabled", true);
      transaction credential_update(db);
      if (enabled) {
        auto password = body.at("password").get<std::string>();
        require(password.size() >= 12 && password.size() <= 1024, "invalid_credentials_format");
        auto hash = nt_hash(password), encrypted = seal(vault, hash, name);
        OPENSSL_cleanse(hash.data(), hash.size());
        OPENSSL_cleanse(password.data(), password.size());
        statement set(db, "INSERT INTO smb_credentials VALUES(?,?) ON CONFLICT(name) DO UPDATE SET "
                          "cipher=excluded.cipher");
        set.bind(1, name);
        set.bind(2, encode_bytes(encrypted));
        set.row();
      } else {
        statement del(db, "DELETE FROM smb_credentials WHERE name=?");
        del.bind(1, name);
        del.row();
      }
      statement revoke(db, "DELETE FROM sessions WHERE name=? AND kind='smb'");
      revoke.bind(1, name);
      revoke.row();
      credential_update.commit();
      exchanges.clear();
      // Every SMB request reauthorizes, so revoked credentials cannot continue using an old token.
      return {{"username", name}, {"enabled", enabled}, {"management_password_changed", false}};
    }
    require(ctx.caller == "smb", "forbidden");
    std::erase_if(exchanges, [](const auto &item) { return item.second.expires <= now(); });
    if (op == "smb_negotiate") {
      require(exchanges.size() < 64, "overloaded");
      auto id = random_hex(16);
      auto it =
          exchanges
              .emplace(id,
                       ntlm_exchange(ntlm_token(decode_bytes(body.at("token").get<std::string>()))))
              .first;
      return {{"exchange", id}, {"token", encode_bytes(it->second.challenge)}};
    }
    require(op == "smb_authenticate", "not_supported");
    auto it = exchanges.find(body.at("exchange").get<std::string>());
    require(it != exchanges.end(), "unauthorized");
    auto exchange = std::move(it->second);
    exchanges.erase(it); // One use, even when validation fails.
    auto token = ntlm_token(decode_bytes(body.at("token").get<std::string>()));
    auto start = get(token, 40, 4), size = get(token, 36, 2);
    require(start <= token.size() && size <= token.size() - start, "unauthorized");
    auto name = utf8(std::string_view(token).substr(start, size));
    throttle("smb:" + path_fold(name));
    statement q(db, "SELECT u.name,c.cipher FROM users u JOIN smb_credentials c ON c.name=u.name "
                    "WHERE u.name=? COLLATE NOCASE AND u.enabled=1");
    q.bind(1, name);
    require(q.row(), "unauthorized");
    name = q.text(0);
    auto hash = unseal(vault, decode_bytes(q.text(1)), name);
    require(!q.row(), "unauthorized");
    json result;
    try {
      result = exchange.verify(token, hash);
    } catch (...) {
      OPENSSL_cleanse(hash.data(), hash.size());
      throw;
    }
    OPENSSL_cleanse(hash.data(), hash.size());
    ctx.check();
    authenticated_attempt("smb:" + path_fold(name));
    statement prune(db, "DELETE FROM sessions WHERE expires<=?");
    prune.bind(1, now());
    prune.row();
    statement count(db, "SELECT count(*) FROM sessions");
    count.row();
    require(count.integer(0) < 4096, "session_limit");
    auto access = random_hex();
    auto expires = now() + 3600000;
    statement add(db, "INSERT INTO sessions VALUES(?,?,'smb','files','',?)");
    add.bind(1, digest(access));
    add.bind(2, name);
    add.bind(3, expires);
    add.row();
    result["token"] = access;
    result["username"] = name;
    result["expires"] = expires;
    return result;
  }
  json dispatch(const std::string &op, const json &body, const call_context &ctx) {
    std::lock_guard l(mutex);
    ctx.check();
    if (op.starts_with("smb_"))
      return smb_dispatch(op, body, ctx);
    if (op == "nfs_authorize" || op == "nfs_exports" || op == "policy_list" || op == "policy_write" || op == "authorize")
      return policy_dispatch(db, cfg, op, body, ctx);
    if (op == "bootstrap") {
      auto name = body.at("username").get<std::string>(),
           pass = body.at("password").get<std::string>();
      require(!name.empty() && name.size() <= 64 &&
                  name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJK"
                                         "LMNOPQRSTUVWXYZ0123456789_-. ") == std::string::npos &&
                  pass.size() >= 12 && pass.size() <= 1024,
              "invalid_credentials_format");
      transaction tx(db);
      statement check(db, "SELECT hash,expires,used FROM bootstrap WHERE id=1");
      require(check.row() && !check.integer(2) && now() < check.integer(1) &&
                  equal(check.text(0), digest(body.at("token").get<std::string>())),
              "bootstrap_denied");
      statement count(db, "SELECT count(*) FROM users");
      count.row();
      require(count.integer(0) == 0, "bootstrap_denied");
      auto salt = random_hex(16), verifier = password_hash(pass, salt);
      ctx.check();
      statement add(db,
                    "INSERT INTO users(name,salt,verifier,role,enabled) VALUES(?,?,?,'admin',1)");
      add.bind(1, name);
      add.bind(2, salt);
      add.bind(3, verifier);
      add.row();
      sql(db, "UPDATE bootstrap SET used=1 WHERE id=1");
      tx.commit();
      std::error_code ec;
      fs::remove(cfg.state / "bootstrap.json", ec);
      return {{"created", name}};
    }
    if (op == "login") {
      auto name = body.at("username").get<std::string>(),
           pass = body.at("password").get<std::string>(), kind = body.value("kind", "cli"),
           scope = body.value("scope", "read");
      require(name.size() <= 64 && pass.size() <= 1024 && (kind == "cli" || kind == "browser") &&
                  (scope == "read" || scope == "files" || scope == "admin"),
              "invalid_request");
      throttle(name);
      std::string salt(32, '0'), verifier, role;
      {
        statement find(db, "SELECT salt,verifier,role FROM users WHERE name=? AND enabled=1");
        find.bind(1, name);
        if (find.row()) {
          salt = find.text(0);
          verifier = find.text(1);
          role = find.text(2);
        }
      }
      auto actual = password_hash(pass, salt);
      ctx.check();
      require(equal(actual, verifier), "unauthorized");
      require(scope != "admin" || role == "admin", "forbidden");
      authenticated_attempt(name);
      auto token = random_hex(), csrf = random_hex();
      int64_t expires = now() + (kind == "cli" ? 3600000 : 1800000);
      transaction tx(db);
      statement prune(db, "DELETE FROM sessions WHERE expires<=?");
      prune.bind(1, now());
      prune.row();
      statement count(db, "SELECT count(*) FROM sessions");
      count.row();
      require(count.integer(0) < 4096, "session_limit");
      statement add(db, "INSERT INTO sessions VALUES(?,?,?,?,?,?)");
      add.bind(1, digest(token));
      add.bind(2, name);
      add.bind(3, kind);
      add.bind(4, scope);
      add.bind(5, digest(csrf));
      add.bind(6, expires);
      add.row();
      tx.commit();
      return {{"token", token}, {"csrf", csrf},     {"expires", expires},
              {"scope", scope}, {"username", name}, {"kind", kind}};
    }
    if (op == "validate" || op == "logout") {
      auto token = body.at("token").get<std::string>();
      require(token.size() == 64, "unauthorized");
      statement get(db, "SELECT s.name,s.kind,s.scope,s.csrf,s.expires,u.role FROM sessions s JOIN "
                        "users u ON s.name=u.name WHERE s.hash=? AND u.enabled=1");
      get.bind(1, digest(token));
      require(get.row() && get.integer(4) > now() &&
                  get.text(1) == body.at("kind").get<std::string>(),
              "unauthorized");
      if (body.value("admin", false))
        require(get.text(2) == "admin" && get.text(5) == "admin", "forbidden");
      if (body.value("write", false)) {
        if (body.value("file_write", false))
          require(get.text(2) == "admin" || get.text(2) == "files", "forbidden");
        if (get.text(1) == "browser")
          require(equal(get.text(3), digest(body.value("csrf", ""))), "csrf_denied");
      }
      json result = {{"username", get.text(0)},
                     {"scope", get.text(2)},
                     {"expires", get.integer(4)},
                     {"role", get.text(5)}};
      if (op == "logout") {
        statement del(db, "DELETE FROM sessions WHERE hash=?");
        del.bind(1, digest(token));
        del.row();
      }
      return result;
    }
    throw error("not_supported");
  }
};
identity_store::identity_store(const config &c) : impl_(std::make_unique<impl>(c)) {}
identity_store::~identity_store() = default;
json identity_store::dispatch(const std::string &o, const json &b, const call_context &ctx) {
  return impl_->dispatch(o, b, ctx);
}
} // namespace tc
