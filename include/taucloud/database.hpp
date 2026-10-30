#pragma once
#include <taucloud/core.hpp>
#include <sqlite3.h>
namespace tc {
struct statement {
  sqlite3_stmt *p = nullptr;
  statement(sqlite3 *db, const char *text) {
    require(sqlite3_prepare_v2(db, text, -1, &p, nullptr) == SQLITE_OK, "database_error");
  }
  ~statement() { sqlite3_finalize(p); }
  statement(const statement &) = delete;
  void bind(int n, const std::string &value) {
    require(sqlite3_bind_text(p, n, value.data(), static_cast<int>(value.size()),
                              SQLITE_TRANSIENT) == SQLITE_OK,
            "database_error");
  }
  void bind(int n, int64_t value) {
    require(sqlite3_bind_int64(p, n, value) == SQLITE_OK, "database_error");
  }
  void bind(int n, const json &value) {
    if (value.is_string())
      bind(n, value.get<std::string>());
    else {
      require(value.is_number_integer(), "invalid_request");
      bind(n, value.get<int64_t>());
    }
  }
  bool row() {
    auto r = sqlite3_step(p);
    require(r == SQLITE_ROW || r == SQLITE_DONE, "database_error");
    return r == SQLITE_ROW;
  }
  std::string text(int n) const {
    auto v = sqlite3_column_text(p, n);
    return v ? reinterpret_cast<const char *>(v) : "";
  }
  int64_t integer(int n) const { return sqlite3_column_int64(p, n); }
};
inline void sql(sqlite3 *db, const char *text) {
  require(sqlite3_exec(db, text, nullptr, nullptr, nullptr) == SQLITE_OK, "database_error");
}
struct transaction {
  sqlite3 *db;
  bool committed = false;
  explicit transaction(sqlite3 *d) : db(d) { sql(db, "BEGIN IMMEDIATE"); }
  void commit() {
    sql(db, "COMMIT");
    committed = true;
  }
  ~transaction() {
    if (!committed)
      sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
  }
};
class database {
  sqlite3 *db_ = nullptr;

public:
  explicit database(const fs::path &path) {
    int code = sqlite3_open_v2(path.string().c_str(), &db_,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                               nullptr);
    if (code != SQLITE_OK) {
      sqlite3_close(db_);
      throw error("database_error");
    }
    sqlite3_busy_timeout(db_, 2000);
    sql(db_, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON");
    statement check(db_, "PRAGMA quick_check");
    require(check.row() && check.text(0) == "ok", "database_corrupt");
  }
  ~database() { sqlite3_close(db_); }
  operator sqlite3 *() const { return db_; }
};
inline void backup_database(sqlite3 *source, const fs::path &path) {
  database destination(path);
  auto b = sqlite3_backup_init(destination, "main", source, "main");
  int status = b ? sqlite3_backup_step(b, -1) : SQLITE_ERROR;
  if (b)
    sqlite3_backup_finish(b);
  require(status == SQLITE_DONE, "backup_failed");
}
} // namespace tc
