#pragma once
#include <taucloud/database.hpp>
namespace tc {
void migrate_policy(sqlite3 *db);
json policy_dispatch(sqlite3 *db, const config &, const std::string &, const json &,
                     const call_context &);
} // namespace tc
