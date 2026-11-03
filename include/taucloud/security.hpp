#pragma once
#include <taucloud/core.hpp>
namespace tc::security {
// Stable service principals, distinct from the host service account and Unix IDs.
std::string principal(const std::string &name, bool group = false);
json token(const json &grant);
uint32_t map_mask(uint32_t mask);
json decode(std::string_view wire);
std::string encode(const json &descriptor, uint32_t information);
json defaults(const std::string &owner, const std::string &group);
json inherit(const json &parent, const std::string &owner, const std::string &group, bool directory,
             bool fallback = true);
uint32_t allowed(const json &descriptor, const json &token);
} // namespace tc::security
