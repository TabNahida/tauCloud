#pragma once
#include <taucloud/core.hpp>
namespace tc {
// Process protocol v1 uses the existing authenticated, bounded local RPC envelope.
int plugins(const config &, const std::string &, std::atomic_bool &);
int docker_plugin(const config &, const std::string &, std::atomic_bool &);
json docker_endpoint(const json &);
json docker_call(const json &endpoint, const std::string &operation, const json &,
                 const call_context &);
} // namespace tc
