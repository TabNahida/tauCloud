#pragma once
#include <taucloud/core.hpp>
#include <string_view>
namespace tc {
// Owns one Kerberos acceptor context. No passwords, tickets or session keys
// cross the RPC/identity IPC boundary; callers receive only the verified name.
class gss_context {
  struct impl;
  std::unique_ptr<impl> impl_;
public:
  struct result { uint32_t major, minor, lifetime; std::string token, principal; };
  gss_context(const std::string &service, const std::string &keytab);
  ~gss_context();
  result accept(std::string_view token);
  std::string sign(std::string_view message);
  bool verify(std::string_view message, std::string_view token);
  std::string wrap(std::string_view message);
  std::string unwrap(std::string_view token);
};
}
