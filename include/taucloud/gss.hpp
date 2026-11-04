#pragma once
#include <taucloud/core.hpp>
#include <string_view>
namespace tc {
// Owns one Kerberos acceptor context. Protocol workers keep keys locally and
// send only verified principal names to identity policy over authenticated IPC.
class gss_context {
  struct impl;
  std::unique_ptr<impl> impl_;
public:
  enum class purpose { rpcsec_gss, smb };
  struct result { uint32_t major, minor, lifetime; std::string token, principal; };
  gss_context(const std::string &service, const std::string &keytab, purpose use = purpose::rpcsec_gss);
  ~gss_context();
  result accept(std::string_view token);
  std::string session_key();
  std::string sign(std::string_view message);
  bool verify(std::string_view message, std::string_view token);
  uint32_t wrap_size_limit(uint32_t token_limit);
  std::string wrap(std::string_view message);
  std::string unwrap(std::string_view token);
};
}
