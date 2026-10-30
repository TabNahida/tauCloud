#pragma once
#include <taucloud/core.hpp>
#include <string_view>
namespace tc::smb_detail {
using bytes = std::string;
uint64_t get(std::string_view b, size_t off, size_t n);
void put(bytes &b, size_t off, uint64_t value, size_t n);
bytes utf16(std::string_view text);
std::string utf8(std::string_view text);
bytes hmac(std::string_view key, std::string_view data, bool sha256 = false);
bytes signature(std::string_view key, bytes packet, bool smb3 = false);
bytes cmac(std::string_view key, std::string_view data);
bytes preauth(std::string_view previous, std::string_view packet);
bytes kdf(std::string_view key, std::string_view label, std::string_view context);
bytes encrypt(std::string_view key, unsigned cipher, uint64_t session, std::string_view nonce,
              std::string_view plain);
bytes decrypt(std::string_view key, unsigned cipher, uint64_t session, std::string_view packet);
struct negotiation {
  unsigned dialect = 0, cipher = 0;
  uint32_t capabilities = 0;
  bytes client_info;
  bytes accept(std::string_view packet, std::string_view guid);
  bytes validate(std::string_view input, std::string_view guid) const;
};
bytes nt_hash(std::string_view password);
bytes seal(std::string_view key, std::string_view plain, std::string_view aad);
bytes unseal(std::string_view key, std::string_view encrypted, std::string_view aad);
bytes vault_key(const config &);
bytes ntlm_token(std::string_view token);
bytes spnego(std::string_view token, bool complete = false);
bytes mechanisms();
struct ntlm_exchange {
  bytes negotiate, challenge;
  int64_t expires;
  explicit ntlm_exchange(bytes type1);
  json verify(bytes type3, std::string_view hash) const;
};
} // namespace tc::smb_detail
