#pragma once
#include <taucloud/nfs.hpp>
#include <deque>
#include <array>

namespace tc::nfs_detail {
// RFC 8881 2.10.9. Serialized by the NFS dispatcher; shared by all of a
// client's RPC handles, whose RPC sequence windows remain independent.
class ssv_context {
  struct keys {
    std::string value;
    std::array<std::string, 4> subkeys;
  };
  uint32_t hash_, cipher_, window_, sequence_ = 0;
  std::deque<keys> versions_;
  keys derive(std::string value) const;
  const keys &version(uint32_t sequence) const;
  std::string hmac(std::string_view key, std::string_view data) const;
  std::string crypt(std::string_view key, std::string_view iv, std::string_view data, bool encrypt) const;
public:
  ssv_context(uint32_t hash_bits, uint32_t cipher_bits, uint32_t window);
  ~ssv_context();
  ssv_context(const ssv_context &) = delete;
  ssv_context &operator=(const ssv_context &) = delete;
  uint32_t hash_bits() const { return hash_; }
  uint32_t cipher_bits() const { return cipher_; }
  uint32_t window() const { return window_; }
  uint32_t length() const { return hash_ == 1 ? 20 : hash_ / 8; }
  uint32_t sequence() const { return sequence_; }
  uint32_t mic_size() const { return 8 + length(); }
  uint32_t wrap_size_limit(uint32_t limit) const;
  std::string update(std::string_view delta, std::string_view request, std::string_view digest,
                     std::string_view response);
  std::string sign(std::string_view data) const;
  bool verify(std::string_view data, std::string_view token) const;
  std::string wrap(std::string_view data) const;
  std::string unwrap(std::string_view token) const;
};
}
