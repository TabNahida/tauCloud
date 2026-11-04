#include <taucloud/nfs_ssv.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace tc::nfs_detail {
namespace {
const EVP_MD *hash_algorithm(uint32_t bits) {
  switch (bits) {
  case 1: return EVP_sha1();
  case 224: return EVP_sha224();
  case 256: return EVP_sha256();
  case 384: return EVP_sha384();
  case 512: return EVP_sha512();
  default: throw error("ssv_algorithm");
  }
}
const EVP_CIPHER *cipher_algorithm(uint32_t bits) {
  switch (bits) {
  case 128: return EVP_aes_128_cbc();
  case 192: return EVP_aes_192_cbc();
  case 256: return EVP_aes_256_cbc();
  default: throw error("ssv_algorithm");
  }
}
bool equal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
std::string random_bytes(size_t n) {
  std::string value(n, '\0');
  require(RAND_bytes(reinterpret_cast<unsigned char *>(value.data()), int(n)) == 1, "crypto_error");
  return value;
}
void wipe(std::string &value) { OPENSSL_cleanse(value.data(), value.size()); }
}
ssv_context::ssv_context(uint32_t hash, uint32_t cipher, uint32_t window)
    : hash_(hash), cipher_(cipher), window_(window) {
  hash_algorithm(hash); cipher_algorithm(cipher);
  require(window >= 1 && window <= 16 && cipher / 8 <= length(), "ssv_algorithm");
  versions_.push_front(derive(std::string(length(), '\0')));
}
ssv_context::~ssv_context() {
  for (auto &keys : versions_) {
    wipe(keys.value);
    for (auto &key : keys.subkeys) wipe(key);
  }
}
std::string ssv_context::hmac(std::string_view key, std::string_view data) const {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned size = 0;
  require(HMAC(hash_algorithm(hash_), key.data(), int(key.size()),
      reinterpret_cast<const unsigned char *>(data.data()), data.size(), result, &size), "crypto_error");
  std::string out(reinterpret_cast<char *>(result), size);
  OPENSSL_cleanse(result, sizeof(result));
  return out;
}
ssv_context::keys ssv_context::derive(std::string value) const {
  keys result{std::move(value), {}};
  for (uint32_t i = 1; i <= 4; ++i) {
    auto full = hmac(result.value, writer().u32(i).data);
    result.subkeys[i - 1] = full.substr(0, cipher_ / 8);
    wipe(full);
  }
  return result;
}
const ssv_context::keys &ssv_context::version(uint32_t seq) const {
  require(seq && seq <= sequence_ && sequence_ - seq < versions_.size(), "ssv_context");
  return versions_[sequence_ - seq];
}
std::string ssv_context::update(std::string_view delta, std::string_view request,
                              std::string_view digest, std::string_view response) {
  require(delta.size() == length(), "ssv_length");
  require(sequence_ != UINT32_MAX, "ssv_exhausted");
  require(equal(hmac(versions_.front().subkeys[0], request), digest), "ssv_digest");
  std::string value = versions_.front().value;
  for (size_t i = 0; i < value.size(); ++i) value[i] ^= delta[i];
  auto prepared = derive(std::move(value));
  auto result = hmac(prepared.subkeys[1], response);
  versions_.push_front(std::move(prepared));
  ++sequence_;
  if (versions_.size() > window_) {
    wipe(versions_.back().value);
    for (auto &key : versions_.back().subkeys) wipe(key);
    versions_.pop_back();
  }
  return result;
}
std::string ssv_context::sign(std::string_view data) const {
  const auto &keys = version(sequence_);
  return writer().u32(sequence_).opaque(hmac(keys.subkeys[1],
      writer().u32(sequence_).opaque(data).data)).data;
}
bool ssv_context::verify(std::string_view data, std::string_view token) const {
  try {
    reader r(token);
    auto seq = r.u32();
    auto digest = r.opaque(64); r.end();
    return equal(digest, hmac(version(seq).subkeys[0], writer().u32(seq).opaque(data).data));
  } catch (...) { return false; }
}
std::string ssv_context::crypt(std::string_view key, std::string_view iv, std::string_view data,
                             bool encrypt) const {
  require(iv.size() == 16 && !data.empty() && data.size() % 16 == 0 && data.size() <= max_record,
          "ssv_context");
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  require(bool(ctx), "crypto_error");
  require(EVP_CipherInit_ex(ctx.get(), cipher_algorithm(cipher_), nullptr,
      reinterpret_cast<const unsigned char *>(key.data()), reinterpret_cast<const unsigned char *>(iv.data()),
      encrypt ? 1 : 0) == 1 && EVP_CIPHER_CTX_set_padding(ctx.get(), 0) == 1, "crypto_error");
  std::string out(data.size() + 16, '\0');
  int written = 0, tail = 0;
  require(EVP_CipherUpdate(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &written,
      reinterpret_cast<const unsigned char *>(data.data()), int(data.size())) == 1 &&
      EVP_CipherFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(out.data()) + written, &tail) == 1,
      "ssv_context");
  out.resize(size_t(written + tail));
  return out;
}
uint32_t ssv_context::wrap_size_limit(uint32_t limit) const {
  // Outer sequence/IV/ciphertext/HMAC, plus a 16-byte confounder and
  // inner sequence/three opaque lengths. Round both XDR and CBC blocks.
  uint32_t overhead = 32 + length();
  if (limit < overhead + 32) return 0;
  return ((limit - overhead) & ~15u) - 32;
}
std::string ssv_context::wrap(std::string_view data) const {
  const auto &keys = version(sequence_);
  writer plain;
  plain.opaque(random_bytes(16)).u32(sequence_).opaque(data);
  plain.opaque(std::string((16 - ((plain.data.size() + 4) % 16)) % 16, '\0'));
  auto iv = random_bytes(16);
  auto encrypted = crypt(keys.subkeys[3], iv, plain.data, true);
  return writer().u32(sequence_).opaque(iv).opaque(encrypted).opaque(hmac(keys.subkeys[1], plain.data)).data;
}
std::string ssv_context::unwrap(std::string_view token) const {
  reader r(token);
  auto seq = r.u32();
  const auto &keys = version(seq);
  auto iv = r.opaque(16), encrypted = r.opaque(max_record), digest = r.opaque(64); r.end();
  auto plain = crypt(keys.subkeys[2], iv, encrypted, false);
  require(equal(digest, hmac(keys.subkeys[0], plain)), "ssv_context");
  reader p(plain);
  p.opaque(max_record);
  require(p.u32() == seq, "ssv_context");
  auto data = p.opaque(max_record), pad = p.opaque(max_record); p.end();
  require(pad.find_first_not_of('\0') == std::string::npos, "ssv_context");
  return data;
}
}
