#include <taucloud/smb.hpp>
#include <taucloud/files.hpp>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <algorithm>
#include <map>
namespace tc::smb_detail {
bytes cmac(std::string_view key, std::string_view data) {
  require(key.size() == 16, "crypto_error");
  std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, "CMAC", nullptr),
                                                        EVP_MAC_free);
  require(bool(mac), "crypto_error");
  std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(mac.get()),
                                                                EVP_MAC_CTX_free);
  char algorithm[] = "AES-128-CBC";
  OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, algorithm, 0),
                         OSSL_PARAM_END};
  bytes result(16, '\0');
  size_t size = 0;
  require(ctx &&
              EVP_MAC_init(ctx.get(), reinterpret_cast<const unsigned char *>(key.data()),
                           key.size(), params) == 1 &&
              EVP_MAC_update(ctx.get(), reinterpret_cast<const unsigned char *>(data.data()),
                             data.size()) == 1 &&
              EVP_MAC_final(ctx.get(), reinterpret_cast<unsigned char *>(result.data()), &size,
                            result.size()) == 1 &&
              size == 16,
          "crypto_error");
  return result;
}
bytes preauth(std::string_view previous, std::string_view packet) {
  require(previous.size() == 64 && packet.size() <= 1024 * 1024, "invalid_packet");
  bytes input = bytes(previous) + bytes(packet), result(64, '\0');
  unsigned size = 0;
  require(EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char *>(result.data()),
                     &size, EVP_sha512(), nullptr) == 1 &&
              size == 64,
          "crypto_error");
  return result;
}
bytes kdf(std::string_view key, std::string_view label, std::string_view context) {
  // SP800-108 counter mode. SMB labels include their NUL, then the KDF separator.
  require(key.size() == 16, "crypto_error");
  bytes input("\0\0\0\1", 4);
  input += label;
  input.append(2, '\0');
  input += context;
  input.append("\0\0\0\x80", 4);
  return hmac(key, input, true).substr(0, 16);
}
namespace {
bytes crypt(std::string_view key, unsigned cipher, std::string_view nonce, std::string_view aad,
            std::string_view data, bytes &tag, bool sealing) {
  require(key.size() == 16 && (cipher == 1 || cipher == 2) &&
              nonce.size() == (cipher == 1 ? 11u : 12u) && data.size() >= 64 &&
              data.size() <= 1024 * 1024 && tag.size() == 16,
          "invalid_packet");
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
                                                                      EVP_CIPHER_CTX_free);
  auto *c = ctx.get();
  auto *algo = cipher == 1 ? EVP_aes_128_ccm() : EVP_aes_128_gcm();
  auto ptr = [](std::string_view v) { return reinterpret_cast<const unsigned char *>(v.data()); };
  bytes out(data.size() + 16, '\0');
  auto *dst = reinterpret_cast<unsigned char *>(out.data());
  int n = 0, end = 0;
  require(c && EVP_CipherInit_ex(c, algo, nullptr, nullptr, nullptr, sealing) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                                  nullptr) == 1,
          "crypto_error");
  if (!sealing || cipher == 1)
    require(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, sealing ? nullptr : tag.data()) == 1,
            "crypto_error");
  require(EVP_CipherInit_ex(c, nullptr, nullptr, ptr(key), ptr(nonce), sealing) == 1,
          "crypto_error");
  if (cipher == 1)
    require(EVP_CipherUpdate(c, nullptr, &n, nullptr, static_cast<int>(data.size())) == 1,
            "crypto_error");
  require(EVP_CipherUpdate(c, nullptr, &n, ptr(aad), static_cast<int>(aad.size())) == 1,
          "crypto_error");
  // CCM authenticates in Update; GCM authenticates in Final. Never release unauthenticated bytes.
  require(EVP_CipherUpdate(c, dst, &n, ptr(data), static_cast<int>(data.size())) == 1 &&
              (cipher == 1 && !sealing ? true : EVP_CipherFinal_ex(c, dst + n, &end) == 1),
          "invalid_packet");
  require(static_cast<size_t>(n + end) == data.size(), "crypto_error");
  out.resize(data.size());
  if (sealing)
    require(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) == 1, "crypto_error");
  return out;
}
} // namespace
bytes encrypt(std::string_view key, unsigned cipher, uint64_t session, std::string_view nonce,
              std::string_view plain) {
  bytes header(52, '\0'), tag(16, '\0');
  header.replace(0, 4, "\xfdSMB", 4);
  require(nonce.size() == (cipher == 1 ? 11u : 12u), "invalid_packet");
  header.replace(20, nonce.size(), nonce);
  put(header, 36, plain.size(), 4);
  put(header, 42, 1, 2);
  put(header, 44, session, 8);
  auto data = crypt(key, cipher, nonce, std::string_view(header).substr(20), plain, tag, true);
  header.replace(4, 16, tag);
  return header + data;
}
bytes decrypt(std::string_view key, unsigned cipher, uint64_t session, std::string_view packet) {
  auto nonce_size = cipher == 1 ? 11u : 12u;
  require(packet.size() >= 116 && packet.substr(0, 4) == std::string_view("\xfdSMB", 4) &&
              get(packet, 36, 4) == packet.size() - 52 && get(packet, 40, 2) == 0 &&
              get(packet, 42, 2) == 1 && get(packet, 44, 8) == session &&
              packet.substr(20 + nonce_size, 16 - nonce_size) == bytes(16 - nonce_size, '\0'),
          "invalid_packet");
  bytes tag(packet.substr(4, 16));
  return crypt(key, cipher, packet.substr(20, nonce_size), packet.substr(20, 32), packet.substr(52),
               tag, false);
}
bytes negotiation::accept(std::string_view p, std::string_view guid) {
  require(p.size() >= 102 && get(p, 64, 2) == 36 && guid.size() == 16, "invalid_packet");
  auto count = get(p, 66, 2), security = get(p, 68, 2);
  require(count > 0 && count <= 64 && p.size() >= 100 + 2 * count && (security & 3) &&
              !(security & ~3u),
          "invalid_packet");
  dialect = cipher = capabilities = 0;
  for (size_t i = 0; i < count; ++i) {
    auto d = get(p, 100 + i * 2, 2);
    if (d == 0x210 || d == 0x300 || d == 0x302 || d == 0x311)
      dialect = std::max(dialect, static_cast<unsigned>(d));
  }
  require(dialect != 0, "not_supported");
  client_info = bytes(p.substr(72, 20)) + bytes(p.substr(68, 2)) + bytes(p.substr(66, 2)) +
                bytes(p.substr(100, 2 * count));
  bytes contexts;
  unsigned context_count = 0;
  auto add = [&](unsigned type, bytes data) {
    if (!contexts.empty())
      contexts.resize((contexts.size() + 7) / 8 * 8, '\0');
    bytes h(8, '\0');
    put(h, 0, type, 2);
    put(h, 2, data.size(), 2);
    contexts += h + data;
    ++context_count;
  };
  if (dialect == 0x311) {
    auto off = get(p, 92, 4), n = get(p, 96, 2);
    require(n > 0 && n <= 16 && off >= 100 + 2 * count && off % 8 == 0, "invalid_packet");
    std::map<unsigned, bytes> found;
    for (size_t i = 0; i < n; ++i) {
      auto type = static_cast<unsigned>(get(p, off, 2));
      auto size = get(p, off + 2, 2);
      require(get(p, off + 4, 4) == 0 && off + 8 <= p.size() && size <= p.size() - off - 8 &&
                  !found.contains(type),
              "invalid_packet");
      found.emplace(type, p.substr(off + 8, size));
      off = (off + 8 + size + 7) / 8 * 8;
    }
    require(found.contains(1) && found.contains(2), "not_supported");
    auto &hashes = found.at(1);
    auto hashes_count = get(hashes, 0, 2), salt_size = get(hashes, 2, 2);
    require(hashes_count > 0 && hashes_count <= 64 &&
                hashes.size() == 4 + 2 * hashes_count + salt_size,
            "invalid_packet");
    bool sha512 = false;
    for (size_t i = 0; i < hashes_count; ++i)
      sha512 |= get(hashes, 4 + 2 * i, 2) == 1;
    require(sha512, "preauth_hash_overlap");
    auto supports = [](const bytes &data, unsigned value) {
      auto n = get(data, 0, 2);
      require(n > 0 && n <= 64 && data.size() == 2 + 2 * n, "invalid_packet");
      bool match = false;
      for (size_t i = 0; i < n; ++i)
        match |= get(data, 2 + 2 * i, 2) == value;
      return match;
    };
    cipher = supports(found.at(2), 2) ? 2 : (supports(found.at(2), 1) ? 1 : 0);
    require(cipher != 0, "not_supported");
    if (found.contains(8))
      require(supports(found.at(8), 1), "not_supported");
    bytes hashes_response(6, '\0');
    put(hashes_response, 0, 1, 2);
    put(hashes_response, 2, 32, 2);
    put(hashes_response, 4, 1, 2);
    add(1, hashes_response + decode_bytes(random_hex(32)));
    bytes alg(4, '\0');
    put(alg, 0, 1, 2);
    put(alg, 2, cipher, 2);
    add(2, alg);
    if (found.contains(8)) {
      put(alg, 2, 1, 2);
      add(8, alg);
    }
  } else if (dialect >= 0x300) {
    capabilities = 0x40;
    if (get(p, 72, 4) & 0x40)
      cipher = 1;
  }
  auto security_blob = mechanisms();
  bytes b(64, '\0');
  put(b, 0, 65, 2);
  put(b, 2, 3, 2);
  put(b, 4, dialect, 2);
  put(b, 6, context_count, 2);
  b.replace(8, 16, guid);
  put(b, 24, capabilities, 4);
  for (size_t o : {28, 32, 36})
    put(b, o, 65536, 4);
  put(b, 40, (now() + 11644473600000ll) * 10000ull, 8);
  put(b, 56, 128, 2);
  put(b, 58, security_blob.size(), 2);
  b += security_blob;
  if (context_count) {
    b.resize((b.size() + 7) / 8 * 8, '\0');
    put(b, 60, 64 + b.size(), 4);
    b += contexts;
  }
  return b;
}
bytes negotiation::validate(std::string_view input, std::string_view guid) const {
  require((dialect == 0x300 || dialect == 0x302) && input == client_info, "invalid_packet");
  bytes response(24, '\0');
  put(response, 0, capabilities, 4);
  response.replace(4, 16, guid);
  put(response, 20, 3, 2);
  put(response, 22, dialect, 2);
  return response;
}
} // namespace tc::smb_detail
