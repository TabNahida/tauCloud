#include <taucloud/smb.hpp>
#include <taucloud/files.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/rc4.h>
#include <openssl/crypto.h>
#include <utf8proc.h>
#include <map>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif
namespace tc::smb_detail {
uint64_t get(std::string_view b, size_t off, size_t n) {
  require(n <= 8 && off <= b.size() && n <= b.size() - off, "invalid_packet");
  uint64_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v |= uint64_t(static_cast<unsigned char>(b[off + i])) << (8 * i);
  return v;
}
void put(bytes &b, size_t off, uint64_t v, size_t n) {
  require(n <= 8 && off <= b.size() && n <= b.size() - off, "invalid_packet");
  for (size_t i = 0; i < n; ++i)
    b[off + i] = char(v >> (8 * i));
}
bytes utf16(std::string_view s) {
  bytes out;
  for (size_t i = 0; i < s.size();) {
    int32_t cp;
    auto n = utf8proc_iterate(reinterpret_cast<const uint8_t *>(s.data() + i), s.size() - i, &cp);
    require(n > 0 && cp != 0, "invalid_path");
    i += n;
    auto add = [&](uint16_t v) {
      out += char(v);
      out += char(v >> 8);
    };
    if (cp < 0x10000)
      add(static_cast<uint16_t>(cp));
    else {
      cp -= 0x10000;
      add(static_cast<uint16_t>(0xd800 + (cp >> 10)));
      add(static_cast<uint16_t>(0xdc00 + (cp & 1023)));
    }
  }
  return out;
}
std::string utf8(std::string_view s) {
  require(s.size() % 2 == 0 && s.size() <= 8192, "invalid_path");
  bytes out;
  for (size_t i = 0; i < s.size(); i += 2) {
    int32_t cp = static_cast<int32_t>(get(s, i, 2));
    if (cp >= 0xd800 && cp <= 0xdbff) {
      require(i + 4 <= s.size(), "invalid_path");
      auto low = get(s, i + 2, 2);
      require(low >= 0xdc00 && low <= 0xdfff, "invalid_path");
      cp = 0x10000 + ((cp - 0xd800) << 10) + static_cast<int32_t>(low - 0xdc00);
      i += 2;
    } else
      require(cp < 0xdc00 || cp > 0xdfff, "invalid_path");
    require(cp != 0, "invalid_path");
    uint8_t buf[4];
    auto n = utf8proc_encode_char(cp, buf);
    require(n > 0, "invalid_path");
    out.append(reinterpret_cast<char *>(buf), n);
  }
  return out;
}
bytes hmac(std::string_view key, std::string_view data, bool sha256) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned n = 0;
  require(HMAC(sha256 ? EVP_sha256() : EVP_md5(), key.data(), static_cast<int>(key.size()),
               reinterpret_cast<const unsigned char *>(data.data()), data.size(), result,
               &n) != nullptr,
          "crypto_error");
  return bytes(reinterpret_cast<char *>(result), n);
}
bytes signature(std::string_view key, bytes packet, bool smb3) {
  require(packet.size() >= 64, "invalid_packet");
  packet.replace(48, 16, 16, '\0');
  if (smb3)
    return cmac(key, packet);
  return hmac(key, packet, true).substr(0, 16);
}
bytes nt_hash(std::string_view password) {
  auto input = utf16(password);
  unsigned char out[16];
  // OpenSSL's mature primitive, deliberately isolated from the TLS provider policy.
  require(MD4(reinterpret_cast<const unsigned char *>(input.data()), input.size(), out) != nullptr,
          "crypto_error");
  OPENSSL_cleanse(input.data(), input.size());
  return bytes(reinterpret_cast<char *>(out), 16);
}
bytes seal(std::string_view key, std::string_view plain, std::string_view aad) {
  require(key.size() == 32, "crypto_error");
  auto nonce = decode_bytes(random_hex(12));
  bytes out = nonce + bytes(plain.size() + 16, '\0');
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> c(EVP_CIPHER_CTX_new(),
                                                                    EVP_CIPHER_CTX_free);
  int n = 0, total = 0;
  require(c && EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr,
                                  reinterpret_cast<const unsigned char *>(key.data()),
                                  reinterpret_cast<const unsigned char *>(nonce.data())) == 1,
          "crypto_error");
  require(EVP_EncryptUpdate(c.get(), nullptr, &n,
                            reinterpret_cast<const unsigned char *>(aad.data()),
                            static_cast<int>(aad.size())) == 1,
          "crypto_error");
  require(EVP_EncryptUpdate(c.get(), reinterpret_cast<unsigned char *>(out.data() + 12), &n,
                            reinterpret_cast<const unsigned char *>(plain.data()),
                            static_cast<int>(plain.size())) == 1,
          "crypto_error");
  total = n;
  require(EVP_EncryptFinal_ex(c.get(), reinterpret_cast<unsigned char *>(out.data() + 12 + total),
                              &n) == 1,
          "crypto_error");
  require(EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + 12 + plain.size()) ==
              1,
          "crypto_error");
  return out;
}
bytes unseal(std::string_view key, std::string_view encrypted, std::string_view aad) {
  require(key.size() == 32 && encrypted.size() >= 28 && encrypted.size() <= 4096,
          "credential_corrupt");
  bytes out(encrypted.size() - 28, '\0');
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> c(EVP_CIPHER_CTX_new(),
                                                                    EVP_CIPHER_CTX_free);
  int n = 0, total = 0;
  require(c && EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr,
                                  reinterpret_cast<const unsigned char *>(key.data()),
                                  reinterpret_cast<const unsigned char *>(encrypted.data())) == 1,
          "crypto_error");
  require(EVP_DecryptUpdate(c.get(), nullptr, &n,
                            reinterpret_cast<const unsigned char *>(aad.data()),
                            static_cast<int>(aad.size())) == 1,
          "crypto_error");
  require(EVP_DecryptUpdate(c.get(), reinterpret_cast<unsigned char *>(out.data()), &n,
                            reinterpret_cast<const unsigned char *>(encrypted.data() + 12),
                            static_cast<int>(out.size())) == 1,
          "crypto_error");
  total = n;
  require(EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, 16,
                              const_cast<char *>(encrypted.data() + encrypted.size() - 16)) == 1,
          "crypto_error");
  require(EVP_DecryptFinal_ex(c.get(), reinterpret_cast<unsigned char *>(out.data() + total), &n) ==
              1,
          "credential_corrupt");
  return out;
}
bytes vault_key(const config &cfg) {
  auto path = cfg.state / "smb-vault.json";
  bytes key;
  if (fs::exists(path))
    key = decode_bytes(read_json(path).at("key").get<std::string>());
  else {
    key = decode_bytes(random_hex());
#ifdef _WIN32
    DATA_BLOB in{static_cast<DWORD>(key.size()), reinterpret_cast<BYTE *>(key.data())}, out{};
    require(CryptProtectData(&in, L"tauCloud SMB vault", nullptr, nullptr, nullptr,
                             CRYPTPROTECT_UI_FORBIDDEN, &out) != 0,
            "vault_failed");
    write_json(path,
               {{"key", encode_bytes(bytes(reinterpret_cast<char *>(out.pbData), out.cbData))},
                {"protection", "dpapi-user"}});
    LocalFree(out.pbData);
#else
    write_json(path, {{"key", encode_bytes(key)}, {"protection", "private-state-directory"}});
#endif
    return key;
  }
#ifdef _WIN32
  DATA_BLOB in{static_cast<DWORD>(key.size()), reinterpret_cast<BYTE *>(key.data())}, out{};
  require(CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                             &out) != 0,
          "vault_failed");
  key.assign(reinterpret_cast<char *>(out.pbData), out.cbData);
  SecureZeroMemory(out.pbData, out.cbData);
  LocalFree(out.pbData);
#endif
  require(key.size() == 32, "vault_failed");
  return key;
}
namespace {
bytes der(unsigned char tag, std::string_view value) {
  bytes b(1, char(tag));
  if (value.size() < 128)
    b += char(value.size());
  else {
    require(value.size() <= 65535, "invalid_packet");
    b += char(0x82);
    b += char(value.size() >> 8);
    b += char(value.size());
  }
  b += value;
  return b;
}
const bytes oid("\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a", 12);
void extract(std::string_view b, int depth, bytes &token) {
  require(depth <= 8, "invalid_packet");
  size_t pos = 0;
  while (pos < b.size()) {
    auto tag = get(b, pos++, 1);
    size_t len = get(b, pos++, 1);
    if (len & 128) {
      auto count = len & 127;
      require(count > 0 && count <= 2, "invalid_packet");
      len = 0;
      while (count--)
        len = (len << 8) | get(b, pos++, 1);
    }
    require(len <= b.size() - pos, "invalid_packet");
    auto v = b.substr(pos, len);
    pos += len;
    if (tag == 4 && v.starts_with(std::string_view("NTLMSSP\0", 8))) {
      require(token.empty(), "invalid_packet");
      token = v;
    } else if (tag & 32)
      extract(v, depth + 1, token);
  }
}
bytes sec(std::string_view b, size_t off, size_t minimum) {
  auto n = get(b, off, 2), max = get(b, off + 2, 2), start = get(b, off + 4, 4);
  require(n <= max && start <= b.size() && n <= b.size() - start && (n == 0 || start >= minimum),
          "invalid_packet");
  return bytes(b.substr(start, n));
}
void secput(bytes &b, size_t off, std::string_view value) {
  put(b, off, value.size(), 2);
  put(b, off + 2, value.size(), 2);
  put(b, off + 4, b.size(), 4);
  b += value;
}
std::map<int, bytes> avs(std::string_view b) {
  std::map<int, bytes> out;
  size_t p = 0;
  while (p < b.size()) {
    auto id = get(b, p, 2), n = get(b, p + 2, 2);
    p += 4;
    require(n <= b.size() - p && id <= 10 && !out.contains(static_cast<int>(id)), "invalid_packet");
    if (id == 0) {
      require(n == 0 && (p == b.size() || (p + 4 == b.size() && get(b, p, 4) == 0)),
              "invalid_packet");
      return out;
    }
    out[static_cast<int>(id)] = b.substr(p, n);
    p += n;
  }
  throw error("invalid_packet");
}
void av(bytes &b, int id, std::string_view v) {
  size_t p = b.size();
  b.resize(p + 4);
  put(b, p, id, 2);
  put(b, p + 2, v.size(), 2);
  b += v;
}
} // namespace
bytes ntlm_token(std::string_view token) {
  require(token.size() <= 16384, "invalid_packet");
  if (token.starts_with(std::string_view("NTLMSSP\0", 8)))
    return bytes(token);
  bytes out;
  extract(token, 0, out);
  require(!out.empty(), "invalid_packet");
  return out;
}
bytes spnego(std::string_view token, bool complete) {
  bytes b = der(0xa0, der(10, bytes(1, complete ? 0 : 1)));
  if (!token.empty())
    b += der(0xa1, oid) + der(0xa2, der(4, token));
  return der(0xa1, der(0x30, b));
}
bytes mechanisms() {
  return der(0x60, bytes("\x06\x06\x2b\x06\x01\x05\x05\x02", 8) +
                       der(0xa0, der(0x30, der(0xa0, der(0x30, oid)))));
}
ntlm_exchange::ntlm_exchange(bytes type1) : negotiate(std::move(type1)), expires(now() + 10000) {
  require(negotiate.size() >= 32 && get(negotiate, 8, 4) == 1, "unauthorized");
  auto flags = get(negotiate, 12, 4);
  require((flags & 0x80011) == 0x80011, "unauthorized");
  challenge.assign(56, '\0');
  challenge.replace(0, 8, "NTLMSSP\0", 8);
  put(challenge, 8, 2, 4);
  uint32_t chosen = 0xa28a8215u | (static_cast<uint32_t>(flags) & 0x40000000u);
  put(challenge, 20, chosen, 4);
  challenge.replace(24, 8, decode_bytes(random_hex(8)));
  challenge[48] = 10;
  put(challenge, 50, 19041, 2);
  challenge[55] = 15;
  auto domain = utf16("TAUCLOUD"), server = utf16("TAUCLOUD");
  secput(challenge, 12, domain);
  bytes info, timestamp(8, '\0'), avflags(4, '\0');
  put(timestamp, 0, (now() + 11644473600000ll) * 10000ull, 8);
  put(avflags, 0, 2, 4);
  av(info, 1, server);
  av(info, 2, domain);
  av(info, 6, avflags);
  av(info, 7, timestamp);
  av(info, 0, {});
  secput(challenge, 40, info);
}
json ntlm_exchange::verify(bytes type3, std::string_view hash) const {
  require(now() < expires && hash.size() == 16 && type3.size() >= 80 && get(type3, 8, 4) == 3,
          "unauthorized");
  auto flags = get(type3, 60, 4);
  size_t micpos = (flags & 0x02000000) ? 72 : 64;
  require(type3.size() >= micpos + 16 && (flags & 0x80011) == 0x80011 &&
              ((flags ^ get(challenge, 20, 4)) & 0x40000000) == 0,
          "unauthorized");
  auto response = sec(type3, 20, micpos + 16), domain = sec(type3, 28, micpos + 16),
       user = sec(type3, 36, micpos + 16), encrypted = sec(type3, 52, micpos + 16);
  auto name = utf8(user);
  require(!name.empty() && name.size() <= 64, "unauthorized");
  auto upper = name;
  for (auto &c : upper) {
    require(static_cast<unsigned char>(c) < 128, "unauthorized");
    if (c >= 'a' && c <= 'z')
      c -= 32;
  }
  require(response.size() >= 48, "unauthorized");
  auto blob = response.substr(16);
  require(get(blob, 0, 4) == 0x101 && get(blob, 4, 4) == 0 && get(blob, 24, 4) == 0,
          "unauthorized");
  auto entries = avs(std::string_view(blob).substr(28));
  auto offered = avs(sec(challenge, 40, 56));
  for (int id : {1, 2, 7})
    require(entries.contains(id) && entries[id] == offered[id], "unauthorized");
  require(entries.contains(6) && entries[6].size() == 4 && (get(entries[6], 0, 4) & 2) != 0,
          "unauthorized");
  if (entries.contains(10))
    require(entries[10] == bytes(16, '\0'), "unauthorized");
  require(get(blob, 8, 8) == get(offered[7], 0, 8), "unauthorized");
  auto key = hmac(hash, utf16(upper) + domain), proof = hmac(key, challenge.substr(24, 8) + blob);
  require(equal(proof, response.substr(0, 16)), "unauthorized");
  auto session = hmac(key, proof);
  if (flags & 0x40000000) {
    require(encrypted.size() == 16, "unauthorized");
    RC4_KEY rc4;
    RC4_set_key(&rc4, 16, reinterpret_cast<const unsigned char *>(session.data()));
    RC4(&rc4, 16, reinterpret_cast<const unsigned char *>(encrypted.data()),
        reinterpret_cast<unsigned char *>(session.data()));
    OPENSSL_cleanse(&rc4, sizeof(rc4));
  } else
    require(encrypted.empty(), "unauthorized");
  auto mic = type3.substr(micpos, 16);
  type3.replace(micpos, 16, 16, '\0');
  require(equal(mic, hmac(session, negotiate + challenge + type3)), "unauthorized");
  return {{"username", name}, {"session_key", encode_bytes(session)}};
}
} // namespace tc::smb_detail
