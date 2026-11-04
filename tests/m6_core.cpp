#include <taucloud/smb.hpp>
#include <taucloud/files.hpp>
#include <iostream>
using namespace tc;
using namespace tc::smb_detail;
int main() {
  unsigned checks = 0;
  auto ok = [&](bool value) {
    require(value, "test_failed");
    ++checks;
  };
  auto rejected = [&](auto fn) {
    bool failed = false;
    try {
      fn();
    } catch (const error &) {
      failed = true;
    }
    ok(failed);
  };
  try {
    // NIST SP800-38B AES-CMAC vectors, independent of the SMB packet helper.
    auto aes = decode_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    ok(encode_bytes(cmac(aes, "")) == "bb1d6929e95937287fa37d129b756746");
    ok(encode_bytes(cmac(aes, decode_bytes("6bc1bee22e409f96e93d7e117393172a"))) ==
       "070a16b46b4d4144f79bdd9dd04a287c");
    bytes key, packet("\xfeSMB", 4);
    for (unsigned i = 0; i < 16; ++i)
      key += char(i);
    for (unsigned i = 4; i < 80; ++i)
      packet += char(i);
    // Independent AESGCM(empty plaintext, packet as AAD) vectors. The nonce
    // separates request/response and CANCEL, even when MessageId is reused.
    ok(encode_bytes(gmac(bytes(16, '\0'), bytes(12, '\0'), "")) ==
       "58e2fccefa7e3061367f1d57a4e7455a");
    const char *signatures[] = {"e43e2d63521af9bd84757c459e9c42d2", "2d5f2c8fb2ef9fda2b6b2b771c61f837",
                               "428edb1b6b66ac1542af9b73757eb129", "e3e7ce19208a8c8dad207ea5c8524a5a"};
    for (unsigned mode = 0; mode < 4; ++mode) {
      auto input = packet;
      put(input, 12, mode & 1 ? 12 : 13, 2);
      put(input, 16, mode & 2 ? 9 : 8, 4);
      put(input, 24, 0x0102030405060708ull, 8);
      auto expected = signature(key, input, 2);
      ok(encode_bytes(expected) == signatures[mode]);
      for (size_t i = 0; i < input.size(); ++i) {
        auto changed = input; changed[i] ^= 1;
        ok((signature(key, changed, 2) == expected) == (i >= 48 && i < 64));
      }
    }
    rejected([&] { gmac(bytes(15, 'x'), bytes(12, 'n'), packet); });
    rejected([&] { gmac(key, bytes(11, 'n'), packet); });
    rejected([&] { signature(key, packet, 3); });
    // Frozen vectors independently generated with cryptography KBKDFHMAC/AESCCM/AESGCM.
    ok(encode_bytes(kdf(key, "SMB2AESCMAC", bytes("SmbSign\0", 8))) ==
       "6234814cbb8ea9227440ebfeb5eacbe1");
    bytes full_key, transcript;
    for (unsigned i = 0; i < 64; ++i) {
      transcript += char(i);
      if (i < 32) full_key += char(i);
    }
    ok(encode_bytes(kdf(key, "SMBC2SCipherKey", transcript, 32)) ==
       "d09c44a545f554240ddf8ac2777570de0f590e402196d1006261f7448076384d");
    ok(encode_bytes(kdf(full_key, "SMBC2SCipherKey", transcript, 32)) ==
       "e568de865ae188f20138931c5423898fc0d5e94fa094b72d474fc56cf5703db6");
    rejected([&] { kdf("", "label", transcript, 32); });
    rejected([&] { kdf(key, "label", transcript, 24); });
    ok(encode_bytes(preauth(bytes(64, '\0'), packet)) ==
       "a782a30a69d6928f8ec0121c1f89dbe485a48ad87ae96156551afd93c2182bb5066998d6a34a6788873b8a6cf64"
       "2033baa8838be40c9c7923eb1febbfce9e409");
    const char *vectors[] = {
        "fd534d42447ab17917d149c3cce15c7c1b58a831000102030405060708090a000000000050000000000001007b"
        "00000000000000c1cf68e9d24d377bc99102839785c46452e44653e5f3f27e8d45397d62f227721ae7e08fb8cf"
        "0dcfc45d2ddb66567ffa8dfe2112bae1c2723f4a50467cb692119567631b451e2b63a99be18c05138b85",
        "fd534d42ec61682d8a641b88f449a6c67702ffa0000102030405060708090a0b0000000050000000000001007b"
        "000000000000006d3fea8c621ef15343db6b813aae7e07a33708f547f8ebe1fe38eb360859bc73a585f9d4d0a5"
        "91c468dd23cceca4f9bdfcae26c330b2004c167748e9967128dbda4fb70d1b098c596b793b1430774614",
        "fd534d42f472ca23951780579365be440c80fb9b000102030405060708090a000000000050000000000001007b"
        "000000000000008d935c245e45b593b7fd1cbe14cad2d44cf59209b34ebc3232ef2369c9f9e27604466b5ca043"
        "e6e6d8a5cd2b60c44758e4565b6bfe0aa17744ed163dcea8a6176c764814cd597ecf0527eb12f8546984",
        "fd534d42c615f929f70a898f0fdfac77cc4c17aa000102030405060708090a0b0000000050000000000001007b"
        "00000000000000b9519b59c1e0c41c85489d80bde4766293c79527e46e496b207eff9e01741ead21318cdf8be4"
        "34bf5c8d55c6a4aa0617de6852be6ee395ed07ae102224decbd1b07d843997946026541de025a3c240a7"};
    for (unsigned cipher : {1, 2, 3, 4}) {
      const auto &cipher_key = cipher >= 3 ? full_key : key;
      auto encrypted = encrypt(cipher_key, cipher, 123, key.substr(0, cipher % 2 ? 11 : 12), packet);
      ok(encrypted == decode_bytes(vectors[cipher - 1]));
      ok(decrypt(cipher_key, cipher, 123, encrypted) == packet);
      for (size_t i = 0; i < encrypted.size(); ++i) {
        auto bad = encrypted;
        bad[i] ^= 1;
        rejected([&] { decrypt(cipher_key, cipher, 123, bad); });
      }
      rejected([&] { decrypt(cipher_key, cipher, 124, encrypted); });
      rejected([&] { decrypt(bytes(cipher_key.size(), '\0'), cipher, 123, encrypted); });
      rejected([&] { decrypt(cipher >= 3 ? key : full_key, cipher, 123, encrypted); });
      rejected([&] { decrypt(cipher_key, 5, 123, encrypted); });
    }
    auto negotiate = [](std::initializer_list<unsigned> dialects) {
      bytes p(100 + dialects.size() * 2, '\0');
      put(p, 64, 36, 2);
      put(p, 66, dialects.size(), 2);
      put(p, 68, 3, 2);
      put(p, 72, 0x40, 4);
      size_t off = 100;
      for (auto d : dialects) {
        put(p, off, d, 2);
        off += 2;
      }
      return p;
    };
    bytes guid(16, 'g');
    negotiation n;
    for (unsigned d : {0x210, 0x300, 0x302}) {
      auto p = negotiate({0x202, d});
      auto response = n.accept(p, guid);
      ok(n.dialect == d && get(response, 4, 2) == d);
      if (d >= 0x300) {
        ok(n.cipher == 1 && get(n.validate(n.client_info, guid), 22, 2) == d);
        for (size_t i = 0; i < n.client_info.size(); ++i) {
          auto changed = n.client_info;
          changed[i] ^= 1;
          rejected([&] { n.validate(changed, guid); });
        }
      }
    }
    rejected([&] { n.accept(negotiate({0x202}), guid); });
    rejected(
        [&] { n.accept(negotiate({0x311, 0x302}), guid); }); // No silent fallback on bad contexts.
    auto p = negotiate({0x210, 0x300, 0x302, 0x311});
    p.resize(112, '\0');
    put(p, 92, 112, 4);
    put(p, 96, 3, 2);
    auto add = [&](unsigned type, bytes body) {
      p.resize((p.size() + 7) / 8 * 8, '\0');
      bytes h(8, '\0');
      put(h, 0, type, 2);
      put(h, 2, body.size(), 2);
      p += h + body;
    };
    add(1, decode_bytes("010000000100"));
    add(2, decode_bytes("020001000200"));
    add(8, decode_bytes("01000100"));
    auto response = n.accept(p, guid);
    ok(n.dialect == 0x311 && n.cipher == 2 && get(response, 6, 2) == 3);
    {
      auto unknown = p;
      put(unknown, 154, 0xffff, 2);
      auto accepted = n.accept(unknown, guid);
      ok(n.signing == 1 && get(accepted, accepted.size() - 2, 2) == 1);
      auto absent = p.substr(0, 144);
      put(absent, 96, 2, 2);
      accepted = n.accept(absent, guid);
      ok(n.signing == 1 && get(accepted, 6, 2) == 2);
    }
    for (unsigned signing : {0, 1, 2}) {
      auto offer = p;
      put(offer, 154, signing, 2);
      auto accepted = n.accept(offer, guid);
      ok(n.signing == signing && get(accepted, accepted.size() - 2, 2) == signing);
    }
    for (unsigned cipher : {3, 4}) {
      auto offer = p;
      put(offer, 138, cipher, 2);
      put(offer, 140, cipher, 2);
      n.accept(offer, guid);
      ok(n.dialect == 0x311 && n.cipher == cipher);
    }
    rejected([&] { n.validate(n.client_info, guid); });
    for (size_t i = 0; i < p.size(); ++i)
      rejected([&] { n.accept(std::string_view(p).substr(0, i), guid); });
    for (auto offset : {92, 96, 112, 114, 116, 120, 124, 128, 130}) {
      auto bad = p;
      bad[offset] ^= 0x80;
      rejected([&] { n.accept(bad, guid); });
    }
    std::cout << json{{"milestone", "M6"}, {"checks", checks}, {"status", "passed"}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "M6 after " << checks << " checks: " << e.what() << '\n';
    return 1;
  }
}
