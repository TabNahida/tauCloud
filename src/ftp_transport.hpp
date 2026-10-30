#pragma once
#include <taucloud/core.hpp>
#include <pace/tcp.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <array>

namespace tc::ftp_detail {
using tls_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
// A distinct context per control connection gives that connection its own ticket
// keys and session cache. A data connection MUST resume within this context.
inline tls_context make_tls(const config &c) {
  tls_context ctx(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
  require(bool(ctx), "tls_failed");
  require(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) == 1, "tls_failed");
  SSL_CTX_set_options(ctx.get(), SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_SERVER);
  SSL_CTX_sess_set_cache_size(ctx.get(), 64);
  SSL_CTX_set_timeout(ctx.get(), 3600);
  auto id = random_hex(16);
  require(SSL_CTX_set_session_id_context(ctx.get(),
                                         reinterpret_cast<const unsigned char *>(id.data()),
                                         static_cast<unsigned>(id.size())) == 1,
          "tls_failed");
  require(SSL_CTX_use_certificate_chain_file(ctx.get(),
                                             (c.state / "tls-cert.pem").string().c_str()) == 1 &&
              SSL_CTX_use_PrivateKey_file(ctx.get(), (c.state / "tls-key.pem").string().c_str(),
                                          SSL_FILETYPE_PEM) == 1 &&
              SSL_CTX_check_private_key(ctx.get()) == 1,
          "tls_failed");
  return ctx;
}
// OpenSSL memory BIOs over PACE. All SSL calls run on one IO loop. There may be
// one reader and one writer; output extraction and TCP writes are serialized.
// This local adapter exposes session binding without modifying pinned PACE.
struct wire {
  pace::tcp::stream tcp;
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
  bool writing = false;
  explicit wire(pace::tcp::stream socket) : tcp(std::move(socket)) { tcp.set_no_delay(); }
  void close() { tcp.close(); }
  pace::task<void> drain() {
    while (writing)
      co_await tcp.context().sleep_for(1ms);
    writing = true;
    struct unlock {
      bool &v;
      ~unlock() { v = false; }
    } guard{writing};
    std::array<char, 16384> bytes;
    while (BIO_ctrl_pending(SSL_get_wbio(ssl.get()))) {
      int n = BIO_read(SSL_get_wbio(ssl.get()), bytes.data(), static_cast<int>(bytes.size()));
      require(n > 0, "tls_failed");
      auto timer = tcp.context().call_after(5s, [this] { close(); });
      co_await tcp.write_all(std::string_view(bytes.data(), static_cast<size_t>(n)));
    }
  }
  pace::task<void> feed() {
    std::array<char, 16384> bytes;
    auto timer = tcp.context().call_after(5s, [this] { close(); });
    auto n = co_await tcp.read_some(bytes);
    require(n != 0, "tls_truncated"); // EOF is valid only after close_notify.
    require(BIO_write(SSL_get_rbio(ssl.get()), bytes.data(), static_cast<int>(n)) ==
                static_cast<int>(n),
            "tls_failed");
  }
  pace::task<void> upgrade(SSL_CTX *ctx, bool data) {
    ssl.reset(SSL_new(ctx));
    require(bool(ssl), "tls_failed");
    auto *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
    if (!in || !out) {
      BIO_free(in);
      BIO_free(out);
      throw error("tls_failed");
    }
    BIO_set_mem_eof_return(in, -1);
    SSL_set_bio(ssl.get(), in, out);
    SSL_set_accept_state(ssl.get());
    auto timer = tcp.context().call_after(5s, [this] { close(); });
    for (;;) {
      ERR_clear_error();
      int result = SSL_do_handshake(ssl.get());
      int code = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl.get(), result);
      co_await drain();
      if (result == 1)
        break;
      require(code == SSL_ERROR_WANT_READ, "tls_failed");
      co_await feed();
    }
    require(!data || SSL_session_reused(ssl.get()) == 1, "data_session_mismatch");
  }
  pace::task<size_t> read(std::span<char> bytes, std::chrono::milliseconds timeout = 5s) {
    auto timer = tcp.context().call_after(timeout, [this] { close(); });
    if (!ssl)
      co_return co_await tcp.read_some(bytes);
    for (;;) {
      size_t n = 0;
      ERR_clear_error();
      int result = SSL_read_ex(ssl.get(), bytes.data(), bytes.size(), &n);
      int code = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl.get(), result);
      co_await drain();
      if (result == 1)
        co_return n;
      if (code == SSL_ERROR_ZERO_RETURN)
        co_return 0;
      require(code == SSL_ERROR_WANT_READ, "tls_failed");
      // The outer timer bounds the complete read; control connections may idle.
      std::array<char, 16384> encrypted;
      auto count = co_await tcp.read_some(encrypted);
      require(count != 0, "tls_truncated");
      require(BIO_write(SSL_get_rbio(ssl.get()), encrypted.data(), static_cast<int>(count)) ==
                  static_cast<int>(count),
              "tls_failed");
    }
  }
  pace::task<void> write(std::string_view bytes) {
    auto timer = tcp.context().call_after(5s, [this] { close(); });
    if (!ssl) {
      co_await tcp.write_all(bytes);
      co_return;
    }
    while (!bytes.empty()) {
      auto piece = bytes.substr(0, 16384);
      size_t n = 0;
      ERR_clear_error();
      require(SSL_write_ex(ssl.get(), piece.data(), piece.size(), &n) == 1 && n > 0, "tls_failed");
      co_await drain();
      bytes.remove_prefix(n);
    }
  }
  pace::task<void> finish() {
    if (ssl) {
      auto timer = tcp.context().call_after(1s, [this] { close(); });
      ERR_clear_error();
      SSL_shutdown(ssl.get());
      co_await drain();
    }
    co_await tcp.close_gracefully(100ms);
  }
};
} // namespace tc::ftp_detail
