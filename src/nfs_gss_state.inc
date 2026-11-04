// Fore and back RPC sequence spaces are independent; all reverse handles
// sharing a context use one counter to prevent reply-verifier substitution.
struct gss_session {
  std::unique_ptr<gss_context> context;
  std::shared_ptr<ssv_context> ssv;
  uint64_t ssv_client = 0;
  std::shared_ptr<uint32_t> ssv_callback_sequence;
  std::string principal;
  uint32_t program = 0, version = 0, highest = 0;
  uint64_t seen = 0;
  uint32_t callback_sequence = 0, mic_size = 0;
  std::chrono::steady_clock::time_point expires;
  uint32_t callback_counter() const { return ssv_callback_sequence ? *ssv_callback_sequence : callback_sequence; }
  uint32_t next_callback() { return ssv_callback_sequence ? ++*ssv_callback_sequence : ++callback_sequence; }
  std::string sign(std::string_view data) const { return ssv ? ssv->sign(data) : context->sign(data); }
  bool verify(std::string_view data, std::string_view token) const {
    return ssv ? ssv->verify(data, token) : context->verify(data, token);
  }
  std::string wrap(std::string_view data) const { return ssv ? ssv->wrap(data) : context->wrap(data); }
  std::string unwrap(std::string_view data) const { return ssv ? ssv->unwrap(data) : context->unwrap(data); }
  uint32_t wrap_size_limit(uint32_t limit) const {
    return ssv ? ssv->wrap_size_limit(limit) : context->wrap_size_limit(limit);
  }
};
std::map<std::string, gss_session> gss_sessions;
