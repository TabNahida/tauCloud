// Fore and back RPC sequence spaces are independent; all reverse handles
// sharing a context use one counter to prevent reply-verifier substitution.
struct gss_session {
  std::unique_ptr<gss_context> context;
  std::string principal;
  uint32_t program = 0, version = 0, highest = 0;
  uint64_t seen = 0;
  uint32_t callback_sequence = 0, mic_size = 0;
  std::chrono::steady_clock::time_point expires;
};
std::map<std::string, gss_session> gss_sessions;
