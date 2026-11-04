#include <taucloud/gss.hpp>
#include <openssl/crypto.h>
#ifdef __linux__
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <cstring>
namespace tc {
namespace {
struct buffer {
  gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
  ~buffer() { OM_uint32 minor; gss_release_buffer(&minor, &value); }
  std::string str() const { return value.length ? std::string(static_cast<char *>(value.value), value.length) : ""; }
};
struct name {
  gss_name_t value = GSS_C_NO_NAME;
  ~name() { OM_uint32 minor; if (value) gss_release_name(&minor, &value); }
};
struct buffers {
  gss_buffer_set_t value = GSS_C_NO_BUFFER_SET;
  ~buffers() {
    if (!value) return;
    for (size_t i = 0; i < value->count; ++i)
      OPENSSL_cleanse(value->elements[i].value, value->elements[i].length);
    OM_uint32 minor;
    gss_release_buffer_set(&minor, &value);
  }
};
gss_buffer_desc input(std::string_view s) { return {s.size(), const_cast<char *>(s.data())}; }
}
struct gss_context::impl {
  gss_cred_id_t credential = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t context = GSS_C_NO_CONTEXT;
  bool complete = false;
  OM_uint32 required_flags = GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG | GSS_C_MUTUAL_FLAG;
  ~impl() {
    OM_uint32 minor;
    if (context) gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
    if (credential) gss_release_cred(&minor, &credential);
  }
};
gss_context::gss_context(const std::string &service, const std::string &keytab, purpose use)
    : impl_(std::make_unique<impl>()) {
  bool spnego = use == purpose::smb;
  // SMB authenticates the peer with the ticket and protects the channel using
  // the resulting session key. Linux cifs.upcall legitimately requests neither
  // GSS message protection nor AP-REP; its GSS checksum flags are zero. Keep
  // RPCSEC_GSS's mutual/integrity/privacy requirements separate from SMB.
  if (spnego) impl_->required_flags = 0;
  name target;
  auto text = input(service);
  OM_uint32 minor;
  require(gss_import_name(&minor, &text, GSS_KRB5_NT_PRINCIPAL_NAME, &target.value) == GSS_S_COMPLETE,
          "gss_credentials");
  gss_key_value_element_desc element{"keytab", keytab.c_str()};
  gss_key_value_set_desc store{1, &element};
  // SPNEGO needs its own credential entry; a Kerberos-only union credential
  // does not let MIT's mechglue select the SPNEGO acceptor with this keytab.
  unsigned char spnego_oid[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
  gss_OID_desc selected[] = {*gss_mech_krb5, {sizeof(spnego_oid), spnego_oid}};
  gss_OID_set_desc mechanisms{spnego ? 2u : 1u, selected};
  require(gss_acquire_cred_from(&minor, target.value, GSS_C_INDEFINITE, &mechanisms,
                              GSS_C_ACCEPT, &store, &impl_->credential, nullptr, nullptr) == GSS_S_COMPLETE,
          "gss_credentials");
}
gss_context::~gss_context() = default;
std::string gss_context::session_key() {
  require(impl_->complete, "gss_context");
  buffers keys;
  OM_uint32 minor;
  require(gss_inquire_sec_context_by_oid(&minor, impl_->context, GSS_C_INQ_SSPI_SESSION_KEY,
                                       &keys.value) == GSS_S_COMPLETE && keys.value &&
              keys.value->count >= 1 && keys.value->elements[0].length > 0 &&
              keys.value->elements[0].length <= 64, "gss_context");
  auto &key = keys.value->elements[0];
  return std::string(static_cast<const char *>(key.value), key.length);
}
gss_context::result gss_context::accept(std::string_view token) {
  require(!impl_->complete, "gss_context");
  auto in = input(token);
  buffer out;
  name peer;
  gss_OID mechanism = GSS_C_NO_OID;
  OM_uint32 minor = 0, flags = 0, lifetime = 0;
  auto major = gss_accept_sec_context(&minor, &impl_->context, impl_->credential, &in,
      GSS_C_NO_CHANNEL_BINDINGS, &peer.value, &mechanism, &out.value, &flags, &lifetime, nullptr);
  result r{major, minor, lifetime, "", ""};
  if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED) return r;
  r.token = out.str();
  if (major == GSS_S_COMPLETE) {
    if ((flags & impl_->required_flags) != impl_->required_flags)
      log("gss", "context_flags_rejected", std::to_string(flags));
    require(mechanism && mechanism->length == gss_mech_krb5->length &&
                !std::memcmp(mechanism->elements, gss_mech_krb5->elements, mechanism->length) &&
                (flags & impl_->required_flags) == impl_->required_flags &&
                !(flags & GSS_C_ANON_FLAG) && lifetime > 0, "gss_context");
    buffer principal;
    require(gss_display_name(&minor, peer.value, &principal.value, nullptr) == GSS_S_COMPLETE,
            "gss_context");
    r.principal = principal.str();
    require(!r.principal.empty() && r.principal.size() <= 1024 && r.principal.find('\0') == std::string::npos,
            "gss_context");
    impl_->complete = true;
  }
  return r;
}
std::string gss_context::sign(std::string_view message) {
  require(impl_->complete, "gss_context");
  auto in = input(message);
  buffer out;
  OM_uint32 minor;
  require(gss_get_mic(&minor, impl_->context, GSS_C_QOP_DEFAULT, &in, &out.value) == GSS_S_COMPLETE,
          "gss_context");
  return out.str();
}
bool gss_context::verify(std::string_view message, std::string_view token) {
  if (!impl_->complete) return false;
  auto in = input(message), signature = input(token);
  OM_uint32 minor;
  gss_qop_t qop;
  return gss_verify_mic(&minor, impl_->context, &in, &signature, &qop) == GSS_S_COMPLETE &&
         qop == GSS_C_QOP_DEFAULT;
}
uint32_t gss_context::wrap_size_limit(uint32_t token_limit) {
  require(impl_->complete, "gss_context");
  OM_uint32 minor, maximum;
  require(gss_wrap_size_limit(&minor, impl_->context, 1, GSS_C_QOP_DEFAULT,
                             token_limit, &maximum) == GSS_S_COMPLETE, "gss_context");
  return maximum;
}
std::string gss_context::wrap(std::string_view message) {
  require(impl_->complete, "gss_context");
  auto in = input(message);
  buffer out;
  OM_uint32 minor;
  int encrypted = 0;
  require(gss_wrap(&minor, impl_->context, 1, GSS_C_QOP_DEFAULT, &in, &encrypted, &out.value) ==
              GSS_S_COMPLETE && encrypted, "gss_context");
  return out.str();
}
std::string gss_context::unwrap(std::string_view token) {
  require(impl_->complete, "gss_context");
  auto in = input(token);
  buffer out;
  OM_uint32 minor;
  int encrypted = 0;
  gss_qop_t qop;
  require(gss_unwrap(&minor, impl_->context, &in, &out.value, &encrypted, &qop) == GSS_S_COMPLETE &&
              encrypted && qop == GSS_C_QOP_DEFAULT, "gss_context");
  return out.str();
}
}
#else
namespace tc {
struct gss_context::impl {};
gss_context::gss_context(const std::string &, const std::string &, purpose) { throw error("gss_unavailable"); }
gss_context::~gss_context() = default;
std::string gss_context::session_key() { throw error("gss_unavailable"); }
gss_context::result gss_context::accept(std::string_view) { throw error("gss_unavailable"); }
std::string gss_context::sign(std::string_view) { throw error("gss_unavailable"); }
bool gss_context::verify(std::string_view, std::string_view) { return false; }
uint32_t gss_context::wrap_size_limit(uint32_t) { throw error("gss_unavailable"); }
std::string gss_context::wrap(std::string_view) { throw error("gss_unavailable"); }
std::string gss_context::unwrap(std::string_view) { throw error("gss_unavailable"); }
}
#endif
