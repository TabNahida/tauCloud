#include <taucloud/gss.hpp>
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
gss_buffer_desc input(std::string_view s) { return {s.size(), const_cast<char *>(s.data())}; }
}
struct gss_context::impl {
  gss_cred_id_t credential = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t context = GSS_C_NO_CONTEXT;
  bool complete = false;
  ~impl() {
    OM_uint32 minor;
    if (context) gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
    if (credential) gss_release_cred(&minor, &credential);
  }
};
gss_context::gss_context(const std::string &service, const std::string &keytab)
    : impl_(std::make_unique<impl>()) {
  name target;
  auto text = input(service);
  OM_uint32 minor;
  require(gss_import_name(&minor, &text, GSS_KRB5_NT_PRINCIPAL_NAME, &target.value) == GSS_S_COMPLETE,
          "gss_credentials");
  gss_key_value_element_desc element{"keytab", keytab.c_str()};
  gss_key_value_set_desc store{1, &element};
  gss_OID_set_desc mechanisms{1, gss_mech_krb5};
  require(gss_acquire_cred_from(&minor, target.value, GSS_C_INDEFINITE, &mechanisms,
                              GSS_C_ACCEPT, &store, &impl_->credential, nullptr, nullptr) == GSS_S_COMPLETE,
          "gss_credentials");
}
gss_context::~gss_context() = default;
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
    require(mechanism && mechanism->length == gss_mech_krb5->length &&
                !std::memcmp(mechanism->elements, gss_mech_krb5->elements, mechanism->length) &&
                (flags & (GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG | GSS_C_MUTUAL_FLAG)) ==
                    (GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG | GSS_C_MUTUAL_FLAG) &&
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
gss_context::gss_context(const std::string &, const std::string &) { throw error("gss_unavailable"); }
gss_context::~gss_context() = default;
gss_context::result gss_context::accept(std::string_view) { throw error("gss_unavailable"); }
std::string gss_context::sign(std::string_view) { throw error("gss_unavailable"); }
bool gss_context::verify(std::string_view, std::string_view) { return false; }
std::string gss_context::wrap(std::string_view) { throw error("gss_unavailable"); }
std::string gss_context::unwrap(std::string_view) { throw error("gss_unavailable"); }
}
#endif
