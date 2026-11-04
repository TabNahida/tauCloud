# SMB Kerberos and SPNEGO

The Linux SMB backend accepts Kerberos and SPNEGO with a `cifs/host@REALM` service keytab. This extends the existing NTLMv2/MIC backend: passwords are not needed for Kerberos login, and NTLM enrollment does not create a Kerberos principal mapping. Windows GSS acceptor support, SMB reauthentication, durable sessions and the full compatibility gate remain unfinished.

## Configuration

Linux builds require MIT `libkrb5-dev`; deployment needs its GSSAPI runtime. Set both fields in the existing state `config.json`:

```json
{
  "smb_gss_service": "cifs/files.example.org@EXAMPLE.ORG",
  "smb_gss_keytab": "/secure/taucloud/cifs.keytab"
}
```

The exact service principal must exist in the KDC and keytab. Keep the keytab outside exported storage, restricted to the service account. Use the normal Kerberos configuration or `KRB5_CONFIG`. Incomplete configuration, a relative keytab path or a non-CIFS service principal fails validation. Enabling GSS on an unsupported host fails explicitly. An unreadable keytab fails SMB startup. Authentication does not change the existing loopback listener binding.

An administrator provisions an explicit mapping through the management API's `smb-principals` resource:

```json
{
  "id": "alice-kerberos",
  "principal": "alice@EXAMPLE.ORG",
  "username": "alice",
  "enabled": true
}
```

Updates include `update:true` and all fields. Listing requires administrator authority. Names match the verified Kerberos principal exactly, including realm; duplicate principal bindings are rejected. There is no local-name stripping, implicit domain trust or PAC group import. The existing enabled service account, current groups, share permissions and file DACLs determine access. Creating a mapping grants no space/share permissions by itself.

Updating or disabling a mapping invalidates its existing SMB authority tokens, including sessions under the previous principal when the record is rebound. Each file request obtains current identity authority. A revoked session loses its file handles/locks through the existing SMB cleanup path; re-enabling the mapping requires fresh authentication. Account disable and ordinary policy revocation continue to apply. Mapping records and their session provenance use the existing identity database schema.

## Authentication and keys

The server advertises Kerberos only when configured. MIT handles the real Kerberos/SPNEGO tokens and validates the service ticket; only a completed Kerberos mechanism with mutual authentication, integrity and a nonanonymous principal is accepted. SMB uses its own message protection, so GSS confidentiality is not required for this profile. NFS RPCSEC_GSS retains its separate confidentiality requirement.

GSS contexts and session keys remain inside the SMB worker. Identity receives the verified principal through the SMB-only authenticated IPC operation. The server obtains the GSS session key, uses its first 16 bytes (zero-padding a shorter key) and derives the existing SMB3 signing/encryption keys with the negotiated preauthentication transcript. SMB2 HMAC-SHA256, SMB3 AES-CMAC, AES-CCM and AES-GCM retain their existing checks. AES-256 ciphers remain unadvertised and unimplemented.

Pending GSS exchanges have a ten-second deadline and live within the existing bounded connection set. Each new context reloads the keytab, supporting atomic key rotation. Established SMB sessions retain their already-derived keys. Authority expires at the shorter of the accepted context's remaining lifetime and one hour. Service restart discards protocol contexts; subsequent access requires fresh authentication. Failed Kerberos authentication never switches that exchange to NTLM or guest access.

## Acceptance

`tests/smb_gss_integration.py` uses a disposable real MIT KDC, unmodified smbprotocol/pyspnego and optional unmodified Samba `smbclient`. It covers raw Kerberos and SPNEGO across SMB2.1/3.0/3.0.2/3.1.1, signed/encrypted data and metadata operations, administrator-only mappings, unmapped/wrong-service/tampered tickets, AP-REP and SMB2 HMAC verification, authenticator replay, live mapping revocation, key rotation and expiry. It also verifies Kerberos access with NTLM credentials disabled and preserves the existing NTLM/MIC regression.

The Linux GCC/Clang Actions jobs run these checks. The targeted GCC job additionally uses `--native` to mount the real Linux kernel CIFS client with Kerberos: signed SMB2.1 and encrypted SMB3.0/3.0.2/3.1.1. This native gate is pending its first remote execution and is not inferred from userspace clients. The fixture uses a host-specific temporary request-key rule, private Kerberos configuration/cache and known temporary mount points, removing them on exit. Keytabs and caches are not uploaded. Windows runs existing NTLM/shared-file tests and checks explicit rejection of unavailable GSS configuration.

References: [MS-SMB2 session keys](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c), [MIT GSSAPI](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html), [MIT SPNEGO acceptor](https://github.com/krb5/krb5/blob/master/src/lib/gssapi/spnego/spnego_mech.c), [cifs-utils upcall documentation](https://github.com/piastry/cifs-utils/blob/master/cifs.upcall.rst.in).
