# SMB Kerberos and SPNEGO

The Linux SMB backend accepts Kerberos and SPNEGO with a `cifs/host@REALM` service keytab. This extends the existing NTLMv2/MIC backend: passwords are not needed for Kerberos login, and NTLM enrollment does not create a Kerberos principal mapping. Same-session NTLM and Kerberos reauthentication is implemented. Windows GSS acceptor support, durable sessions and the full compatibility gate remain unfinished.

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

The server advertises Kerberos only when configured. MIT handles the real Kerberos/SPNEGO tokens and validates the service ticket; only a completed Kerberos mechanism with a nonanonymous principal, positive lifetime and usable session key is accepted. SMB provides its own mandatory channel protection. Linux cifs.upcall legitimately requests neither GSS message protection nor mutual AP-REP, so SMB does not require those GSS flags. Clients that request mutual authentication still receive and verify AP-REP. NFS RPCSEC_GSS retains its separate mutual/integrity/confidentiality requirements; an independent negative test ensures an SMB-style one-leg context is rejected by NFS.

GSS contexts and session keys remain inside the SMB worker. Identity receives the verified principal through the SMB-only authenticated IPC operation. The server obtains the full GSS session key. SMB signing and AES-128 derivation use its first 16 bytes (zero-padding a shorter key); SMB 3.1.1 AES-256-CCM/GCM derives 32-byte cipher keys from the complete GSS key. The negotiated preauthentication transcript binds all SMB 3.1.1 derivation. SMB2 HMAC-SHA256 and SMB3 AES-CMAC retain their existing checks. Independent Kerberos/SPNEGO clients exercise both AES-256 ciphers with real 32-byte GSS keys and same-handle renewal; remote acceptance is pending.

Pending GSS exchanges have a ten-second deadline and live within the existing bounded connection set. Each new context reloads the keytab, supporting atomic key rotation. Established SMB sessions retain their already-derived keys. Authority expires at the shorter of the accepted context's remaining lifetime and one hour. Service restart discards protocol contexts; subsequent access requires fresh authentication. Failed Kerberos authentication never switches that exchange to NTLM or guest access.

## Acceptance

### Session renewal

An authenticated client can issue SESSION_SETUP for its existing SessionId with fresh NTLMv2, Kerberos or SPNEGO credentials. The exchange uses the established signing/encryption protection. A successful renewal retains its SessionId, tree connections, open handles, locks, signing/cipher keys and encryption nonce history. Identity atomically replaces the authority token and expiration after verifying both the original canonical account and authentication provenance. A Kerberos principal cannot replace another principal mapped to the same account, and switching between NTLM and Kerberos requires a new session.

Expired authority returns `STATUS_NETWORK_SESSION_EXPIRED` without discarding opens. The identity store retains expired SMB renewal candidates for at most one hour, within the existing 4096-session bound; they provide no data access. Administrative revocation deletes the candidate, so reenabling an account or mapping cannot revive its old session. Connection teardown/logout removes expired candidates too. Failed renewal releases all session opens and locks before returning its error, protected with the original keys. Transport loss still requires a new session; durable reconnection is a separate open gate.

`tests/smb_reauthentication.py` exercises repeated NTLM renewal on all supported SMB2/3 dialects, independent verification of original-key signatures, preservation of exclusive byte locks, expiry, wrong credentials, identity substitution and administrative revocation. The real KDC suite additionally exercises Kerberos/SPNEGO renewal, real ticket expiry, same-account principal substitution and mapping revocation. These tests are wired into GCC, Clang sanitizers and MSVC Actions (Kerberos on Linux only). At `456e2b4`, GCC and Clang pass renewal; MSVC prints all six functional passes but fails cleanup because the test retained an SQLite connection. Explicit connection closing corrects the harness, with Windows reacceptance pending.

The earlier unmodified Samba `smb2.session.reauth1` through `reauth6` diagnostic failed at the preceding BATCH-oplock assertion. With BATCH and cached delete-on-close implemented, reauth1/6 and reconnect1/2 pass locally ([BATCH evidence](evidence/pre-m8/smb-batch-local.json)). Reauth2–5 remain failed. The security-query correction lets reauth3–5 pass their initial descriptor query; all four now stop at anonymous SESSION_SETUP with LOGON_FAILURE ([current diagnostic](evidence/pre-m8/smb-security-query-local.json)). Anonymous reauthentication and broader session conformance remain open; the original failed full-suite evidence is retained.

### Kerberos integration

`tests/smb_gss_integration.py` uses a disposable real MIT KDC, unmodified smbprotocol/pyspnego and optional unmodified Samba `smbclient`. It covers raw Kerberos and SPNEGO across SMB2.1/3.0/3.0.2/3.1.1, signed/encrypted data and metadata operations, administrator-only mappings, unmapped/wrong-service/tampered tickets, AP-REP and SMB2 HMAC verification, authenticator replay, live mapping revocation, key rotation and expiry. It also verifies Kerberos access with NTLM credentials disabled and preserves the existing NTLM/MIC regression.

The Linux GCC/Clang Actions jobs run these checks. At `4ef5199`, both Linux jobs pass all eight userspace Kerberos/Samba groups, including Clang ASan/UBSan; Windows NTLM/shared-file regression also passes. The targeted GCC job additionally uses `--native` to mount the real Linux kernel CIFS client with Kerberos: signed SMB2.1 and encrypted SMB3.0/3.0.2/3.1.1. Its first run fails before SMB authentication with `Required key not available`: the fixture's host-specific request-key pattern contains two wildcards, but keyutils 1.6.x supports only one per field. The corrected rule uses the kernel v2 description prefix and one trailing wildcard; the next run (`456e2b4`) reaches SESSION_SETUP and exposes the incorrect GSS flag requirement described above. Its ten userspace groups and all three native NFS Kerberos profiles pass; native CIFS remains failed until reacceptance of the flag correction. The fixture now uses the actual credential UID, avoiding an initial UID-0 permission failure after cifs.upcall drops DAC override capabilities. Both failures remain recorded ([initial evidence](evidence/pre-m8/smb-gss-4ef5199-remote.json), [subsequent evidence](evidence/pre-m8/smb-gss-456e2b4-remote.json)). The fixture uses a host-specific temporary request-key rule, private Kerberos configuration/cache and known temporary mount points, removing them on exit. Keytabs and caches are not uploaded. Windows checks explicit rejection of unavailable GSS configuration.

References: [MS-SMB2 session keys](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c), [server reauthentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ecc02fb-0e60-4cba-afeb-f13100a6e65e), [GSS completion and failure processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654), [MIT GSSAPI](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html), [MIT SPNEGO acceptor](https://github.com/krb5/krb5/blob/master/src/lib/gssapi/spnego/spnego_mech.c), [cifs-utils ticket flags](https://github.com/piastry/cifs-utils/blob/master/cifs.upcall.c), [cifs-utils upcall documentation](https://github.com/piastry/cifs-utils/blob/master/cifs.upcall.rst.in).
