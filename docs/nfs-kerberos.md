# NFS RPCSEC_GSS / Kerberos

The Linux backend now implements RPCSEC_GSS version 1 using the system MIT Kerberos GSSAPI. It supports authenticated NFSv3 and NFSv4.1 with `krb5` (header authentication), `krb5i` (integrity), and `krb5p` (privacy). This is an implementation increment toward Full SMB/NFS, not completion of that gate. Windows acceptor support, native-client security negotiation coverage and SMB Kerberos remain unfinished.

## Configuration

Linux builds require `libkrb5-dev`; deployed binaries require the system `libgssapi_krb5` runtime and its dependencies. Windows builds retain AUTH_SYS and explicitly reject enabling an unavailable GSS acceptor.

Add both fields to the existing state `config.json`:

```json
{
  "nfs_gss_service": "nfs/files.example.org@EXAMPLE.ORG",
  "nfs_gss_keytab": "/secure/taucloud/nfs.keytab"
}
```

The service must have the matching KDC-issued principal/keytab. Set the normal system Kerberos realm configuration, or supply `KRB5_CONFIG` in the supervisor environment. Restrict the keytab to the service account, keep it outside published storage roots, and provision it separately from metadata backups. Keys and tickets are never serialized in identity/file IPC or acceptance artifacts. An explicitly configured acceptor with unavailable keys fails startup.

Provision the existing users, groups, memberships, NFS share and space grants, then create/update an export:

```json
{
  "id": "nfs",
  "update": true,
  "trust": "rpcsec-gss",
  "anonymous": "guest",
  "uids": {"1000": "alice"},
  "gids": {"1000": "unix-users"},
  "principals": {
    "alice@EXAMPLE.ORG": {"uid": 1000, "gid": 1000}
  },
  "security": ["krb5p"],
  "enabled": true
}
```

Names are exact GSS-verified principal names, including realm. There is no implicit local-name/realm stripping, PAC group trust, AUTH_SYS fallback or password fallback. Every mapping must select an existing nonzero UID mapping and a primary group of that user. Supplementary authority comes from current tauCloud memberships that are present in the export's GID map. The `anonymous` field remains required by the export schema, but does not grant access to an unmapped Kerberos principal. File UID/GID ownership projections use these server-side maps.

`security` is an explicit nonempty list of `krb5`, `krb5i`, and/or `krb5p`; it defaults to `krb5p`. Every file authorization enforces the requested service and current mapping/membership/share policy. AUTH_SYS cannot access a GSS-only export. Existing AUTH_SYS exports continue to use `trust: "loopback-auth-sys"`. The listener remains restricted to the documented loopback addresses; changing authentication does not publish a network listener.

## Protocol and lifecycle

- INIT/CONTINUE_INIT use real GSS acceptor tokens and an authenticated sequence-window reply. Only the Kerberos mechanism and mutually authenticated, integrity/confidentiality-capable contexts are accepted.
- DATA verifies the MIC over the RPC header through the credential before advancing a 64-entry sequence window. Duplicate/old requests are silently discarded; valid out-of-order requests are accepted. Integrity/privacy bodies carry the same sequence number and default QOP. Privacy requires an actually encrypted GSS wrap.
- Accepted RPC replies, including argument/procedure errors, authenticate the request sequence. Successful results use the requested integrity/privacy envelope. A failed reply signature never falls back to AUTH_NONE.
- V3 retries may use the same XID with a fresh GSS sequence and obtain the durable result without reexecuting a mutation. Current export authority is rechecked for these cached results. V4 slot replay retains its existing principal and export-authority checks.
- MOUNT replies advertise Kerberos pseudoflavors. SECINFO/SECINFO_NO_NAME describe the Kerberos OID, QOP and export services even when the current AUTH_SYS or verified Kerberos service is not accepted for file access. PUTFH/SAVEFH/RESTOREFH and LOOKUPP place WRONGSEC according to the following operation; successful SECINFO consumes the current handle. Discovery grants permit only handle validation and security traversal, retain current identity/share/traversal checks, and cannot authorize ordinary metadata, data reads or mutations. Cached security replies are reauthorized after policy changes. AUTH_NONE negotiation and broader native-client negotiation remain open.
- Authenticated DESTROY invalidates a context. Contexts survive a TCP reconnect, but never a service restart. Capacity is 128 contexts, a pending context expires after 60 seconds, and an established context expires at the shorter of its GSS lifetime or one hour. Context handles are random 32-byte values and are never persisted.
- Each new context acquires credentials from the configured keytab. Atomic keytab replacement supports rotation without killing established contexts. Retain old key versions during a production rollover if old service tickets must continue to establish new contexts. An unreadable/replaced keytab cannot cause authentication downgrade.

## Acceptance

`tests/nfs_gss_integration.py` creates a disposable, loopback-only MIT KDC, service/user keytabs and isolated credential caches. It exercises real mutual authentication, all three services, NFSv3/v4.1 operations, forged headers, modified bodies/ciphertext, sequence windows, revoked mappings/memberships, duplicate mutations, reconnect/DESTROY, key rotation, ticket expiry and service restart. All eight local groups pass, including cross-service SECINFO negotiation and 15 selected original pynfs cases (five per security service). `--pynfs build/pynfs/nfs4.1` uses the pinned upstream suite without editing it.

The Linux GCC and Clang ASan/UBSan Actions jobs run this same acceptance; MSVC continues the existing AUTH_SYS/shared-security regression. The targeted GCC job also runs `--native`: an isolated foreground `rpc.gssd` and the Linux kernel NFSv4.1 client mount and perform file operations for each service. That new native gate is pending remote execution; it is not counted as passing from the userspace tests. Temporary keytabs, KDC databases and credential caches are cleaned up and are not uploaded. The first Clang runs reached the upstream client and exposed hostbased principal qualification by the hosted runner DNS search suffix. The disposable realm now disables short-name qualification and maps localhost explicitly; a synthetic DNS suffix exercises this isolation locally. Those earlier remote failures are retained and are not counted as passes.

References: [RPCSEC_GSS wire protocol, RFC 2203](https://www.rfc-editor.org/rfc/rfc2203.html), [MIT GSSAPI acceptor credentials](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html), [MIT KDC configuration](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/kdc_conf.html), [MIT hostname qualification](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html), [NFSv4.1 security negotiation](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.6.3), [upstream rpc.gssd manual](https://man7.org/linux/man-pages/man8/rpc.gssd.8.html).
