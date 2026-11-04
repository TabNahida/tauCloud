# NFS RPCSEC_GSS / Kerberos

The Linux backend now implements RPCSEC_GSS version 1 using the system MIT Kerberos GSSAPI. It supports authenticated NFSv3 and NFSv4.1 with `krb5` (header authentication), `krb5i` (integrity), and `krb5p` (privacy). This is an implementation increment toward Full SMB/NFS, not completion of that gate. Windows acceptor support and broader native-client security negotiation coverage remain unfinished. Linux SMB Kerberos is documented separately in [SMB Kerberos](smb-kerberos.md).

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

Names are exact GSS-verified principal names, including realm. There is no implicit local-name/realm stripping, PAC group trust, AUTH_SYS file-access fallback or password fallback. Every mapping must select an existing nonzero UID mapping and a primary group of that user. Supplementary authority comes from current tauCloud memberships that are present in the export's GID map. The `anonymous` field remains required by the export schema and governs AUTH_NONE security discovery, but does not grant file access or map an unmapped Kerberos principal. File UID/GID ownership projections use these server-side maps.

`security` is an explicit nonempty list of `krb5`, `krb5i`, and/or `krb5p`; it defaults to `krb5p`. Every file authorization enforces the requested service and current mapping/membership/share policy. AUTH_SYS cannot access a GSS-only export. Existing AUTH_SYS exports continue to use `trust: "loopback-auth-sys"`. The listener remains restricted to the documented loopback addresses; changing authentication does not publish a network listener.

## Protocol and lifecycle

- INIT/CONTINUE_INIT use real GSS acceptor tokens and an authenticated sequence-window reply. Only the Kerberos mechanism and mutually authenticated, integrity/confidentiality-capable contexts are accepted.
- DATA verifies the MIC over the RPC header through the credential before advancing a 64-entry sequence window. Duplicate/old requests are silently discarded; valid out-of-order requests are accepted. Integrity/privacy bodies carry the same sequence number and default QOP. Privacy requires an actually encrypted GSS wrap.
- Accepted RPC replies, including argument/procedure errors, authenticate the request sequence. Successful results use the requested integrity/privacy envelope. A failed reply signature never falls back to AUTH_NONE.
- V3 retries may use the same XID with a fresh GSS sequence and obtain the durable result without reexecuting a mutation. Current export authority is rechecked for these cached results. V4 slot replay retains its existing principal and export-authority checks.
- MOUNT replies advertise Kerberos pseudoflavors. SECINFO/SECINFO_NO_NAME describe the Kerberos OID, QOP and export services even when the current AUTH_SYS or verified Kerberos service is not accepted for file access. PUTFH/SAVEFH/RESTOREFH and LOOKUPP place WRONGSEC according to the following operation; successful SECINFO consumes the current handle. Discovery grants permit only handle validation and security traversal, retain current identity/share/traversal checks, and cannot authorize ordinary metadata, data reads or mutations. Cached security replies are reauthorized after policy changes. AUTH_NONE can establish a discovery session and query security using the configured anonymous service identity only when that identity has space/share/traversal access. It is distinct from AUTH_SYS root squash, cannot read file metadata/data or mutate files, is never advertised as a file-access flavor, and cannot replay an AUTH_SYS cached response. NFSv3 file operations continue to reject AUTH_NONE. Broader native-client negotiation remains open.
- Authenticated DESTROY invalidates a context. Contexts survive a TCP reconnect, but never a service restart. Capacity is 128 contexts, a pending context expires after 60 seconds, and an established context expires at the shorter of its GSS lifetime or one hour. Context handles are random 32-byte values and are never persisted.
- Each new context acquires credentials from the configured keytab. Atomic keytab replacement supports rotation without killing established contexts. Retain old key versions during a production rollover if old service tickets must continue to establish new contexts. An unreadable/replaced keytab cannot cause authentication downgrade.

## Machine credential state protection

`EXCHANGE_ID` now accepts `SP4_MACH_CRED` over Kerberos integrity or privacy.
The authenticated principal and Kerberos mechanism identify the machine; a
local UID mapping is not sufficient. The returned `spo_must_enforce` bitmap is
enforced for client/session maintenance and in-session operations, including
before `CREATE_SESSION` replay. When it includes `BIND_CONN_TO_SESSION`, an
unbound connection cannot attach itself with `SEQUENCE`. An authenticated
explicit bind admits the transport, on which ordinary user credentials may
subsequently operate subject to the negotiated bitmap and export policy.

The confirmed protection method and both operation lists are immutable, even
under an explicit `EXCHANGE_ID` update. Confirmed-owner requests cannot replace
the machine principal or downgrade its authentication. Protected session replay
distinguishes integrity/privacy from authentication-only requests; switching
between integrity and privacy preserves valid replay. `SP4_NONE` retains its
existing implicit connection binding.

The negotiated `spo_must_allow` result accepts requested `CLOSE`, `LOCKU`,
`OPEN_DOWNGRADE` and `FREE_STATEID` bits. These permit the machine to release
this client's user-owned state after a user mapping or credential is gone.
They do not grant file data/namespace access, cross-client authority, or the
ability to close an open with outstanding locks. `PUTFH` permits the exact
known handle for the agreed cleanup operation. All other file operations keep
their ordinary authorization checks. Write locks can still be unlocked after
an open has been downgraded to read-only. Protected clients advertise
`EXCHGID4_FLAG_BIND_PRINC_STATEID` with these negotiated cleanup exceptions.

Sixteen real-KDC groups exercise both integrity and privacy, hostile
principals/services, connection binding, immutable policy, replay, mapping
revocation and bounded cleanup. Shared session tests verify AUTH_SYS rejection and are scheduled on all
configured platforms. Local evidence is recorded in
[machine protection acceptance](evidence/pre-m8/nfs-machine-local.json);
[GCC remote acceptance](evidence/pre-m8/nfs-machine-2d-gcc.json) passes all 16 groups; Clang is pending. Windows GSS, delegation and
other remaining protocol gates are still unfinished. This increment follows
[RFC 8881 state protection](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.10.8.3)
and [EXCHANGE_ID](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.35.3).

## SSV state protection

Linux now accepts `SP4_SSV` over Kerberos integrity/privacy. The confirming
CREATE_SESSION (and its cached retry) uses the original machine credential;
subsequent protected maintenance uses the client's shared SSV credential.
The confirmed protection method, operation bitmaps, hash/cipher and SSV length
are immutable. EXCHANGE_ID negotiates SHA-1/224/256/384/512 and
AES-128/192/256-CBC, selects a compatible pair, prefers stronger hashes, returns
indexes into the offered OID arrays, and rejects invalid combinations. The
SSV length equals the hash output length. The history window is 1–16 versions,
never larger than requested. A request creates up to eight random RPC handles,
subject to the shared 128-handle capacity; zero initial handles and subsequent
additive allocation are supported. Each handle has a 64-entry forward RPC
sequence window. SSV handles are not usable before confirmation and the first
successful SET_SSV, and their context ends with the client ID or server restart.

SET_SSV verifies the old-key HMAC of the exact SEQUENCE arguments, XORs the
new contribution, derives four directional subkeys, and returns the new-key
HMAC of the SEQUENCE result. Incorrect digests/lengths leave the keys unchanged;
slot replay does not rotate again. RPC authentication/integrity/privacy use
RFC 8881 XDR tokens, constant-time HMAC comparison, random CBC IV/confounder,
zero-filled XDR padding and truncated derived subkeys. Old versions inside
the negotiated window remain usable; version zero, future and evicted versions
are rejected. SSV-protected SET_SSV authenticates the request under the old
key and the result under the new key. Destroying an individual RPC handle does
not destroy other handles or the SSV. Authenticated MAXSEQ overflow destroys
that handle for both Kerberos and SSV; a forged header cannot retire it.

SSV can bind transports, create/destroy sessions and release agreed user state.
It grants no user file/namespace access. The negotiated cleanup exceptions
also apply after the user's principal mapping has been revoked. SSV callbacks
use the same directional cryptography; all handles sharing an SSV use one
monotonic reverse RPC counter and bounded outstanding window, preventing
reply-verifier substitution between handles. Forechannel counters remain
independent per handle.

`tests/nfs_ssv_integration.py` uses real Kerberos for bootstrap and independent
Python HMAC/AES plus upstream generated XDR codecs for SSV. It covers all five
hashes, all three AES key sizes and RPC services, immutable negotiation,
key windows, exact replay, cross-client isolation, additive/retired handles,
CB_NULL/CB_SEQUENCE and revoked-user cleanup. `tests/m7_core.cpp` also runs
fixed independently generated vectors and bytewise tampering checks on every
platform. [Local evidence](evidence/pre-m8/nfs-ssv-local.json) records the exact
source hashes and results. GCC and Clang pass all 25 SSV wire groups, and GCC/Clang/MSVC core vectors pass
at `546919a` ([remote evidence](evidence/pre-m8/nfs-ssv-546-remote.json)).
Both Linux jobs pass; the Windows job retains an unrelated
M2 `lease_expired` failure; Windows GSS bootstrap remains unavailable. Native
client SSV/recovery and delegation-related conformance remain open, and this
increment does not complete Full SMB/NFS.

References: [SSV mechanism](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.10.9),
[multiple-handle security](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.10.10),
[negotiation](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.35.3),
[SET_SSV](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.47).

## Authenticated backchannel

NFSv4.1 CREATE_SESSION and BACKCHANNEL_CTL accept established NFSv4 RPCSEC_GSS context handles with the client's reverse handle and requested `krb5`, `krb5i` or `krb5p` service. CB_NULL, CB_SEQUENCE and CB_NOTIFY_LOCK use that shared Kerberos context in the reverse direction. The RPC counter is independent of the forechannel and shared by all reverse handles using one context, so reply verifiers cannot be substituted between equal-numbered requests on different handles. Outstanding callbacks cannot advance beyond the peer's 64-entry replay window. The existing one-slot NFS callback replay mechanism remains separate: uncertain completion closes the original transport, then resends identical NFS plaintext with a fresh authenticated RPC sequence.

BACKCHANNEL_CTL adds GSS tuples, retains prior live tuples, and validates the entire offer before changing the callback program or credentials. Unknown/expired handles return NOENT; invalid service/oversized RPC credentials return INVAL; more than sixteen live tuples returns RESOURCE. Repeated tuples do not consume capacity. The server verifies the exact reply sequence, header verifier, integrity MIC or encrypted wrap, complete result and transport before advancing the callback slot or renewing a lease. Crypto failures never trigger an unoffered AUTH_NONE fallback. Negotiated request/response limits account for the full credential, MIC, XDR padding and GSS wrap overhead using `gss_wrap_size_limit`.

Context expiration, authenticated DESTROY and service restart invalidate the associated reverse authority. SEQUENCE reports when all assigned contexts are within one lease of expiry, or expired/destroyed; the latter remains visible until a fresh context is assigned. Reconfiguration can restore callbacks without recreating the NFS session. CB_RECALL, delegations and Windows GSS remain unfinished. Machine and SSV state credentials are described above.

`tests/nfs_gss_backchannel.py` uses a disposable real MIT KDC and an independent reverse-RPC client. Eight local groups cover the three services and lock notifications, atomic invalid offers, additive handles, capacity, a 32-session shared-context replay window, exact packet limits, forged replies and exact retry, expiry/destroy/recovery. All pass with Clang ASan/UBSan/LSan. The ordinary nineteen-group callback regression, 98 core checks, forward GSS/pynfs and session negotiation are also exercised. [GCC/Clang remote callback acceptance at `70838b7`](evidence/pre-m8/nfs-gss-backchannel-708-remote.json) passes all eight groups; MSVC passes shared AUTH_SYS regression. See [local evidence](evidence/pre-m8/nfs-gss-backchannel-local.json).

Complete CB_SEQUENCE errors now pass the same authentication checks as successes.
DELAY retains the exact request and retries on the live connection after
backoff; initial session-installation BADSESSION races are also recoverable.
Established slot faults are reported as BACKCHANNEL_FAULT instead of closing
unrelated forechannel traffic. Tampered/verifier-invalid replies retain the
existing disconnect-before-retry behavior. Two real-KDC service variants cover
this distinction; see [callback recovery](nfs-operation-coverage.md).

Protocol references: [RFC 8881 callback security](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.10.8.2), [context pairs](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.36.3), [BACKCHANNEL_CTL](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.33.3), [SEQUENCE flags](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.46.3).

## Acceptance

`tests/nfs_gss_integration.py` creates a disposable, loopback-only MIT KDC, service/user keytabs and isolated credential caches. It exercises real mutual authentication, all three services, NFSv3/v4.1 operations, forged headers, modified bodies/ciphertext, sequence windows, revoked mappings/memberships, duplicate mutations, reconnect/DESTROY, key rotation, ticket expiry and service restart. All eight local groups pass, including cross-service SECINFO negotiation and 15 selected original pynfs cases (five per security service). `--pynfs build/pynfs/nfs4.1` uses the pinned upstream suite without editing it.

The Linux GCC and Clang ASan/UBSan Actions jobs run this same acceptance; MSVC continues the existing AUTH_SYS/shared-security regression. The targeted GCC job also runs `--native`: an isolated foreground `rpc.gssd` and the Linux kernel NFSv4.1 client mount and perform file operations for each service. The native gate passes at `b5442ad` for all three services; GCC and Clang sanitizer jobs pass and MSVC passes its existing AUTH_SYS regression ([fixed-source evidence](evidence/pre-m8/nfs-gss-b5442ad-remote.json)). Windows GSS is not inferred from that MSVC result. Temporary keytabs, KDC databases and credential caches are cleaned up and are not uploaded. The first Clang runs reached the upstream client and exposed hostbased principal qualification by the hosted runner DNS search suffix. The disposable realm now disables short-name qualification and maps localhost explicitly; a synthetic DNS suffix exercises this isolation locally. Those earlier remote failures are retained and are not counted as passes.

References: [RPCSEC_GSS wire protocol, RFC 2203](https://www.rfc-editor.org/rfc/rfc2203.html), [MIT GSSAPI acceptor credentials](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html), [MIT KDC configuration](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/kdc_conf.html), [MIT hostname qualification](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html), [NFSv4.1 security negotiation](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.6.3), [upstream rpc.gssd manual](https://man7.org/linux/man-pages/man8/rpc.gssd.8.html).
