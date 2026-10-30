# ADR 0007 — Bounded FTP/FTPS profile and data-session ownership

[简体中文](0007-ftp-profile.zh-CN.md)

Status: implemented for the M4 backend preview; FileZilla's interoperability gate remains open.

## Context and decision

FTP splits commands and file bytes across connections. Matching only the source IP does not establish that a protected data connection belongs to a particular authenticated control connection. The locked PACE TLS API does not expose the session-resumption checks this profile needs.

Use an isolated `taucloud_ftp` worker and PACE TCP/coroutines. A small local OpenSSL memory-BIO adapter provides explicit TLS upgrade and the resumption check without changing pinned dependencies. Give each control connection its own SSL context/session-id context/cache/ticket keys, require peer-address equality and successful session reuse for protected data, and reject fresh or foreign sessions before opening a data-bearing file handle. TLS 1.2/1.3 remain OpenSSL implementations. Explicit TLS is the default; plaintext requires a stopped configuration change. No active mode, FXP, anonymous access or TLS downgrade.

Map the virtual share namespace to short identity grants and the existing file authority. Keep FTP outside mixed writable protocol combinations. Use staged, flushed uploads with atomic publication, authenticated EOF on FTPS, prefix-copy plus ETag validation for REST STOR, and cleanup-only signed grants after revocation. A process ownership lock plus authenticated recovery in each file worker reclaims only FTP handles and unpublished FTP stages. Committing jobs retain the existing journal semantics. Core durable jobs and sibling processes survive FTP recovery.

## Consequences

- Clients must resume TLS sessions on data connections. The automated Python client uses the standard FTP implementation with an explicit `SSLSession` argument; unmodified Python `FTP_TLS` does not supply it. Tested curl builds resume successfully.
- Incoming TLS truncation is a failed upload. Outgoing reciprocal shutdown after valid EOF is best effort: curl may have closed its TCP data socket already. A published file must not be misreported as a failed transfer for that reason.
- Plain FTP FIN does not authenticate an intended length. File transfers are binary only; TYPE A is useful for listings but cannot silently transform files.
- REST resumes a published file. Invisible interrupted FTP stages are discarded. Resume replaces the suffix and checks the original representation before commit.
- Unknown-length uploads conservatively reserve up to 1 GiB or remaining quota. The bounded local profile trades broad legacy compatibility and unrestricted slow transfers for explicit memory, connection and time budgets.
- FileZilla is not claimed compatible until its separate gate is run. See [evidence](../evidence/m4/README.md) and [profile limits](../m4.md).

References: [RFC 4217](https://www.rfc-editor.org/rfc/rfc4217), [RFC 3659](https://www.rfc-editor.org/rfc/rfc3659), [RFC 2428](https://www.rfc-editor.org/rfc/rfc2428).
