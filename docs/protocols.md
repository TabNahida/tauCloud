# Native protocol server plan

[简体中文](protocols.zh-CN.md) · [Documentation](README.md)

Status: the matrix below describes the production target. Current bounded previews are documented in [M3](m3.md), [M4](m4.md) and [M5](m5.md). The [M0 loopback SMB experiment](m0.md) is a disposable protocol slice, not a supported server.

## 1. Implementation policy

Build protocol framing, parsing, negotiation, session state and file-operation mapping primarily in C++20 over PACE. Reuse mature TLS, cryptography and authentication providers where practical. Reuse is not a requirement to launch a separate operating-system protocol daemon. Authentication libraries must prove nonblocking integration, licensing and Windows/Linux behavior; record which layers remain native.

Samba and established NFS/WebDAV servers supply independent behavior references and test peers. They are not mandatory serving backends. A future optional service-management adapter must be advertised separately from native protocol support.

Each protocol family runs in its own worker process; FTP and FTPS share one worker, while WebDAV is separate from the management API. All listeners call the common file-service contract over authenticated local IPC. A protocol crash must not terminate sibling protocol or management processes. Protocol restart may disconnect that protocol's clients; preserve or invalidate locks and sessions according to the recovery contract. Do not implement a second permission or quota system inside each protocol. Protocol-specific credentials and wire semantics still need explicit translation; one login mechanism cannot simply be reused for every protocol.

## 2. Scope matrix

| Protocol | Initial implementation milestone | Subsequent target | Initial exclusions |
| --- | --- | --- | --- |
| WebDAV | M3: HTTPS file access and tested Class 1 profile | Class 2 locking after conformance tests | CalDAV, CardDAV, versioning extensions |
| FTP/FTPS | M4: passive transfers and explicit TLS | Additional client-driven compatibility features | Anonymous access, FXP, active mode and implicit FTPS |
| SMB | M5: signed SMB 2.1; optional 2.0.2 compatibility | M6: 3.0, 3.0.2, 3.1.1 | SMB1, AD domain controller, RDMA, QUIC, clustering |
| NFS | M7a: v4.1 over TCP | M7b: v3 compatibility, including related services | v2, v4.0 initially, v4.2 initially, pNFS, RDMA |

Each advertised version must implement its mandatory behavior. A mount/read/write demo is a prototype, not compliance. Optional features are negotiated truthfully; unsupported required operations block release of that profile.

## 3. WebDAV

Implement the HTTP methods and property/collection behavior required for the chosen RFC 4918 compliance class, including `OPTIONS`, `GET`, `HEAD`, `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `PROPFIND` and `PROPPATCH`. Store dead properties persistently. Bound XML size/depth, disable external entities and control recursive traversal. Handle multistatus responses, conditional requests, overwrite rules and namespace escaping. Validate Class 1 before advertising it; Class 2 additionally requires tested `LOCK`/`UNLOCK` semantics. [RFC 4918](https://www.rfc-editor.org/info/rfc4918/)

Project gates: PACE streaming integration, large-file transfers with bounded memory, range/resume behavior, cancellation cleanup and credential isolation. A DAV lock must be checked by other tauCloud writers before cross-protocol writable access is enabled. Lock scope, expiry, token ownership and restart policy must be documented.

Test with Windows Explorer, macOS Finder and Linux DAV clients, recording OS/client versions and their authentication/TLS constraints. If a client is incompatible, publish the limitation; do not weaken all deployments to make one client pass.

## 4. FTP and FTPS

Use separate control and data state machines over PACE. Implement authenticated directory listing, binary transfer, upload/download, rename/delete, directory creation, restart offsets and passive negotiation (`PASV`/`EPSV`). Include machine-readable listings and feature discovery. Declare supported transfer types; reject unsupported types accurately. [RFC 959](https://www.rfc-editor.org/info/rfc959/), [RFC 3659](https://www.rfc-editor.org/info/rfc3659/)

Explicit FTPS adds `AUTH TLS`, `PBSZ` and protected data channels with `PROT P`. Require encryption of both credentials and file data in the normal profile. [RFC 4217](https://www.rfc-editor.org/info/rfc4217/)

Plain FTP is a separately enabled compatibility option with a visible configuration warning. Reserve a bounded passive port range; validate advertised addresses and data-peer association to prevent bounce/hijack behavior. Define NAT configuration, idle timeouts, aborted-transfer cleanup and safe resume semantics. Control and data TLS sessions need a tested binding policy.

Test with FileZilla, curl and an independent FTP client on both hosts, including simultaneous sessions, partial uploads, TLS failures and passive-port exhaustion.

## 5. SMB

### Dialects and rollout

| Dialect | Code | Planned policy |
| --- | --- | --- |
| 2.0.2 | `0x0202` | Explicit legacy compatibility profile after shared SMB2 implementation |
| 2.1 | `0x0210` | First signed SMB interoperability target, initially limited evaluation use |
| 3.0 | `0x0300` | Add required dialect behavior and tested encryption |
| 3.0.2 | `0x0302` | Validate dialect-specific behavior independently |
| 3.1.1 | `0x0311` | Modern default target after negotiation, integrity and crypto validation |

Dialect values follow [Microsoft MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8). This sequence is a project delivery choice. SMB1 is excluded. Never negotiate a dialect merely because the parser recognizes its number.

Build shared SMB2 framing/compound parsing, credit accounting, session setup, tree connect, create/open, read/write, directory queries, information operations, flush/close, locking, cancellation and error mapping. Implement the required signing/key derivation for each enabled dialect. Add SMB3 encryption and SMB 3.1.1 preauthentication integrity before those profiles are exposed. Use bounded parsing and validate all offsets, lengths, IDs and compound chains.

Use SPNEGO/authentication-provider boundaries. Plan local-account NTLMv2 interoperability and separate SMB credential enrollment; never assume an Argon2 password verifier can answer an NTLM challenge. Kerberos/domain integration is later work, not required for the local-account milestone. See [credential design](security.md).

Windows-style share modes, delete-on-close, case behavior, Unicode names, file attributes and security descriptors require explicit translation on Linux. A minimal authenticated `IPC$`/named-pipe/RPC surface for share enumeration may be required for client experience; scope and test it separately. Do not imply a full Windows server or directory service.

Optional leases/oplocks, durable handles, multichannel, change notifications and advanced copy operations need individual feature decisions and tests. Do not advertise optional caching/reconnect features before recovery and invalidation work. Assess mandatory behavior separately for every dialect; exclusions must not contradict the selected specification profile.

Test Windows Explorer and command-line access, Linux kernel CIFS mounts and `smbclient`, plus macOS SMB. Use applicable Samba torture cases and packet traces. Gates include signed traffic, refused tampering/downgrade, access revocation, concurrent opens, conflicting locks, rename/delete while open, reconnect, disk-full and restart recovery. Passing one client does not establish broad SMB support.

## 6. NFS

Current implementation: [M7 experimental subset](m7.md). Full M7a/M7b gates below remain open; the preview does not publish complete NFS compatibility.

Implement an ONC RPC/XDR layer over PACE TCP with bounded record assembly, checked arrays, request identity and authentication dispatch. NFSv4.1 is the primary target; NFSv3 is a distinct later compatibility track. NFSv4.1 does not require implementing v4.0 first. [RFC 8881](https://www.rfc-editor.org/rfc/rfc8881.html)

For v4.1, design stable file handles, export namespaces, COMPOUND operations, sessions/slots, replay handling, state IDs, open/lock ownership, leases, recovery grace and reclaim behavior. Persist the state required for server restart semantics. Initially decline optional delegations/layouts where permitted. Validate mandatory operations before marking the server compatible.

For v3, implement the required file operations, stable/unstable write and COMMIT semantics, reboot verifier changes and duplicate-request handling. Plan MOUNT/rpcbind discovery and NLM/NSM locking/recovery as part of the compatibility profile; an isolated port-2049 read/write demo is insufficient. Prefer TCP; UDP is outside the initial v3 profile. [RFC 1813](https://www.rfc-editor.org/info/rfc1813/)

NFS identities use export policy plus explicit UID/GID or principal mapping. AUTH_SYS trusts client-supplied identities and belongs only in an explicitly configured trusted-network profile with root squashing and export restrictions. RPCSEC_GSS/Kerberos is the later authenticated multi-user profile. Never describe AUTH_SYS as equivalent to a tauCloud password session.

The native user-space NFS server targets Linux and Windows; it does not depend on Windows Server's NFS role. Windows still needs a proven file-ID, permission and locking mapping. Client support is separate: Microsoft's native Windows NFS client lists v2/v3, so it cannot be assumed to test the initial v4.1 target. [Microsoft NFS overview](https://learn.microsoft.com/en-us/windows-server/storage/nfs/nfs-overview)

Use Linux clients for v4.1, and Linux/macOS plus eligible Windows clients for v3. Run applicable NFS conformance suites and filesystem stress cases, including retransmission, server reboot, file replacement, stale handles, lock reclaim, duplicate mutations and disk-full. A crash must not cause acknowledged stable writes to vanish within the documented storage durability contract.

## 7. Common publication gate

Before publishing a supported protocol profile, record host OS/filesystem, client version, negotiated protocol, authentication, encryption, limits and known deviations. Include malformed-input fuzzing, traversal/authorization tests, resource exhaustion, transfers larger than RAM, interrupted connections and mixed-client concurrency.

Keep test data disposable. Capture payload-free diagnostics by default; packet captures can contain credentials or file contents and require controlled handling. Performance results must include hardware, storage/cache conditions, encryption settings and workload, with no unmeasured parity claims across Windows and Linux.

Existing services may occupy SMB 445, NFS 2049 or FTP 21. Detect conflicts without disabling host services. A nonstandard port is not transparent to every client; report when the intended client requires a dedicated host address or a deliberate administrator configuration change.
