# Security, platforms and integrations

[简体中文](security.zh-CN.md) · [Documentation](README.md)

Status: proposed requirements. These are implementation and release gates, not existing protections.

## 1. Trust boundaries and defaults

Protect against unauthenticated network peers, authenticated users accessing other spaces, malformed protocol input, compromised plugins and accidental host configuration changes. The host administrator and kernel remain trusted: tauCloud cannot protect files from an administrator who controls the machine or its disks.

Start with loopback-only management and all file protocols disabled. A local bootstrap command creates the first administrator through a one-use, expiring mechanism; never ship default credentials. Enabling a network listener requires an explicit binding and access policy. Use TLS for remote management, WebDAV and the normal FTP profile. SMB uses its own protocol security rather than an invented TLS wrapper.

Use short-lived, revocable management sessions, secure/HttpOnly/SameSite cookies for browser sessions, CSRF protection, restricted CORS and explicit trusted-proxy configuration. CLI/API tokens have scopes and revocation. Add login throttling, request limits and an audit trail. External access, MFA, OIDC and account recovery need separate designs; the initial product does not auto-open router ports or create a public relay.

Changing a grant or disabling a user must invalidate authorization caches and trigger defined session/handle revocation across processes. Push revocations with acknowledgements; bounded lease expiry is the fallback when a worker is unreachable, as specified in the architecture. Test already-open handles and in-flight writes, not only new logins. Stop further access as soon as the protocol permits and report the revocation boundary; do not promise to retract bytes already sent or written.

## 2. Credentials across protocols

| Use | Proposed storage/verification |
| --- | --- |
| Web/API, WebDAV, FTP/FTPS passwords | Salted Argon2id verifier through a maintained library, calibrated parameters and rehash policy |
| SMB local accounts | Separate protocol credential enrollment/provider; protected password-equivalent material where NTLMv2 requires it |
| NFS AUTH_SYS | Explicit export-level UID/GID mapping, root squashing and trusted-client policy |
| Kerberos later | GSSAPI/SSPI provider integration and protected service credentials |

An application password verifier cannot be transformed into every protocol's required credential. SMB enrollment may use a password transiently to derive the necessary material; never retain plaintext for convenience. Store SMB secrets separately with a key outside the metadata database, backed by host protection where available. Document that compromise of password-equivalent material can enable authentication even without the plaintext password.

Keep protocol credential revocation, password rotation and user disablement coherent. Never silently reuse a management bearer token as a file-protocol password. NFS AUTH_SYS has a different trust model and must not be presented as password-authenticated user isolation.

Backups must distinguish public configuration, password verifiers and decryptable secrets. Define key backup/restore or re-enrollment procedures before advertising portable recovery. Redact passwords, tokens, keys and sensitive paths from logs and error responses.

## 3. Filesystem security and consistency

Use handle-relative traversal with platform-specific checks for symlinks, junctions, reparse points and mount changes. Initial policy rejects user-created links and special files inside managed namespaces unless an explicit safe feature is implemented. Importing an existing root scans and reports unsupported objects; it must not silently follow them.

Canonicalization alone does not prevent a check/use race. Test concurrent rename/link swaps and root replacement. Validate Unicode decoding, case collisions, reserved Windows names and alternate data stream syntax. Do not silently rename user files to fit a different platform; return a precise compatibility error.

Native file operations run with deliberate privileges. A restricted service account accesses registered roots; a narrow helper performs approved elevated operations. Keep authentication, application authorization and OS enforcement distinct. Full per-user impersonation is a later capability that requires platform-specific testing.

Host processes writing directly into managed roots bypass tauCloud permissions, quotas and locks. Detect changes where practical and reconcile indexes/accounting, but do not promise universal cross-process locking or backup consistency. Snapshot-based consistency requires a supported native snapshot adapter; otherwise backups need an explicit consistency level.

## 4. Windows and Linux capability matrix

Both hosts are first-class backend targets. Initial test candidates are Ubuntu 24.04 LTS x86-64 with ext4 and Windows 11 x86-64 with NTFS; M0 pins an actively supported Windows build and exact compiler/SDK versions. Broader distributions, Windows Server, other filesystems and ARM64 are added only with evidence.

| Capability | Linux plan | Windows plan | Contract |
| --- | --- | --- | --- |
| Service lifecycle | systemd adapter; foreground mode for development | Service Control Manager adapter; console mode for development | Clean start/stop and recoverable upgrade |
| Native protocol servers | PACE and filesystem adapters | PACE and filesystem adapters | Same advertised protocol semantics, tested separately |
| Files and paths | Handle-relative POSIX operations | Win32/NT handles and reparse-point checks | No assumption of identical path/ACL behavior |
| CPU/memory/network | procfs/sysfs and OS counters | Windows APIs and performance counters | Units, sampling interval and freshness included |
| Disk inventory/health | sysfs, block-device APIs; optional smartctl adapter | Storage APIs/IOCTLs; optional smartctl adapter | Distinguish permission, hardware and transport limits |
| Hard quotas | Filesystem-specific quota adapter | Filesystem-specific quota adapter | Advertise only verified modes |
| Disk/RAID management | Linux MD and validated volume/filesystem adapters | Storage Spaces and validated volume/filesystem adapters | M8b; native capabilities and explicit operation plans |
| Snapshots | Future filesystem adapters | Future VSS adapters | Separate follow-on feature |
| Elevated operations | Restricted helper and narrowly scoped permissions | Restricted Windows service and ACL-protected IPC | No arbitrary shell or user-supplied command execution |
| Docker transport | Unix-domain socket or approved TLS endpoint | Named pipe or approved TLS endpoint | Requires a running, compatible Engine |

Standard protocol ports may conflict with existing services, especially native SMB on Windows. M0 must prove the Windows SMB listener deployment story on a disposable host. Do not promise transparent coexistence on TCP 445; an alternative port can require specific clients, and a separate address may still conflict with a wildcard listener. Report a deployment prerequisite when the host service must be reconfigured by its administrator.

## 5. Monitoring and host management

Start with read-only inventory: CPU utilization, memory, network throughput, uptime, filesystem capacity, disk identity, temperature/health where available and service status. Distinguish physical disks, partitions, volumes, mounts and logical spaces. Prefer stable disk IDs; device names can change across boots.

Each sample includes timestamp, units, source, collection error and freshness. USB bridges, RAID controllers, virtual disks and insufficient privileges can hide SMART/NVMe data. Report `unavailable`, `permission_denied` or `stale`, not zero temperature or a false healthy state. Disk health indicators are observations, not guarantees against failure.

Collectors run with timeouts, bounded concurrency, configurable retention and backoff. Health rules include capacity thresholds, repeated collector failures, unhealthy disks and protocol failures. Deduplicate alerts; notification connectors are opt-in plugins. Audit administrative mutations separately from high-volume metrics and sampled access logs.

Disk/RAID administration is a planned M8b capability: topology, import/create, replacement/rebuild, check and supported growth, with explicit plans for formatting, partition and mount changes. Operations require native-provider validation, stable device IDs, administrator confirmation and recovery records. Protect system/in-use disks and refuse unknown safety conditions. See [operations](operations.md). Plugins cannot obtain these actions merely by declaring a generic monitoring permission.

## 6. Privileged helper

Define typed, allowlisted requests over authenticated local IPC: Unix-domain sockets with peer validation on Linux, ACL-protected named pipes on Windows. Validate paths against registered resources and recheck permissions in the helper. Never accept arbitrary executable names, shell strings or raw filesystem control commands.

Return structured errors and audit actor, operation, target and result. Use timeouts and rate limits. Keep network-facing parsing in unprivileged API/protocol workers. The helper independently verifies caller identity, scoped authorization and the approved plan; process separation alone is not a security boundary. Where a platform requires the listener itself to run elevated, document and minimize that exception rather than disguising it as least privilege.

## 7. Plugin system

Use separate worker processes and a versioned, bounded message protocol. A manifest declares ID, version, compatible host API range, executable/package digest, entry point, configuration schema and requested capabilities. Initial capabilities can include metrics publishing, scheduled work, scoped file-service calls and an approved external integration. Default to no permissions.

The supervisor handles install, explicit enable/disable, start/stop, health, crash backoff, upgrade, rollback and uninstall. Uninstall preserves user data unless separately requested. Permission increases require an explicit approval step in the product. Validate package paths and provenance; a signature authenticates an author but does not prove safe behavior.

Process separation provides fault isolation, not an automatic security sandbox. An untrusted-plugin release requires OS restrictions on filesystem access, network access, child processes, credentials and resource usage. If these restrictions are not implemented on a host, mark plugins as trusted-code-only and disable untrusted installation. Avoid public marketplace and hot-loading promises in the first plugin milestone.

First-party protocol modules remain build-time components, deployed as separate family worker processes. Do not allow a plugin to bypass the file-service policy by requesting raw access to all managed storage.

## 8. Docker integration

Implement a first-party integration against the versioned Docker Engine HTTP API, negotiating a supported API range. Start with engine information and container/image/volume/network inventory, then stats/logs and explicit lifecycle actions. Define create/recreate/delete behavior separately; Compose import, terminals and arbitrary exec are later features. [Docker Engine API](https://docs.docker.com/reference/api/engine/)

Docker access can grant broad host control. Keep the socket/pipe or client credentials inside a dedicated integration boundary and restrict mutations to authorized administrators. Do not expose a general HTTP proxy to the daemon. Prefer local sockets/pipes or mutually authenticated TLS; never automatically expose an unauthenticated TCP endpoint. [Docker daemon access](https://docs.docker.com/engine/security/protect-access/)

PACE TCP/HTTP support does not automatically provide Unix-domain sockets, Windows named pipes, Docker hijacked streams or asynchronous streaming clients. M0/M8 must select and test platform transport adapters; prioritize inventory and lifecycle API calls before interactive streams.

On Windows, distinguish Windows-container engines from Linux-container engines running in a VM/WSL2 environment. Paths, bind mounts, resource metrics and filesystem access belong to the actual engine host. Do not assume a Windows path is a valid path inside a Linux engine. Missing engines disable the integration gracefully; tauCloud does not install or reconfigure Docker automatically.

## 9. Recovery and release evidence

Online component upgrades are an explicit M8c capability with signed artifacts, side-by-side staging, affected-worker draining, health checks and guarded rollback. See [operations](operations.md) for compatibility and recovery gates. Ship configuration validation, per-service schema migration backups, metadata restore, preserved user data on uninstall and documented upgrade/rollback limits. Restoring metadata does not restore file payloads. Test restart during uploads, grant updates, migrations and protocol state changes, including incompatible schema downgrade rejection.

Before an externally reachable release, require a threat-model review, parser fuzzing, privilege-boundary tests, credential/secret handling review, real-client interoperability and crash-recovery evidence. Dependency versions and licenses must be recorded. This is part of delivering a file server with native protocol implementations, not a claim that a checklist eliminates all defects.
