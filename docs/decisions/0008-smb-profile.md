# ADR 0008 — SMB 2.1 authority and credential boundary

The original no-blocking-queue restriction below is superseded by the Full SMB/NFS expansion: bounded asynchronous lock queues, cancellation and lifecycle cleanup are now implemented; see the current M5 guide and fixed-source evidence. Other original exclusions are historical scope, not permission to omit the full-compatibility work.

[简体中文](0008-smb-profile.zh-CN.md)

Status: implemented as a bounded backend preview; complete client-matrix acceptance remains open.

SMB brings long-lived opens, share modes, byte locks and password-equivalent NTLM material. Keep those authorities out of the network parser: an isolated PACE worker owns wire sessions, identity owns NTLMv2/MIC and the AES-GCM vault, and the existing file workers own access/share/lock/delete state. The worker receives only its short internal session and SMB signing key. Management Argon2id verification cannot be reused as an NT hash, so enrollment is separate and explicit.

Require signing and MIC, do not negotiate a weaker compatibility dialect, and decline caching/durable handles. Use OpenSSL primitives without weakening TLS provider settings. Protect the vault key with the Linux service-account boundary or Windows user DPAPI. Metadata restore intentionally drops SMB enrollment rather than moving password-equivalent material across hosts/accounts.

Persist delete intent by native object identity; discard volatile opens on protocol recovery. Validate every compound signature before executing its first operation. Renew authorization on each file operation. Fail unsupported ACL mutations rather than fabricate persistent Windows security. Implement only the authenticated `srvsvc` NDR32 share-enumeration surface needed for discovery, filtering every result through file authorization.

The price is a deliberately small compatibility profile: loopback/non-445 deployment, no encrypted SMB, no arbitrary desktop metadata preservation, no blocking lock queue, no moving directories with open descendants, and no general administrative RPC server. Independent client results, host checks and exclusions are published in the [M5 guide](../m5.md) and [evidence](../evidence/m5/README.md). This is not a claim of Samba or Windows-server equivalence.
