# M4 evidence / M4 验证记录

Recorded 2026-10-29. Scope: bounded loopback FTP/explicit FTPS backend preview, with M1–M3 regression. [English guide](../../m4.md) · [中文指南](../../m4.zh-CN.md) · [Decision](../../decisions/0007-ftp-profile.md).

## Hosts and reports

| Server host | Full regression | FTP/FTPS workflows |
| --- | --- | --- |
| Ubuntu 24.04.4, WSL2 kernel 6.18.40.1, GCC 13.3, ext4 | [GCC](linux-gcc.json) | [257 MiB roundtrip and fault cases](linux-gcc.ftp.json) |
| Same Linux host, Clang 18.1.3 with ASan/UBSan | [Clang](linux-clang.json) | [1 MiB roundtrip and fault cases](linux-clang.ftp.json) |
| Windows 11 25H2 build 26200.9457, VS 2026 toolset 14.51.36231, SDK 10.0.26100.0, NTFS | [MSVC](windows-msvc.json) | [Native 257 MiB roundtrip and fault cases](windows-msvc.ftp.json) |

Each final run includes 29 M1, 35 M2, 28 M3 and 18 M4 native checks, M1/M2 integration, M3 WebDAV/metadata recovery, and 11 M4 workflows. Linux also reruns litmus 0.18: 105 executed cases, zero failures. The M4 native tests specifically verify configuration rejection, protocol/path-bound cleanup, expired grants unable to publish, empty-directory enforcement, and FTP recovery preserving core handles and durable jobs.

The FTP workflows cover old-state role enrollment, disabled plaintext/anonymous/active mode/downgrade, two-user isolation, UTF-8, PASV/EPSV/ALL, MLSD/MLST selection, rename and empty RMD, binary transfer/type rejection, TLS 1.2/1.3, correct and incorrect data-session reuse, wrong peer address, untrusted certificates, handshake timeout, oversized commands, exhausted passive ports, in-band ABOR, truncated TLS upload cleanup, quota overflow, conditional resume races, share and credential revocation, worker kill/restart, sibling API/DAV survival, and explicit plaintext opt-in after restart.

Release uploads/downloads are 269,484,032 bytes (257 MiB), SHA-256 `4abab08ceed920de81ff10ce3d81795bf053df432b4c024734b1d9507f8b2233`. FTP and file processes have a 256 MiB hard allocation ceiling: Linux `RLIMIT_DATA`, Windows Job Object private-commit limit, plus supervisor RSS accounting. This proves bounded streaming beyond the worker allocation ceiling, not beyond physical host RAM. ASan/UBSan uses 1 MiB and 512 MiB configured budgets without a Linux hard allocation limit. Elapsed times in the reports are observations, not controlled performance benchmarks.

## Client matrix and remaining gate

| Client | Linux server | Native Windows server |
| --- | --- | --- |
| curl | 8.5.0 / OpenSSL 3.0.13: verified explicit FTPS upload/download and opted-in plaintext | 8.21.0 / Schannel: verified explicit FTPS upload/download and opted-in plaintext |
| Python standard-library FTP client | Python 3.12.3 / OpenSSL 3.0.13: full workflows | Python 3.13.3 / OpenSSL 3.0.16: full workflows |
| FileZilla GUI | **Not tested** | **Not tested** |

The Python client adds only an explicit `SSLSession` parameter when wrapping data sockets; FTP framing and client state machines remain stdlib `ftplib`. Unmodified `FTP_TLS` does not pass this parameter and therefore does not meet the server's mandatory resumption policy. Tests prove that fresh TLS sessions and sessions from another control connection are rejected. Certificate verification remains enabled for Python and curl. TLS close-notify truncation tests deliberately omit graceful TLS shutdown.

FileZilla was absent from the installed Linux and standard Windows application locations; no GUI automation environment was available. Its TODO checkbox remains open. These results do not establish the full planned M4 client matrix, remote/NAT deployment, implicit FTPS, ASCII file conversion, urgent Telnet ABOR, hostile sibling isolation or complete FTP RFC conformance. Plain TCP FIN does not authenticate file length; interrupted FTP stages are discarded and REST resumes only published files. See the guide for all budgets and exclusions.

Reports normalize checkout/temp/user paths and terminal colors. The source digest covers xmake, dependencies, source/headers, apps, tests, scripts and packaging, excluding documentation. Windows builds run from a disposable NTFS copy; Linux uses the workspace. No system service, firewall, certificate store or real disk configuration was changed. Hosted CI is configured but not claimed to have run.

中文摘要：记录证明本地 Linux/Windows 的 FTP/显式 FTPS、统一权限与配额、续传校验、TLS 数据会话归属、撤权、中断清理和进程隔离恢复。两平台均完成 257 MiB 校验传输，curl 和经会话复用适配的 Python 标准客户端通过。FileZilla 尚未测试，完整客户端矩阵验收项保持未勾选；当前发布范围为有界回环后端预览。

Final source SHA-256: `dcce8e3c4744759f69ce5b5dcb3fdcc17734e8db504833fe356e0943c3289d04`.

Development observation: one GCC large-upload run interrupted while other build/test work was active; its precise cause was not established. A diagnostic 257 MiB rerun and the frozen-source final regression both passed. No soak-test or overload-availability guarantee is inferred from these runs; the documented transfer timeouts remain in effect.
