# M1 acceptance evidence

[简体中文](README.zh-CN.md) · [Implementation and reproduction](../../m1.md)

Recorded 2026-10-29. Linux/GCC, Linux/Clang with ASan/UBSan, and native Windows/MSVC each passed **29 core checks and 15 end-to-end scenarios**. All reports identify the same source digest:

`a04f231378b377404a7c668364ee6bfe7e166f77db9a451cd90ae0f2dc04e462`

| Host | Build/core record | Independent HTTPS/process record |
| --- | --- | --- |
| Ubuntu 24.04, GCC 13.3.0, clean temporary source checkout | [GCC](linux-gcc.json) | [GCC integration](linux-gcc.integration.json) |
| Ubuntu 24.04, Clang 18.1.3, ASan + UBSan | [Clang](linux-clang.json) | [Clang integration](linux-clang.integration.json) |
| Windows 11 build 26200.9457, VS 2026 toolset 14.51.36231 / SDK 10.0.26100.0, native NTFS | [MSVC](windows-msvc.json) | [MSVC integration](windows-msvc.integration.json) |

The digest includes source, headers, application entry point, tests, scripts, packaging, xmake and dependency lock. Documentation is excluded. Personal checkout/user paths and terminal color escapes are normalized in saved reports. GCC ran after copying only declared inputs and verified dependency exports to an empty temporary directory. MSVC ran from the isolated native checkout created by `windows_m1.ps1`; its report uses `--skip-build` after the wrapper's successful xmake configure/build. The full compiler and OS reference is in [toolchains.lock.json](../../../toolchains.lock.json).

Core checks cover configuration including integer overflow, native owner locking, IPC authentication/version/nonce/generation rejection, caller-owned cancellation, one-use bootstrap, Argon2id verification, scopes/revocation/throttling, transactional migrations and backups. Integration uses Python's independent HTTPS client plus the C++ CLI and real subprocesses. It exercises trusted/untrusted TLS, admission and idle deadlines, cookies/CSRF/Origin, idempotent restart, sibling continuity, supervisor crash adoption, unexpected worker death, persistent crash-loop limits, shutdown, abrupt SQLite transaction loss and recovery. Child logs are checked for secret leakage and sanitizer diagnostics.

`systemd-analyze verify` also passed after replacing only the template's installation executable path with the built binary in a temporary copy. SCM code compiled and native foreground start/stop was exercised. Persistent systemd/SCM registration, hosted GitHub CI, CPU quotas, file-protocol support, hostile sibling-process isolation, storage mutation and update installation were **not** tested or claimed. These are documented scope boundaries, not TCP-445 blockers.
