# M3 evidence / M3 验证记录

Recorded 2026-10-29. Scope: local WebDAV backend preview; see [English guide](../../m3.md) / [中文指南](../../m3.zh-CN.md). FTP/FTPS, SMB, NFS and desktop GUI compatibility are not implied.

## Reference hosts and results

| Server host | Build/regression | DAV acceptance |
| --- | --- | --- |
| Ubuntu 24.04.4, WSL2 kernel 6.18.40.1, GCC 13.3, ext4 | [GCC](linux-gcc.json) | [DAV, litmus and 257 MiB transfer](linux-gcc.dav.json) |
| Same Linux host, Clang 18.1.3, ASan/UBSan | [Clang](linux-clang.json) | [DAV and litmus, 1 MiB](linux-clang.dav.json) |
| Windows 11 25H2 build 26200.9457, VS 2026 toolset 14.51.36231, SDK 10.0.26100.0, NTFS | [MSVC](windows-msvc.json) | [Native DAV and 257 MiB transfer](windows-msvc.dav.json) |

The reports include M1/M2 regressions and the M3 parser tests. M3 workflows cover schema-1 upgrades with backups, role-key enrollment, verified TLS, Unicode filenames, collections and type-changing overwrite, conditional/range requests, authentication before body admission, chunked uploads, disconnect cleanup, dead-property persistence, locks across process death, core/DAV cross-writer denial, expiry and ownership, exposure revocation, COPY journal recovery before publication, protocol inventory/monitoring, offline backup/restore and corrupt-package rejection.

The COPY crash cut is deterministic fixture injection: the stopped service's completed copy is moved back to its private stage and its journal set to `committing`, then restarted. It is not a power-loss or physical-media-fault test. M2's native adapter tests retain short-write/disk-full injection without exhausting a real disk.

Large-file acceptance is 269,484,032 bytes (257 MiB), uploaded and downloaded with SHA-256 `4abab08ceed920de81ff10ce3d81795bf053df432b4c024734b1d9507f8b2233`. File and DAV workers have a 256 MiB hard allocation ceiling: Linux `RLIMIT_DATA`, Windows Job Object private-commit limit, plus existing supervisor RSS accounting. Linux virtual-address reservations are not counted as live data allocations; `RLIMIT_AS` was not the accepted profile. Sanitizers use 512 MiB configured budgets and a 1 MiB payload; Linux sanitizer allocations are not constrained by RLIMIT_DATA. No claim of a payload exceeding physical host RAM is made.

The source digest covers xmake, dependency locks, source, headers, app entry points, tests, scripts and packaging, excluding docs. Records normalize personal checkout/temp paths and terminal color codes. Native MSVC runs from a disposable NTFS copy via `scripts/windows_m3.ps1`; Linux runs from the workspace with verified pinned PACE/recipe exports. Hosted GitHub CI is configured but was not executed in this local session.

## Independent clients and compliance / 独立客户端与合规

| Client | Result / boundary |
| --- | --- |
| litmus 0.18, bundled neon 0.37.1, Linux | basic 16/16, copymove 13/13, props 33/33, locks 40/40, http 3/3: **105 executed cases pass**, zero failures/warnings. One `Expect` case is skipped by litmus for TLS and covered by explicit Python header-only tests. |
| Linux curl | Verified TLS PUT/GET with generated CA file; exact version is in the DAV report. |
| Native Windows curl | Verified TLS PUT/GET on native MSVC services; exact version is in the DAV report. |
| Python standard-library HTTPS clients | Native Linux and Windows acceptance, including bounded transfer, conditional requests, locks/recovery and metadata restore. |
| Windows Explorer / WebClient | **Not tested; no compatibility claim.** Read-only inspection found WebClient stopped, manual startup. No Explorer mount, certificate-store import or service configuration change was performed. |
| macOS Finder | **Not tested; no compatibility claim.** No macOS host was available. |

The litmus archive is pinned by SHA-256 `efb3a1b91472760f66f2fcb4ca2b58af19c024fb0263ca725f1f1b44182fd8ca`. Reproduce with `python3 scripts/fetch_litmus.py`, then `--litmus build/litmus/installed/bin/litmus` on the M3 runner. Its TLS conformance fixture uses `--insecure` only against the generated disposable certificate; separate Python and curl tests validate certificates. The official [litmus documentation](https://notroj.github.io/litmus/) explicitly distinguishes passing its test suite from compatibility with real DAV clients. Native Windows does not execute the Unix litmus binary; shared protocol code is tested independently on Linux, and native filesystem behavior is covered by Windows acceptance.

Limits: only loopback TLS, HTTP/1.1 close-after-response, strict portable UTF-8 NFC names, finite PROPFIND, bounded trees and 16 MiB COPY. No external-client remote network deployment, Explorer/Finder compatibility, hostile sibling sandbox, power-loss durability, or portable file-data restore is claimed. Metadata restore requires original native storage identities; file data and TLS secrets need separate recovery planning.

中文摘要：当前结果证明 Linux/Windows 本地后端的 DAV、流式传输、统一锁、撤权与恢复功能；并不代表全部桌面客户端兼容。litmus 的 105 个实际执行用例全部通过，TLS 下被跳过的 Expect 用例由独立 Python 测试覆盖。Windows Explorer 与 macOS Finder 均明确记录为未测试。257 MiB 传输验证的是超过 256 MiB 工作进程分配上限，而非超过主机物理内存。

Final source SHA-256: `0d5d4f24c892e28367368157e8e08eb6d677b9f8d36319e04eb3eae699bc32ae`. Linux sampled large-transfer RSS peaks: file 13.57 MiB, DAV 15.14 MiB; samples are not absolute peak guarantees.

Windows sampled large-transfer RSS peaks: file 14.00 MiB, DAV 14.65 MiB. All three final reports share the source digest above. Each passes 29 M1, 35 M2 and 28 M3 native checks, 15 M1 integration scenarios and 10 M2 file workflows. M3 adds 10 native workflows on Windows and 11 on Linux (the extra workflow is litmus).
