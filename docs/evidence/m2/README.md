# M2 acceptance evidence

[简体中文](README.zh-CN.md) · [Implementation and limits](../../m2.md)

Recorded 2026-10-29. Acceptance covers the local file core on Linux and native Windows, with M1 regression. It does not depend on TCP 445 or claim support for a file-sharing protocol.

All three builds passed **29 M1 core checks, 35 M2 core checks, 15 M1 integration scenarios and 10 M2 workflow groups**, on the identical source digest:

`516bce9dff77bbdf9793c952759b5151c8c67824e57293522341f9321cf5b520`

| Host / compiler | Build and core | M1 regression | M2 file workflows |
| --- | --- | --- | --- |
| Ubuntu 24.04 / GCC 13.3.0, clean checkout | [GCC](linux-gcc.json) | [Regression](linux-gcc.integration.json) | [257 MiB, RLIMIT_DATA](linux-gcc.files.json) |
| Ubuntu 24.04 / Clang 18.1.3, ASan + UBSan | [Clang](linux-clang.json) | [Regression](linux-clang.integration.json) | [Sanitizer workflows](linux-clang.files.json) |
| Windows 11 build 26200.9457 / VS 2026, toolset 14.51.36231, SDK 10.0.26100.0 | [MSVC](windows-msvc.json) | [Regression](windows-msvc.integration.json) | [257 MiB, Job Object](windows-msvc.files.json) |

The tested source digest covers xmake, the dependency lock, source, headers, application entry points, tests, scripts and packaging; it excludes documentation. Saved records normalize personal checkout/temp paths and terminal color escapes. Exact compiler references remain in [toolchains.lock.json](../../../toolchains.lock.json). GCC uses a clean temporary source copy with verified pinned PACE/recipe exports; MSVC uses the isolated NTFS checkout from `windows_m2.ps1`. The wrapper configures and builds before invoking its runner with `--skip-build`.

Core tests exercise signed/expired grants, portable paths, partial native writes and deterministic disk-full injection, quota reservation recovery, uncertain random-write retries, offsets above 4 GiB, stale handles, publication recovery at both sides of atomic rename, cross-actor handle denial, symlink races and hardlink rejection. Fault hooks are compiled only into the unit-test adapter. Symlink creation is conditional on OS permission and the check count reflects any skip.

Independent Python HTTPS clients and the C++ CLI exercise users/groups, disabling/re-enabling users, ownership isolation, administrator/file-right separation, root/space/mixed-writer restrictions, aliases with single quota charging, locks, idempotent rename/delete, revoke acknowledgements, domain death/restart, inventory, audit, hash-verified transfer, clean shutdown and SQLite integrity. Logs are checked for credentials and sanitizer diagnostics.

Large-file acceptance means **257 MiB transferred with a 256 MiB worker allocation ceiling**, not a file larger than the development workstation's entire physical RAM. Linux applies `RLIMIT_DATA` to the file and API fixture processes in addition to supervisor RSS sampling; Windows uses each worker's Job Object private-commit limit. This tests bounded allocation without changing global host memory or filling disks. Sanitizer acceptance uses a 512 MiB budget and a 1 MiB transfer because instrumentation itself increases memory consumption. Native adapter injection tests disk-full/short-write recovery without exhausting a real filesystem.

No power-loss test, physical-media fault injection, persistent SCM/systemd registration, hostile sibling sandbox, Unicode interoperability, cross-volume copy/delete job, real protocol-client interoperability or hosted GitHub CI is claimed. Disk telemetry remains dependent on native drivers, hardware and permissions. See [the first-profile decision](../../decisions/0005-m2-file-profile.md).

Sampled RSS peaks during large transfers (sampling, not an absolute peak guarantee): linux-gcc: file 14.20 MiB, API 18.75 MiB; windows-msvc: file 16.54 MiB, API 20.17 MiB.
