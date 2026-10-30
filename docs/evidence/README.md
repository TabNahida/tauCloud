# M0 recorded evidence

[简体中文](README.zh-CN.md) · [Reproduction and limitations](../m0.md)

Recorded 2026-10-29. All three executable suites passed. **M0 is accepted** following the user’s 2026-10-29 decision that functional evidence suffices without port 445. Historical JSON statuses are preserved; this decision supersedes their deployment gate. No production protocol support is claimed.

| Record | Environment | Result |
| --- | --- | --- |
| [Linux GCC](linux-gcc.json) | Ubuntu 24.04.4 / GCC 13.3.0 / ext4 | Runtime, filesystem, Unix IPC recovery, signed updates, SMB vectors and Impacket 0.12.0 interoperability passed |
| [Linux Clang + sanitizers](linux-clang-sanitizers.json) | Clang 18.1.3 / ASan + UBSan / ext4 | Same suite passed with instrumented PACE and bridge |
| [Windows MSVC](windows-msvc.json) | Windows 11 25H2 26200.9457 / toolset 14.51.36231 / SDK 10.0.26100.0 / NTFS | Runtime, filesystem, named-pipe recovery, signed updates, SMB vectors and smbprotocol 1.15.0 using native SSPI passed |
| [Dependency acquisition](dependency-acquisition.json) | Exact upstream PACE Git object and offline committed export | Same source hash; modified export rejected; restored export accepted |

The core runtime probe reports 13 checks, process recovery 17, update recovery 11 and SMB vectors 12. Filesystem and interoperability report their actual capabilities/events instead of a synthetic assertion count. Windows reports `AddressAlreadyInUse` for exclusive TCP-445 binding and success for a temporary alternative loopback listener. This is an observed deployment prerequisite, not a passing standard-port deployment.

The JSON files preserve source digests, commands, outputs, statuses and timings. Absolute checkout, temporary-directory and interpreter paths are normalized to placeholders; tool-version banners are shortened to their first line. The complete local run logs remain under ignored `build/m0`. MSVC's standalone `cl` inventory command is unavailable outside its developer environment; successful xmake configuration/build explicitly selects the recorded VS/toolset/SDK. This informational inventory failure is separate from probe results.

The reference Linux kernel is WSL2 6.18.40.1 and reports 24 logical CPUs and 197226000 KiB RAM; filesystem probes used native temporary directories. Tests call flush APIs and terminate child processes abruptly, but never emulate host power loss. They do not operate RAID disks, install services, alter SMB configuration or prove untrusted-plugin confinement. Refer to the ADRs for the deliberately limited Windows path and SMB authentication surfaces.

M2 implementation evidence: [identity and file-core acceptance](m2/README.md).

## M3 backend preview / M3 后端预览

See [M3 results and client limitations](m3/README.md) for independent DAV conformance, native host workflows, bounded transfers and metadata recovery.
