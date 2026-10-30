# Pre-M8 acceptance work — 2026-10-30

This work is in progress. M8 has not started, and the full M4/M5/M7 release gates remain open. A successful selected-profile run is not full protocol conformance. All public pushes use the explicitly authorized `codex/pre-m8-acceptance` branch.

## Recorded remote runs

| Commit | Run | Result |
| --- | --- | --- |
| `1e5d683` | [40988085815](https://github.com/TabNahida/tauCloud/actions/runs/40988085815) | GCC and Clang regression passed; Windows dependency hash failed because Git line-ending conversion changed the source archive. Fixed by forcing LF during export. |
| `4ed2c80` | [40988548036](https://github.com/TabNahida/tauCloud/actions/runs/40988548036) | Windows and Clang regression passed; Linux native-client stage exposed protocol incompatibilities. |
| `9ea06f7` | [40989812663](https://github.com/TabNahida/tauCloud/actions/runs/40989812663) | Windows and Clang regression passed. GCC core regression, 37 selected upstream pynfs tests and competing-lock/restart checks passed; native-client stage failed. |
| `6e38ee1` | [40992503744](https://github.com/TabNahida/tauCloud/actions/runs/40992503744) | Windows full regression and NFS state/recovery passed. Linux Samba 2.1/3.1.1 and kernel NFSv3 roundtrips passed. Kernel NFSv4.1 mounted and transferred/truncated data, but READDIR failed. Clang exposed an atime-dependent ETag regression. Matrix fail-fast cancelled GCC's remaining stages; cancellation is not a pass. |

The workflow now disables matrix fail-fast so one platform's failure does not cancel another platform's evidence. Artifacts retain raw results, client failures and bounded server/kernel logs.

## Implemented corrections

- Deterministic dependency export on Windows and repeatable clean-checkout Actions.
- SMB 3.1.1 priority flags, successful-login accounting that preserves failed-attempt budgets, and explicit missing-MIC diagnostics.
- NFS share reservations, byte locks, split unlock ranges, durable reclaim, session/client lifecycle, channel negotiation, connection binding and principal-isolated shared sessions/replay.
- Native access/modify timestamps, durable mode/owner projection across export aliases, closed-destination rename replacement, namespace error handling and non-reserved directory cookies.
- Exclude access time from WebDAV ETags so reads cannot invalidate FTP/WebDAV conditional mutations.

Local regression passed M1–M6 including litmus. The M7 test was corrected to omit SET-only attributes from GETATTR, then all 15 M7 integration groups passed. Four NFS attribute/enumeration groups and four competing-principal/lock/restart groups passed. Selected unmodified upstream cases cover OPEN/current-stateid/SEQUENCE/reclaim, lifecycle and ordinary-file/directory namespace operations. Final fixed-commit remote reruns are still pending.

## Explicit compatibility boundaries and remaining gates

- Ubuntu's tested kernel CIFS client omits the NTLM MIC required by this server. It is **not compatible**. The dedicated negative test must observe `ntlm_mic_required` rejection for every selected dialect; it is not a file-roundtrip pass. Signing/MIC policy was not weakened.
- Samba 4.19.5 `smbclient` performs real signed 2.1 and 3.1.1 roundtrips. Broader unmodified `smbtorture` cases request unsupported full Windows security rights and remain failing. A Windows-2008-only skipped test is not counted as passed.
- Windows native redirector testing uses Server 2025's `New-SmbMapping -TcpPort`, requires signing/encryption, and removes only its disposable mapping. It is a separate gate from Python/SSPI client coverage; the new remote result is pending.
- FileZilla, macOS Finder/native SMB/NFS, and eligible Windows NFS remain unverified. No entire client-matrix checkbox is closed.
- NFSv3 NLM/NSM is absent. V4.1 full mandatory-operation coverage, unlink-open behavior, directory change/cache guarantees, multi-export sessions and full reboot/trunking conformance remain open. Active destination OPENs currently cause FILE_OPEN on remove/replacement.
- Special files, hardlinks and symlinks are outside the current confined regular-file/directory profile. Tests requiring those objects are not relabeled as successful applicable tests.
- Larger-than-RAM/soak, sudden power-loss, namespace durability on Windows, and persistent service registration require their own evidence.

中文：补齐工作尚未全部完成，M8 未开始。已补充真实远程构建、原版上游协议测试和内核客户端检查，并修复发现的多项实现问题。Linux 内核 CIFS 因缺少强制 MIC 被拒绝，不能算作兼容通过；Samba torture 的失败、未运行的平台及 NFS 的剩余实现门槛均保留。不能将选定场景通过或 CI 的部分成功解读为 M0–M7 全部验收完成。
