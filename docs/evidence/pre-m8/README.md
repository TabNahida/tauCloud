# Pre-M8 acceptance work — 2026-10-30

This work is in progress. M8 has not started, and the full M4/M5/M7 release gates remain open. A successful selected-profile run is not full protocol conformance. All public pushes use the explicitly authorized `codex/pre-m8-acceptance` branch.

## Recorded remote runs

| Commit | Run | Result |
| --- | --- | --- |
| `1e5d683` | [40988085815](https://github.com/TabNahida/tauCloud/actions/runs/40988085815) | GCC and Clang regression passed; Windows dependency hash failed because Git line-ending conversion changed the source archive. Fixed by forcing LF during export. |
| `4ed2c80` | [40988548036](https://github.com/TabNahida/tauCloud/actions/runs/40988548036) | Windows and Clang regression passed; Linux native-client stage exposed protocol incompatibilities. |
| `9ea06f7` | [40989812663](https://github.com/TabNahida/tauCloud/actions/runs/40989812663) | Windows and Clang regression passed. GCC core regression, 37 selected upstream pynfs tests and competing-lock/restart checks passed; native-client stage failed. |
| `6e38ee1` | [40992503744](https://github.com/TabNahida/tauCloud/actions/runs/40992503744) | Windows full regression and NFS state/recovery passed. Linux Samba 2.1/3.1.1 and kernel NFSv3 roundtrips passed. Kernel NFSv4.1 mounted and transferred/truncated data, but READDIR failed. Clang exposed an atime-dependent ETag regression. Matrix fail-fast cancelled GCC's remaining stages; cancellation is not a pass. |

| `5a00380` | [40994316771](https://github.com/TabNahida/tauCloud/actions/runs/40994316771) | GCC/Clang/Windows core regression passed; 37 + 34 + 30 selected upstream cases passed. Native Linux v4.1 exposed optional directory-delegation handling; Windows native mapping failed. |
| `9be16de` | [40996860599](https://github.com/TabNahida/tauCloud/actions/runs/40996860599) | GCC including kernel NFSv3/v4.1 and Samba roundtrips passed. Windows core passed but native rename failed. Clang exposed a LOGOFF transport race. macOS guest failed during boot. |
| `e4d1937` | [40998763054](https://github.com/TabNahida/tauCloud/actions/runs/40998763054) | GCC/Clang passed. Windows native rename still failed; macOS guest boot/SSH worked, but server initialization exceeded the IPC deadline under software emulation. |
| `92f230c` | [41000056554](https://github.com/TabNahida/tauCloud/actions/runs/41000056554) | GCC/Clang passed, including Linux FileZilla. Windows core/state/attributes and native SMB redirector passed; FileZilla stopped at its welcome dialog because Windows ignored the redirected APPDATA variable. macOS result pending at this revision. |

The workflow now disables matrix fail-fast so one platform's failure does not cancel another platform's evidence. Artifacts retain raw results, client failures and bounded server/kernel logs.

## Implemented corrections

- Deterministic dependency export on Windows and repeatable clean-checkout Actions.
- SMB 3.1.1 priority flags, successful-login accounting that preserves failed-attempt budgets, and explicit missing-MIC diagnostics.
- NFS share reservations, byte locks, split unlock ranges, durable reclaim, session/client lifecycle, channel negotiation, connection binding and principal-isolated shared sessions/replay.
- Native access/modify timestamps, durable mode/owner projection across export aliases, closed-destination rename replacement, namespace error handling and non-reserved directory cookies.
- Exclude access time from WebDAV ETags so reads cannot invalidate FTP/WebDAV conditional mutations.
- SMB wildcard negotiation, native CREATE flags, partial information replies and normalized names; same-transport LOGOFF/reauthentication and authenticated session replacement.
- Bounded SMB credit replenishment that preserves unused message IDs across gaps; tested replay rejection. Native EOF/allocation shrink semantics without pretending to support quota-free preallocation.
- Decline optional NFS directory delegations with the specified nonfatal response, allowing Linux kernel enumeration.
- Durable NFS change counters from native metadata and projected attributes, independent of access time; actual non-atomic namespace change_info. Alias, restored-mtime, read-only and restart checks cover the counter behavior.

Local regression passed M1–M6 including litmus. The M7 test was corrected to omit SET-only attributes from GETATTR, then all 15 M7 integration groups passed. Five NFS attribute/enumeration groups and four competing-principal/lock/restart groups passed. Selected unmodified upstream cases cover OPEN/current-stateid/SEQUENCE/reclaim, lifecycle and ordinary-file/directory namespace operations. The latest local counter regression and fixed-commit remote reruns are recorded separately; earlier successful runs do not validate later source changes.

## Explicit compatibility boundaries and remaining gates

- Ubuntu's tested kernel CIFS client omits the NTLM MIC required by this server. It is **not compatible**. The dedicated negative test must observe `ntlm_mic_required` rejection for every selected dialect; it is not a file-roundtrip pass. Signing/MIC policy was not weakened.
- Samba 4.19.5 `smbclient` performs real signed 2.1 and 3.1.1 roundtrips. Broader unmodified `smbtorture` cases request unsupported full Windows security rights and remain failing. A Windows-2008-only skipped test is not counted as passed.
- Windows native redirector testing uses Server 2025's `New-SmbMapping -TcpPort`, requires signing/encryption, and removes only its disposable mapping. It is a separate gate from Python/SSPI client coverage; the `92f230c` remote run passed create/write/flush/read/rename/truncate/enumerate/delete with dialect 3.1.1 and encryption. Windows reports `Signed=false` for encrypted traffic; AEAD provides integrity, and the test requests both RequireIntegrity and RequirePrivacy.
- Unmodified FileZilla 3.66.5 GUI upload/download passed on Linux, locally and remotely (see [local report](filezilla-linux.json)); Windows GUI config isolation is being corrected. macOS Finder/native SMB/NFS and eligible Windows NFS remain unverified. No entire client-matrix checkbox is closed. [Local Windows redirector evidence](windows-native-local.json) supplements the independent Server 2025 runner result.
- NFSv3 NLM/NSM is absent. V4.1 full mandatory-operation coverage, unlink-open behavior, complete cache/client consistency, multi-export sessions and full reboot/trunking conformance remain open. Active destination OPENs currently cause FILE_OPEN on remove/replacement.
- Special files, hardlinks and symlinks are outside the current confined regular-file/directory profile. Tests requiring those objects are not relabeled as successful applicable tests.
- Larger-than-RAM/soak, sudden power-loss, namespace durability on Windows, and persistent service registration require their own evidence.

中文：补齐工作尚未全部完成，M8 未开始。已补充真实远程构建、原版上游协议测试和内核客户端检查，并修复发现的多项实现问题。Linux 内核 CIFS 因缺少强制 MIC 被拒绝，不能算作兼容通过；Samba torture 的失败、未运行的平台及 NFS 的剩余实现门槛均保留。不能将选定场景通过或 CI 的部分成功解读为 M0–M7 全部验收完成。
