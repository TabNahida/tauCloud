# Pre-M8 acceptance — 2026-10-30

M8 has not started. The M4 client gate is closed; full M5 and M7 conformance gates remain open. A passing selected-profile workflow does not establish complete SMB/NFS compatibility. All public pushes use the explicitly authorized `codex/pre-m8-acceptance` branch.

## File semantics follow-up

[Local evidence](file-semantics-local.json) records 14 passing Samba file/lock/directory selectors plus all three credit tests (including 8191 writes), 11 SMB2 and 18 SMB3 regression groups, and the original 15 NFS groups. The broad pre-fix pynfs diagnostic selected 166 cases: 139 passed and 27 failed; it is retained as a diagnostic, not a conformance pass. After native-descriptor retention, the original RNM21 replacement/CLOSE test and TRUNK1/TRUNK2 pass.

MOUNT now supplies scoped DUMP/EXPORT/UMNT operations and rpcbind supplies bounded DUMP/GETVERSADDR. NFS REMOVE/RENAME retain active native descriptors, preserve old-object I/O, charge quota and release it after last CLOSE or expiry. NFS-worker crash/reclaim retains these objects while the file domain remains alive. The subsequent [durable NFS local checks](durable-nfs-local.json) add private links and journal recovery across file-domain/all-service restart, including interrupted prepare and reaping boundaries. They also record 145 passing applicable upstream cases, with 121 unselected cases retained as skipped, and explicit BACKCHANNEL_CTL/SP4_NONE/obsolete-operation checks. Run 41139081075 passes durable-unlink/restart assertions on Linux and Windows; Windows pin-recovery assertions also pass but an unclosed test SQLite connection fails cleanup (now corrected, rerun pending). The NLM/NSM addition has [local wire/callback evidence](nlm-local.json); native lock recovery and the Windows NFS-client gate remain open. M8 is not implemented yet.

## Current verification

Commit `c180501` passes all four jobs in [run 41028021382](https://github.com/TabNahida/tauCloud/actions/runs/41028021382). [The downloaded fixed-commit reports](verified-namespace-c180501.json) confirm seven new namespace/revocation groups on GCC, Clang ASan/UBSan and MSVC, native Linux pseudo-root mounting and simultaneous opens across two exports, plus the existing native Linux/Windows/macOS and FileZilla checks. The selected upstream NFS groups remain 37 + 34 + 30 passes. [Local evidence](nfs-namespace-local.json) also records the old NOTSUPP reproduction and 14 additional upstream traversal/security-information checks.

This closes the selected pseudo-root and multi-export session gaps. READDIR enforces caller visibility, cookie/verifier validation, complete maxcount accounting and forward progress. Cached replies revalidate all touched export scopes, including reads without an OPEN, and fence revoked or retargeted authority without blocking new sequences on unaffected exports. Full M5/M7 gates below remain open.

The earlier fixed-commit matrix follows for historical comparison.

Commit `b64bd47` passes all four jobs in [run 41009694197](https://github.com/TabNahida/tauCloud/actions/runs/41009694197). The downloaded reports confirm 11 SMB2 and 18 SMB3 regression groups on GCC, Clang and MSVC, including the credit/session-error corrections. See the [fixed-commit matrix](verified-matrix-b64bd47.json) and [macOS client report](macos-native-b64bd47.json).

| Environment | Verified scope at `b64bd47` |
| --- | --- |
| Ubuntu / GCC | M1–M7 regression, Samba SMB 2.1/3.1.1, kernel NFSv3/v4.1, FileZilla GUI FTPS, selected upstream NFS and state/attribute/creation tests |
| Ubuntu / Clang | M1–M7 regression with ASan/UBSan |
| Windows Server 2025 / MSVC | M1–M7 regression, NFS server state/attribute/creation tests, native encrypted SMB redirector, FileZilla GUI FTPS |
| macOS 15.7.9 Intel client | Native signed SMB and NFSv3 file roundtrips against the same Linux server source in an isolated Ubuntu guest |

Native roundtrips cover mkdir, write, fsync, read verification, rename, truncate, enumerate and delete. macOS uses alternate ports and NFSv3 `nolocks`; its 1,028,096-byte payload SHA-256 is `08e33aedf25337c87eb15e08c32a58f6f4caa21fe073d00b53014c57f8d148e0`. The client requested uppercase `SMB`, confirming the share-name mismatch fixed by `c4f0f79`.

## Corrections and evidence

- Fixed Windows LF dependency export and repeatable clean-checkout builds; matrix fail-fast is disabled so one failure does not cancel another platform's evidence.
- Corrected login accounting: verified logins neither consume the failed-attempt budget nor erase earlier failures.
- Added NFS share reservations, competing-principal byte locks, split unlock ranges and durable reclaim; corrected lifecycle/channel/session handling and principal-isolated replay.
- Added native timestamps, alias-stable mode/owner projection, persistent change counters and actual non-atomic namespace change_info. Counter tests include equal-size writes with restored mtime, reads and restart. WebDAV ETags exclude atime.
- Corrected NFS namespace replacement, directory cookies, optional directory-delegation refusal, EXCLUSIVE4_1 attributes and safe UNCHECKED truncation after share checks.
- Corrected SMB wildcard bootstrap, native CREATE flags, partial information replies, dialect-specific normalized names, LOGOFF/reauthentication, authenticated session replacement, bounded credits and allocation shrink.
- Corrected NTLM response-clock validation: five-minute skew bound, exact echoed target information, ten-second one-use challenge, valid proof and MIC. macOS authentication previously failed with only -378 ms of clock difference. [Local clock regression](ntlm-clock.json) and [the subsequent authenticated macOS run](macos-native-ca51016.json) preserve the evidence.
- Corrected SMB share lookup without case sensitivity, with canonical authorization IDs, rejected ambiguous publications and no shadowing by non-SMB exposures. [Native macOS SMB/NFS evidence](macos-native-b64bd47.json) records successful complete roundtrips.
- Further corrected unsolicited 32-credit negotiation grants and unknown-session errors. The minimum-one/maximum-64 policy remains bounded. An unknown-session LOGOFF cannot terminate the real session; known-session signatures remain validated before compound side effects. Local and remote GCC/Clang/MSVC SMB2/SMB3 regressions pass; native client checks also pass on that same source.
- Unmodified FileZilla GUI upload/download passes on Linux and Windows with a pinned disposable certificate and source/server/download hash comparison. [Linux report](filezilla-linux.json), [Windows report](filezilla-windows.json), and [local Windows redirector evidence](windows-native-local.json) supplement Actions artifacts.

The `ca51016` [verified matrix](verified-matrix-ca51016.json) records independently passing GCC/Clang/MSVC jobs despite that run's macOS TREE_CONNECT failure. The earlier `edbcbe3` [matrix](verified-matrix.json) is historical. Selected upstream NFS groups contain 37, 34 and 30 passing cases; they are not the full upstream suite.

Expanded upstream control-plane diagnostics: **71 passed / 6 failed of 77 selected** ([report](pynfs-control-expanded.json)). Five failures require delegations/callbacks not granted by this profile; EID50 requires SSV and receives SERVERFAULT. RPCSEC_GSS/SSV remains outside this AUTH_SYS preview; those failures are not counted as passes.

[Unmodified Samba session/credit diagnostics](samba-session-diagnostics.json) retain all failures/skips. After the credit correction, the single-credit assertion passes, but the full case fails on unsupported CREATE rights. The bad-VUID tcon case still fails after the client rejects the response; larger credit windows exceed the 64-credit profile. Algorithm tests that first require AES-GMAC are skipped, not passed.

## Remaining gates and restrictions

- Kernel CIFS omits the mandatory NTLM MIC and is **incompatible**. Dedicated negative tests require `ntlm_mic_required` rejection for all selected dialects; they are not compatibility passes. MIC/signing requirements remain enforced.
- Broader unmodified Samba torture remains incomplete, including full Windows security rights and session-error interoperability. Persistent Windows ACL changes and optional caching/durable handles are not granted by this preview.
- NFSv3 NLMv4 synchronous locks/NSMv1 recovery now have local wire/callback tests. Native recovery acceptance is pending; earlier native v3 evidence uses `nolocks`.
- Full NFSv4.1 mandatory-operation conformance, unlink-open, complete cache/client consistency and full reboot/trunking remain open. The later follow-up above adds retained-object replacement and recovery; complete conformance remains open.
- Special files, hardlinks and symlinks are outside the confined regular-file/directory profile. Tests requiring them are not relabeled as successful applicable cases.
- Windows Client for NFS and Finder GUI remain unverified. Native Windows redirector tests require integrity and privacy; Windows reports `Encrypted=true, Signed=false` because AEAD supplies integrity for encrypted traffic.
- Larger-than-RAM/soak, sudden power-loss, Windows namespace durability and persistent service registration require their own evidence.

The macOS fixture uses a private offline identity seed with production Argon2id parameters (64 MiB/3/1), explicitly excluding management bootstrap/login from this client test. Linux/Windows regression still exercises those flows. SMB performs real NTLMv2/MIC authentication against normally enrolled credentials. Seed files, databases and keys are excluded from artifacts; the relay records only bounded protocol metadata. Reused server artifacts are accepted only after comparing `src`, `include`, `apps`, `xmake.lua` and the dependency lock against their recorded source commit.

中文：已修复多项遗留实现问题并完成真实跨平台回归，M4 客户端验收已补齐。M5/M7 的完整合规门槛仍未关闭，不能把选定配置的全绿 Actions 当作 M0–M7 全部验收完成；M8 未开始。

## Earlier remote runs

| Commit | Run | Result |
| --- | --- | --- |
| `1e5d683` | [40988085815](https://github.com/TabNahida/tauCloud/actions/runs/40988085815) | GCC and Clang regression passed; Windows dependency hash failed because Git line-ending conversion changed the source archive. Fixed by forcing LF during export. |
| `4ed2c80` | [40988548036](https://github.com/TabNahida/tauCloud/actions/runs/40988548036) | Windows and Clang regression passed; Linux native-client stage exposed protocol incompatibilities. |
| `9ea06f7` | [40989812663](https://github.com/TabNahida/tauCloud/actions/runs/40989812663) | Windows and Clang regression passed. GCC core regression, 37 selected upstream pynfs tests and competing-lock/restart checks passed; native-client stage failed. |
| `6e38ee1` | [40992503744](https://github.com/TabNahida/tauCloud/actions/runs/40992503744) | Windows full regression and NFS state/recovery passed. Linux Samba 2.1/3.1.1 and kernel NFSv3 roundtrips passed. Kernel NFSv4.1 mounted and transferred/truncated data, but READDIR failed. Clang exposed an atime-dependent ETag regression. Matrix fail-fast cancelled GCC's remaining stages; cancellation is not a pass. |
| `5a00380` | [40994316771](https://github.com/TabNahida/tauCloud/actions/runs/40994316771) | GCC/Clang/Windows core regression passed; 37 + 34 + 30 selected upstream cases passed. Native Linux v4.1 exposed optional directory-delegation handling; Windows native mapping failed. |
| `9be16de` | [40996860599](https://github.com/TabNahida/tauCloud/actions/runs/40996860599) | GCC including kernel NFSv3/v4.1 and Samba roundtrips passed. Windows core passed but native rename failed. Clang exposed a LOGOFF transport race. macOS guest failed during boot. |
| `e4d1937` | [40998763054](https://github.com/TabNahida/tauCloud/actions/runs/40998763054) | GCC/Clang passed. Windows native rename still failed; macOS guest boot/SSH worked, but server initialization exceeded the IPC deadline under software emulation. |
| `92f230c` | [41000056554](https://github.com/TabNahida/tauCloud/actions/runs/41000056554) | GCC/Clang passed, including Linux FileZilla. Windows core/state/attributes and native SMB redirector passed; FileZilla stopped at its welcome dialog because Windows ignored the redirected APPDATA variable. macOS software-emulated guest again exceeded the management bootstrap IPC deadline. |
| `69b8289` | [41001476891](https://github.com/TabNahida/tauCloud/actions/runs/41001476891) | GCC, Clang and Windows all passed, including new NFS cache counters/alias/restart tests and both FileZilla GUIs. Windows native encrypted SMB, Linux Samba and kernel NFSv3/v4.1 pass. macOS HVF guest booted but management bootstrap still exceeded its IPC deadline. |
| `edbcbe3` | [41002404337](https://github.com/TabNahida/tauCloud/actions/runs/41002404337) | GCC/Clang/MSVC all passed, including new NFS creation semantics, native Linux/Windows clients and both FileZilla GUIs. The overall run failed in macOS guest initialization; see [verified matrix](verified-matrix.json) for the individually passing jobs. |

Additional harness history: [41003681135](https://github.com/TabNahida/tauCloud/actions/runs/41003681135) failed because the fixture retained SSH descriptors; [41004406480](https://github.com/TabNahida/tauCloud/actions/runs/41004406480) fixed startup and passed macOS NFSv3 but failed SMB authentication ([report](macos-native.json)). [41005235402](https://github.com/TabNahida/tauCloud/actions/runs/41005235402) added safe NTLM diagnostics and reproduced that failure. [41006409767](https://github.com/TabNahida/tauCloud/actions/runs/41006409767) fixed authentication but exposed share-name lookup; [41008665113](https://github.com/TabNahida/tauCloud/actions/runs/41008665113) passed all jobs after that fix. Duplicate [41003681053](https://github.com/TabNahida/tauCloud/actions/runs/41003681053) was intentionally cancelled; cancellation is not a pass.
