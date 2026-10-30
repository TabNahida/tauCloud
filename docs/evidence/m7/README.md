# M7 experimental NFS validation — 2026-10-30

This page preserves the original preview's historical evidence. Subsequent implementation changes and remote runs are recorded in [pre-M8 acceptance](../pre-m8/README.md); statements below about missing locks/attributes describe the original snapshot.

M7 is **partially implemented**. These records validate the bounded experimental server and regress earlier milestones. They do not establish full M7a/NFSv4.1 or M7b/NFSv3 compatibility. See the [English](../../m7.md) / [中文](../../m7.zh-CN.md) guides and [ADR 0010](../../decisions/0010-nfs-preview.md).

| Host/build | Existing regression | M7 native checks | M7 independent-codec TCP scenarios |
| --- | --- | --- | --- |
| Ubuntu 24.04.4 / ext4 / GCC 13.3 release | M1–M6 passed; WebDAV litmus 105 checks | 58 passed | 15 passed |
| Ubuntu 24.04.4 / ext4 / Clang 18.1.3 debug ASan+UBSan | M1–M6 passed; WebDAV litmus 105 checks | 58 passed | 15 passed |
| Windows 11 25H2 build 26200.9457 / NTFS / MSVC 14.51.36231 release | M1–M6 passed on isolated rerun | 58 passed | 15 passed after test-fixture cleanup correction |

Native totals are 29, 35, 28, 18, 80, 509 and 58 for M1–M7 respectively (757 checks). Integration groups are 15 / 10 / 11 / 11 / 9 / 14 / 15 on Linux; Windows omits the Linux litmus group (10 DAV groups). Release SMB transfer tests use 17 MiB; sanitizer SMB tests use 1 MiB. NFS's transfer check uses 64 KiB and is not a throughput, beyond-RAM or soak claim. Release service budgets are 256 MiB and sanitizer fixtures use 512 MiB.

The NFS scenarios use generated codecs from `linux-nfs/pynfs` commit `cd4701827a8261fedbfb4c6e39029fb9671321a6`, verified against `dependencies.lock.json`. PLY 3.11 and xdrlib3 0.1.1 generate the independent v3/v4.1 wire definitions. The transport/test harness is repository code. **The full upstream pynfs conformance suite was not run**, and this is not evidence of a Linux kernel, macOS or Windows NFS client mount. The Windows evidence is a native Windows **server** with the independent Python test harness, not Windows Client for NFS.

Verified scenarios include fragmented RPC; explicit UID/GID/group denial; root squash with both denied and read-only anonymous access; TCP discovery without advertising NLM; guarded creation; short-write/disk-full failure; malformed trailing XDR with no write; FILE_SYNC upgrades of UNSTABLE requests; READ/COMMIT; exact v3 mutation replay; server reboot verifier changes; MAC tampering; handle persistence through external rename and service restart; deletion/recreation staleness; directory operations; v4.1 sessions/slots, OPEN/WRITE/READ/CLOSE, false retry and foreign stateid rejection; owner-only OPEN reclaim; export revocation; and backup capability stripping.

## Records and source identity

- [GCC full run](linux-gcc.json) and [NFS scenarios](linux-gcc.nfs.json).
- [Clang sanitizer full run](linux-clang.json) and [NFS scenarios](linux-clang.nfs.json).
- [Windows regression and cleanup failure](windows-msvc.before-fixture-cleanup-fix.json), followed by the [corrected NFS test](windows-msvc.nfs.json).
- [Source verification manifest](validation-manifest.json) and each host's `.integration`, `.files`, `.dav`, `.ftp`, `.smb`, `.smb3` and `.nfs` companion records.

Final full source digest: `47331f31c9362b358d927341f0498162878c00997af646d2973aa8ee206ae0f8`.
C++ implementation/build-definition digest: `da9bc15f98062e31fdd367b04fed2e9a8aee8ef5a44591c50de5252591074d93`.
Final NFS integration script: `31204526a352b306a5afbb2aa90c111e0972df73190488dcd34c6de8619ceed1`.
All three final NFS records carry that test digest. GCC's complete runner uses the final full digest. The Clang and Windows runner snapshots were taken at `a1a6a6d6cad4c1a4db7cf799c5abc19e42fca1d36c12e7617e145bf6808f39b8`, before the Python-only explicit SQLite close and test-digest field were added. C++ code did not change. The Clang runner executed the corrected NFS test; Windows reran that affected test separately. The final Windows source tree was compared byte-for-byte by hash with the workspace before its disposable NTFS checkout was removed. Historical failed reports are retained unchanged rather than relabeled as successful full runs.

The NFS payload SHA-256 is `7daca2095d0438260fa849183dfc67faa459fdf4936e1bc91eec6b281b27e4c2` on all three builds. Runner timestamps retain the host clock; the date above is the session's reporting date. Exact reproduction toolchains are in [toolchains.lock.json](../../../toolchains.lock.json); these are measured baselines, not immutable machine images.

## Failures investigated

The first [Windows full attempt](windows-msvc.initial-ftp-failure.json) stopped in the pre-existing FTP passive-port exhaustion fixture with `425 Passive ports exhausted`. An isolated rerun passed with unchanged production port/timeout policy. The exact cause was not established; the failed attempt is not hidden or counted as a pass.

That rerun passed M1–M6 and the M7 native tests, then failed while deleting the final NFS fixture's backup database. Python's SQLite transaction context had not closed its connection, which Windows correctly kept open. The test now closes it explicitly in `finally`. The entire affected NFS integration suite then passed on Windows; no server workaround or timeout change was made.

During development, fault injection exposed a real NFS short-write acknowledgement bug. The adapter now loops over actual native bytes written, checks authorization between writes, and flushes before success. Injected disk exhaustion produces an error, retains accurate partial quota accounting and rejects uncertain replay. Directory tests also exposed stale shared index entries after external replacement; namespace reconciliation and relocation quota reconciliation were added and verified.

## Open release gates

V4.1 mandatory operation/state semantics, POSIX byte locks and lock reclaim, share-deny/open upgrade coordination, precise directory changes/cache semantics, exclusive create and replacing/unlinked-open handling remain incomplete. V3 NLM/NSM is absent. Full MOUNT/rpcbind behavior and system-client discovery are not claimed. The service is loopback TCP only; the testing does not require 2049/111, a kernel mount, privileged handle reopening or changes to host services.

Kerberos/GSS, delegated/persistent state, multi-export sessions, stress, large-file replay-cache capacity, storage rollback/cloning, sudden power-loss tests and complete Linux/macOS/eligible Windows client matrices are unverified or unimplemented as documented. Windows directory namespace durability retains the M2 limitation. These gaps keep the overall M7 milestone open even though the selected tests pass.

中文摘要：三种原生构建均通过 58 项 M7 单元检查和 15 个 NFS 场景；Windows 的既有 FTP 首次失败与 NFS 测试清理失败均保留原始记录，修正测试连接关闭后重跑通过。这里使用 pynfs 生成的独立编解码器，不等于跑过完整 pynfs 或系统 NFS 客户端矩阵。锁恢复、NLM/NSM、必需操作等仍未实现完整，M7 不能标记为全部完成。
