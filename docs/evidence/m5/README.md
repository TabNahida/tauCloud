# M5 validation evidence / 验证记录

The bounded signed SMB 2.1 backend profile is implemented. These runs validate the stated subset, not complete SMB conformance or the full client-matrix release gate. 本目录证明有界 SMB 2.1 后端的已测试功能，不代表完整协议或完整客户端矩阵验收。

Final source fingerprint (the runner hashes `src`, `include`, `apps`, `tests`, `scripts`, `packaging`, `xmake.lua` and `dependencies.lock.json`):

`a4c5efc0d99839f17c58bf3fbe2fb07832dfc462cf5983de0585992ce02f3a02`

| Host / build | Native M1 / M2 / M3 / M4 / M5 checks | M5 workflows | SMB transfer |
| --- | --- | --- | --- |
| Ubuntu 24.04.4, WSL2 6.18.40.1, ext4, GCC 13.3 release | 29 / 35 / 28 / 18 / 80 | 9 passed | 17 MiB, SHA-256 matched |
| Same Linux host, Clang 18.1.3 debug, ASan + UBSan | 29 / 35 / 28 / 18 / 80 | 9 passed | 1 MiB, SHA-256 matched |
| Windows 11 25H2 / 26200.9457, NTFS, MSVC 14.51.36231 | 29 / 35 / 28 / 18 / 80 | 9 passed | 17 MiB, SHA-256 matched |

Each main JSON report contains exact commands, return codes, stdout/stderr, locked dependencies and the same source fingerprint. Companion reports retain M1 integration (15 checks), M2 (10), M3 (11 on Linux including litmus / 10 on Windows), M4 (11) and M5 (9). Linux ran the existing litmus 0.18 suite; its 105 passes concern WebDAV, **not** SMB torture. Windows uses a disposable native NTFS checkout, not execution from the WSL UNC source tree.

- [Linux GCC](linux-gcc.json) · [SMB integration](linux-gcc.smb.json)
- [Linux Clang + sanitizers](linux-clang.json) · [SMB integration](linux-clang.smb.json)
- [Windows MSVC](windows-msvc.json) · [SMB integration](windows-msvc.smb.json)

The 17 MiB SMB payload hash on both release hosts is `ec50baf7fce21cbdb746f461b49328154ecce497b9fb1f5675ee13704c605bc4`. Clients stream 64 KiB requests. Tests configure 256 MiB worker budgets on release and 512 MiB for sanitizers. This transfer does not exceed host RAM or establish a maximum-memory/soak guarantee.

## What was exercised

The independent protocol client is smbprotocol 1.15.0 / pyspnego 0.12.4, pinned with dependencies in `tests/smb-requirements.txt`. Linux uses pyspnego's NTLM implementation. Windows uses sspilib 0.6.0 / native SSPI. Windows tests also exercise user-scoped DPAPI vault protection. These libraries are test clients only; the server is native C++/PACE.

- M4 identity/file schemas and missing SMB IPC key migrate with backups; credentials are AES-GCM ciphertext in SQLite.
- NTLMv2 MIC, raw NTLM and SPNEGO, required HMAC-SHA256 signatures, UTF-16 names, arbitrary binary reads/writes, FLUSH, directory and file information queries, Unicode wildcard matching and the default data stream.
- Authenticated IPC$/srvsvc NDR32 bind and level-1 share enumeration through both named-pipe READ/WRITE and FSCTL_PIPE_TRANSCEIVE; inaccessible/private and non-SMB shares are absent. The bounded DCE/NDR probe is test-owned; it is not a Samba RPC conformance suite.
- Bidirectional share-mode conflicts, shared/exclusive byte locks, rollback of failed lock vectors, rename with live handles, EOF truncation, pending-delete denial and final-close deletion. Native tests additionally recover a persisted deletion after destroying the file-authority instance.
- Signed related CREATE/WRITE/READ/CLOSE compounds, credit accounting, nonrecursive directory deletion, traversal/ADS/non-NFC rejection and explicit unsupported security descriptor queries.
- Bad MIC/proof, unsigned or tampered packets, oversized/truncated framing and invalid compound offsets fail closed. Malformed probes use disposable accounts and pyspnego-generated tokens, not a replacement server.
- Separate SMB credential removal invalidates live file access; re-enrollment reconnects. Killing only the SMB process preserves API, identity, file and DAV PIDs, reclaims old handles, completes pending deletion and permits fresh connections.
- Native crypto vectors, strict Unicode/DER bounds, ciphertext tamper/AAD checks, invalid configuration, quota failures, partial native writes, injected disk-full and uncertain-write retry behavior.

## Explicit limits and remaining gate

Not run: Windows Explorer/system redirector at 445, Linux kernel CIFS mount, macOS Finder/kernel client, Samba smbclient/smbtorture, broad fuzzing, overload/soak or power-loss campaigns. Those client environments/tools were not part of these runs. Do not infer their compatibility from smbprotocol/SSPI success. The TODO client-matrix item remains open. M4's FileZilla gate is also unchanged.

All SMB tests used alternative loopback ports. No system SMB service, firewall, certificate store or real storage was modified. Windows' existing port-445 service was left in place. Native tests and integration fixtures clean up disposable data/services; final Windows scratch output was copied into these reports before cleanup.

SMB3/encryption, SMB 2.0.2, Kerberos, guest, oplocks/leases/durable reconnect, persistent ACLs, arbitrary attribute/timestamp writes and general administrative RPC remain unsupported. Metadata timestamps/attributes are a documented conservative projection. See [M5 English](../../m5.md), [M5 中文](../../m5.zh-CN.md), and [ADR 0008](../../decisions/0008-smb-profile.md).

During implementation, independent clients exposed raw-NTLM versus SPNEGO wrapping and non-UTF-8 write-fingerprint bugs; both were fixed before the recorded runs. An initial recovery test incorrectly assumed a restarting process always had a PID; it now waits for `running` before reading identity. Final reports are full reruns on the fingerprint above, not stitched pass fragments. Compiler warnings for OpenSSL's legacy NTLM MD4/RC4 APIs are expected; the implementation deliberately does not enable legacy TLS provider algorithms globally.
