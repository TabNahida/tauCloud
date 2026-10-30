# M6 validation — SMB3 backend profile

Acceptance notes: 2026-10-30. Scope: [M6 English](../../m6.md), [简体中文](../../m6.zh-CN.md), [ADR 0009](../../decisions/0009-smb3-security.md). JSON timestamps preserve the runner host clock.

The final source digest is `3dff0de6346aa92dcf9c24556cbe2dbd7101f1b76bd271572c5bdc3a6503e55b`. The runner hashes `src`, `include`, `apps`, `tests`, `scripts`, `packaging`, `xmake.lua` and `dependencies.lock.json`; documentation/evidence and Python bytecode caches are excluded. M5 historical evidence is retained unchanged.

## Recorded matrix

All three frozen-source M1–M6 matrices passed. The 21 JSON files include three main command/stdout/stderr reports and six companion integration reports per host.

| Host / build | Native M6 assertions | M6 workflows | Encrypted stream, each SMB3 dialect |
| --- | --- | --- | --- |
| Ubuntu 24.04.4 / WSL2 6.18.40.1 / ext4 / GCC 13.3 release | 509 passed | 14 passed | 17 MiB, SHA-256 matched |
| Same Linux host / Clang 18.1.3 debug / ASan + UBSan | 509 passed | 14 passed | 1 MiB, SHA-256 matched |
| Windows 11 25H2 / 26200.9457 / NTFS / MSVC 14.51.36231 | 509 passed | 14 passed | 17 MiB, SHA-256 matched |

Reports: [GCC](linux-gcc.json) / [SMB3](linux-gcc.smb3.json), [Clang](linux-clang.json) / [SMB3](linux-clang.smb3.json), [MSVC](windows-msvc.json) / [SMB3](windows-msvc.smb3.json).

17 MiB SHA-256: `ec50baf7fce21cbdb746f461b49328154ecce497b9fb1f5675ee13704c605bc4`. 1 MiB SHA-256: `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`. The locked xmake/PACE/recipes/OpenSSL baseline is verified by each runner; toolchains are recorded in [the toolchain lock](../../../toolchains.lock.json).

## What the M6 checks establish

The native executable has **509 assertions**, including NIST AES-CMAC known-answer vectors, independently generated SP800-108/SHA-512/CCM/GCM vectors, every-byte transform mutation rejection, wrong session/key/cipher rejection, independent 2.1/3.0/3.0.2 selection/validate checks, and truncated/invalid 3.1.1 negotiate-context parsing. These are assertions, not 509 separately advertised protocol features.

The **14 integration workflows** use unchanged smbprotocol 1.15.0 / pyspnego 0.12.4 plus independent cryptography wire probes:

- Each of 3.0, 3.0.2 and 3.1.1 independently authenticates and exercises AES-CMAC signed operations; 3.0/3.0.2 validate-negotiate succeeds.
- Each independently encrypts Unicode create/read/write/flush, metadata/EOF, rename/delete, related CREATE/WRITE/READ/CLOSE, authenticated `srvsvc` enumeration and a streamed SHA-256 roundtrip.
- Default negotiation selects 3.1.1; a CCM-only 3.1.1 client works; ordinary modern offers select GCM. Encryption-required clients succeed.
- Lease/durable contexts return no grants, durable reconnect and CHANGE_NOTIFY are explicitly unsupported, and multichannel is not advertised.
- Simultaneous signed 2.1 and encrypted 3.1.1 sessions see writes immediately and share mandatory byte locks through the file authority.
- Unsupported cipher/signing/hash offers and malformed contexts fail without dialect fallback. A hash-overlap failure returns its dedicated SMB status.
- Independent CCM/GCM decoding verifies encrypted replies; replayed encrypted ECHOs fail for all three dialects.
- Modified tags, ciphertext, AAD, session ID, original length, nonce padding, signatures, unsigned requests, changed preauthentication chain and reused nonce with a fresh MessageId close the connection. Invalid 3.0 validation and forbidden 3.1.1 validation also close it.
- A fatal validation error followed by an unrelated signed WRITE in the same compound cannot mutate the file. A new exclusive open acts as a cleanup barrier before asserting the file remains empty.
- Killing only the SMB worker invalidates the old encrypted session, reaps committed delete intent, leaves other workers running and permits fresh encrypted authentication/reopen with preserved file data.

M1–M5 regressions retain their previous functional coverage (native checks 29/35/28/18/80; integration groups 15/10/11-or-10/11/9). Linux M3 includes litmus 0.18, 105 passing checks. The previous milestones' docs define these tests; WebDAV litmus is not an SMB torture suite.

## Limits and issues found during development

All listeners use randomly selected loopback ports, not 445. The Windows path is a disposable NTFS checkout with native MSVC binaries and Windows SSPI through sspilib 0.6.0; the Linux path uses native ELF binaries and pyspnego NTLM. These are independent Python SMB clients on both hosts, not Windows Explorer, Linux kernel mounts or macOS Finder. Samba `smbclient`/`smbtorture` and the complete system-client matrix remain untested.

Release runs use a 256 MiB process budget; ASan/UBSan uses 512 MiB. A 17 MiB stream is below those budgets and is not evidence of a greater-than-memory transfer or long-running soak. The 65,536 encrypted-frame limit, 32-connection saturation and automatic client recovery at limits are not load-tested. Persistent handles, leases, notification and multichannel remain unsupported.

Development probes exposed a real compound-dispatch bug: a fatal secure-negotiation failure closed the transport but could still execute a later unrelated command in the same compound. The final implementation stops dispatch immediately; its regression was observed failing before the fix and passing after it. The final selected profile includes that regression. An intermediate Windows M2 regression also hit a monitoring RPC deadline while three matrices shared the host; the final Windows run passed separately without changing that timeout or weakening the check. The transient failure remains documented here rather than being treated as a protocol failure or hidden by a retry inside the test.

Encryption remains optional on the server; clients must require it to obtain confidentiality and prevent falling back to unencrypted compatibility. No claim is made that legacy 2.1 acquires 3.1.1 preauthentication guarantees.

## Reproduce

```sh
.deps/smbprotocol-venv/bin/python scripts/run_m6.py --compiler gcc --large-mib 17 --litmus build/litmus/installed/bin/litmus
.deps/smbprotocol-venv/bin/python scripts/run_m6.py --compiler clang --mode debug --sanitizers --litmus build/litmus/installed/bin/litmus
```

For native Windows from WSL, run `scripts/windows_m6.ps1`; it copies the pinned dependencies and source into a temporary NTFS checkout, installs `tests/smb-requirements.txt` in an isolated environment, runs the release matrix and copies JSON reports back. No production services, certificate stores, disks or firewall rules are changed.
