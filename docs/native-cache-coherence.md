# Native cache exclusion

This is an implementation prerequisite for SMB oplocks/leases and NFS
delegations. It does **not** grant any network cache authority yet. Full
SMB/NFS compatibility remains open.

`native_file::cache_guard()` pins the same native object as the open file.
Successful acquisition excludes conflicting native data access, including
ordinary opens outside tauCloud. A null result means the caller must decline
caching. `breaking()` is nonblocking; `release()` admits the contender after
the holder has flushed its dirty data. Destruction also releases the guard.
Retaining the file cannot create a second guard on the same native description.
Callers serialize guard acquisition, release and file operations.

| Host | Mechanism | Current guarantee and limits |
| --- | --- | --- |
| Linux | `F_SETLEASE` read/write leases | Native conflicting opens/truncates wait. Read leases permit other read-only opens. The kernel may force a break after `lease-break-time`; the protocol must establish a safe recall deadline before granting network caching. Namespace operations are not protected. |
| Windows | `FSCTL_REQUEST_OPLOCK`, RW | Conflicting data access waits for acknowledgement. An overlapping request stays alive until break/cancellation completion. R/RH-only caching is declined because a write can proceed without waiting for its acknowledgement. No network handle-caching guarantee is implied. |

Linux reserves SIGIO only when no application handler owns it and reads the
kernel break target with `F_GETLEASE`. Confined opens use `O_NONBLOCK` so the
file worker can return `locked` instead of blocking the worker that must
process the cache holder's flush.

Windows converts an eligible file description to overlapped I/O through
`ReOpenFile`, retaining native identity and existing shared references. It
does not reopen a pathname. Per-operation events and explicit offsets preserve
ordinary reads, writes and sparse allocation. Confined opens use
`FILE_COMPLETE_IF_OPLOCKED`: its positive `STATUS_OPLOCK_BREAK_IN_PROGRESS`
result is closed and returned as `locked`, never treated as permission to read
unflushed data. Voluntary release cancels only the guard's request, waits for
completion and handles a break that wins the cancellation race. A pending
break is acknowledged to NONE. Release failure closes the shared descriptor
instead of leaving an undisclosed exclusion behind.

## Acceptance

`tests/m2_core.cpp` checks actual blocking native opens, holder writes/flushes,
release visibility, retained descriptors, conflicting existing opens, repeated
idle cancellation, reads at EOF, offsets above 4 GiB, sparse writes,
allocation/truncation and timestamp changes. Linux additionally checks shared
read leases and a writer-triggered break. Windows uses blocking `CreateFileW`
with DELETE sharing rather than MSVC fstream's incompatible share mode.

Local Clang ASan/UBSan/LSan: 75 M2 checks, 12,422 SMB core checks and 98 NFS core
checks passed. Windows implementation acceptance is pending the remote MSVC
job. The [local evidence](evidence/pre-m8/native-cache-local.json) identifies
the exact source hashes. The existing SMB metadata matrix executes this core
test before its protocol tests on GCC, Clang and MSVC.

## Remaining integration

The file-domain coordinator must recall caches before any conflicting
cross-protocol operation and prevent stale handles from flushing after
revocation. SMB still needs signed/encrypted unsolicited breaks, ACK
validation, asynchronous conflicting operations, cancellation and disconnect
cleanup. NFS still needs delegation state, recalls and revocation. Linux's
finite kernel break deadline and namespace changes need explicit treatment.
Passing these native tests alone cannot enable network caches or close the
full compatibility gate.

References: [Linux file leases](https://www.man7.org/linux/man-pages/man2/F_SETLEASE.2const.html),
[Windows oplock requests](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock),
[Windows break semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/breaking-oplocks),
[acknowledgements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/acknowledging-oplock-breaks).
