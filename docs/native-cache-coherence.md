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
checks passed. The [native core step at `4fe2b79`](evidence/pre-m8/native-cache-4fe-remote.json)
passes GCC, Clang ASan/UBSan and Windows MSVC. Subsequent protocol regression
was still in progress when this result was recorded. The [local evidence](evidence/pre-m8/native-cache-local.json) identifies
the exact source hashes. The existing SMB metadata matrix executes this core
test before its protocol tests on GCC, Clang and MSVC.

## File-domain authority

`file_cache.inc` now owns the cache grant beneath SMB. Only an authenticated
SMB caller with the matching actor, space, path and writable/readable open can
acquire it. Directory and delete-pending opens cannot acquire this authority.
Each acquisition gets a new random cookie; polling, acknowledgement and
voluntary release must identify that exact acquisition. Repeating acquisition
does not reset an outstanding break. An ACK without a pending break is rejected.

Conflicting SMB/core opens and native NFS handle resolution trigger recall.
The existing holder can still write and flush through its descriptor while
the contender waits. Unconditional DAV lock checks no longer reopen that same
file merely to evaluate absent HTTP conditions. Native lease conflicts are
distinguished from byte locks; NFS maps cache recall to DELAY/JUKEBOX.

Authority expires at the signed grant's lifetime (at most 2.5 seconds), measured
with a monotonic timer. A fresh authenticated poll renews that authority but
cannot extend the separate five-second break deadline. The actual file worker
runs maintenance independently of IPC. Timeout, native failure or revocation
fences the entire open and removes its locks/waiters before another writer can
proceed; it does not leave an old handle able to flush stale client data.
Close, worker recovery and voluntary release also clean up native exclusion.
Linux caching is declined when the kernel break interval is unavailable or
below ten seconds; the setting is never modified.

The [coordinator's local evidence](evidence/pre-m8/cache-authority-local.json)
includes direct SMB/core/NFS conflicts, independent files, invalid callers and
cookies, ACK/flush visibility, real expiry, five seconds of fresh polling that
cannot prevent recall, revocation/recovery, and an actual file-worker process
which receives no IPC while native access waits for autonomous expiry.
This internal authority is not yet called by SMB CREATE, so network clients
still receive no caching grant. Wire-level pending operations and break/ACK
acceptance remain necessary before enabling that grant.

## Remaining integration

The coordinator's namespace and complete cross-protocol behavior still need
wire-level acceptance. SMB still needs signed/encrypted unsolicited breaks, ACK
validation, asynchronous conflicting operations, cancellation and disconnect
cleanup. NFS still needs delegation state, recalls and revocation. Linux's
finite kernel break deadline and namespace changes need explicit treatment.
Passing these native tests alone cannot enable network caches or close the
full compatibility gate.

References: [Linux file leases](https://www.man7.org/linux/man-pages/man2/F_SETLEASE.2const.html),
[Windows oplock requests](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock),
[Windows break semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/breaking-oplocks),
[acknowledgements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/acknowledging-oplock-breaks).
