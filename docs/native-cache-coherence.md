# Native cache exclusion

Native exclusion now backs SMB EXCLUSIVE, BATCH and Level II oplock grants,
downgrade and invalidation on eligible regular-file opens. Complete BATCH timeout
and namespace behavior, SMB leases, directory caching and NFS delegations remain unfinished. Full SMB/NFS compatibility
remains open.

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
and the complete targeted protocol matrix pass GCC, Clang ASan/UBSan and
Windows MSVC. The separate Windows native NFS workflow also passes. These
results precede the coordinator increment below. The [local evidence](evidence/pre-m8/native-cache-local.json) identifies
the exact source hashes. The existing SMB metadata matrix executes this core
test before its protocol tests on GCC, Clang and MSVC.

## File-domain authority

`file_cache.inc` now owns the cache grant beneath SMB. Only an authenticated
SMB caller with the matching actor, space and path can acquire it. EXCLUSIVE
requires a writable/readable open and current write authority. Level II
also admits read-only opens, including read-only shares, with no write-authority renewal. Directory and delete-pending opens cannot acquire this authority.
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
The coordinator now passes the complete GCC/Clang ASan+UBSan/MSVC matrix at
`9b32f48` ([fixed-source evidence](evidence/pre-m8/cache-authority-9b-remote.json)).
SMB CREATE now uses it for EXCLUSIVE grants as described below. The separate
Windows backend DAV-after-restore and M8 fake-engine failures in that evidence
are still explicit; targeted success does not imply those workflows passed.

## Asynchronous related SMB operations

The SMB transport now retains dependent operations after an asynchronous LOCK,
CHANGE_NOTIFY or cache-blocked CREATE. Each operation has its own nonzero
AsyncId and interim response. Later operations execute only after their
predecessor finishes, using the resulting FileId and tree. Final replies use
the owning session's signing/encryption keys and grant no additional credits.
A resumed LOCK/CHANGE_NOTIFY can itself wait without changing its announced ID.
Notification order follows registration order, independently of those IDs.

CANCEL by AsyncId or MessageId, predecessor failure, tree/session teardown and
revocation complete or discard the dependent work without executing its writes.
The transport bounds retained commands to 128 and request bytes to 1 MiB.
Cache-blocked CREATE, WRITE, LOCK and metadata retries reauthorize and have a ten-second monotonic
retry deadline. Authentication continuations remain in their dedicated flow;
a SESSION_SETUP dependent on a waiting operation is explicitly refused.

Independent clients exercise signed SMB 2.1 and encrypted SMB 3.0/3.0.2/3.1.1
chains, nested waits, cancellation, generated/inherited FileIds, teardown,
notification FIFO and resource exhaustion in
`tests/smb_compound_async.py`. [Local evidence](evidence/pre-m8/smb-compound-async-local.json)
records the exact source hashes and results. This verifies transport continuation;
the subsequent wire-oplock tests below also exercise actual cache-blocked CREATE
and related READ/CLOSE continuation.

The continuation follows Microsoft's
[related compound processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46dd4182-62d3-4e30-9fe5-e2ec124edca1)
and [asynchronous interim response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c1692ece-7c6d-45c8-a0e3-6b53c0483030)
rules.

## SMB EXCLUSIVE data-oplock wire integration

An explicit EXCLUSIVE request on a writable regular-file open with both READ_DATA
and WRITE_DATA may now receive an EXCLUSIVE grant if the file domain obtains
native exclusion. Read-only opens, directories, delete-on-close and conflicting
native access receive NONE for EXCLUSIVE requests. Explicit Level II requests
can receive shared read caching as described below. BATCH/lease requests are not granted yet.
An incompatible sharing request fails without recalling the existing cache.
An attribute-only OPEN/OPEN_IF (READ_ATTRIBUTES, WRITE_ATTRIBUTES, SYNCHRONIZE)
against a cached file retains its pinned native description and receives NONE
without recalling data. The new handle still checks the DACL, space write policy,
create options and its own granted rights. It cannot read/write file data.
Actual attribute changes recall before mutation; metadata CLOSE does not release
the holder's cache. This exception does not apply to MAXIMUM_ALLOWED, truncation
or delete-on-close.

The front end renews authority every 250 ms using fresh identity grants. A
separate coroutine, which never waits for RPC or the dispatch gate, closes a
cache-bearing transport before its authority or fixed recall deadline expires.
A stalled RPC, slow socket or repeated fresh grants cannot prolong recall.
CREATE replies precede any break for their new FileId.

Break notifications use command 18, MessageId UINT64_MAX, TreeId zero, zero
credits and the owning session/FileId. Unencrypted breaks are unsigned as
recommended by MS-SMB2 3.3.4.6; in particular the fixed MessageId is never reused
as an AES-GMAC signing nonce. Encrypted opens receive authenticated encrypted
breaks with fresh transform nonces. Client ACKs still pass ordinary session,
tree, FileId and signing/encryption validation. An unsolicited or duplicate ACK
returns INVALID_DEVICE_STATE; a foreign handle returns FILE_CLOSED. A reply to
a completed Level II no-ACK break returns INVALID_OPLOCK_PROTOCOL. EXCLUSIVE
can recall to NONE or downgrade to Level II. Invalid classic ACK levels
release the native recall and return the appropriate protocol error.

The holder can write/flush while a competing CREATE waits. ACK flushes native
file data before admitting the contender. SET_INFO and directory enumeration
recall affected caches before mutations/enumeration; their asynchronous retries
cannot replay a mutation that occurred before the recall boundary. Closing the
holder completes recall; CANCEL drops the waiter; timeout, credential revocation,
worker-authority loss and disconnect invalidate the old open.

[Local wire evidence](evidence/pre-m8/smb-oplock-local.json) covers four dialects,
same-transport and related CREATE/READ/CLOSE waits, nested session keys, CANCEL,
ACK ownership, sharing denial, unsupported grants, native host reads/writes,
SET_INFO ordering, NFSv3 JUKEBOX retries, DAV retries, revoked credentials and
an identity process paused while a polling RPC holds the dispatch gate. Windows
native probes use CreateFileW with DELETE sharing, avoiding a CRT sharing
violation unrelated to oplocks. The targeted Actions matrix now includes these
checks plus original Samba exclusive1/exclusive3 sharing scenarios and the
exclusive4 attribute-only scenario. At `5a78b29`, the independent wire checks
pass all three platforms (24 Linux / 23 Windows), while the targeted Linux
jobs fail original exclusive3: a MAXIMUM_ALLOWED open recalled before failing
sharing. [Remote evidence](evidence/pre-m8/smb-oplock-5a-remote.json) preserves
that failure. The corrected ordering resolves effective rights and sharing
from pinned security metadata before recall; original exclusive1/3/4 now pass
locally and on GCC/Clang at `4420774`. The same targeted run fails on Windows
when an initial NFS EXCHANGE_ID times out, before its wire-cache tests.
[Fixed-source evidence](evidence/pre-m8/smb-shared-cache-442-remote.json) preserves
that failure; it is not considered fixed.

The attribute-open increment adds four independent dialect groups (28 total on
Linux; 27 scheduled on Windows), including a second transport, share-none, query/close,
data-access rejection and deferred attribute mutation. File-domain tests also
check an explicit deny ACE and read-only policy on the retained path. See
[local acceptance](evidence/pre-m8/smb-oplock-attributes-local.json). Remote
acceptance remains pending.

## Shared read-cache authority (file domain)

The file domain can now retain the native exclusion guard when EXCLUSIVE
acknowledges a downgrade to Level II. Other authorized read-cache opens share
that same guard, with distinct cookies and authority deadlines. Physical
retention never removes logical sharing, DACL or per-handle access checks.
Existing data opens also prevent an acquisition from claiming EXCLUSIVE merely
because their descriptors refer to the same underlying native description.

Writes and byte locks invalidate all affected read caches before any mutation.
A stricter conflict cannot extend the original five-second recall deadline.
Acknowledging or closing one reader releases only its participation. Native
exclusion remains until the final reader acknowledges, closes or is fenced;
expiring a reader also invalidates its open before any later write. Metadata-only
opens retain the no-break behavior across multiple readers. EXCLUSIVE write
cache renewal still requires current write authority.

[Local coordinator evidence](evidence/pre-m8/smb-shared-cache-local.json) covers downgrade,
shared and read-only acquisition, denied writes, full-group invalidation,
last-reader release, individual expiry, retained-descriptor reacquisition and
actual conflicting native opens. This coordinator now backs the Level II wire
integration below.

## Level II wire integration

Explicit Level II CREATE requests can receive read caching. A compatible cached
CREATE against EXCLUSIVE recalls it to Level II: the holder flushes and ACKs,
then both opens share native exclusion. Ordinary readers can coexist without
recall; a writer that needs a physically writable descriptor first invalidates
a group backed by a read-only descriptor. Network rights are never expanded by
retaining a native description. Windows RW kernel exclusion is requested even
for a read-only handle; unsupported native grants still return NONE. Read-cache
release/close never attempts a write-only native flush.

WRITE and LOCK invalidate every affected Level II holder before acting. Each
transport sends its authenticated notification, then releases its file-domain
participation without waiting for a client ACK, as required by
[MS-SMB2 client break processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7bfe0275-5aff-4b63-b683-a0bae96bdb57).
Native exclusion survives until the last notification/close/fence. Related
WRITE/READ/CLOSE continuation preserves order and final responses grant no extra
credits. CREATE responses precede their cache notifications.

A native writer or cached byte-lock flush can tighten a pending EXCLUSIVE-to-II
downgrade. The original ACK remains valid, but the same fixed recall deadline
survives and a second II-to-NONE notification follows. Cached locks preclude a
new shared read-cache grant. CANCEL drops the waiting operation without
cancelling the holder's required downgrade. SET_INFO delete-pending and
DELETE_ON_CLOSE preserve existing read caches until last close; sticky ownership
checks use the pinned native identity without triggering an incidental open.

[Local Level II evidence](evidence/pre-m8/smb-level2-local.json) includes four
dialects, independent transports, actual native writers, read-only-share renewal,
locks and downgrade races, cancellation, compound writes and both deletion modes.
The full unmodified Samba oplock diagnostic is retained with every failure.
The earlier eight selectors exclusive1/2/3/4/5/9 and levelii500/501 remain in remote
acceptance alongside the independent wire tests. Level II passes the complete
GCC/Clang/MSVC targeted matrix at `07a7fe5` ([evidence](evidence/pre-m8/smb-level2-07-remote.json));
the newer overwrite/BATCH acceptance is separate. These cache steps continue after unrelated test failures when the build
succeeded, while the job retains its original failure status.

## Overwrite and shared native descriptions

Existing-file SUPERSEDE, OVERWRITE and OVERWRITE_IF add the unnamed stream's
implicit access rights before DACL and sharing checks, as required by
[MS-FSA 2.1.5.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/41f3734a-5bba-4c3b-9d04-7baafc9b7bfe).
They require WRITE_EA and WRITE_ATTRIBUTES plus DELETE for supersede or
WRITE_DATA for overwrite. MAXIMUM_ALLOWED cannot silently drop these required
rights. Read-only files and mismatched hidden/system attributes reject the
operation before recall or truncation. This does not implement the outstanding
backup/restore privilege bypasses.

After authorization and recall, SMB opens can retain an existing native file
description with the same object identity and sufficient physical write access.
This avoids a self-created kernel conflict when granting Level II after an
overwrite. Network access, sharing, locks and cache cookies remain per open.
Level II itself does not grant READ_DATA: an attribute-only overwrite can receive
the oplock while READ remains denied. The original handle's next WRITE recalls
that new cache before touching the shared description.

[Overwrite evidence](evidence/pre-m8/smb-overwrite-local.json) records independent
four-dialect checks, rejection without recall/data loss, metadata/allocation
regressions, and the complete unmodified oplock diagnostic (8 passed, 34 failed).
Original exclusive5 and exclusive9 now pass. Exclusive6's expected parent-DELETE
sharing violation follows the older Windows behavior described in
[product note 185](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4e3695bd-7574-4f24-a223-b4679c065b63);
the current rename algorithm permits that destination-directory open. Its raw
failure remains visible, and later cache assertions in that case remain unproved.

## BATCH handle caching

BATCH grants now retain the server open until a cached CLOSE, acknowledged
downgrade, teardown or fencing. Unlike EXCLUSIVE, a conflicting BATCH open
recalls before access/sharing checks: the holder may close its cached handle and
remove the conflict. If it ACKs Level II while keeping incompatible sharing,
the waiting open fails sharing after the ACK. The same conflict does not recall
the remaining Level II cache again. This follows the BATCH ordering in
[MS-FSA open](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/41f3734a-5bba-4c3b-9d04-7baafc9b7bfe)
and [oplock breaks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/306239fb-cb60-49fe-b293-df4d1a5f757a).

CREATE type/parameter validation precedes BATCH recall. Attribute-only preserving opens do not recall BATCH; attribute-only creation
can itself receive BATCH without acquiring data rights. Read-only BATCH grants
use read authority for renewal and skip write-only native flush operations.
Compatible data opens downgrade to shared Level II; overwrite recalls to NONE.
Native data conflicts, cached-lock flushes during downgrade, cancellation,
ACK ownership, close and fixed deadlines use the shared coordinator.
DELETE_ON_CLOSE can receive BATCH: a recalled cached CLOSE activates deletion,
and a waiting OPEN observes the missing file. Original session replacement and
failed-reauthentication cleanup cases now exercise these cached deletion handles.

[Local BATCH evidence](evidence/pre-m8/smb-batch-local.json) includes 37 independent
groups across four signed/encrypted dialects, 40 Level II and 28 EXCLUSIVE
regression groups, 12,573 SMB core checks and 98 NFS core checks. The complete
original oplock suite now passes 35/42 with no skips. The seven failures remain:
exclusive6/batch19/batch20 (old parent-directory sharing expectation),
batch22a (same-transport unacknowledged timeout recovery), batch22b (requires
Samba's test-only transport-blocking FSCTL or an external firewall setup), and
batch26/stream1 (alternate data streams). Neither those differences nor their
later unexecuted assertions count as passes. Cross-platform BATCH acceptance
is pending. The native primitive still guarantees data exclusion only; the
new BATCH state does not add host-level namespace exclusion to Linux leases or
Windows RW oplocks.

## Remaining integration

BATCH same-transport timeout recovery, SMB leases, complete namespace/handle caching, remaining Level II/exclusive
transitions and the complete
original Samba suite still need implementation and evidence. NFS still needs
delegation state, recalls and revocation. Linux's finite kernel break deadline
and namespace changes need explicit treatment for handle/delegation caching.
The implemented data-cache paths do not close any of these broader compatibility gates.

References: [Linux file leases](https://www.man7.org/linux/man-pages/man2/F_SETLEASE.2const.html),
[Windows oplock requests](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock),
[Windows break semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/breaking-oplocks),
[acknowledgements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/acknowledging-oplock-breaks).
