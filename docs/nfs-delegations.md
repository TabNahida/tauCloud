# NFS delegation implementation

Full delegation support remains an open compatibility requirement. The protocol
engine now implements READ delegation state, CB_RECALL, return and revocation,
and has component tests using an injected native file-domain provider. The
production file authority still declines wire handout: acknowledged native
protection through the complete reply lifetime, worker replacement and reclaim
remain unfinished. Linux 6.19 native namespace protection and retention across
file-worker death now have component acceptance; Windows equivalents remain open.
There is no configuration switch that bypasses this production gate. Component
passes below are not end-to-end delegation or complete RFC conformance.

Linux [F_SETLEASE](https://man7.org/linux/man-pages/man2/F_SETLEASE.2const.html)
documents open/truncate exclusion. The newer
[F_SETDELEG](https://man7.org/linux/man-pages/man2/F_GETDELEG.2const.html), introduced
in Linux 6.19, is now implemented by the native adapter and exercised in an
isolated Linux 6.19 guest. The development host remains on 6.18.40.1 and correctly
declines that API. Surviving-owner recovery and production file-authority
integration are still required before wire handout.

OPEN preserves the client's delegation preference independently of ordinary
READ/WRITE access. A request without new flags retains the legacy NONE reply.
Explicit preferences and availability hints receive NONE_EXT: NOT_WANTED for
NO_DELEG, CANCELLED for CANCEL, or RESOURCE with will_signal=false when no
native delegation authority is available. No pending want or future callback
promise is registered. Requesting WRITE delegation cannot turn a read-only
OPEN into a writable open. Invalid access/preference fields are rejected before
creating or truncating a file.

WANT_DELEGATION accepts the ordinary CLAIM_FH path without creating OPEN state.
It ignores data-access bits, rejects absent/NO_DELEG-only preferences, preserves
the current filehandle, reports IS_DIR for directory requests, and supports
idempotent cancellation. Previous-client recovery still returns NOTSUPP because
it requires DELEGPURGE and retained delegation state. Server-reclaim requests
return NO_GRACE outside recovery and RECLAIM_BAD when no matching delegation
was persisted. File-sensitive replies require current export authority,
including on slot replay. Unknown principals and revoked exports cannot obtain
cached replies through this operation.

The wire formats and behavior follow RFC 8881
[OPEN](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.16) and
[WANT_DELEGATION](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.49).
`tests/nfs_delegation_negotiation.py` checks all 72 OPEN access/preference/hint
combinations, exact XDR arms, ordinary access rights, invalid-request mutation
boundaries, standalone requests, cancellation, state/client cleanup and replay
authorization. The original pynfs DELEG4 is a mandatory Actions check. The full
unmodified `deleg` selection remains a diagnostic that retains failed grants,
callbacks and revocation tests. Passing negotiation does not close that gate.

Local Clang sanitizer acceptance passes seven independent negotiation groups,
nine discovery groups, five state/recovery groups, 1,537 core checks and eight
original OPEN/DELEG4 cases. The complete unmodified 13-case delegation selection
is **two passed, eleven failed**, compared with one passed/twelve failed before
the change. DELEG9 already passed without positive delegation handout; DELEG4
now verifies the explicit refusal. Both full logs and every failure remain in
[local evidence](evidence/pre-m8/nfs-delegation-negotiation-local.json).

## Required before granting a delegation

- Provide native protection for host metadata/namespace operations as well as
  data opens. Linux F_SETLEASE alone is insufficient for the former. The
  Linux F_SETDELEG adapter now passes actual data, attribute and namespace
  conflicts on tmpfs/ext4, including parent protection for directory rename.
  Integrate it with the surviving guard owner and file-domain conflict scopes;
  Windows still needs equivalent native namespace protection.
- Complete durable delegation reclaim, including server/client restart and
  file-domain failure. Recorded delegation ownership alone is not recovery.
- Validate authenticated CB_RECALL against independent Kerberos/SSV clients.
  The component suite currently covers AUTH_NONE callbacks, CLAIM_DELEG_CUR_FH
  and named CLAIM_DELEGATE_CUR with native namespace identity checks.
- Preserve exclusion through the required recall/revocation interval. The new
  configurable lease reconciles the advertised duration with the native bound;
  default settings still decline a native guard on a host with a 45-second
  kernel bound and the default 60-second NFS lease. Do not copy SMB's transport
  close behavior: an NFS delegation survives ordinary transport disconnection.
- Keep authorization revocation separate from coherence retention. Expired
  short-lived grants must deny data access, but releasing exclusion before the
  delegation can legally be revoked would expose incoherent cached reads.
  Worker crashes and missing callbacks require bounded recovery as well.

Read/write grants, native exclusion, recall, revocation, recovery, CB_GETATTR,
optional availability/push callbacks and the expanded native-client matrix are
still required for the Full SMB/NFS objective.

## File-domain native coordinator

`nfs_delegation` is a private IPC operation restricted to the NFS worker. Its
acquire/renew operations require a fresh signed export grant and file READ
permission. The opaque cookie binds the client, actor, export, root, space and
filehandle. Up to 256 records retain the exact native file incarnation and a
Linux lease or Windows RW oplock. Acquisition refuses existing file-domain
opens/locks and unavailable native exclusion. Native RW protection confers no
additional data-write permission.

The monotonic lifetime distinguishes active, recalling, returned, revoked and
expired state. Repeated conflicts and client renewal never extend the first
recall deadline. Explicit return, client lease expiry, or the end of a complete
recall interval releases exclusion. Terminal records remain visible until
forgotten and cannot be renewed. Polling does not renew the client lease.
Expired signed grants can inspect or clean up their own cookie; they cannot
read data, create state or perform ordinary authorized renewal. The private
`retain` operation preserves an already-held guard while initiating recall. It
checks the same caller, client, export, root, handle, actor and cookie binding,
never restores IO rights, and cannot extend the first recall deadline or revive
terminal state. This coherence-only path lets an active client return its state
after policy loss without exposing the file before its recall interval ends.
Policy revocation still denies IO immediately.

SMB, DAV and FTP file-domain conflicts initiate recall before opening the file;
NFS mutation through a retained filehandle does the same. Native conflicting
opens trigger the kernel break. NFS filehandle reads/metadata use the retained
incarnation and still perform normal grant/ACL checks. Pathname lookup resolves
the namespace independently and may request a recall. The primitive currently
serializes more access than a fully optimized shared READ delegation would.

`nfs_lease_seconds` accepts 5–3600 seconds, default 60. GETATTR lease_time,
client/session creation and renewal, callback renewal and GSS expiry warnings
use that value. Persisted lease history prevents a shorter configuration from
shortening old clients' recovery grace, including repeated restarts during
grace. Linux native acquisition additionally requires the host's existing
lease-break-time to be at least this duration plus five seconds; the service
does not modify the system setting. Native exclusion assumes that setting
remains stable during the guard's lifetime.

`tests/nfs_delegation_native.cpp` tests real exclusion, NFS reads, SMB/DAV/FTP
conflicts, permission boundaries, fixed recall deadlines, expiry, revocation
and cleanup. `tests/nfs_lease_lifetime.py` independently checks advertised lease,
renewal, session/state expiry and recovery after reducing the lease. Both are
mandatory in the GCC/Clang sanitizer/MSVC Actions matrix.

On supported Linux kernels the coordinator now uses the independent native
owner described below; older Linux and Windows retain the private local
primitive. Durable protocol ownership records exist, but network renewal
acknowledgment, reclaim and complete restart fencing remain open. The production
file authority therefore still refuses `wire:true` acquisition.

## Protocol state and recall components

The protocol uses a separate delegation stateid bound to client, filehandle and
principal. OPEN and WANT_DELEGATION can consume a provider-certified READ
guard; no new guard is published if a writer/deny-read open or byte lock exists.
READ delegation state permits READ, not WRITE. A deny-all delegation ACE keeps
per-user ACCESS checks necessary. Existing READ-to-WRITE upgrade requests get
NOT_SUPP_UPGRADE. CLOSE and transport loss do not discard the delegation.

Conflicting OPEN/lock requests recall and return DELAY. CB_RECALL uses the
existing authenticated callback transport and exact slot retry machinery.
Replies are checked against the actual queued operation, so a CB_NOTIFY_LOCK
reply cannot acknowledge a CB_RECALL. A successful callback only confirms
receipt. A definitive DELAY retries on a new callback sequence; malformed
replies preserve the old sequence until transport loss is confirmed.

DELEGRETURN releases the corresponding native cookie. A fixed recall timeout
produces DELEG_REVOKED even when SEQUENCE/callbacks keep renewing the ordinary
client lease. SEQUENCE advertises RECALLABLE_STATE_REVOKED until FREE_STATEID
acknowledges the marker; TEST_STATEID exposes it. Compatible ordinary OPEN
state remains valid. Renewal rechecks current identity scope, and policy loss
recalls using the original signed cleanup capability rather than dropping the
guard. Authenticated cleanup remains possible when ordinary access is denied.

`tests/nfs_delegation_protocol.cpp` first verifies that the real production
provider declines handout without creating a guard. Only then does its
test-only injected provider connect the actual native primitive to real RPC
messages. It checks exact OPEN/WANT replay, state isolation, read-only access,
CLOSE/disconnect lifetime, callback error/retry/return, revocation flags and
policy cleanup. The fixture explicitly does not simulate crash-safe exclusion
or claim successful delegation recovery. Actions runs this component suite on
GCC, Clang sanitizers and MSVC alongside the unchanged full pynfs diagnostic.

## Linux kernel delegation provider

`native_file::delegation_guard` uses the stable F_SETDELEG/F_GETDELEG UAPI even
when libc headers predate Linux 6.19. Unsupported acquisition returns no guard;
it never substitutes F_SETLEASE. READ permits compatible readers; WRITE needs
a writable descriptor and refuses conflicting opens. The guard shares the
exact native file incarnation, serializes ownership against ordinary cache
guards, detects requested breaks and supports explicit or RAII release.

The initial native directory test exposed a real gap: Linux 6.19
`vfs_rename`/`vfs_rmdir` break the containing directory's delegation, without
breaking the moved/removed directory's own delegation. The adapter therefore
retains both the directory and its immediate parent, verifies that parent
identity after acquisition, and declines a raced or unavailable acquisition.
Reacquisition after a cross-parent move follows `..` on the retained descriptor,
not an old pathname. The extra parent guard also recalls on sibling mutations;
future file-domain integration must account for this wider conflict scope.

`tests/native_delegation_kernel.cpp` exercises the real adapter in a separate
Linux 6.19 QEMU guest, with no network or host filesystem shares. Both tmpfs and
a disposable ext4 disk must pass. Forked processes perform ordinary host
syscalls: reads/writes, truncate, rename, unlink, chmod/chown, timestamps, xattrs,
hardlink creation, directory entry changes, cross-parent moves and rmdir. Each
conflict must signal recall, remain blocked, and complete after explicit release.
The suite also checks compatible readers, conflicting pre-existing opens,
duplicate ownership, release/reacquisition and retained-descriptor RAII cleanup.
The initial expanded local run passes 216 checks; its pinned-kernel Actions
run also passes ([remote evidence](evidence/pre-m8/native-delegation-kernel-c8-remote.json)). The original directory-rename failure
and corrected acceptance are retained in
[evidence](evidence/pre-m8/native-delegation-kernel-local.json).

`native-delegation.yml` builds a SHA256-pinned official kernel and runs the same
mandatory guest acceptance on Actions; neither an unsupported host nor a QEMU
exit counts as a positive guest pass. This validates a native building block,
not production NFS delegation, crash retention, reclaim or SMB directory leases.
The file worker still uses its existing private coordinator primitive and
declines wire handout until the surviving-owner and recovery requirements pass.

## Independent native guard owner

`native_delegation_owner` now provides an independent Linux process that owns
up to 256 native delegation records. A private AF_UNIX SOCK_SEQPACKET channel
passes already-confined descriptors with SCM_RIGHTS. The owner accepts no path,
network request or data IO. Its process starts through the registered helper
entry point, closes unrelated descriptors and stdio, uses an empty environment,
and has a separate session so ordinary worker/terminal shutdown does not kill it.
The application must register the helper entry before creating an owner; otherwise
creation fails without recursively executing an unaware program.

Acquire, inspect, renew, recall and explicit release use bounded, validated
messages. The worker must await an acknowledgment before publishing a grant or
extending network state. Lost replies disconnect the channel and retain uncertain
native ownership until expiry. Control-object destruction and worker death do not
send RELEASE. The owner independently detects native breaks and expires guards
using monotonic time. Renewal never extends the original recall deadline, expired
records cannot revive, and old terminal records cannot clear a later local guard.
The native break-time bound is checked before acquiring. A failed kernel query
fences the control channel while retaining descriptors through their lifetime.

The Linux 6.19 guest suite exercises both tmpfs and ext4 with the actual owner
process. It checks explicit release, renewals through a complete recall interval,
revocation, compatible reads, local duplicate exclusion, write-right refusal,
unknown IDs, disconnect retention and automatic expiry. It also SIGKILLs a real
worker after acquisition acknowledgment and proves an ordinary host writer
remains excluded, then succeeds after the accepted lease expires. Descriptor
handoff also preserves validated private-pin and unlinked-incarnation flags;
both recovery-related object forms pass real native acquisition and release.
The final local guest run passes 364 checks, with evidence in
[native owner acceptance](evidence/pre-m8/native-delegation-owner-local.json).
The corresponding remote kernel run and Windows native SMB/NFS runs also
succeed ([remote evidence](evidence/pre-m8/native-delegation-owner-0bf-remote.json)).

This is the native ownership component, **not yet the production NFS provider**.
The file-domain coordinator now binds owner IDs to its existing signed-grant,
client, export, filehandle and unguessable-cookie checks. On supported Linux it
uses the independent owner; an acknowledged capability refusal permits the old
private primitive, while an uncertain owner call never falls back to another
acquisition. Provider identity and availability are exposed in private snapshots.
Fresh authorized renewal must receive the owner ACK before extending the local
lifetime. Owner terminal state retires local state; control failure starts recall,
refuses renewal and retains the native descriptor until authorized cleanup.

Acquire and renew carry absolute monotonic deadlines, so queued requests cannot
restart a relative lease after a controller timeout. A regular-file guard can
be explicitly released via the retained shared open description after confirmed
owner death. EOF alone is insufficient: a live disconnected owner could later
clean up its old guard and unlock a new guard on the same description. Directory
parent guards cannot use this local fallback. Controller destruction still only
detaches.

The updated 6.19 tmpfs/ext4 guest passes 431 checks. Tests stop the owner until an
acquire times out, prove the expired request cannot create a late guard, and
verify that release while the owner lives stays fenced while release after its
confirmed death succeeds. File-domain tests cover owner selection, native recall,
renewal, return, store destruction, stale cookies after replacement, and SIGKILL
of a real file-domain worker with protection retained until expiry. The isolated
kernel explicitly enables FHANDLE for real stable file identities. See
[file-domain owner evidence](evidence/pre-m8/nfs-owner-domain-local.json).
The corresponding remote kernel run succeeds with file-domain SIGKILL checks on
both filesystems ([remote evidence](evidence/pre-m8/nfs-owner-domain-3fe-remote.json)).

Ensuring successful network SEQUENCE/callback renewals never outlive owner ACKs,
recovering state across worker replacement, and durable delegation reclaim remain
open. The private disconnected owner deliberately cannot be reattached by a new
worker yet. Simultaneous owner/worker loss and full server restart still require
recovery/fencing; this test does not prove those cases. Windows owner and native
namespace protection also remain open. Wire handout stays gated.


## Client lease and coherence retention

Following [RFC 8881 section 8.3](https://www.rfc-editor.org/rfc/rfc8881.html#section-8.3),
all sessions of one client share a lease. Successful SEQUENCE, exact replay and
validated CB_SEQUENCE replies renew every session of that client. A completed
COMPOUND also refreshes the lease after execution, including failed operations
following a successful SEQUENCE; slow execution no longer consumes the subsequent
lease interval. Expiry still removes an inactive client's sessions and OPENs.

Automatic delegation renewal first checks current file authority. If identity or
file-domain authorization fails, it uses the original bound cleanup capability
through `retain`: extend coherence retention, enter recall, and preserve the fixed
recall deadline. This does not authorize READ/WRITE or keep a revoked state alive
indefinitely. Renewing Alice's delegation on a session used by Bob must not add
Alice's export scope to Bob's reply-cache authorization; only operations belonging
to the actual COMPOUND contribute those scopes.

Native lifecycle tests exercise an expired signed capability, foreign-client and
caller rejection, retention beyond the previous expiry, non-extension of recall,
IO denial, return and non-resurrection. Protocol tests cover shared-session user
replay, a delayed READ response, and mapping revocation near lease expiry followed
by SEQUENCE, callback acknowledgment and DELEGRETURN. The independent pynfs-codec
socket fixture tests two sessions of one client, renewal through exact replay,
joint idle expiry, and recovery when the configured lease is reduced. The pinned
kernel guest exercises `retain` through the actual independent owner on tmpfs and
ext4. The local run passes 186 lifecycle checks, 703 protocol checks, 441 guest checks,
four independent lease groups and 15 M7 regression groups. The matching remote
Linux 6.19 run succeeds ([remote evidence](evidence/pre-m8/nfs-coherence-ddcb-remote.json)).
Results are recorded in [coherence lease evidence](evidence/pre-m8/nfs-coherence-lease-local.json).

**Still required before production handout:** owner failure must not allow a
successful network renewal to outlive confirmed protection. Validated COMPOUND replies now have explicit transport lifetime accounting as
described below. Native protection still needs an acknowledged reservation for
that entire lifetime, including slow execution and callback response windows. Reattachment,
reclaim, complete restart fencing and Windows native ownership remain open.


## Reply delivery lifetime

The TCP runtime now requests a private completion token from the protocol engine.
A validated new SEQUENCE or cached replay binds its own token to the client ID.
The token is not part of XDR, GSS plaintext or ciphertext, and transmissions of the
same RPC/XID have separate tokens. The table is bounded at 512 entries before
protocol side effects. Calls with no valid session do not keep a token.

Client state, OPENs, byte locks, lock notifications, sessions and SSV ownership
use the client's expiry plus outstanding reply pins. The redundant per-session
expiry field is removed. Maintenance attempts to refresh retained coherence while replies
are pending. On completion it applies the actual recorded completion time, not
the later maintenance time; duplicates and unknown tokens cannot extend leases.
A retired client cannot be recreated by an old completion. Dispatch without a
requested token retains the existing in-process convention that returning the
response is delivery.

A successful complete-frame write records completion. Cancellation, rejected
queue admission, failed writes, discarded queued frames and connection loss also
end their pins conservatively. Processing abandoned while a worker is still
running is completed by the worker's eventual completion notification. A separate
small mutex lets the I/O thread record completion without waiting for the main
protocol mutex or any file-domain RPC. The engine consumes these events before
expiration and before evaluating state-protection context lifetime.

Component tests hold a real OPEN through a reply delayed beyond the lease,
complete one of two independently pinned replays, and verify that a late duplicate
cannot renew the client. They also check disconnect retention and eventual expiry,
unknown-token handling, absence of pins for BADSESSION, and completion registration
while a slow READ holds the protocol mutex. Independent TCP lease tests detect
immortal transport pins by requiring idle sessions and OPENs to expire. M7,
callback retry/recovery, real Kerberos callbacks and SSV checks cover the runtime
integration. Local validation passes 835 protocol checks, four lease groups,
15 M7 groups, six callback-recovery groups, nine real-Kerberos callback groups
and 25 SSV groups. See [reply lifetime evidence](evidence/pre-m8/nfs-reply-lifetime-local.json).

This is client-state lifetime accounting, not proof of full delegation retention.
The independent native owner still needs reservations covering slow dispatch,
transport completion and backchannel responses, with failure handling before wire
success. Request receipt tracking now covers executor and protocol-mutex waits
as described below. Worker replacement/reclaim and full restart fencing
remain open; production delegation handout remains disabled.

## Namespace lookup under a delegation

Internal namespace reconciliation now reads metadata without opening files for
data access. Linux uses confined `openat2` with O_PATH; Windows uses a relative
NtCreateFile handle with FILE_READ_ATTRIBUTES and SYNCHRONIZE. Neither API
returns a data handle to the caller. Existing root/volume/type checks, symlink
and reparse-point rejection, reserved-name checks and hardlink confinement stay
in force. See [Linux O_PATH](https://man7.org/linux/man-pages/man2/open.2.html)
and [Windows metadata-open oplock behavior](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create2).

NFS LOOKUP and directory enumeration may reuse an active delegation's retained
descriptor only after matching its root, space and path, then comparing the
actual confined directory entry with the retained native incarnation. A cached
pathname alone is insufficient. Missing/replaced entries cannot revive old
state; normal parent traversal, file permissions and stateid checks still run.
This removes two unintended data opens: whole-space reconciliation and the
DAV existence query previously used by LOOKUP.

Named CLAIM_DELEGATE_CUR can consequently materialize OPEN state without
recalling its own guard. The protocol component tests cover exact replay,
independent OPEN/delegation stateids, foreign file/state/client/principal and
write-access rejection. They also materialize a named OPEN after CB_RECALL and
prove that OPEN remains readable after DELEGRETURN. This implements the named
claim's normal and recall-time behavior in
[RFC 8881 section 18.16](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.16);
server-restart reclaim remains a separate unfinished requirement.

Native tests verify that metadata observation, LOOKUP and enumeration leave the
guard active. The older Linux component provider additionally permits a real
host rename/replacement, proving that the replacement gets its own filehandle;
the Linux 6.19 guest requires namespace mutations to block instead. The core
adapter test covers concurrent symlink substitution and hardlink rejection for
metadata access. [Local evidence](evidence/pre-m8/nfs-named-delegation-local.json)
records component and shared-protocol regressions. These results do not enable
production wire handout or close the remaining recovery and lifetime gates.
The [fixed-source Linux 6.19 Actions run](evidence/pre-m8/nfs-named-delegation-229-remote.json)
also passes all 479 native checks on tmpfs/ext4 for commit `2294038`.

## Request receipt before execution

Complete TCP records are registered before submission to the bounded executor,
using a separate small mutex shared with reply-completion bookkeeping. A record
waiting for either a worker or the protocol mutex cannot prematurely lose client
state that was live at receipt. Authentication still runs before any SEQUENCE
renewal or file operation. The record does not itself change client expiry or
renew a native delegation.

RPC privacy prevents safely selecting a client before authentication. Until
authentication finishes, cleanup is deferred only for clients that existed
before that record arrived and whose fixed expiry is later than its receipt
time. A monotonically increasing admission boundary excludes future clients.
Late traffic cannot extend that eligibility window. Successful SEQUENCE/replay
then uses the existing authenticated renewal and reply-delivery tracking;
failed authentication/SEQUENCE, malformed records, executor submit failure,
cancellation and disconnect release the reservation. Admission is limited to
32 records, matching the bounded transport/executor model without an unbounded
queue. Tokens are single-use, bound to the transport connection, never on wire,
and duplicate cancellation is harmless.

This implements the receipt-time requirement in
[RFC 8881 section 8.3](https://www.rfc-editor.org/rfc/rfc8881.html#section-8.3)
for protocol-owned client/OPEN/lock/session state. Native delegation-owner
retention across the same interval still needs its own acknowledged reservation;
this change does not enable production handout.

Component acceptance covers delayed admission across expiry and maintenance,
rejected SEQUENCE without renewal, cancelled/late records, exclusion of clients
created after receipt, nonblocking registration during a slow operation, capacity
and disconnect cleanup. A real TCP fixture briefly suspends only its disposable
file worker: one NFS executor worker waits in file IPC, the second waits for the
protocol mutex and a third client queues. Its request is sent before the
five-second lease expires and reads its original OPEN after expiry. The fixture
checks timings, successful SEQUENCE replies and unchanged worker identity, and
always resumes the file process during cleanup. See
[local evidence](evidence/pre-m8/nfs-arrival-local.json).
