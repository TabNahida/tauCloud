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
for protocol-owned client/OPEN/lock/session state. The native reservation route
described below now covers the component provider's corresponding interval;
production handout remains disabled.

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

## Native acknowledged deadlines

The independent owner now returns absolute monotonic lease expiry and recall
deadlines in its private versioned IPC protocol. File authority imports the
confirmed upper bound; delayed observation cannot start a new recall interval.
Snapshots expose `lease_expires_ms`, `recall_deadline_ms` and
`protected_until_ms`; terminal or unavailable protection reports no usable
protection window. Local time passing does not itself clear an owned native
descriptor: release still requires confirmed owner termination or an explicit
release acknowledgment.

Renewal imports the owner's acknowledgment before rechecking a short-lived data
grant. If that grant expires during IPC, data authorization still fails, but
the already acknowledged coherence retention is preserved. Importing a later
observation cannot extend an earlier recall deadline or revive terminal state.
These timestamps are private to processes sharing one host's monotonic clock;
they are not persistent restart identifiers or NFS wire timestamps.

[Local evidence](evidence/pre-m8/nfs-native-deadline-local.json) records 222 native
lifecycle checks, 1074 protocol checks and 576 Linux 6.19 VM checks on tmpfs/ext4.
The VM delays file-domain observation after a real native write conflict and
verifies that the imported recall deadline remains anchored to the owner.
The received-RPC route below extends these acknowledged deadlines across
admission, execution and reply delivery in component tests. Production handout
stays disabled pending failure fencing and recovery.

The [fixed-source Actions acceptance](evidence/pre-m8/nfs-native-deadline-d66-remote.json)
for `d66ff7c` passes 257 host checks and 584 guest checks with the required
Linux 6.19 tmpfs/ext4 PASS marker. This confirms the same native deadline
implementation remotely; the network lifetime and recovery gates remain open.

## Native request reservations

The independent owner provides an acknowledged reservation token for in-flight
work received before its current lease expiry. A reservation preserves native
exclusion across that expiry while execution or reply completion is pending.
Completion consumes the token and preserves a full lease from the owner's
completion time; cancellation consumes it without renewal. Another outstanding
token keeps the object protected. Tokens are unique within the owner lifetime,
bound to their delegation record, and cannot be replayed to renew a lease.
Late unrelated reservations cannot borrow an existing reservation's protection;
a validated renewal must first advance the lease.

There are at most 32 tokens per delegation and 512 per owner. Cancellation
returns capacity. The private TCD4 IPC packet includes the token and confirmed
reservation count. `protected_until_ms` is INT64_MAX only while an acknowledged
reservation has no recall deadline; the count makes this conditional retention
explicit. Native conflict detection still establishes a fixed recall deadline,
which neither reservation nor completion can extend. After revocation, a late
completion can remove its token but cannot restore the guard.

Controller EOF cannot establish whether a reply reached the client. The owner
therefore completes outstanding reservations conservatively with a full lease
from EOF detection, clears the tokens and expires autonomously. A fixed recall
deadline still takes precedence. Explicit release remains a caller-owned proof
that caching has ended; it is not a substitute for cancelling outstanding work.

[Local evidence](evidence/pre-m8/nfs-owner-reservations-local.json) records 534
lifecycle checks and 630 real Linux 6.19 checks on tmpfs/ext4. The guest verifies
actual native write exclusion beyond the original lease, full post-completion
retention, duplicate/foreign token rejection, capacity recovery, cancellation,
recall despite an incomplete request and SIGKILL of a worker after a reservation
ACK. Its independent owner retains protection for the bounded post-death lease.

The private file-domain capability now routes `reserve`, `complete` and `cancel`
to this owner. Each operation checks the signed original grant, delegation
cookie, client, actor, root, export, filehandle and path scope. It conveys no
file-data authority and remains usable for coherence cleanup after grant expiry
or policy revocation. A legacy local primitive explicitly refuses reservations.

A caller supplies positive, monotonically increasing 64-bit reservation IDs per
delegation. Retrying an outstanding ID returns the existing reservation without
renewing or consuming capacity, even after a higher ID has arrived. A bounded
high-water mark rejects completed/replayed older IDs; completed IDs cannot renew
again. At most 32 IDs are outstanding. New reservations after nominal expiry are
refused even when another request still holds protection. Local bookkeeping is
allocated before IPC and exposes success only after the native ACK. The owner
decides expiry and capacity across every controller. Completion imports the ACK;
cancellation never renews.
Explicit DELEGRETURN or confirmed native termination clears outstanding IDs.

[File-domain evidence](evidence/pre-m8/nfs-domain-reservations-local.json) covers
536 host lifecycle checks, 1074 protocol component checks and 761 real Linux
6.19 tmpfs/ext4 checks, including
binding/replay/capacity rejection, expired cleanup grants, revoked data access,
post-completion retention, cancellation and a file-worker SIGKILL beyond nominal
expiry. [Fixed-source remote evidence](evidence/pre-m8/nfs-reservations-d7-remote.json)
also confirms the earlier owner primitive on Linux 6.19 and native Windows NFSv3
roundtrips; it does not include the subsequent file-domain integration.

The received-RPC route below now covers admission and transport completion with
independent owner ACKs and asynchronous exchange. Monitoring and instance fencing
are described below; production handout, replacement recovery and reclaim remain
incomplete.

## Independent reservation capability channel

The native owner can export a private, same-host capability bound to one live
delegation. `native_delegation_reservation_channel` connects directly to that
owner, independently of the file worker's execution queue and primary control
connection. The Linux abstract Unix socket name is public routing information;
a distinct random 128-bit secret authenticates each delegation. A fresh nonce
and direction-separated HMAC-SHA256-128 proofs bind the endpoint and record.
The client verifies the owner's proof before trusting its snapshot; reflecting
a client proof or rebinding an old socket address cannot impersonate the owner
without the secret. The secret itself is never sent in the channel handshake.
Both peers also check the Unix peer UID. Neither the capability nor its secret
belongs on the NFS wire or in diagnostics.

A bound channel supports only inspection, reservation and completion/cancellation.
The owner rejects acquisition, renewal, recall, release, capability export and
cross-record requests on it. Reservation tokens are bound to the originating
connection, including separation from the primary controller; a sibling cannot
consume a token. Export retries retain the same capability for the same record.
Returning the delegation closes its channels and invalidates its capability.

The owner admits at most 512 channels and 32 unauthenticated handshakes, with a
1.5-second handshake deadline and at most eight accepts per maintenance cycle.
The existing 32-per-record/512-per-owner reservation limits remain shared across
all controllers. Closing a channel conservatively completes only its tokens with
a full lease; sibling requests remain outstanding. Primary-controller death
invalidates all channels, completes outstanding work conservatively and retains
the existing autonomous expiry behavior. Fixed native recall still takes
precedence over every form of retention.

[Local Linux 6.19 evidence](evidence/pre-m8/nfs-reservation-channel-local.json)
records 927 ASan/UBSan checks and verifies actual tmpfs/ext4 protection,
raw-packet operation restrictions,
capability and token binding, duplicate/capacity rejection, per-channel EOF,
SIGSTOP of the file worker while another process obtains native ACKs, and bounded
retention after SIGKILL. Received-RPC routing and reactor scheduling are described
below; failure fencing and recovery/reclaim remain open, and production handout
is disabled.

[Remote acceptance at `5d76595`](evidence/pre-m8/nfs-reservation-channel-5d-remote.json)
passes the complete GCC release and Clang ASan/UBSan Linux 6.19 workflow. Their
guest suites report 911 and 968 checks respectively, including both filesystems
and the mandatory VM pass marker. This source precedes the file-domain integration
described below.

The file service now publishes the capability through its private `channel`
operation after verifying the signed original grant, cookie, client, actor,
root, export, filehandle and path scope. Ordinary snapshots do not contain it.
Export retries return the same capability. Cleanup grants remain valid for this
coherence-only operation after expiry/revocation; they still cannot authorize IO.
Legacy local guards refuse channel export.

An owner-backed file-service lifetime is an authoritative mirror: it imports the
owner's lease deadline, terminal state and total reservation count, including
tokens created through independent channels. A stale snapshot with no tokens
cannot authorize local expiry, because a side channel may have reserved work
since that observation. Completing a side token or losing its channel can extend
the native lease; the file service imports that extension even after its old
deadline. Explicit return remains authoritative and invalidates every channel.
Owner communication loss starts a bounded local recall fence; native descriptor
release still requires an acknowledgment or confirmed owner death.

Local recalls carry their original absolute monotonic cutoff to the owner. IPC
delay cannot start a later recall interval; a cutoff already in the past revokes
before acknowledgment, including when reservations remain outstanding.
[Integration evidence](evidence/pre-m8/nfs-channel-domain-local.json) records 585
host lifecycle checks and 991 Linux 6.19 ASan/UBSan guest checks across tmpfs and
ext4, including independent completion/cancellation/EOF across nominal expiry,
mixed primary/side tokens, binding rejection, return invalidation and revoked
data authority.

The native-client handshake regression also runs on hosts without F_SETDELEG:
a separate test peer proves the server direction or reflects the client proof;
only the former is accepted. This transport test does not claim native exclusion.
GCC and Clang sanitizer host builds both pass its 19 checks/capability probes.

The VM uses a small unsanitized init shim to mount procfs before starting the
instrumented PID 1 program. ASan otherwise cannot discover that process's stack
bounds and can leave stale stack poison after exceptions. SDK-resolved libraries
are also installed under their SONAMEs in the guest's default loader directory.
The required remote kernel matrix now covers GCC release and Clang ASan/UBSan.

## Native reservations on received RPCs

The protocol component now publishes each independent owner's private channel
before emitting a delegation. A complete received RPC obtains native reservations
before entering the executor or protocol mutex. Until authentication identifies
its client, the record protects each delegation whose fixed client expiry makes
that receipt eligible. Successful SEQUENCE binds the matching reservations to
its reply; other clients' reservations are cancelled. Publication also reserves
for eligible receipts and replies already in flight. A capacity or ACK failure
during publication declines the new delegation and cleans up its native guard.

Validated SEQUENCE and callback renewal acknowledge a full native lease and
reserve the next execution phase before advancing the network lease. Slot state
is committed only after that confirmation. Failed cached-reply authorization has
no lease-renewing completion token and preserves the original cache entry for a
valid retry. This ordering follows the lease and SEQUENCE rules in
[RFC 8881 section 8.3](https://www.rfc-editor.org/rfc/rfc8881.html#section-8.3) and
[section 18.46.3](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.46.3).

The native reservation survives execution and delayed transport delivery. Reply
completion confirms a full native lease independently of the file worker;
duplicate completion is inert. Cancellation before authentication does not renew.
Disconnect conservatively completes validated replies, while an executing
dispatch retains its holds until it finishes. Synchronous component callers treat
return from dispatch as completion. Explicit return and terminal native snapshots
remove the route and its outstanding reservations.

Autonomous native recall can finish before the protocol's next file-domain poll.
The independent channel now imports that terminal state as delegation revocation,
so subsequent SEQUENCE reports revoked state while ordinary session/OPEN state
continues. A first VM run exposed an uncaught `stale_handle` at this boundary; the
corrected route is exercised by the existing recall-deadline protocol checks.

The required Linux 6.19 VM now runs the complete protocol component suite using
its actual independent native owner, in addition to tmpfs/ext4 native exclusion
tests. Added cases cover queued receipt past nominal expiry, native admission and
reply completion while the file-domain renewal callback is deliberately paused,
independent replay tokens, cancellation, invalid SEQUENCE and duplicate completion.
The test-only provider still explicitly removes the production wire gate; these
tests do not demonstrate production delegation handout.

Owner exchanges now run through the bounded nonblocking scheduler described
below. Network admission and completion do not wait for the file worker, the
protocol mutex or native ACKs. An instance-level protection-loss fence is described below. Callback dispatch
priority, worker replacement, durable restart fences and reclaim still remain
required before production handout.
Local Clang ASan/UBSan acceptance passes 1,087 host protocol checks and, with
mandatory native protection in Linux 6.19, 1,105 protocol checks plus 997 native
checks. See [local routing evidence](evidence/pre-m8/nfs-request-routing-local.json).

## Nonblocking native channel exchanges

The independent reservation channel now also supports a nonblocking mode. Its
constructor sends the mutual-authentication handshake and returns without
waiting for the owner. The caller polls that ACK before beginning inspection,
reservation or completion. Each channel permits one outstanding exchange;
overlapping submissions are rejected without consuming or replacing that request.
The ordinary synchronous methods are refused in nonblocking mode, preventing an
accidental wait through that API.

Polling uses a zero-timeout readiness check and a nonblocking packet receive.
Every exchange has one absolute 1.5-second monotonic deadline. Polling does not
move it, and timeout, EOF, malformed state, mismatched operation/record/token or
unexpected descriptors close the channel. Uncertain reservations are retained by
the independent owner through its existing EOF/full-lease behavior. Valid negative
ACKs such as capacity exhaustion or an already-consumed token allow a subsequent
operation; authentication failure closes the channel.

An independent wire peer controls when it acknowledges each request, testing
pending handshake/operation behavior, mutual proof, duplicate polling, capacity
recovery, invalid responses and timeout. Real Linux 6.19 tests additionally stop
the owner with SIGSTOP: polling returns while it cannot respond, resumed
completion confirms the full lease, and timeout followed by EOF preserves the
native guard and the uncertain token's full lease.
Clang ASan/UBSan acceptance passes 447 independent channel checks (467 total on
the capability-refusing host), then 1,512 native checks plus 1,105 protocol checks
in the mandatory Linux 6.19 guest
([evidence](evidence/pre-m8/nfs-channel-nonblocking-local.json)).

The receipt/reply registry now uses this primitive through a bounded scheduler.
The original nonblocking primitive passes the GCC release and Clang ASan/UBSan
Linux 6.19 Actions matrix at `4a9fb7a`
([remote evidence](evidence/pre-m8/nfs-nonblocking-4a-remote.json)).
Owner monitoring and instance fencing are described below; callback dispatch
priority and durable recovery fences remain required before production handout.


## Reactor reservation scheduling

Each native route serializes at most 96 queued/active reservation, refresh and
completion jobs over its nonblocking authenticated channel. Refresh confirms
completion of the old token before reserving the next execution phase. Jobs for
one hold preserve order; eligible completion/cancellation jobs run before new
reservations to release capacity. A poll handles at most eight steps per route;
there are at most 32 protocol delegations. Native timeout and uncertain failures
close the channel and fail its outstanding jobs, leaving conservative retention
to the owner. A capacity rejection can fail an initial reserve without disabling
other holds.

The reactor registers complete RPC records immediately, then yields until all
eligible native reservations are acknowledged before submitting protocol work.
It polls channels while otherwise idle. Reply delivery, cancellation and confirmed
transport loss enqueue cleanup without waiting for ACKs or taking the protocol
mutex. Session/backchannel teardown is applied subsequently by a protocol worker;
its pending connection set is bounded, with overflow conservatively invalidating
all known bindings. Existing synchronous component APIs drive the same queues but
wait outside the receipt/reply lock.

Publication registers the route before waiting so concurrent arrivals are also
covered; it refuses handout if the native guard has already become terminal.
Validated renewal advances protocol state only after the queued refresh ACKs.
Completed replies keep their client pin until native completion is settled, and
only acknowledged completions advance route eligibility. Cancellation before
validation does not renew; reply/arrival tokens remain single use.

The mandatory actual-owner protocol test pauses the native owner with SIGSTOP
while a protocol worker is blocked inside the file-domain renewal callback. During
both pauses, reactor admission, reply completion, cancellation, disconnect and
polling return without waiting. Resumption drains the same jobs, preserves exactly
the surviving reservations and completes with a full native lease. Separate actual
TCP tests exercise executor saturation and shared-client lease/replay/restart
behavior using the production service binaries. The native delegation provider is
still injected only in the component test; production wire handout remains gated.

Local Clang ASan/UBSan acceptance passes 1,087 host protocol checks, 1,132
actual-owner protocol checks plus 1,512 native checks in Linux 6.19, two real-TCP
queue checks, four lease/restart groups and six callback-recovery groups.
See [scheduler acceptance](evidence/pre-m8/nfs-native-scheduler-local.json).
The actual-owner scheduler and simultaneous SIGSTOP/paused-file callback checks
also pass both compiler jobs at `b445fca`
([remote evidence](evidence/pre-m8/nfs-scheduler-b445-remote.json)).


## Native protection monitoring and instance fencing

Nonblocking channels now expose an idle health check. It consumes no ACK and does
not renew a lease: EOF, socket errors, unsolicited idle packets and an expired
outstanding exchange permanently close that channel. The scheduler also issues
an inspection after 250 ms without an acknowledged exchange. Inspection does not
renew state, and a stopped/unresponsive owner must answer within the existing
fixed 1.5-second exchange deadline. Polling these probes never waits for the file
worker or the protocol mutex.

Losing a published, still-required native route latches a fault for the current
NFS server instance. New and already-queued requests are refused. Domain calls
check the latch before invocation and after return, and dispatch cannot return a
successful result once fenced. The reactor closes its existing transports,
refuses new connections and reports `business_ready=false` with
`native_delegation_fenced=true`. Removing a route or completing a stale request
does not reset the latch.

Failed publication does not fence a server that never handed out the delegation.
An acknowledged terminal cutoff is distinguished from losing protection while it
is owed. Explicit DELEGRETURN marks the route as retiring before its file RPC, so
the expected native channel close cannot race the RPC ACK and be mistaken for an
owner crash. On a failed return the suppression ends; unexpected loss is still
fatal. The protocol fixture deliberately polls in the return/ACK interval.

The actual-owner Linux 6.19 test kills its verified child owner while the protocol
thread is blocked in a file-domain renewal callback. Reactor polling detects the
loss, rejects both new and previously queued requests, refuses the in-flight
result after unblocking and remains fenced after cleanup. Independent wire tests
also prove idle EOF detection and that health checks do not consume pending ACKs.

This is an **instance fence**, not durable recovery or a replacement native guard.
It cannot undo file operations already submitted, immediately invalidate a remote
client's cached delegation, or prevent unrelated host syscalls after owner death.
A supervisor/process restart needs durable file-domain/coherence fences and
reclaim handling before wire handout can safely be enabled. Production `wire:true`
continues to decline delegations. See
[monitoring evidence](evidence/pre-m8/nfs-native-health-local.json): 491 independent
channel checks, 1,087 host protocol checks and, in Linux 6.19, 1,188 actual-owner
protocol checks plus 1,554 native checks pass under Clang ASan/UBSan. Two real-TCP
queue checks and all six callback-recovery groups also pass.

Remote Linux 6.19 acceptance at `21cf7d9` passes with GCC and Clang/ASan. Both
jobs include actual-owner SIGKILL while renewal is blocked: GCC reports 1,194
protocol and 1,541 native checks; Clang reports 1,176 and 1,603 respectively.
Scheduling affects polling counts. See the
[fixed-source remote evidence](evidence/pre-m8/nfs-native-health-21-remote.json).
The production handout and durable recovery gates above remain open.

## Bounded concurrent TCP record receipt

The connection reader now registers a complete record immediately and continues
reading while its dispatch awaits native ACKs, executor capacity or file IPC.
This matters for pipelined calls and shared fore/backchannel connections; their
association is described in [RFC 8881 §2.10.3.1](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.10.3.1).
Previously, the reader waited for a reply before receiving the next record.
A real TCP reproduction sent an invalid SEQUENCE followed by a valid READ before
the five-second lease expired. Delaying the first dispatch until after expiry
made the subsequent READ fail with BADSESSION, even though both records had
already been sent. The invalid request does not renew the lease.

The initial correction captured at most 16 processing records per connection and
32 globally; the class reservations below now refine these limits, in addition
to the existing bounded executor and output queues.
Overflow closes the affected transport and abandons undispatched admissions.
Replies still use one writer per stream, and native completion tracking remains
attached to delivery. Shutdown drains processing coroutines before stopping the
reactor. UDP discovery keeps its existing sequential path.

Four queue/pipeline/overflow checks, 19 backchannel groups, six callback-recovery
groups and four lease-lifetime groups pass locally under Clang ASan/UBSan;
[evidence](evidence/pre-m8/nfs-pipeline-local.json) retains the failing baseline.
This change does not remove the protocol mutex or provide callback dispatch
priority. Callback deadlines under executor delay are addressed below; durable
fencing and reclaim still require work before production delegation handout.
Remote acceptance is pending.

## Callback response receipt deadlines

A separate real-TCP reproduction at `476e931` demonstrated that a valid
CB_SEQUENCE response received before the five-second probe timeout could still
close its connection when file IPC delayed protocol dispatch beyond the timeout.
Admission now records only the untrusted RPC reply XID alongside connection and
receipt time. Probe issuance captures an arrival boundary. Timeout maintenance
defers a probe only while a matching connection/XID record, received after that
boundary and before the unchanged deadline, remains pending in bounded dispatch.

The dispatcher evaluates the response against its receipt time, then performs
all existing transport, RPCSEC_GSS, context lifetime, sequence, slot and full-XDR
checks. A header hint alone cannot advance a slot, validate a callback path or
renew a client. Cancellation and disconnect remove the pending hint. Unknown
XIDs, other connections, pre-existing receipts and genuinely late replies cannot
defer that probe. Invalid matched responses keep their existing failure behavior.

Five delayed-dispatch scenarios pass: timely success, malformed body, wrong XID,
wrong transport and late arrival. The negatives also verify that the expired
session cannot be revived. Regression passes 19 backchannel groups, six callback
recovery groups, nine real-MIT-KDC groups and 1,146 protocol component checks under
Clang ASan/UBSan. [Evidence](evidence/pre-m8/nfs-callback-queue-local.json) retains
the failing baseline and test-fixture corrections. The new TCP fault scenarios
are included in the Linux GCC/Clang Actions matrix. Remote results are pending.
Bounded incoming callback priority is described below; durable native recovery
and production delegation handout remain open.

The native/component regression at `0135dd0` passes both GCC and Clang Linux
6.19 jobs ([evidence](evidence/pre-m8/nfs-callback-queue-0135-native.json)). This
workflow does not run the delayed TCP callback scenarios; their separate
cross-platform matrix remains pending.

## Bounded priority for callback responses

Incoming RPC replies now use a separate executor with one worker and eight
outstanding records. Ordinary RPC calls retain two workers and sixteen records;
the per-connection and global receipt bounds described below also apply. The RPC
direction header selects scheduling capacity only. Unknown XIDs, wrong
transports, invalid GSS and malformed responses still undergo the same checks.
Overflow closes the affected transport, and shutdown drains both executors.

The protocol state gate prefers already-waiting callback dispatches. When
ordinary work is also waiting, at most four consecutive priority holders can
run before ordinary work gets a turn. The currently executing operation is not
preempted; state remains serialized. Maintenance and disconnect processing use
the ordinary path. This bounds the scheduling advantage available to forged
reply headers without making authentication depend on queue selection.

An independent TCP fault test fills the ordinary executor while its first file
RPC is blocked, confirms rejection of the overflowing ordinary transport, then
successfully submits a valid callback through reserved capacity. Concurrent gate
tests verify priority over earlier ordinary waiters, the four-holder burst limit,
ordinary-only/priority-only progress and exception-safe release. Six callback
queue cases, 19 backchannel groups, nine real-KDC groups, four ordinary admission
groups and 1,185 protocol checks pass locally. Linux 6.19 additionally passes
1,286 protocol component and 1,555 native checks, including real-owner loss during
blocked renewal ([evidence](evidence/pre-m8/nfs-priority-local.json)). Remote
acceptance is pending. This first reservation covered executor capacity only;
the shared receipt limit correction below extends it before scheduling.

## Reserved callback receipt capacity

A real TCP regression at `f702f25` filled one shared connection with a blocked
READ and fifteen RPC NULL calls. A valid CB_SEQUENCE response sent before its
deadline became the seventeenth record and closed the connection before dispatch,
despite the independent callback executor having free capacity.

Receipt admission now reserves eight of the existing 32 global records for RPC
replies, leaving 24 for ordinary calls. Each TCP connection allows at most sixteen
ordinary calls and four replies. Both the captured-coroutine counters and protocol
arrival map enforce their class limits before native ACK waits. Completion,
cancellation, disconnect and scheduling failure release their original class.
The eight-byte RPC header selects capacity only: it never authenticates a reply,
advances a callback slot or renews client state. Overflow still closes the affected
transport; a flood of forged reply headers is bounded independently.

The new same-connection regression requires all sixteen ordinary replies and a
healthy callback path without retry after delayed dispatch. Protocol component
tests independently fill both classes, reject their overflow and recover after
cancellation. Local ASan/UBSan passes seven callback queue cases, four ordinary
admission groups, 19 backchannel groups, nine real-KDC groups and 1,186 protocol
checks. Linux 6.19 passes 1,287 protocol and 1,553 native checks; native polling
counts vary with scheduling. Remote acceptance is pending. See
[baseline and acceptance](evidence/pre-m8/nfs-shared-admission-local.json).
Outgoing callback scheduling, durable recovery and production delegation handout
remain open; this change does not establish fairness between individual clients.

## Bounded callback output scheduling

The TCP writer now reserves a separate queue for server-generated reverse RPCs.
Ordinary responses retain sixteen records and 1 MiB; callbacks have four records
and 256 KiB. Both budgets include the frame currently being written. Selection
happens only between complete RPC frames, prefers callbacks, and admits an
ordinary response after at most four consecutive callbacks when both classes
are waiting. This does not preempt a partial frame or reorder bytes already
accepted by the kernel. Only the trusted reverse-RPC send path chooses the
callback class; incoming request headers cannot mark ordinary replies as callbacks.

The queue owns reply-completion tokens from successful admission through actual
write completion or cancellation. Socket failure drains the active frame and
both waiting classes exactly once. Rejected enqueue and writer-start failure
also release tokens. Queue ownership cannot be copied. The existing per-frame
five-second write timeout remains in effect.

Component checks cover reserved record/byte budgets, non-interleaving active
frames, sustained callback traffic with ordinary progress, overflow and exact
cleanup. A Linux TCP test stops reading, observes the kernel send queue reach a
plateau, requests another callback, then verifies that it arrives ahead of
queued READ replies while every data payload remains intact. This is transport
backpressure evidence, distinct from the component tests. The same test against
an isolated `dd65a14` FIFO service fails because its callback arrives only after
all READ responses. Local ASan/UBSan passes 1,290 protocol checks, seven callback
receipt groups, 19 backchannel groups and nine real-KDC groups. Linux 6.19 passes
1,391 protocol and 1,553 native checks. See
[local acceptance](evidence/pre-m8/nfs-output-local.json).

The callback response deadline still starts at probe creation; priority does not
account for time spent behind the currently blocked frame. Explicit transport
send/deadline coordination, durable owner recovery and production delegation
handout remain open. Remote acceptance is pending.
