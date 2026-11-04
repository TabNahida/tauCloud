# NFS delegation implementation

Full delegation support remains an open compatibility requirement. The protocol
engine now implements READ delegation state, CB_RECALL, return and revocation,
and has component tests using an injected native file-domain provider. The
production file authority still declines wire handout: it cannot yet protect
every host metadata/namespace change or retain guards across worker death.
There is no configuration switch that bypasses this production gate. Component
passes below are not end-to-end delegation or complete RFC conformance.

Linux [F_SETLEASE](https://man7.org/linux/man-pages/man2/F_SETLEASE.2const.html)
documents open/truncate exclusion. The newer
[F_SETDELEG](https://man7.org/linux/man-pages/man2/F_GETDELEG.2const.html), introduced
in Linux 6.19, also describes namespace and directory delegation support. It is
a candidate for the native provider, not an already validated replacement.
The development kernel is 6.18.40.1; newer-kernel Actions/VM acceptance, metadata
coverage and surviving-owner recovery still need implementation and evidence.

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
  protocol OPEN/lock checks and file-domain conflicts are now connected, but
  that does not prove coherence for arbitrary host mutations.
- Complete durable delegation reclaim, including server/client restart and
  file-domain failure. Recorded delegation ownership alone is not recovery.
- Validate authenticated CB_RECALL against independent Kerberos/SSV clients,
  and complete named CLAIM_DELEGATE_CUR namespace handling. The component
  suite currently covers AUTH_NONE callbacks and CLAIM_DELEG_CUR_FH.
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
Expired signed grants can only inspect or clean up their own cookie; they
cannot read data, create state or renew it. Policy revocation denies IO
immediately and initiates recall while preserving the coherence guard.

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

The guard still lives in the file worker. It does not survive that worker's
death. Durable protocol ownership records are now written, but reclaim and a
surviving native guard owner do not exist yet. This is why the production file
authority refuses `wire:true` acquisition. Actual client handout and
crash/recovery coherence remain required rather than being counted as passed.

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
