# NFS delegation implementation

Full delegation support remains an open compatibility requirement. The current
wire implementation handles negotiation and refusal; it does not grant
read/write delegations, send CB_RECALL, or establish delegation recovery state.
The file domain now has a separately tested native exclusion/lifetime primitive
that will back those grants. Its private IPC availability is not wire support.

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

- Connect the native cache coordinator below to protocol OPEN/lock state and
  client lease renewal, including other NFS clients' existing writers/locks.
  Conflict detection must precede exposure of changed data.
- Give delegation state its own client/file/principal identity and lifecycle,
  including DELEGRETURN, stateid use and validation, CLOSE-independent lifetime,
  TEST_STATEID/FREE_STATEID revocation, and durable reclaim evidence.
- Queue authenticated CB_RECALL using the existing bound backchannel and slot
  replay machinery. A callback ACK confirms receipt; it does not release the
  delegation. Only return or verified revocation permits conflicting access.
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
death; no crash-safe native guard broker or durable delegation reclaim record
exists yet. This is why the primitive is not wired into positive OPEN/WANT
responses. Positive grants, callback delivery, protocol revocation stateids and
crash/recovery coherence remain required rather than being counted as passed.
