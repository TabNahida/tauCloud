# NFS delegation implementation

Full delegation support remains an open compatibility requirement. The current
implementation handles negotiation and refusal; it does not grant read/write
delegations, send CB_RECALL, or establish delegation recovery state.

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

- Coordinate a native cache guard with SMB, NFSv3, other NFSv4 clients, DAV/FTP
  and host mutations. Conflict detection must precede exposure of changed data.
- Give delegation state its own client/file/principal identity and lifecycle,
  including DELEGRETURN, stateid use and validation, CLOSE-independent lifetime,
  TEST_STATEID/FREE_STATEID revocation, and durable reclaim evidence.
- Queue authenticated CB_RECALL using the existing bound backchannel and slot
  replay machinery. A callback ACK confirms receipt; it does not release the
  delegation. Only return or verified revocation permits conflicting access.
- Preserve exclusion through the required recall/revocation interval. Current
  NFS leases last 60 seconds, while Linux's native lease-break setting on the
  development host is 45 seconds. Declining a grant is required until the native
  bound and advertised NFS lease can be reconciled. Do not copy SMB's transport
  close behavior: an NFS delegation survives ordinary transport disconnection.
- Keep authorization revocation separate from coherence retention. Expired
  short-lived grants must deny data access, but releasing exclusion before the
  delegation can legally be revoked would expose incoherent cached reads.
  Worker crashes and missing callbacks require bounded recovery as well.

Read/write grants, native exclusion, recall, revocation, recovery, CB_GETATTR,
optional availability/push callbacks and the expanded native-client matrix are
still required for the Full SMB/NFS objective.
