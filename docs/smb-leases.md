# SMB lease implementation

The shared protocol state and wire encoders are implemented in
`include/taucloud/smb_lease.hpp` and `src/smb_lease.cpp`. They are compiled into the core library and connected to the
file-domain native-cache coordinator and network SMB CREATE, break delivery and
ACK routing. Negotiation advertises file leasing on SMB 2.1/3.0/3.0.2/3.1.1;
directory leasing and multichannel remain unadvertised. This is file-lease
implementation and targeted acceptance, not complete SMB compatibility.

`lease_registry` indexes entries by ClientGuid and LeaseKey. The caller supplies
a canonical, namespace-qualified filename and a unique open identifier before
the asynchronous open. Failed CREATE releases its reservation; successful opens
retain it through backend CLOSE. Multiple opens share one state; another client using the
same key has a separate state. Filename mismatches are rejected unless the
record has delete-on-close intent. Closing the last associated open removes the
entry and clears its protocol state. Failed registration does not leave an
empty entry. Rename updates the recorded filename. The registry is bounded and
requires serialized access; authorization and native handle lifetime remain
the integrating caller's responsibility.

CREATE context parsing handles both 32-byte v1 and 52-byte v2 forms. Reserved
request fields are ignored and response fields are zeroed. Parent keys and v2
epochs are retained. Promotion requires an available native caching state,
never removes existing rights, and is suppressed while a break is unsettled.
A partial initial grant is allowed; promotion of an existing lease requires
the complete requested state to be available.
The state machine supports NONE, R, RW, RH and RWH; requests with unsupported
combinations cannot manufacture native authority.

Breaks carry the current and target states, an internal delivery serial and the
v2 epoch. Tightened conflicts are retained while the original notification is
in flight. Acknowledgments may only remove bits from that notification's target;
invalid acknowledgments leave authority and the deadline unchanged. A second
break communicates any additional loss after a valid first acknowledgment.
R-to-NONE needs no client acknowledgment, but retains unsettled state until the
notification is actually transmitted. A valid ACK can overtake its asynchronous send completion on another connection.
A stale or duplicate send completion
cannot consume another notification or extend its timer. Timeout detection
does not release native exclusion: the caller must fence the associated
opens/transports before calling `fence`.

`taucloud_smb_lease_tests` checks fixed binary vectors, all supported
initial/target/acknowledgment combinations, authority monotonicity, delayed
delivery, chained breaks, epoch wraparound, client/key isolation, resource
bounds and final-close cleanup. It passes 3,213 checks locally under Clang
ASan/UBSan/LSan ([evidence](evidence/pre-m8/smb-lease-state-local.json)). The
GCC/Clang/MSVC core steps pass at `b478fac` ([remote evidence](evidence/pre-m8/smb-lease-state-b478-remote.json)); the whole jobs were still running when recorded.

The file domain now accepts a trusted SMB worker's client GUID/lease context,
and shares one state and native exclusion across that key's opens. Each open
keeps its own signed authority deadline, granted rights and actor. Ordinary
operations and revocation retain their existing checks. Expiring or closing
one member does not drop a fresh sibling's native exclusion. Same-key opens
can join during a pending break; compatible foreign opens recall WRITE while
retaining READ/HANDLE. An incompatible sharing reservation recalls HANDLE so
the holder can close a cached handle. Foreign writes/locks and native or NFS
access recall before accessing conflicting data. Classic Level II and leases
can share physical exclusion while retaining separate acknowledgment state.

The backend returns the exact CREATE context and pending notification bytes.
`smb_cache_sent` confirms delivery by serial; an R-only invalidation keeps its
native guard until this confirmation. A racing CREATE response already reports
NONE, so it cannot re-advertise invalidated read caching at the new epoch.
`smb_cache_ack` validates on a copy, flushes writable members before committing
the transition, and retains exclusion for any subsequent tightened break.
Successful opens associate a stable native identity before acquiring cache
rights; a reused key cannot silently move to another file or namespace.

`taucloud_smb_lease_native_tests` exercises actual native exclusion, shared
opens, legacy-cache coexistence, permission isolation, expiry, NFS read/write
coherence and delivery boundaries. The initial file-domain integration passed
58 checks in seven scenarios, alongside 3,214 state checks; see
[file-domain evidence](evidence/pre-m8/smb-lease-domain-local.json).
The complete targeted GCC/Clang/MSVC jobs pass at `c45d5f2` ([remote evidence](evidence/pre-m8/smb-lease-domain-c45-remote.json)).

The frontend now reserves client/key/name tuples across connections and file
domains before CREATE suspends. It returns v1/v2 RqLs contexts, ignores v2 on
SMB 2.1, rejects malformed contexts, and keeps per-open renewal/watchdogs active
even for NONE leases that a sibling may later promote. Leases do not confer
additional file permissions. The backend remains authoritative for grants.

Break delivery uses a per-cookie serial watermark shared across connections.
A stale poll cannot retransmit a completed notification; failed delivery can
be retried by another member, and final-close cleanup removes the watermark.
Notifications have zero inner SessionId/TreeId and preserve session encryption.
ACKs use ClientGuid/LeaseKey, can arrive through another authenticated connection,
and reauthorize the owning open before applying the file-domain transition.
Cross-connection dispatch releases its own gate before waiting on a peer.

Twenty-one independent wire groups pass locally under ASan/UBSan/LSan, including
four dialects, same-key joins during recall, client isolation, invalid ACKs,
shared upgrades, native no-ACK invalidation, failed CREATE cleanup and timeout
fencing. Updated state checks total 3,217; native checks total 62. See
[current network evidence](evidence/pre-m8/smb-lease-sharing-local.json).
The initial 13-group network step passes GCC/Clang/MSVC at `3450ec6`, while
that run fails a Windows security/oplock regression after eight cases. Its
root cause remains open ([remote evidence](evidence/pre-m8/smb-lease-wire-3450-remote.json)).
The later metadata/sharing additions still await remote acceptance.

Metadata-only and write-only opens can hold native-backed RWH without gaining
READ_DATA or WRITE_DATA. Renewal and ACK use the open's actual authority,
including read-only shares. For leases, READ_CONTROL joins the attribute/SYNCHRONIZE stat
access mask: these opens retain the pinned description and do not recall data
caches merely to query metadata. An initial metadata-only open pins an RW native
description when permitted so a later write-only lease can share that object;
the logical rights of both handles remain unchanged. A foreign data open or
cache prevents WRITE caching. Classic oplocks prevent a new HANDLE lease, and
an existing HANDLE lease prevents new classic oplocks. Read-only lease/native
exclusion can still coexist with Level II.

A sharing violation first recalls HANDLE caching only: RWH becomes RW,
retaining dirty-data authority while the client has an opportunity to close
cached handles. If it ACKs without closing the conflicting open, CREATE still
fails with SHARING_VIOLATION. A later compatible CREATE independently removes
WRITE, taking RW to R. READ_CONTROL is exempt from recalling a lease, while a
classic oplock retains the narrower attribute/SYNCHRONIZE exemption required
by MS-FSA 2.1.4.12. These distinctions are covered by four-dialect wire tests
and the original Samba break_twice, statopen4 and oplock.statopen1 cases.
The full original suite now reports 27 passed, nine failed and three skipped
([sharing-recall evidence](evidence/pre-m8/smb-lease-sharing-local.json)).

All four original Samba statopen cases and its bidirectional oplock/lease
matrix pass, alongside 17 independent wire groups, 61 native checks, 12 security
and oplock regression groups and 12,583 M5 checks; see
[metadata lease evidence](evidence/pre-m8/smb-lease-metadata-local.json).
The full unmodified lease suite on this source now reports **26 passed,
10 failed, three skipped**, up from 19/17/3 before the two correction rounds.
These are local results; their remote acceptance remains pending.

The first full unmodified Samba lease run on the network integration snapshot
(before the partial-promotion correction) reports 19 passed, 17 failed and
three skipped. No test was edited. The final source is also checked with a
strict eight-case selected regression, with all eight passing; five additional
metadata/mixed-cache cases now pass and join the strict Actions selection; the full suite remains a separately labelled
non-gating diagnostic in Actions, with its failure reports retained.
Known remaining work includes sharing and chained recalls, notification connection selection,
rename/delete/recreate lifetime, timeout behavior that preserves usable opens,
ADS and directory/parent leases.
Durable handles and multichannel session binding remain separate open gates.

The implementation follows Microsoft's [lease object-store rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d8df943d-6ad7-4b30-9f58-96ae90fc6204),
[per-lease state](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/212eb853-7e50-4608-877e-22d42e0664f3),
[v1 CREATE processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/24cfce29-5d80-4651-ba5f-a2661c666b41),
[v2 CREATE processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8),
[break notifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c367fad4-c00f-4778-913d-c0560ead1360)
and [acknowledgment validation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0ccd85cd-5e1d-4dc2-9698-71b4c87c0cec).
