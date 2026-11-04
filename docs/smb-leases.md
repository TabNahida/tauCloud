# SMB lease implementation

The shared protocol state and wire encoders are implemented in
`include/taucloud/smb_lease.hpp` and `src/smb_lease.cpp`. They are compiled into
the core library and connected to the file-domain native-cache coordinator,
but are **not yet connected to network SMB CREATE or break delivery**. File leasing is not advertised
by negotiation. This is an implementation prerequisite, not lease acceptance
or complete SMB compatibility.

`lease_registry` indexes entries by ClientGuid and LeaseKey. The caller supplies
a canonical, namespace-qualified filename and a unique open identifier after
the open succeeds. Multiple opens share one state; another client using the
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
coherence and delivery boundaries. The current local result is 58 checks in
seven scenarios, alongside the updated 3,214 state checks; see
[file-domain evidence](evidence/pre-m8/smb-lease-domain-local.json).
Windows native acceptance is scheduled in Actions and is not yet established.

Remaining integration includes CREATE
contexts/capabilities, notifications and ACK routing across sessions and
connections, frontend per-open renewal/watchdogs (including NONE-to-cached
upgrades), global key/name reservation across concurrent CREATEs and file
domains, directory/parent leases, delete/recreate lifecycle, and original
Samba/native client tests. The frontend registry is not yet wired to these
operations; its metadata alone cannot grant native caching authority.
Durable handles and multichannel session binding remain separate open gates.

The implementation follows Microsoft's [lease object-store rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d8df943d-6ad7-4b30-9f58-96ae90fc6204),
[per-lease state](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/212eb853-7e50-4608-877e-22d42e0664f3),
[v1 CREATE processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/24cfce29-5d80-4651-ba5f-a2661c666b41),
[v2 CREATE processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8),
[break notifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c367fad4-c00f-4778-913d-c0560ead1360)
and [acknowledgment validation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0ccd85cd-5e1d-4dc2-9698-71b4c87c0cec).
