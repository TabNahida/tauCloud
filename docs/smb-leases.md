# SMB lease implementation

The shared protocol state and wire encoders are implemented in
`include/taucloud/smb_lease.hpp` and `src/smb_lease.cpp`. They are compiled into
the core library, but are **not yet connected to SMB CREATE, the file-domain
cache coordinator or network break delivery**. File leasing is not advertised
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
GCC/Clang/MSVC workflow has a separate core step; remote results are pending.

Remaining integration includes native exclusion shared by lease identity,
same-key opens during breaks, per-open policy renewal and fencing, CREATE
contexts/capabilities, notifications and ACK routing across sessions and
connections, directory/parent leases, and original Samba/native client tests.
Durable handles and multichannel session binding remain separate open gates.

The implementation follows Microsoft's [lease object-store rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d8df943d-6ad7-4b30-9f58-96ae90fc6204),
[per-lease state](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/212eb853-7e50-4608-877e-22d42e0664f3),
[v1 CREATE processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/24cfce29-5d80-4651-ba5f-a2661c666b41),
[v2 CREATE processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8),
[break notifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c367fad4-c00f-4778-913d-c0560ead1360)
and [acknowledgment validation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0ccd85cd-5e1d-4dc2-9698-71b4c87c0cec).
