# ADR 0010 — NFS experimental profile and confined persistent handle lookup

Status: accepted for the bounded M7 preview; the complete M7a/M7b release gates remain open.

The server is an isolated PACE TCP process. Identity owns opt-in AUTH_SYS export policy; file domains own native traversal, quota, durable mutation journals and persistent handle mappings. The NFS process never opens export paths directly. No OS NFS server is a runtime dependency.

## Persistent handles

This refines ADR 0003's direct native-handle reopening requirement. Linux uses `name_to_handle_at(AT_EMPTY_PATH)` on the exact confined descriptor, recording the opaque exportfs token, handle type and native birth identity. Windows restricts the preview to NTFS and records the volume/FileId128/creation identity obtained from the confined handle. Filesystems without the required native evidence fail closed.

A saved path is a lookup hint. If it no longer identifies the same native incarnation, a bounded traversal beneath the current export locates candidates. Every candidate is opened with the existing no-symlink/no-reparse/no-cross-volume adapter and its native incarnation is compared before use. A successful relocation reconciles the quota index. Search exhaustion returns a retry error; a completed search without a match returns STALE. An external rename racing the traversal does not cause permanent tombstoning. Service-mediated deletion records a tombstone. UUIDs are never reused. Native tokens plus birth identity are stored server-side rather than exposed as a capability.

The 50-byte wire handle is version (1), file-domain number (1), export UUID (16), object UUID (16), MAC (16). The object UUID refers to the immutable native incarnation record, so a separate wire incarnation counter is unnecessary. File-domain generation is deliberately absent. The MAC key and mappings are private to each domain's `file*.nfs.db`. A worker restart retains handles; metadata restore excludes these capabilities and requires NFS export enrollment again.

This strategy needs no `open_by_handle_at` privilege and cannot reopen an object outside the authorized root. Its bounded scan is unsuitable for very large or rapidly changing trees. It does not claim universal filesystem or exportfs conformance. Native ID reuse after filesystem repair/rollback, storage cloning and identity-database corruption remain outside this preview's validated recovery model.

## Authentication and state

Only loopback is supported. An administrator explicitly accepts `loopback-auth-sys`, chooses UID→user and GID→group maps, and names the anonymous user. UID 0 and all its supplied groups are squashed. All non-root primary/supplementary GIDs must map to groups of the mapped user. Unknown values are denied. AUTH_SYS is forgeable local client input, not a password or cryptographically authenticated identity. Root/host administrators are outside the threat boundary.

V4.1 sessions are nonpersistent, capped, and use slot sequence/hash/reply checks. They belong to the trusted AUTH_SYS host and can multiplex mapped users; open/lock authority and replay identity remain principal-bound. OPEN/share reservations and lock ranges are durable before success, including partial-unlock splits. Matching client/principal/owner/file state can reclaim during a 60-second grace before RECLAIM_COMPLETE. Ordinary new opens are denied during grace. Repeated OPEN upgrades its existing owner/file state; OPEN_DOWNGRADE narrows it. Only one export per session remains supported. These implemented paths do not establish full v4.1 conformance.

V3 mutation replay is a bounded persistent request/principal/hash/result cache. A conflicting XID or unfinished outcome does not reexecute the mutation. File-domain journals reserve an operation before native mutation and persist completed results; uncertain outcomes return retry errors. The preview has no automatic uncertain-write reconciliation. Cache exhaustion fails closed rather than silently evicting duplicate protection. All accepted writes, including UNSTABLE requests, complete the full write loop and a native file flush before returning FILE_SYNC; COMMIT performs a real flush. Each NFS process incarnation has a new verifier. Namespace durability retains the M2 Windows directory-flush limitation.

## Remaining compatibility work

Mode/UID/GID projections are persisted by native incarnation across export aliases; application ACLs remain authoritative. Timestamp setters operate on pinned native handles. Rename can atomically replace closed destinations; active NFS destination opens are rejected with FILE_OPEN rather than invalidated. Mandatory operation coverage, unlink-open coordination, directory change guarantees, full client reboot/trunking and multi-export sessions still need work. V3 supplies selected file procedures, MOUNT and read-only portmapper/rpcbind discovery on the configured port, but lacks NLM/NSM. UDP, rpcbind mutation/CALLIT, Kerberos, v2/v4.0/v4.2 and pNFS/RDMA remain excluded. Neither complete M7a nor M7b compatibility is published.

A later RPCSEC_GSS profile must validate GSS contexts and sequence windows, bind Kerberos principals to tauCloud users, protect integrity/privacy as selected, and use principal identity in state/reclaim/replay keys. It must have separate credential lifecycle and downgrade tests. AUTH_SYS maps cannot be reused as evidence of GSS authentication.

References: [ONC RPC](https://www.rfc-editor.org/rfc/rfc5531.html), [XDR](https://www.rfc-editor.org/rfc/rfc4506.html), [NFSv3](https://www.rfc-editor.org/rfc/rfc1813.html), [NFSv4.1](https://www.rfc-editor.org/rfc/rfc8881.html), [Linux native handles](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html), [Windows file IDs](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid).
