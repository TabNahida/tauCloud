# Development tasks

This is the English implementation checklist for the [roadmap](docs/roadmap.md). M0 experiments and decisions are implemented within the scope documented in the [M0 guide](docs/m0.md); functional acceptance does not require TCP 445 (user decision, 2026-10-29). [M1](docs/m1.md) implements the local management foundation. The M4 preview adds WebDAV and FTP/FTPS; later business capabilities remain unavailable; prototype evidence does not establish product feature support.

Milestones share the identifiers in the roadmap. Complete an item only with inspectable code, tests or a recorded decision. Release a protocol profile only after its acceptance gate passes on the declared host/client matrix.

## M0 — Feasibility and decisions

- [x] Pin a clean PACE revision and reproducible dependency acquisition; do not depend on adjacent local changes.
- [x] Select exact Linux/Windows, compiler, SDK, xmake and initial filesystem versions.
- [x] Record component dependency boundaries and project/PACE build-option names.
- [x] Prototype bounded blocking execution, context-safe completions, cancellation and shutdown on both hosts.
- [x] Define per-connection/global memory, queue, concurrency and timeout budgets on reference hardware.
- [x] Design PACE incremental request bodies, async response producers and `100-continue` integration.
- [x] Prove root confinement, stable object IDs and rename/delete/flush behavior on ext4 and NTFS (M0 live-object/single-component scope; persistent identity and full nested-path gates remain M2/M7).
- [x] Prototype process kill/restart, supervisor adoption, scoped grants, lease expiry and storage-generation fencing.
- [x] Select native RAID providers and disposable-disk fixtures; define preview/confirmation and recovery contracts.
- [x] Prototype verified side-by-side updates, durable journals and mixed-version IPC compatibility.
- [x] Prototype SMB negotiate/authenticate/signed-open and separate local-account credential enrollment (disposable accounts; production credential vault/MIC remain M5).
- [x] Validate SMB functionality on alternative loopback ports and document Windows port-445 coexistence limits (user-approved acceptance scope).
- [x] Specify NFS stable handles, replay/reclaim persistence and identity mapping.
- [x] Select local IPC and Docker Unix-socket/Windows-pipe transport adapters.
- [x] Record dependency licenses and security boundaries; create bilingual decision records.

Evidence: [M0 runs](docs/evidence/README.md), [decisions](docs/m0.md#decisions-and-remaining-gate). The existing Windows host's system SMB occupies 445; the probe records this without changing services. M0 is accepted under the user’s 2026-10-29 functional criterion; standard-port deployment remains a later deployment concern. Checked prototypes are not M1/M5 production implementations.

## M1 — Backend foundation

- [x] Create C++20/xmake supervisor, API, identity, file, protocol, monitor, updater, storage-admin and helper process targets plus CLI.
- [x] Implement authenticated versioned IPC with deadlines, bounded queues, cancellation and scoped caller identity.
- [x] Add per-process health/resource budgets, restart backoff, crash-loop limits and verified child adoption.
- [x] Give each database/journal one owning service; implement idempotent cross-service reconciliation.
- [x] Add Linux/GCC, Linux/Clang and Windows/MSVC CI without frontend tooling.
- [x] Implement configuration schema, validation, redacted structured logging and stable error codes.
- [x] Implement PACE listener/task ownership, admission limits, connection tracking and graceful shutdown.
- [x] Add SQLite schema, transactions, migrations, migration backups and interrupted-start recovery.
- [x] Implement TLS management endpoints, minimal health checks and capability reporting.
- [x] Implement local first-admin bootstrap, password verification, sessions, revocation and login throttling.
- [x] Add browser session/CSRF/CORS policy and scoped CLI/API authentication.
- [x] Publish OpenAPI alongside implemented `/api/v1` routes and a working CLI client.
- [x] Add foreground/service lifecycle integration for systemd and Windows SCM.
- [x] Verify clean-checkout build, authenticated CLI access and clean stop on both hosts.

Evidence: [M1 runs](docs/evidence/m1/README.md), [implemented contracts/limits](docs/m1.md), and [pre-M8 remote acceptance](docs/evidence/pre-m8/README.md). Service adapters and unit are implemented; native foreground lifecycle was tested, without registering persistent host services. Linux and Windows clean-checkout GitHub Actions have now run; each fixed-commit result is recorded separately.

## M2 — Shared identity, policy and file core

- [x] Implement users, groups, memberships and separate management roles/file grants.
- [x] Implement storage roots, private/team spaces, shares and per-protocol exposure settings.
- [x] Reject overlapping space ownership and unsafe aliases; preserve policy and single quota charging across shares.
- [x] Add root-handle resolution and traversal/reparse-point/link race protection.
- [x] Define portable path, Unicode, case-collision and unsupported-name behavior.
- [x] Implement bounded blocking file I/O with 64-bit offsets, partial I/O and explicit flush semantics.
- [x] Add per-storage-domain file workers with opaque handles, stable object identity and one lock/quota authority.
- [x] Fence failed generations, drain outstanding writes and reject stale handles/uncertain write retries.
- [x] Push policy revocation with acknowledgements and bounded lease expiry; fail closed on expired grants.
- [x] Restrict mixed writable protocols until per-combination consistency tests pass.
- [x] Implement quota reservations, accounting reconciliation and enforcement-strength reporting.
- [x] Implement staged whole-file uploads and correct random-write/cross-volume-move behavior.
- [x] Add durable jobs, idempotent recovery, progress, cancellation and attributable audit events.
- [x] Add CPU/memory/network/capacity inventory and stable disk identities on both platforms.
- [x] Add bounded disk-health collectors with unavailable/stale/permission-denied states.
- [x] Prove two-user isolation, revoked access, disk-full recovery and transfers larger than the worker hard allocation budget on both hosts (the bounded-memory acceptance profile; not larger than physical host RAM).

Evidence: [M2 runs](docs/evidence/m2/README.md), [implemented contracts/limits](docs/m2.md), and [profile decision](docs/decisions/0005-m2-file-profile.md). Initial limits include ASCII-only names, four domains with one root per volume, service-enforced quotas, and explicit rejection of cross-space moves. No external file protocol is advertised.

## M3 — WebDAV and first backend preview

- [x] Deliver tested PACE streaming integration before enabling large WebDAV uploads/downloads.
- [x] Implement authentication before body admission, range/conditional requests and cancellation cleanup.
- [x] Implement required DAV methods, persistent properties, collections and multistatus responses.
- [x] Harden XML parsing, recursive traversal and destination/path validation.
- [x] Pass Class 1 conformance before advertising Class 1.
- [x] Implement and validate locks, expiry/restart policy and cross-writer enforcement before advertising Class 2.
- [x] Record Windows Explorer, macOS Finder and Linux DAV interoperability results and limitations.
- [x] Cover users/spaces/shares/protocols/jobs/monitoring through documented API and CLI.
- [x] Implement metadata backup/restore with separate file-data and secret recovery instructions.
- [x] Publish a backend preview explicitly listing unimplemented protocols and supported hosts.

Acceptance: [M3 evidence](docs/evidence/m3/README.md). Explorer and Finder are recorded as untested; the accepted preview is loopback TLS with the documented limits.

## M4 — FTP and FTPS

- [x] Implement an isolated FTP/FTPS worker with independent health, resource limits and restart policy.
- [x] Implement FTP control/data state machines, passive ports, directory/file operations and safe resume.
- [x] Add EPSV/PASV, feature discovery, machine-readable listings and accurate transfer-type errors.
- [x] Implement explicit FTPS and protected, correctly associated data channels.
- [x] Keep plaintext FTP explicit opt-in; reject anonymous/FXP/unsupported active-mode requests.
- [x] Verify FileZilla, curl and an independent FTP client on both server hosts.
- [x] Test revoked credentials, interrupted transfers, TLS failures and passive-port exhaustion.
- [x] Kill/restart the worker during transfer; verify sibling protocols survive and storage ownership reconciles.

Implementation and recorded scope: [M4 guide](docs/m4.md), [M4 evidence](docs/evidence/m4/README.md). Unmodified FileZilla GUI FTPS upload/download, curl and Python FTP clients pass on Linux and Windows; fixed-commit results are recorded in [pre-M8 evidence](docs/evidence/pre-m8/README.md). The deployment scope remains the documented loopback preview.

## M5 — SMB2

- [x] Implement bounded SMB2 framing/compound codecs, credits and request/session lifetime.
- [x] Implement local-account authentication with protected SMB credentials and signing.
- [x] Implement tree/file operations, attributes, information queries and error translation.
- [x] Implement share modes, byte-range locks, delete-on-close and rename/open consistency.
- [x] Define truthful security descriptor/ACL behavior across Linux and Windows.
- [x] Evaluate and implement the minimal authenticated share-enumeration RPC surface required by clients.
- [x] Pass the signed SMB 2.1 profile; add 2.0.2 only as explicit compatibility mode.
- [x] Keep optional leases/oplocks/durable handles disabled until individually verified.
- [ ] Complete full SMB standards/client compatibility, including the additional feature gates below. The earlier ADR 0008/0009 matrix is passing: Native Windows encrypted SMB, macOS 15.7.9 signed SMB, Samba smbclient, independent wire clients and 60 torture selectors / 76 cases pass. Kernel CIFS without NTLM MIC remains explicitly incompatible; excluded feature groups are mapped in the applicability report.
- [x] Document deployment conflicts, dialect limits and revocation/recovery behavior.

Implementation scope and exclusions: [M5 guide](docs/m5.md), [ADR 0008](docs/decisions/0008-smb-profile.md), [evidence](docs/evidence/m5/README.md). Signed SMB 2.1 only; DOS attributes, four timestamps, bounded EAs, native preallocation and per-open modes are implemented; persistent DACLs and shared file access checks are implemented; NFS mode synchronization and simple NFSv4 ACLs are implemented; privileged owner/SACL and full permission semantics remain open. The selected client evidence passes, but the full M5 compatibility gate is open; the user explicitly requires expanding beyond the earlier ADR exclusions before further M8 development. See [applicability](docs/smb-torture-coverage.md) and [fixed-commit evidence](docs/evidence/pre-m8/README.md).

## M6 — SMB3

- [x] Implement and validate 3.0 and 3.0.2 requirements independently.
- [x] Implement tested encryption, signing/key derivation and negotiated algorithm policy.
- [x] Implement SMB 3.1.1 negotiate contexts and preauthentication integrity.
- [x] Reject tampering, replay and invalid negotiation/downgrade paths.
- [x] Evaluate durable handles, caching, notifications and multichannel as separate capabilities.
- [x] Validate reconnect, mixed-client consistency and restart behavior before publishing support.
- [x] Make 3.1.1 the modern target default only after the full selected profile passes.

Selected-profile evidence: [M6 guide](docs/m6.md), [ADR 0009](docs/decisions/0009-smb3-security.md), [three-host validation](docs/evidence/m6/README.md). Highest-common 3.1.1 is the modern default; signed 2.1 compatibility remains. Encryption is client-selected, not server-mandated. Durable handles, caching, notification and multichannel are separately evaluated and deliberately not granted. Complete native-client/Samba conformance and load testing remain outside this backend-preview acceptance.

## M7 — NFS

- [x] Implement bounded TCP ONC RPC record framing, XDR and authentication dispatch (loopback experimental profile).
- [x] Implement export policy, UID/GID mapping, root squash and explicit AUTH_SYS trust restrictions.
- [x] Implement stable file handles, filesystem identity and stale-handle detection on ext4 and NTFS (bounded native-incarnation lookup; ADR 0010).
- [x] Implement v4.1 required fore-channel operations, sessions/slots, state IDs and replay handling for the regular-file/directory AUTH_SYS profile; map supported/refused behavior and tests in the operation coverage report.
- [x] Implement authorized pseudo-root enumeration/traversal, multi-export sessions and per-reply authorization checks on replay (selected profile; full conformance remains open).
- [x] Implement lock/open ownership, leases, recovery grace and reclaim persistence (bounded AUTH_SYS profile; cross-user, split-range and restart tests).
- [x] Verify v4.1 FILE_SYNC, server reboot, retransmission, durable unlinked OPEN recovery and Linux kernel close-to-open cache revalidation, including equal-size external writes with restored mtime.
- [ ] Complete full M7a conformance, including authenticated security and the additional gates below. Earlier ADR 0010 profile evidence: 145 applicable upstream cases pass, 121 exclusions remain visible. Full RFC 8881 / RPCSEC_GSS conformance is not claimed.
- [x] Add policy-filtered MOUNT discovery, bounded mount records and read-only rpcbind DUMP/GETVERSADDR.
- [x] Retain unlinked/replaced OPEN objects with durable private links and recovery journals; charge quota through file-domain/all-service restart and release it after last CLOSE/lease expiry (Linux and Windows recovery assertions and corrected test cleanup pass).
- [x] Implement v3 operations, MOUNT/rpcbind and the selected NLMv4/NSMv1 recovery profile; real Linux blocking locks, GRANTED callback and post-reboot kernel reclaim pass.
- [x] Verify FILE_SYNC upgrades of UNSTABLE requests, COMMIT, duplicate requests and reboot verifiers in the experimental profile.
- [x] Complete M7b Linux/macOS/eligible Windows client tests; publish restrictions. Linux kernel v3/v4.1, macOS 15.7.9 v3 and Windows Server 2025 Client for NFS v3 TCP roundtrips pass. macOS/Windows use nolock; Linux separately proves NLM/NSM recovery.
- [x] Design RPCSEC_GSS/Kerberos as a later authenticated profile; do not conflate it with AUTH_SYS (ADR 0010).

Selected-profile acceptance: [M7 guide](docs/m7.md), [中文](docs/m7.zh-CN.md), [ADR 0010](docs/decisions/0010-nfs-preview.md), [operation coverage](docs/nfs-operation-coverage.md), [fixed-commit evidence](docs/evidence/pre-m8/README.md). Share-deny, locks/reclaim, OPEN upgrades, native timestamps, durable unlink/replacement retention, alias metadata and persistent change counters are implemented and tested. Windows directory metadata handles and Linux zero-state NLM reclaim are corrected. This validates the earlier confined regular-file/directory AUTH_SYS contract only. The full M7 gate remains open and is a prerequisite to further M8 development.

## Full SMB/NFS compatibility prerequisite (user decision, 2026-10-31)

Native exclusion uses Linux leases / Windows RW oplocks. The adapter and file-domain
coordinator pass the full GCC/Clang ASan+UBSan/MSVC targeted matrix at `9b32f48`
([evidence](docs/evidence/pre-m8/cache-authority-9b-remote.json)). The separate Windows
backend DAV-after-restore and M8 fake-engine failures remain explicitly unresolved.

SMB now grants native-backed EXCLUSIVE data oplocks, recalls to NONE, validates
ACK ownership, flushes before release and fences expired transports independently
of stalled RPCs. Related asynchronous CREATE/READ/CLOSE and pre-mutation SET_INFO
waits retain their AsyncIds and cancellation semantics. [Local wire checks](docs/evidence/pre-m8/smb-oplock-local.json)
cover four dialects, native host IO, NFS/DAV reads, idle renewal, revocation and a
paused identity service. Independent EXCLUSIVE wire checks pass GCC/Clang/MSVC
at `5a78b29`; its targeted matrix fails original Samba exclusive3 on both Linux
compilers ([evidence](docs/evidence/pre-m8/smb-oplock-5a-remote.json)). The maximum-access
sharing-before-recall correction passes original exclusive1/3/4 locally and on
GCC/Clang at `4420774`; that run has an unresolved Windows NFS EXCHANGE_ID
timeout ([evidence](docs/evidence/pre-m8/smb-shared-cache-442-remote.json)). Attribute-only OPEN/OPEN_IF now retains the pinned native
object without recalling data caches; mutation still recalls first. Four-dialect
local checks and original Samba exclusive4 pass; the full targeted three-platform
acceptance passes at `07a7fe5`. The file domain now supports EXCLUSIVE-to-Level-II
downgrade and shared native exclusion with independent reader authority,
write/lock invalidation, close and expiry tests. Level II wire grants, no-ACK
invalidation, read-only-share renewal, compound writes, delete-pending and
downgrade escalation now pass local checks and the entire GCC/Clang/MSVC
targeted matrix at `07a7fe5` ([local](docs/evidence/pre-m8/smb-level2-local.json),
[remote](docs/evidence/pre-m8/smb-level2-07-remote.json)). The full original oplock
suite still fails. Existing-file overwrite/supersede now add and check implicit
rights before recall, retain native descriptions for subsequent shared grants,
and pass original exclusive5/9 locally. The full suite is now 8 passed / 34 failed,
with every failure retained; cross-platform overwrite acceptance is pending
([evidence](docs/evidence/pre-m8/smb-overwrite-local.json)). BATCH grants now recall
before sharing checks and permit cached CLOSE, attribute-only creation, read-only
renewal and downgrade. Local independent checks pass and the full original
oplock suite is 35 passed / 7 failed without skips; all remaining failures are
retained ([evidence](docs/evidence/pre-m8/smb-batch-local.json)). Cross-platform
BATCH acceptance, same-transport timeout recovery, leases, remaining cache transitions, namespace/handle
caching and NFS delegations remain open; see
[native cache coherence](docs/native-cache-coherence.md).

The earlier ADR exclusions describe the existing implementation, not permission to exclude features from this expanded goal. Preserve the passing limited-profile evidence while adding independent evidence for the following gates. Optional protocol facilities must be explicitly negotiated/refused according to the standards; refusal alone is not feature implementation.

Latest targeted evidence: overwrite implicit access and retained Level II native
descriptions pass GCC/Clang/MSVC at `0b93c80` (40 Level II groups per platform,
28/28/27 EXCLUSIVE groups and eight original Samba cache selectors on Linux;
[remote record](docs/evidence/pre-m8/smb-overwrite-0b93-remote.json)). Security
QUERY_INFO now ignores unknown/SET-only flags, filters requested descriptor
sections and preserves exact required-size error contexts through synchronous
and asynchronous completion. All 20 four-dialect local groups, 13 shared ACL
groups and 12,573 M5 core checks pass; cross-platform acceptance of this follow-up
is pending ([local record](docs/evidence/pre-m8/smb-security-query-local.json)).
That diagnostic reached anonymous reauthentication, which the subsequent
increment below implements. These corrections do not close the full
security, session, cache or NFS gates below.

Anonymous NTLM reauthentication now retains an existing valid security context,
keys and authority lifetime; it cannot establish new file authority or revive
expired/revoked sessions. Eleven independent local groups and 12,583 M5 checks
pass, and original Samba reauth2/3 now pass. That increment left reauth4 failing
at SET_INFO and reauth5 at unlinking a nonexistent destination; the session gate stays
open ([evidence](docs/evidence/pre-m8/smb-anonymous-local.json)). BATCH's Windows
run at `ccdcd08` passes all 37 BATCH groups but fails NFS CB_NOTIFY_LOCK testing
when a later OPEN returns INVAL. This differs from the earlier first-EXCHANGE_ID
timeout. Original domain errors are now logged before NFS status translation to
diagnose the cause; no timeout/root-cause fix is claimed
([failure evidence](docs/evidence/pre-m8/nfs-notify-ccd-windows-failure.json)).

Classic oplock metadata semantics now distinguish SET_SECURITY from data
invalidation and exclude the originating EXCLUSIVE/BATCH open from EOF/allocation
recall. Level II still invalidates every reader; missing WRITE_DATA fails before
recall. Original reauth4 now passes, and reauth5 remains failed. Twelve independent
four-dialect groups verify preserved grants, shared-reader invalidation and ACL
boundaries ([local evidence](docs/evidence/pre-m8/smb-security-oplocks-local.json)).
Windows native first-write failure at `e9c7f8b` is retained with its SET_INFO
self-recall trace. The complete GCC/Clang/MSVC metadata matrix and Windows native security
operations now pass at `61b1bbd`
([failure evidence](docs/evidence/pre-m8/smb-native-e9c-windows-failure.json),
[remote acceptance](docs/evidence/pre-m8/smb-security-61-remote.json)).

SET_SECURITY now sets regular-file Archive and preserves explicit ChangeTime;
automatic ChangeTime and attribute notifications share the durable close queue
with rename. Directory security updates leave these metadata fields unchanged.
Twenty local signed/encrypted groups cover four dialects, failed requests,
freeze/re-enable, peer close and process-loss recovery; rename, classic-cache
and cross-protocol ACL regressions pass. Windows remote acceptance passes at
`0276cbb`; GCC, Clang and MSVC targeted acceptance now all pass
([local evidence](docs/evidence/pre-m8/smb-security-metadata-local.json),
[three-platform evidence](docs/evidence/pre-m8/smb-security-metadata-027-remote.json)). This does not
close the full metadata or security gates below.

Backend M7 at `0e69a2f` exposed a stale M5 integration assertion that still
expected empty security selection to be unsupported. It now verifies the exact
20-byte self-relative header without READ_CONTROL and the short-buffer error;
all 12 M5 integration groups pass locally. Windows DAV `lease_expired` remains a
separate unresolved failure ([diagnosis](docs/evidence/pre-m8/m7-0e69-failure-diagnosis.json),
[local acceptance](docs/evidence/pre-m8/smb-security-query-m5-local.json)).

- [x] Implement AlSi CREATE/overwrite allocation with durable quota, initial EA prevalidation and failed-new-CREATE cleanup; targeted GCC/Clang ASan+UBSan/MSVC checks pass at `fc28c4c`, including the smaller sparse-overwrite correction.
- [x] Implement selected-name EA queries with bounded output and independent enumeration cursors; all three targeted jobs pass at `fc28c4c`.
- [x] Implement MxAc current-policy maximal-access responses, optional timestamps and chained QFid replies, including encrypted SMB3 contexts; all three targeted jobs pass at `fc28c4c`.
- [x] Report native allocated bytes in NFSv3 used/NFSv4 space_used, verified independently for empty/small/sparse-or-extended/truncated files on Linux and Windows; all three targeted jobs pass at `fc28c4c`.
- [ ] Complete SMB metadata conformance. Rename archive/deferred ChangeTime, close notification and persistent recovery now pass seven independent local groups plus original Samba `notify.mask-change`; the GCC/Clang ASan+UBSan/MSVC matrix passes at `7fd15ce` ([local evidence](docs/evidence/pre-m8/smb-rename-metadata-local.json), [remote evidence](docs/evidence/pre-m8/smb-rename-7fd-remote.json)). CREATE delete-on-close now uses durable per-open intents, activates at close, preserves nonempty directories and retains native identity across rename/recovery; independent/core checks and the GCC/Clang ASan+UBSan/MSVC matrix pass at `d48e9a2` ([evidence](docs/evidence/pre-m8/smb-d48-remote.json)). Persistent DOS attributes, distinct timestamps, per-handle freeze/re-enable, EAs (pagination, change time, exact aggregate limit and status codes), native-object retention, preallocation with durable logical quota and per-open modes pass the targeted GCC/Clang ASan+UBSan/MSVC matrix at `e7388f2`. The additional CREATE/EA/maximal-access checks above pass at `fc28c4c`. Full timestamp range, short names and remaining upstream cases are open.
- [ ] Complete Windows security descriptor/ACL and NFS permission conformance. Persistent simple DACLs, creation inheritance, SecD, ordered access checks, owner/group boundaries, access-based enumeration and cross-protocol enforcement are implemented; see [shared security](docs/file-security.md). GCC/Clang ASan+UBSan/MSVC security tests and native Windows Get-Acl/Set-Acl pass at `993f29f` ([evidence](docs/evidence/pre-m8/security-993f29f-remote.json)). Explicit per-user/space ownership take/restore authority now closes the original privileged-owner failure locally: unmodified Samba `smb2.acls` passes 14/14 with restoration enabled, and the ordinary 13-case profile is retained. Independent ownership/revocation tests now pass GCC/Clang ASan+UBSan/MSVC at `179e060`; the full restore ACL suite passes GCC but disconnected under Clang. A same-binary local diagnostic identifies the 512 MiB ASan fixture budget: 1 GiB passes the full 14 cases and an additional SDFLAGSVSCHOWN run with stable PID/descriptor count; production limits remain unchanged. Remote reacceptance at `682b007` passes the full 14 cases on both GCC and Clang, plus MSVC ownership/security checks ([local diagnostic](docs/evidence/pre-m8/smb-owner-local.json), [remote evidence](docs/evidence/pre-m8/smb-security-682b007-remote.json)); broader ACL conformance remains open. NFS low-nine-bit chmod, ALLOW/DENY ACLs, AUTH_SYS group enforcement and shared SMB access pass the GCC/Clang ASan+UBSan/MSVC matrix at `28e7852` ([evidence](docs/evidence/pre-m8/nfs-acl-28e7852-remote.json)). Twelve-bit mode, mode_set_masked, setgid inheritance, sticky namespace checks and cross-protocol set-ID clearing are implemented with independent tests; their GCC/Clang ASan+UBSan/MSVC matrix passes at `1920af2` ([evidence](docs/evidence/pre-m8/nfs-mode-1920af2-remote.json)). A subsequent native Linux setgid check exposed numeric GID alias inheritance; it is reproduced, corrected and passes native Linux reacceptance at `2364720` ([failure evidence](docs/evidence/pre-m8/nfs-mode-1920af2-native.json), [passing evidence](docs/evidence/pre-m8/nfs-gid-2364720-native.json)). Full backup/restore privileges, SACL/conditional ACE and domain mapping remain open.
- [x] SMB asynchronous blocking lock queues, cancellation, disconnect/close races and fairness. [Fixed-source GCC/Clang ASan+UBSan/MSVC acceptance](docs/evidence/pre-m8/smb-blocking-03ca0f4-remote.json) passes at `03ca0f4`: 113 core checks, 27 GCC / 25 Clang / 25 MSVC client groups and four original Samba async/cancel cases on both Linux compilers. Includes idle/frame deadlines. A later credential-revocation holder-lock race is fixed at `993f29f`; the same three-platform matrix passes, including a regression that keeps the revoked transport open until a fresh session acquires the old range. Resilient/durable replay remains a separate unfinished gate.
- [ ] SMB named streams/EAs, broader names/directory enumeration, filesystem information and allocation semantics. CREATE dot normalization now preserves share-root confinement, canonical handles and final-object authority; three independent signed/encrypted groups pass locally ([implementation](docs/smb-paths.md), [evidence](docs/evidence/pre-m8/smb-paths-local.json)). Remaining names/streams and remote acceptance stay open.
- [ ] SMB session reauthentication/reconnect, Kerberos, advertised signing/encryption algorithms and Linux kernel-client compatibility. SMB3.1.1 now negotiates GMAC/CMAC/HMAC-SHA256 with mandatory CMAC fallback; targeted GCC/Clang ASan+UBSan/MSVC signing acceptance passes at `682b007` ([evidence](docs/evidence/pre-m8/smb-security-682b007-remote.json)). Cipher-free negotiation, ignored repeated contexts and mandatory preauthentication errors now pass 1,137 core checks and 23 independent M6 client groups locally; remote acceptance for this follow-up passes all three platforms at `1e92b0d` ([evidence](docs/evidence/pre-m8/smb-nfs-1e92b0d-remote.json)). AES-256-CCM/GCM for SMB 3.1.1 is implemented with full Kerberos key derivation and independent primitive/client/renewal tests; GCC and MSVC acceptance passes at `179e060`; Clang was blocked earlier by the full restore ACL diagnostic ([historical evidence](docs/evidence/pre-m8/smb-security-179e060-remote.json)); the complete targeted three-platform matrix now passes at `682b007`. Linux Kerberos/SPNEGO now implements explicit principal mapping, signed/encrypted SMB2/3, mapping revocation and key/context lifecycle; independent Python and unmodified Samba clients pass locally. Same-session NTLM and Kerberos/SPNEGO renewal now preserves keys, opens and locks, distinguishes expiry from revocation and rejects identity substitution in local tests. GCC/Clang userspace Kerberos and MSVC shared regression pass at `4ef5199`; the corrected native CIFS request-key pattern reaches authentication at `456e2b4`, exposing an overly strict SMB GSS flag check. The flag check is corrected and regression-tested with real tickets; native CIFS reacceptance passes for signed SMB2.1 and encrypted SMB3.0/3.0.2/3.1.1 at `179e060` ([evidence](docs/evidence/pre-m8/smb-gss-456e2b4-remote.json)). GCC/Clang renewal passes; MSVC renewal and SQLite cleanup pass at `179e060`; Windows Kerberos, reconnect and the upstream oplock-dependent session suite remain open ([implementation](docs/smb-kerberos.md)).
- [ ] Negotiate and validate leases/oplocks, notifications, durable/replay and multichannel behavior. A shared ClientGuid/LeaseKey registry, v1/v2 codecs and lease break/ACK state machine pass all three platform core steps at `b478fac`. File-domain native exclusion, same-key opens during breaks, per-open authority, legacy coexistence and NFS coherence now pass 58 local native checks plus 3,217 state checks. Network file leasing now has 34 independent local wire groups covering four dialects, shared CREATE, sessionless breaks with protected ACK/data, cross-connection ACK, renewal and fencing; metadata-only/write-only caching and mixed oplock/HANDLE lease rules now pass five original Samba cases and 61 native checks; the full original Samba lease diagnostic is now 32 passed / 4 failed / 3 skipped ([evidence](docs/evidence/pre-m8/smb-lease-namespace-local.json)); Queued overwrites now chain RWH/RH/R/NONE with 3,243 state checks, 73 native checks and four-dialect ACK/delivery ordering coverage ([evidence](docs/evidence/pre-m8/smb-lease-chain-local.json)); original breaking3 passes while the v2 legacy epoch expectation remains recorded as a failure. Delivered RH invalidation now permits data operations before HANDLE ACK, releases native exclusion, and completes safely to NONE after a verified 35-second timeout; 30 wire groups, 3,271 state checks and 85 native checks cover the behavior ([evidence](docs/evidence/pre-m8/smb-lease-rh-local.json)). Regular-file rename now preserves its originating lease and waits for foreign HANDLE ACK; disposition and DELETE_ON_CLOSE remove only foreign HANDLE caching, with original v2_rename/rename_wait/unlink passing. Native Windows trace exposed an invalid encrypted sessionless notification, now corrected with explicit inner/transform SessionId validation ([failure evidence](docs/evidence/pre-m8/smb-native-lease-transform-e3-remote.json)). Directory and delete/recreate/reconnect lifetime semantics remain unfinished ([implementation and remaining work](docs/smb-leases.md)). Native asynchronous CHANGE_NOTIFY supports all four dialects, host changes, recursive watches, FIFO/cancellation/teardown and bounded overflow. Independent multi-session authentication/replacement (9 groups), confined dot paths (3), subtree watch reuse (440 exact events), peer-notification ordering/teardown (3), notification lifecycle (19 Linux / 16 Windows), and all 23 M6 groups now pass the GCC/Clang ASan+UBSan/MSVC matrix at `4f8ec28`. The complete original Samba `smb2.notify` suite passes 23/23 without skips on both Linux compilers ([fixed-source evidence](docs/evidence/pre-m8/smb-sessions-notify-4f-remote.json)). Earlier M6 transport-teardown expectations and GCC peer-notification ordering failures remain recorded ([M6 failure](docs/evidence/pre-m8/smb-multisession-dbf-remote.json), [ordering failure and fix](docs/evidence/pre-m8/smb-notify-peers-local.json)). Leases/oplocks, durable/replay/multichannel and BATCH-oplock-dependent original session cases remain open; passing notification conformance does not close these gates. See [notification behavior](docs/smb-notifications.md).
- [ ] NFS RPCSEC_GSS/Kerberos authentication, integrity/privacy, replay windows, principal mapping and key/context lifecycle. Linux MIT GSSAPI now implements all three services, verified principal mappings, replay windows, key rotation, expiry/restart and authenticated destroy; real KDC and 15 selected unmodified pynfs cases pass locally. Cross-service SECINFO/SECINFO_NO_NAME, WRONGSEC placement, isolated discovery grants and anonymous discovery without file-access fallback now pass local regression. GCC/Clang ASan+UBSan/MSVC targeted regression passes at `b5442ad`, including real Linux kernel mounts with krb5/krb5i/krb5p ([evidence](docs/evidence/pre-m8/nfs-gss-b5442ad-remote.json)); Windows acceptor support and broader security negotiation remain open; see [Kerberos implementation](docs/nfs-kerberos.md).
- [ ] NFS link/symlink/special-file semantics with confinement, stable identity and quota safety across protocols.
- [ ] NFS backchannel/delegation/session/trunking/recovery and complete mandatory security/operation behavior against RFC 8881 and NFSv3 specifications. TCP backchannel binding, serialized reverse RPC, AUTH_NONE/AUTH_SYS CB_NULL probes and path-down/reconfiguration/disconnect state now pass independent local lifecycle checks and original pynfs CSESS20/CSESS21 ([evidence](docs/evidence/pre-m8/nfs-backchannel-local.json)); Solo CB_COMPOUND/CB_SEQUENCE probes validate replies and preserve exact slot replay; retries now wait for confirmed original-transport disconnection, including reconfiguration and asynchronous close races ([corrected local evidence](docs/evidence/pre-m8/nfs-cb-retry-local.json)); Definitive callback errors now preserve live transports: initial BADSESSION races and DELAY retry exact slots, unbound paths can rebind, and established slot faults set BACKCHANNEL_FAULT; six independent recovery groups and protected-error regression are recorded ([evidence](docs/evidence/pre-m8/nfs-callback-recovery-local.json)). The complete targeted GCC/Clang/MSVC jobs pass at `ab57b78`, including callback recovery ([remote evidence](docs/evidence/pre-m8/nfs-callback-recovery-ab57-remote.json)). CB_NOTIFY_LOCK now implements bounded advisory notifications, nonblocking cancellation, fresh authority, referring calls, timeout/replay and expired-client cleanup ([local evidence](docs/evidence/pre-m8/nfs-notify-lock-local.json)); Linux RPCSEC_GSS callbacks now support all three services, additive handles, authenticated replies, independent counters, bounded channel sizes and expiry/recovery; eight real-KDC local groups plus shared regression pass ([implementation](docs/nfs-kerberos.md#authenticated-backchannel), [local evidence](docs/evidence/pre-m8/nfs-gss-backchannel-local.json)); GCC/Clang remote acceptance passes all eight groups at `70838b7`; MSVC passes shared AUTH_SYS regression ([fixed-source evidence](docs/evidence/pre-m8/nfs-gss-backchannel-708-remote.json)). Linux SP4_MACH_CRED now protects negotiated operations, connection binding and replay, and permits agreed machine cleanup of user state after mapping revocation; 16 real-KDC groups pass locally ([implementation](docs/nfs-kerberos.md#machine-credential-state-protection), [evidence](docs/evidence/pre-m8/nfs-machine-local.json)). GCC remote acceptance passes all 16 groups; Clang is pending ([evidence](docs/evidence/pre-m8/nfs-machine-2d-gcc.json)). Linux SSV negotiation, directional HMAC/AES RPC protection, key rotation/window, additive handles, authenticated callbacks and negotiated cleanup now have independent wire and fixed-vector acceptance ([implementation](docs/nfs-kerberos.md#ssv-state-protection), [local evidence](docs/evidence/pre-m8/nfs-ssv-local.json)); GCC/Clang pass all 25 SSV groups and all three platforms pass core vectors at `546919a`; both Linux jobs pass and the Windows M2 lease-expiry failure remains ([remote evidence](docs/evidence/pre-m8/nfs-ssv-546-remote.json)). CB_RECALL/other callbacks, delegation, native SSV recovery and Windows GSS remain unfinished. CREATE_SESSION backchannel buffer limits and preserved operation/concurrency counts now pass independent local boundary/replay checks; the unmodified create_session selection passes 28 cases with three delegation-dependent failures retained ([evidence](docs/evidence/pre-m8/nfs-session-negotiation-local.json)). The channel-limit/CB_NULL transport correction passes three-platform acceptance at `1e92b0d` ([evidence](docs/evidence/pre-m8/smb-nfs-1e92b0d-remote.json)); the CB_SEQUENCE/retry correction passes all three platforms at `c425fc6` ([evidence](docs/evidence/pre-m8/nfs-cb-retry-remote.json)); the CB_NOTIFY_LOCK addition passes all three platforms at `3d65a90`, including the unmodified pynfs client scenario on both Linux compilers ([evidence](docs/evidence/pre-m8/nfs-notify-lock-3d65-remote.json)). Native allocated-byte reporting is verified by the checked subtask above; these do not close the remaining operation/security gates.
- [ ] Run the expanded unmodified Samba/pynfs suites and native Linux/Windows/macOS matrix; retain every failure/exclusion with an explicit standards-based applicability reason.

## M8 — Plugins and Docker

- [x] Define manifests, IPC versions, bounded messages and explicit capability grants.
- [x] Implement worker supervision, health, crash backoff and private configuration/data directories; recover the same verified worker across manager crashes, including startup.
- [x] Implement package validation, install/enable/disable/upgrade/rollback/uninstall with data preservation.
- [x] Require explicit approval for increased plugin permissions in the management API flow.
- [x] Enforce trusted-code-only mode with explicit administrator acceptance; OS confinement is not verified and untrusted native plugins are not accepted.
- [x] Implement Docker API negotiation and approved Unix-socket/named-pipe/mutual-TLS transports. Unix, Windows named pipe and mutual TLS fixtures pass the GCC/Clang/MSVC Actions matrix.
- [x] Implement container/image/volume/network inventory, bounded stats/logs and authorized start/stop/restart/remove actions. Arbitrary create/exec/build/pull and daemon proxying are not exposed.
- [x] Enforce engine OS/capability distinctions and return engine-side paths without Windows/VM/WSL host path translation.
- [x] Prevent general daemon proxying and withhold daemon configuration/permissions from unrelated plugins at the IPC boundary. Trusted same-account native code is not an OS security boundary against direct socket access.
- [x] Test missing/disconnected/malformed engines, unauthorized actions, permission changes, plugin crash loops and manager crash recovery with GCC and Clang ASan/UBSan.
- [x] Run the MSVC/Windows named-pipe matrix and real Linux Docker Engine Actions job: all three jobs pass at `8784ce8`. Native Windows-container/VM/WSL deployment compatibility remains unverified and is not inferred from protocol fixtures.

Implementation and limits: [M8 API/SDK](docs/m8.md), [中文](docs/m8.zh-CN.md), [local validation](docs/evidence/m8/README.md). The existing implementation and Linux fault/transport tests pass locally; the prepared GCC/Clang/MSVC and real Linux engine matrix passes. Further M8 development is deferred until the expanded SMB/NFS prerequisite above passes.

## M8b — Disk and RAID administration

- [ ] Model disks, partitions, arrays/pools, virtual disks, filesystems, mounts and user spaces separately.
- [ ] Implement Linux MD/mdadm and Windows Storage Spaces capability-aware adapters; validate mirror/RAID1 first.
- [ ] Add read-only discovery and explicit adoption/import of supported existing arrays.
- [ ] Implement topology-bound plans with stable device IDs, affected consumers and erasure/downtime previews.
- [ ] Protect system/in-use/state disks; require administrator confirmation bound to each destructive plan.
- [ ] Implement create, replacement/rebuild, check and supported expansion through typed privileged operations.
- [ ] Serialize mutations, quiesce affected shares/consumers and reject topology drift or unsafe access.
- [ ] Persist native operation identities and reconcile restart/timeouts without repeating destructive steps.
- [ ] Verify partial failures, cancellation limits, member loss and rebuild on disposable disks and representative hardware.
- [ ] Report unsupported RAID layouts, hardware controllers and filesystem operations accurately.

## M8c — Online component updates

- [ ] Define signed manifests, trusted-key rotation, package identity/freshness and downgrade policy.
- [ ] Implement check/download/offline-import/verify/stage separately from authorized installation.
- [ ] Add durable update journals, side-by-side version directories and recoverable active-version selection.
- [ ] Preview compatibility, affected services, disconnects, restart/reboot requirements and rollback boundaries.
- [ ] Implement supported mixed-version IPC, per-component drain/switch and exclusive storage-owner fencing.
- [ ] Add per-owner schema backups/migrations and block unsafe automatic metadata rollback after new writes.
- [ ] Verify post-switch health, guarded rollback and explicit recovery-required outcomes.
- [ ] Implement supervisor/helper installer handoff and test interrupted upgrade recovery on both hosts.
- [ ] Coordinate maintenance locks with disk/RAID jobs; keep unrelated services available where declared.
- [ ] Test every transition under process failure, corrupt packages, version skew, disk-full and power-loss simulation.

## M9 — Desktop WebPanel

- [ ] Choose frontend tooling after the selected initial backend scope and API contracts pass acceptance; keep build/release independent.
- [ ] Implement desktop shell, launcher, taskbar, notifications and per-user preferences.
- [ ] Implement window focus/stacking, move/resize/minimize/maximize/restore, keyboard alternatives and narrow-screen layout.
- [ ] Implement setup/login, users/groups/spaces/shares and protocol management through public APIs.
- [ ] Add File Manager, Control Panel, Storage Manager, Resource Monitor, Applications, Containers and Update Center apps.
- [ ] Add durable Task/Notification Center, safe storage/update previews and reconnect by job ID.
- [ ] Separate server jobs from browser uploads; closing a window must not silently cancel server work.
- [ ] Isolate app view failures; define sandboxed-origin boundaries before allowing third-party UI.
- [ ] Use capability-driven controls and explicit stale/unavailable/error states.
- [ ] Add authenticated event updates with bounded queues and resync, retaining polling fallback.
- [ ] Verify session expiry, access denial, configuration conflicts and recovery flows.
- [ ] Validate accessibility, localization and independent frontend/backend version compatibility.

## Release hardening and ongoing work

- [ ] Run malformed-input fuzzing, sanitizers where supported and privilege-boundary tests.
- [ ] Verify worker crash/hang/overload, policy lease expiry and scoped recovery without whole-service restart.
- [ ] Test cross-protocol lock/cache/revocation combinations before relaxing writer restrictions.
- [ ] Measure throughput/latency/CPU/memory on documented hardware and storage workloads.
- [ ] Validate Linux/Windows install, upgrade, rollback limits and uninstall without user-data loss.
- [ ] Run restore drills and restart/failure injection against disposable datasets.
- [ ] Publish exact host/filesystem/client support, deviations, dependency versions and licenses.
- [ ] Add runnable build/setup guides only when verified commands and targets exist.
- [ ] Keep README and English/Chinese docs aligned with implementation evidence.
- [ ] Plan snapshots, recycle bins, file-data backup, richer ACLs, MFA/OIDC and Kerberos separately.
