# Authorization after cold file-domain preparation

[简体中文](file-authorization.zh-CN.md)

Identity grants remain valid for two seconds. A file domain verifies the signed
grant before attaching a space. Cold attachment can recover internal journals
and scan the directory, so the grant may expire before the requested file
operation starts.

API core operations, SMB operations and NFS file operations now check authority
again immediately after attachment (and NFS initialization). At this boundary
only, expiry produces `grant_refresh_required`. Cancellation and policy
revocation still fail. The requested operation has not run; internal recovery
or index maintenance may have run. Later checks retain `lease_expired` and
cannot request an automatic retry.

The API, SMB and NFS adapters obtain new identity authorization and retry this
specific result once. Payloads and mutation request IDs are preserved. API
rename refreshes both source and target authority. A denied second authorization
stops the operation. An already-expired incoming grant, ordinary lease expiry,
uncertain write, transport failure or cancellation is never retried by this
mechanism. Exhaustion maps to NFS `NFS4ERR_DELAY`/`NFS3ERR_JUKEBOX`, SMB
`STATUS_INSUFFICIENT_RESOURCES`, or the API's existing service error response.
NFS nested namespace lookups cannot multiply the retry budget of an enclosing
remove or rename. Existing SMB cleanup operations retain their cleanup rules.
FTP/WebDAV preparation behavior is unchanged.

The M2/M5/M7 core tests use a test-only, single-use delay inside native root
opening to cross expiry after initial verification. They check that preparation
cannot return a handle or create the requested object until fresh authority is
supplied. The NFS protocol fixture additionally injects pre-operation failures
to verify fresh authorization, stable mutation identity, one execution, bounded
and nested retries, revocation and ordinary-expiry refusal. Fault hooks are not
compiled into service binaries.

The earlier Windows M2 failure took 4,575 ms with a two-second grant
([recorded failure](evidence/pre-m8/windows-m2-4a-failure.json)). Its exact delay
phase remains unproven. This change addresses the demonstrated cold-preparation
boundary; it does not establish that every Windows timeout has that cause.

[Local Clang ASan/UBSan evidence](evidence/pre-m8/grant-preparation-local.json)
records 87 M2, 12,599 M5, 1,550 M7 and 1,146 NFS protocol checks, plus 42 SMB
lease groups, 15 NFS groups, ten API groups and two NFS admission-queue groups.
Remote acceptance of this change remains pending.
