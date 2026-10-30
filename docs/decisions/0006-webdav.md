# ADR 0006 — Bounded PACE WebDAV and metadata recovery

Status: implemented for M3 preview. [简体中文](0006-webdav.zh-CN.md)

PACE's pinned TLS stream supports incremental reads/writes and graceful TLS close. Its HTTP convenience server buffers request bodies. M3 therefore maintains a small HTTP/1.1 adapter in tauCloud, using PACE TLS and the existing bounded executor. It parses bounded headers before obtaining identity grants or admitting request bodies, then moves at most 64 KiB per file RPC. Every connection closes after one response. This avoids an upstream API dependency while leaving the PACE source lock intact. It adds parser ownership and tests to this project; HTTP/2 and keep-alive remain out of scope.

DAV properties, durable mutation journals and expiring exclusive/shared locks live in the storage-domain file authority, not in the protocol worker. Thus API and DAV writes share lock/quota enforcement, and protocol restarts cannot discard locks. Pinned native paths and stable IDs remain authoritative. COPY has explicit byte/tree limits; an oversized mutation fails before publication. Ambiguous native failures retain an uncertain job for recovery rather than silently retrying a potentially destructive operation.

A cancelled DAV stream can close its handle/cancel its own unpublished upload using an authentic, expired grant; this special path never performs ordinary reads/writes. Stored progress leases and startup cancellation reclaim abandoned ephemeral uploads. Resumable core uploads remain separate.

Filename support moves from portable ASCII to strict UTF-8 NFC plus Unicode case-fold collision checks, using utf8proc. XML uses pugixml with explicit size/depth/node/namespace/character checks and no DTD/entity processing. Compliance advertising is gated by independent litmus tests, plus streaming, crash, cross-writer and TLS acceptance tests; desktop-client claims require actual client results.

Offline metadata snapshots require exclusive ownership of every process role. Restore publishes new state, generates new cryptographic identities, revokes sessions and drops locks. Password verifiers remain confidential metadata. File data and native IDs are not remapped or copied; same-volume recovery is the supported contract. An encrypted, portable data backup product remains future work.
