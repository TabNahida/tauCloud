# 0005 — Bounded M2 file profile

[简体中文](0005-m2-file-profile.zh-CN.md)

Status: implemented, 2026-10-29. Complements decisions 0002/0003; does not advertise later protocol compliance.

M2 uses the existing PACE HTTPS and bounded blocking bridge for a 128 KiB chunked core API. It does not wait for WebDAV streaming integration. Each native volume has one assigned file process, SQLite owner, handle registry, lock table and quota authority; four domains are available. Shared aliases retain one underlying policy/accounting object. Management role never implies file rights. Policy changes drain and acknowledge workers, with two-second signed leases as the disconnected fallback.

The initial naming profile deliberately rejects non-ASCII names and case collisions on both hosts. Root-relative native handles, no reparse/symlink/hardlink aliases, and one registered root per volume avoid silently conflicting namespaces. Existing populated directories are not adopted. Unicode normalization, additional domains, root adoption, directory mutation and copy/delete cross-volume jobs require explicit later extensions and tests.

Whole-file publication uses a durable intent and native atomic rename, with object-identity reconciliation after either crash cut. Random writes record uncertain outcomes instead of promising exactly-once execution across a native write/SQLite boundary. Quotas are explicitly service-enforced logical accounting; external host writers remain outside enforcement. Windows file-data flush does not imply directory power-loss durability.

Disk inventory exposes native identifiers only when observed; health distinguishes unavailable/denied/stale from available measurements. Device names are not stable IDs. Monitor RPC deadlines bound caller waiting, while stuck native calls are contained by worker supervision.

Acceptance includes both native hosts, two-user isolation, revocation, file-worker death, disk-full/short-write injection, 64-bit offsets, and a file larger than the worker's hard memory allocation budget. This proves bounded transfer without requiring a file larger than all physical RAM on the development workstation. Reports retain both file size and the exact budget mechanism, and explicitly do not claim the latter experiment.

See [M2 contracts](../m2.md) and [evidence](../evidence/m2/README.md). This remains a local backend preview under one trusted OS account, with no hostile-process sandbox or enabled external file protocol.
