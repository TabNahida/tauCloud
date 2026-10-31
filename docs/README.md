# tauCloud documentation

[简体中文](README.zh-CN.md) · [Project overview](../README.md)

**Baseline: 2026-10-31. M0–M7 backend profiles are implemented and verified within their documented ADR limits. Full SMB/NFS standards conformance is not claimed.**

The [M7 guide](m7.md) describes the current experimental backend; [M6](m6.md) retains the SMB3 instructions. The architecture documents define the broader product and later delivery gates; they are not evidence of file-protocol compliance.

## Reading order

1. [Architecture](architecture.md): component boundaries, execution, storage, and API design.
2. [Protocols](protocols.md): native protocol scope and interoperability requirements.
3. [Security and platforms](security.md): identity, host integration, monitoring, plugins, and Docker.
4. [Operations](operations.md): process recovery, online updates, and disk/RAID administration.
5. [Desktop WebPanel](webpanel.md): desktop interaction, built-in apps, and frontend contracts.
6. [Roadmap](roadmap.md): implementation order, dependencies, and acceptance gates.
7. [TODO](../TODO.md): English implementation checklist using the same milestone identifiers.
8. [M0 experiments](m0.md): reproducible commands, bilingual decisions, evidence and accepted functional scope.

9. [M1 backend](m1.md): build, local bootstrap, HTTPS CLI, service lifecycle and limits.
10. [M2 identity and file core](m2.md): authorization, storage domains, transfer/recovery, quotas and native inventory.

## Established direction

- Software deployed on an existing Windows or Linux host; backend first.
- C++20 and xmake, with PACE for network and coroutine execution.
- Native protocol servers wherever practical; no mandatory Samba/NFS service dependency.
- Mature libraries for cryptographic primitives; no custom cryptographic algorithms.
- One shared identity, policy, and storage core across protocols.
- Separate supervised processes for management, protocols, storage domains, monitoring, plugins, updates and privileged operations.
- Online component upgrades and native-provider disk/RAID management.
- A separately developed desktop-style WebPanel that consumes public backend contracts.
- English README and TODO; English and Simplified Chinese README/docs maintained together.

Other details are proposed defaults. Changes that affect protocol compatibility, data durability, or public interfaces require a recorded design decision and updated acceptance criteria.

## Evidence and terminology

M0 pins PACE commit `d3842473b2bea63e291eb25fe44f610cbd49b02e` in [the dependency lock](../dependencies.lock.json). Acquisition verifies committed source content and does not depend on the adjacent checkout's modified `xmake.lua`. See [the baseline decision](decisions/0001-m0-baseline.md) and [recorded evidence](evidence/README.md).

“Target” means intended scope. “Prototype” means an experiment. “Supported” must mean a recorded passing host/client/feature matrix. “Unavailable” means a capability cannot be provided on the current host; it must never be reported as a healthy zero value.

Specifications and upstream documentation are linked where they inform the design. Their existence does not establish tauCloud compatibility. Decisions marked as proposals are project choices rather than upstream requirements.

11. [M3 WebDAV](m3.md) · [M3 中文](m3.zh-CN.md) · [Evidence / 验证](evidence/m3/README.md)

12. [M4 FTP/FTPS](m4.md) · [M4 中文](m4.zh-CN.md) · [Evidence / 验证](evidence/m4/README.md)

13. [M5 SMB2](m5.md) · [M5 中文](m5.zh-CN.md) · [Evidence / 验证](evidence/m5/README.md)

14. [M6 SMB3](m6.md) · [M6 中文](m6.zh-CN.md) · [Evidence / 验证](evidence/m6/README.md)

- [M7 NFS experimental profile / NFS 实验配置](m7.md) — selected M7a/M7b profile and native-client acceptance complete; exclusions remain explicit.
