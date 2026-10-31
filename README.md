# tauCloud

**τCloud — Thin · Adaptable · Unified**

A modular NAS and private cloud platform for the operating system you already run.

[简体中文](README.zh-CN.md) · [Documentation](docs/README.md) · [Roadmap](docs/roadmap.md) · [Development tasks](TODO.md)

tauCloud aims to bring file sharing, private user spaces, system monitoring, and application management together on Windows and Linux. Install it alongside your existing applications and storage, with a backend that can operate independently of the WebPanel.

> **Project status: full SMB/NFS compatibility work is in progress.** The earlier [M5/M7 profile results](docs/evidence/pre-m8/README.md) remain valid, but do not complete the expanded standards requirement. [M8](docs/m8.md) already has a plugin/Docker backend and is undergoing authorized remote verification; further M8 development waits for the SMB/NFS prerequisite in [TODO](TODO.md). Installers and WebPanel remain later milestones.

## Built around your storage

- **Share with familiar clients.** Planned native servers for SMB 2/3, NFS, FTP/FTPS, and WebDAV.
- **Keep personal and shared files organized.** Private spaces, groups, shared folders, access policies, and capability-aware quotas.
- **Manage storage and updates.** Planned disk/RAID administration and verified component updates with recovery and rollback controls.
- **Keep failures contained.** Separate service processes, supervised restarts, and explicit degraded states.
- **See how your machine is doing.** CPU, memory, network, filesystem capacity, disk health, and service monitoring.
- **Manage applications in one place.** An extensible plugin system and Docker Engine integration.
- **Choose your interface.** A versioned management API and CLI first; an independently developed desktop-style WebPanel later, with application windows, a taskbar, and notifications.
- **Keep your operating system.** A user-space service with platform adapters, without requiring a dedicated NAS distribution or a new filesystem.

## Technology and approach

The backend will use **C++20**, **xmake**, and [PACE](https://github.com/TabNahida/PACE) for coroutine execution, networking, and concurrency. Protocol servers will primarily be implemented in tauCloud over PACE, sharing one identity, authorization, and file-service core. Mature cryptographic and TLS libraries will supply security primitives.

SMB and NFS are substantial protocol implementations. They will arrive in independently tested stages; compatibility will be published per version, feature, client, and host platform. Samba and operating-system NFS servers are interoperability references rather than required runtime services in the planned native-server design.

## Planned compatibility

| Area | Target scope |
| --- | --- |
| Hosts | Linux and Windows; x86-64 first, ARM64 after native validation |
| SMB | 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1 in stages; no SMB1 |
| NFS | v4.1 as the primary target; v3 as a later compatibility track |
| FTP | Passive FTP and explicit FTPS; plaintext FTP requires explicit enablement |
| WebDAV | RFC 4918, with compliance classes advertised only after validation |
| Storage | Existing local directories and filesystems; platform-specific features exposed as capabilities |
| Applications | Docker Engine management; additional integrations through plugins |

Protocol targets are not claims of full specification coverage. See the [protocol plan](docs/protocols.md) for delivery gates and exclusions. Native servers target both hosts, while disk telemetry, filesystem features, reserved ports, and container engines remain dependent on host capabilities.

## Development direction

The first usable backend milestone focuses on secure administration, users and spaces, a safe local file service, basic monitoring, and WebDAV. FTP/FTPS, SMB, and NFS follow as separate protocol tracks. Plugin and Docker work can proceed after the core contracts stabilize. The WebPanel begins after the selected initial backend scope and its APIs pass acceptance.

The initial scope is a single managed host. Disk and RAID management use host-native storage providers; online updates and a desktop-style WebPanel are planned product milestones. High availability, client synchronization, and cloud relay services remain later investigations.

## Explore the design

| Document | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Modules, PACE integration, storage semantics, APIs, and proposed source layout |
| [Protocols](docs/protocols.md) | Native server strategy, protocol versions, and interoperability gates |
| [Security and platforms](docs/security.md) | Identity, permissions, privilege boundaries, Windows/Linux behavior, and extensions |
| [Operations](docs/operations.md) | Process failure recovery, online updates, and disk/RAID management |
| [Desktop WebPanel](docs/webpanel.md) | Desktop shell, application windows, task center, and frontend contracts |
| [Roadmap](docs/roadmap.md) | Dependency order, release gates, and unresolved decisions |
| [TODO](TODO.md) | Actionable implementation checklist |

English and Simplified Chinese documentation are maintained together. See the [M0 build and experiment guide](docs/m0.md) for verified commands and [recorded results](docs/evidence/README.md).

## Contributing

Design feedback, protocol interoperability cases, and Windows/Linux integration experience are welcome. Start with the architecture and roadmap, then discuss focused proposals through [issues](https://github.com/TabNahida/tauCloud/issues). Features should include explicit capability limits and tests against independent clients before being described as supported.

## License

This repository includes the [GNU General Public License, version 3](LICENSE). M0 dependency licenses and distribution boundaries are recorded in the [baseline decision](docs/decisions/0001-m0-baseline.md).

Full SMB/NFS compatibility is the prerequisite for further M8 development. Earlier ADR-profile acceptance does not close that expanded gate; see [TODO](TODO.md).
