# ADR 0001 — Reproducible M0 baseline

[简体中文](0001-m0-baseline.zh-CN.md) · [M0 guide](../m0.md)

Status: accepted for experiments, 2026-10-29. No production server is enabled.

## Decision and rationale

Use C++20 and xmake 3.1.1 (`3ba37a0` build), with the exact observed host/tool versions in [`toolchains.lock.json`](../../toolchains.lock.json). Linux is Ubuntu 24.04.4 x86-64, GCC 13.3.0 / Clang 18.1.3, reference WSL2 kernel 6.18.40.1 and ext4. Windows is Windows 11 25H2 build 26200.9457, MSVC toolset 14.51.36231, SDK 10.0.26100.0 and NTFS. Windows compilation explicitly selects the toolset and SDK. These identify tested environments, not immutable VM images or an assertion that all patch releases behave identically.

Pin PACE to `d3842473b2bea63e291eb25fe44f610cbd49b02e`, the inspected revision, instead of the moving upstream HEAD. `scripts/fetch_pace.py` fetches that Git object and verifies a content SHA-256 over every exported file. Offline acquisition accepts a Git repository, exports the committed tree, and ignores all working-tree changes. No relative dependency on `../PACE` appears in the build. The adjacent modified `xmake.lua` is neither copied nor edited. Existing exports must match the lock; drift fails closed. No dependency download happens implicitly during a build.

The M0 xmake adapter compiles the three unmodified PACE runtime translation units. Including upstream's entire xmake project would leak project-global options and enable its tests/examples; the explicit adapter avoids that. HTTP/TLS/net targets are deliberately not enabled by this runtime experiment. Adding them requires extending the lock and adapter, not copying an adjacent build file.

## Boundaries and build names

| Component | Allowed dependencies / owner |
| --- | --- |
| `core` | Standard library; IDs/errors/config only |
| `runtime` | `core`, `pace_runtime`; bounded jobs and context handoff |
| `platform`, `storage` | Native OS calls, runtime contracts; no protocol codecs |
| `metadata`, `identity`, `policy` | One database writer per authority; no protocol-worker SQL access |
| `ipc`, `supervisor` | Versioned service clients, platform process/transport adapters |
| `protocols/*`, `api` | PACE network modules + IPC clients; no sibling-protocol dependencies |
| `updates`, `storage_admin` | Durable jobs + typed helper calls; no generic privileged shell proxy |

Current tauCloud options: `m0` (default on), `sanitizers` (Linux ASan/UBSan). Targets: `pace_runtime`, `taucloud_m0_runtime`, `taucloud_m0_filesystem`. M1 owns creation of production service targets. No empty service stubs or frontend dependency are introduced.

Upstream names reserved for its own build: `cxxstandard`, `sanitizers`, `profiling`, `http1`, `websocket`, `tls`, `dns`, `quic`, `http2`, `http3`, `tests`, `examples`, `benchmarks`, `components`, `scaling`, `protocol_benchmarks`. The tauCloud adapter does not forward these options implicitly. Future first-party protocol switches will use the `taucloud_` prefix.

## Dependencies, licenses and security

| Dependency | M0 use | License / boundary |
| --- | --- | --- |
| tauCloud | Own experiment code | Repository GPLv3 text; no added “or later” assertion |
| PACE at locked revision | Linked C++ runtime | MIT; preserve upstream LICENSE in export/distribution |
| C++ standard library / native SDK | Platform execution | GCC runtime exception / LLVM exception / Microsoft SDK terms, according to toolchain |
| Python 3.12.3 / 3.13.3 | Development harness only | PSF; never used to deserialize peer pickle data |
| Python SQLite 3.45.1 / 3.49.1 | Disposable update journal | Public domain; one owner, synchronous FULL |
| OpenSSL CLI 3.0.13 / 3.2.3 | Ephemeral Ed25519 fixtures, Linux NT-hash vectors | Apache-2.0; subprocess dependency, not a production TLS choice |
| Windows CNG | Windows NT-hash fixture | OS security provider; MD4 is confined to NTLM enrollment |
| Impacket 0.12.0 | Independent Linux SMB test peer | Apache-2.0; isolated optional test environment |
| smbprotocol 1.15.0 / pyspnego 0.12.4 | Independent SMB test peer, including Windows | MIT; isolated optional test environment |

Optional test-client transitive versions are frozen in the two `experiments/m0/*requirements.txt` files. They are not backend dependencies or a production security recommendation. Reproduction requires trusted package indexes and tool binaries; these pins are not a fully hashed offline software supply chain. Audit transitive notices and security updates before distributing any test environment. Production TLS/credential-vault/library versions need their own M1/M5 review; do not enable PACE's optional packages merely because their upstream defaults exist.

Alternative rejected: linking a local dirty PACE build, embedding an SMB system daemon as the product, or claiming a Windows build from cross-compilation alone. Evidence and outstanding limits live in [M0](../m0.md).
