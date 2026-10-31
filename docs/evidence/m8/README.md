# M8 local acceptance

The user explicitly approved M8 publication and Actions on 2026-10-31. [Run 41171103965](https://github.com/TabNahida/tauCloud/actions/runs/41171103965) passes all three jobs at `8784ce8`: GCC, Clang ASan/UBSan and Windows MSVC, including real Linux Docker Engine operations and Windows named-pipe fixtures. [Fixed-source reports](remote-8784ce8.json) record the checks. The initial Windows install failure at `257aec3` was corrected by releasing pinned staging handles before rename. Live Windows-container/VM/WSL Docker deployments are not claimed. Further M8 development waits for the expanded SMB/NFS prerequisite.

- [GCC local integration](local.json): six groups covering package approval/permissions, install/upgrade/rollback/reinstall/uninstall and retained data, verified worker adoption after manager crash, private IPC credentials, crash backoff, Docker operation/capability restrictions, Unix socket, mutual TLS, malformed/disconnected engines, deadline and revocation.
- [Clang ASan/UBSan integration](clang-local.json): the same six groups under sanitizers, including manager crashes while the worker is running and while it is still starting. Debug information is stripped from the two package executables before packaging so they fit the production 64 MiB file limit; sanitizer instrumentation remains enabled.
- The existing M1 integration suite also passes after adding the plugin supervisor and enforcing administrator scope on management reads.

Reproduce with `python scripts/run_m8.py --compiler gcc` or `--compiler clang --sanitizers`. `.github/workflows/plugins.yml` prepares GCC, Clang and MSVC jobs, including actual Unix/Windows pipe transport fixtures and a separate real Linux Docker Engine check. Windows native/VM platform distinctions are validated against the engine's reported OS; no host path translation is offered. See [M8 scope and API](../../m8.md).

[Fixed-source Linux/real-engine evidence](remote-linux-257aec3.json) records Docker API negotiation, four inventories, logs/stats and lifecycle of uniquely named disposable resources.
