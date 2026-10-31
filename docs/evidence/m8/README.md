# M8 local acceptance

The implementation is currently local and not publicly pushed. The M0–M7 publication approval did not cover M8; automatic approval review rejected publishing these new files. M8 publication/Actions approval has been requested separately. No remote Windows, WSL or real Docker Engine result is claimed here.

- [GCC local integration](local.json): six groups covering package approval/permissions, install/upgrade/rollback/reinstall/uninstall and retained data, verified worker adoption after manager crash, private IPC credentials, crash backoff, Docker operation/capability restrictions, Unix socket, mutual TLS, malformed/disconnected engines, deadline and revocation.
- [Clang ASan/UBSan integration](clang-local.json): the same six groups under sanitizers, including manager crashes while the worker is running and while it is still starting. Debug information is stripped from the two package executables before packaging so they fit the production 64 MiB file limit; sanitizer instrumentation remains enabled.
- The existing M1 integration suite also passes after adding the plugin supervisor and enforcing administrator scope on management reads.

Reproduce with `python scripts/run_m8.py --compiler gcc` or `--compiler clang --sanitizers`. `.github/workflows/plugins.yml` prepares GCC, Clang and MSVC jobs, including actual Unix/Windows pipe transport fixtures and a separate real Linux Docker Engine check. Windows native/VM platform distinctions are validated against the engine's reported OS; no host path translation is offered. See [M8 scope and API](../../m8.md).
