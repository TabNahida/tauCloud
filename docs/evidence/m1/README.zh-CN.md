# M1 验收证据

[English](README.md) · [实现与复现说明](../../m1.zh-CN.md)

记录日期为 2026-10-29。Linux/GCC、Linux/Clang（ASan/UBSan）及原生 Windows/MSVC 均通过 **29 项核心检查、15 组端到端场景**，三者源码摘要一致：

`a04f231378b377404a7c668364ee6bfe7e166f77db9a451cd90ae0f2dc04e462`

| 宿主 | 构建/核心记录 | 独立 HTTPS/进程记录 |
| --- | --- | --- |
| Ubuntu 24.04、GCC 13.3.0，全新临时源码目录 | [GCC](linux-gcc.json) | [GCC 集成](linux-gcc.integration.json) |
| Ubuntu 24.04、Clang 18.1.3、ASan + UBSan | [Clang](linux-clang.json) | [Clang 集成](linux-clang.integration.json) |
| Windows 11 build 26200.9457、VS 2026 toolset 14.51.36231 / SDK 10.0.26100.0、原生 NTFS | [MSVC](windows-msvc.json) | [MSVC 集成](windows-msvc.integration.json) |

摘要包含源码、头文件、入口、测试、脚本、部署文件、xmake 与依赖锁，不包含文档。保存的报告规范化了用户/工作目录路径并去掉终端颜色。GCC 仅复制声明的输入及已校验依赖到空临时目录后构建；MSVC 在 `windows_m1.ps1` 创建的独立原生目录运行，报告中的 `--skip-build` 位于包装脚本成功配置、构建之后。完整工具链与系统基线见 [toolchains.lock.json](../../../toolchains.lock.json)。

核心检查覆盖配置整数溢出、原生所有权锁、IPC 认证/版本/随机值/代际拒绝、取消权限、一次性引导、Argon2id、权限/撤销/限流及迁移备份。集成测试使用 Python 独立 HTTPS 客户端、C++ CLI 和真实子进程，覆盖可信/不可信证书、连接准入与空闲期限、Cookie/CSRF/Origin、幂等重启、兄弟进程连续运行、监督者崩溃接管、工作进程异常死亡、跨重启崩溃循环限制、停机及真实 SQLite 事务中断恢复。子进程日志还检查秘密泄漏和 sanitizer 错误。

另在临时副本中仅替换安装位置为已构建二进制后通过 `systemd-analyze verify`。SCM 代码已编译，原生前台启停已验证；未声称执行常驻 systemd/SCM 注册、托管 GitHub CI、CPU 配额、文件协议、恶意兄弟进程沙箱、存储变更或更新安装。这些是明确的范围边界，与 445 端口无关。
