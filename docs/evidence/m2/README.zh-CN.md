# M2 验收证据

[English](README.md) · [实现与限制](../../m2.zh-CN.md)

记录日期 2026-10-29。验收覆盖 Linux 与原生 Windows 的本地文件核心及 M1 回归，不依赖 TCP 445，也不宣称文件共享协议已支持。

三套构建均通过 **29 项 M1 核心检查、35 项 M2 核心检查、15 项 M1 集成场景及 10 组 M2 流程**，使用相同源码摘要：

`516bce9dff77bbdf9793c952759b5151c8c67824e57293522341f9321cf5b520`

| 宿主 / 编译器 | 构建与核心 | M1 回归 | M2 文件流程 |
| --- | --- | --- | --- |
| Ubuntu 24.04 / GCC 13.3.0，干净构建 | [GCC](linux-gcc.json) | [回归](linux-gcc.integration.json) | [257 MiB，RLIMIT_DATA](linux-gcc.files.json) |
| Ubuntu 24.04 / Clang 18.1.3，ASan + UBSan | [Clang](linux-clang.json) | [回归](linux-clang.integration.json) | [Sanitizer 流程](linux-clang.files.json) |
| Windows 11 build 26200.9457 / VS 2026 toolset 14.51.36231、SDK 10.0.26100.0 | [MSVC](windows-msvc.json) | [回归](windows-msvc.integration.json) | [257 MiB，Job Object](windows-msvc.files.json) |

源码摘要包含 xmake、依赖锁、源码、头文件、应用入口、测试、脚本及打包定义，不含文档。保存的结果规范化个人工作目录、临时路径及终端颜色转义；工具链参考见 [toolchains.lock.json](../../../toolchains.lock.json)。GCC 使用只复制声明输入与已校验 PACE/recipe 的干净临时目录；MSVC 使用 `windows_m2.ps1` 创建的独立 NTFS 目录，包装脚本先完成配置、构建，再以 `--skip-build` 调用运行器。

核心测试覆盖签名与过期授权、路径规则、原生短写与确定性磁盘满注入、配额预留恢复、不确定随机写重试、超过 4 GiB 的偏移、旧句柄失效、原子发布前后两个崩溃点的恢复、跨用户句柄拒绝、符号链接竞态和硬链接拒绝。故障钩子仅存在于测试适配层；符号链接创建受 OS 权限影响，若跳过会反映在检查数量中。

独立 Python HTTPS 客户端与 C++ CLI 验证用户和组、禁用再启用、所有权隔离、管理与文件权限分离、根/空间/混写限制、别名单次计费、锁、重命名及删除幂等、撤权确认、存储域进程崩溃恢复、监控、审计、哈希一致传输、正常停机与 SQLite 完整性。日志同时检查凭据泄露和 Sanitizer 错误。

大文件验收采用 **256 MiB 工作进程分配上限下传输 257 MiB 文件**，并不声称文件超过开发工作站全部物理 RAM。Linux 对文件及 API 测试进程施加 `RLIMIT_DATA`，并保留 supervisor RSS 检查；Windows 使用工作进程 Job Object 的 private commit 上限。实验不修改整机内存配置，也不填满真实磁盘。Sanitizer 因插桩本身的内存开销，使用 512 MiB 预算与 1 MiB 传输。磁盘满及短写恢复由原生适配层注入验证。

未宣称完成突然断电、真实磁盘故障注入、持久 SCM/systemd 注册、恶意同账号进程沙箱、Unicode 互操作、跨卷复制删除任务、实际文件协议客户端互操作或托管 GitHub CI。磁盘遥测依赖实际驱动、硬件及权限。详见[首阶段配置档决策](../../decisions/0005-m2-file-profile.zh-CN.md)。

大文件传输时采样 RSS 峰值（采样值，不是绝对峰值保证）：linux-gcc: file 14.20 MiB, API 18.75 MiB; windows-msvc: file 16.54 MiB, API 20.17 MiB.
