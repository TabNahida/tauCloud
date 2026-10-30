# M0 实测证据

[English](README.md) · [复现与限制](../m0.zh-CN.md)

记录日期为 2026-10-29，三个可执行测试套件均通过。**M0 已验收**：用户于 2026-10-29 明确接受功能证据，无须占用 445。历史 JSON 状态保留，此决定覆盖其中的部署门槛。不声明任何生产协议支持。

| 记录 | 环境 | 结果 |
| --- | --- | --- |
| [Linux GCC](linux-gcc.json) | Ubuntu 24.04.4 / GCC 13.3.0 / ext4 | 运行时、文件系统、Unix IPC 恢复、签名更新、SMB 向量及 Impacket 0.12.0 互操作通过 |
| [Linux Clang + sanitizer](linux-clang-sanitizers.json) | Clang 18.1.3 / ASan + UBSan / ext4 | PACE 和桥接代码启用检测后同套测试通过 |
| [Windows MSVC](windows-msvc.json) | Windows 11 25H2 26200.9457 / 工具集 14.51.36231 / SDK 10.0.26100.0 / NTFS | 运行时、文件系统、命名管道恢复、签名更新、SMB 向量及使用原生 SSPI 的 smbprotocol 1.15.0 互操作通过 |
| [依赖获取](dependency-acquisition.json) | 上游精确 PACE Git 对象和离线已提交导出 | 源码哈希一致；篡改导出被拒绝；还原后通过 |

运行时报告 13 项检查，进程恢复 17 项，更新恢复 11 项，SMB 向量 12 项。文件系统和互操作直接报告能力/事件，不编造断言数量。Windows 对独占 445 绑定报告 `AddressAlreadyInUse`，临时替代回环监听成功。这是实测部署前提，不是标准端口部署已通过。

JSON 保留源码摘要、命令、输出、状态和耗时，检出目录、临时目录和解释器绝对路径归一化为占位符，工具版本 banner 缩为首行。完整本地报告保留在忽略的 `build/m0` 下。MSVC 开发环境以外无法直接执行 `cl` 清单命令，但 xmake 已成功按记录的 VS/工具集/SDK 配置并编译；这条信息性清单失败与实验结果分开记录。

参考 Linux 内核为 WSL2 6.18.40.1，报告 24 逻辑 CPU、197226000 KiB RAM；文件系统实验使用原生临时目录。实验调用 flush 并直接终止测试子进程，不模拟宿主断电、不操作 RAID 磁盘、不安装服务、不修改 SMB 配置，也不证明不可信插件隔离。Windows 路径和 SMB 认证的有限实验范围见 ADR。

M2 实现证据：[身份与文件核心验收](m2/README.zh-CN.md)。
