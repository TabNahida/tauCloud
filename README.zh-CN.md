# tauCloud

**τCloud — Thin · Adaptable · Unified（轻量 · 灵活 · 统一）**

运行在现有操作系统上的模块化 NAS 与私人云平台。

[English](README.md) · [文档](docs/README.zh-CN.md) · [路线图](docs/roadmap.zh-CN.md) · [开发任务（英文）](TODO.md)

tauCloud 希望在 Windows 和 Linux 上统一提供文件共享、私人空间、系统监控与应用管理。它可以与已有应用和存储一起部署，后端能够脱离 WebPanel 独立运行。

> **项目状态：正在补齐完整 SMB/NFS 标准兼容。** 原有 [M5/M7 受限配置结果](docs/evidence/pre-m8/README.md) 仍有效，但不代表扩展后的完整兼容门槛完成。[M8](docs/m8.zh-CN.md) 已有插件/Docker 后端，正在执行获授权的远程验收；进一步开发须等待 [TODO](TODO.md) 中的 SMB/NFS 前置要求完成。安装器与 WebPanel 仍属后续阶段。

## 围绕你的存储构建

- **使用熟悉的客户端访问文件。** 规划提供原生 SMB 2/3、NFS、FTP/FTPS 和 WebDAV 服务器。
- **管理个人与共享文件。** 私人空间、用户组、共享目录、访问策略以及按能力提供的配额。
- **管理存储与更新。** 规划硬盘与 RAID 管理，以及具备恢复和回滚控制的组件更新。
- **限制故障范围。** 独立服务进程、受监督的重启与明确的降级状态。
- **了解机器运行情况。** CPU、内存、网络、文件系统容量、硬盘健康与服务监控。
- **集中管理应用。** 可扩展插件系统与 Docker Engine 集成。
- **选择自己的界面。** 优先提供版本化管理 API 和 CLI，之后独立开发桌面式 WebPanel，提供应用窗口、任务栏和通知。
- **保留现有操作系统。** 通过用户态服务和平台适配层运行，无需专用 NAS 发行版或新文件系统。

## 技术与实现方向

后端采用 **C++20**、**xmake** 和 [PACE](https://github.com/TabNahida/PACE)，由 PACE 提供协程执行、网络和并发基础。各协议服务器主要在 tauCloud 中基于 PACE 自研，共用身份、授权和文件服务核心。密码学原语与 TLS 使用成熟库。

SMB 和 NFS 都是规模较大的协议工程，将按独立验证的阶段交付，并按版本、特性、客户端和宿主平台公布兼容性。Samba 和操作系统 NFS 服务器 是互操作参照，不是规划中原生服务器的必需运行服务。

## 兼容性目标

| 领域 | 目标范围 |
| --- | --- |
| 宿主系统 | Linux 和 Windows；先覆盖 x86-64，ARM64 在原生验证后加入 |
| SMB | 分阶段支持 2.0.2、2.1、3.0、3.0.2、3.1.1；不支持 SMB1 |
| NFS | 以 v4.1 为主要目标；v3 作为后续兼容性路线 |
| FTP | 被动模式 FTP 与显式 FTPS；明文 FTP 必须显式启用 |
| WebDAV | RFC 4918；通过验证后才声明相应合规等级 |
| 存储 | 现有本地目录和文件系统；平台特性通过能力接口暴露 |
| 应用 | Docker Engine 管理；其他集成通过插件扩展 |

协议目标不代表完整实现全部规范。各协议的交付门槛与排除项见[协议规划](docs/protocols.zh-CN.md)。原生服务器面向两种宿主系统，但硬盘遥测、文件系统特性、保留端口和容器引擎仍受宿主能力影响。

## 开发方向

首个可用后端里程碑聚焦安全管理、用户与空间、安全的本地文件服务、基础监控和 WebDAV。FTP/FTPS、SMB 与 NFS 分别作为后续协议路线。核心契约稳定后可以推进插件和 Docker；选定的初始后端范围及 API 通过验收后再开发 WebPanel。

初期范围为单机管理。硬盘与 RAID 管理使用宿主原生存储提供者，在线升级和桌面式 WebPanel 纳入产品里程碑。高可用、客户端同步和云中继仍属于后续研究。

## 了解设计

| 文档 | 内容 |
| --- | --- |
| [架构](docs/architecture.zh-CN.md) | 模块、PACE 集成、存储语义、API 和拟定源码布局 |
| [协议](docs/protocols.zh-CN.md) | 原生服务器路线、协议版本与互操作验收 |
| [安全与平台](docs/security.zh-CN.md) | 身份、权限、特权边界、Windows/Linux 行为与扩展 |
| [运维](docs/operations.zh-CN.md) | 进程故障恢复、在线升级、硬盘与 RAID 管理 |
| [桌面式 WebPanel](docs/webpanel.zh-CN.md) | 桌面壳、应用窗口、任务中心与前端契约 |
| [路线图](docs/roadmap.zh-CN.md) | 依赖顺序、交付门槛和待决策项 |
| [TODO（英文）](TODO.md) | 可执行的开发清单 |

英文与简体中文文档同步维护。已验证的构建与运行命令见 [M0 实验指南](docs/m0.zh-CN.md)，实测结果见[验收记录](docs/evidence/README.zh-CN.md)。

## 参与项目

欢迎设计反馈、协议互操作案例和 Windows/Linux 集成经验。请先阅读架构与路线图，再通过 [Issues](https://github.com/TabNahida/tauCloud/issues) 讨论具体提案。特性应明确能力边界，并在通过独立客户端测试后再标记为支持。

## 许可证

仓库包含 [GNU 通用公共许可证第 3 版](LICENSE)。M0 的依赖许可证与分发边界已记录在[基线决策](docs/decisions/0001-m0-baseline.zh-CN.md)中。

用户已指定完整 SMB/NFS 标准兼容为继续开发 M8 的前置条件；原 ADR 受限配置通过不等于该门槛完成，详见 TODO。
