# tauCloud 文档

[English](README.md) · [项目介绍](../README.zh-CN.md)

**基线：2026-10-31。M0–M7 后端配置已在文档所列 ADR 限制内实现并验证；不宣称完整 SMB/NFS 标准合规。**

[M7 指南](m7.zh-CN.md)说明当前实验后端；SMB3 操作仍见 [M6](m6.zh-CN.md)。架构文档定义完整产品目标与后续交付门槛，不作为文件协议合规证明。

## 建议阅读顺序

1. [架构](architecture.zh-CN.md)：组件边界、执行模型、存储和 API 设计。
2. [协议](protocols.zh-CN.md)：原生协议范围与互操作要求。
3. [安全与平台](security.zh-CN.md)：身份、宿主集成、监控、插件和 Docker。
4. [运维](operations.zh-CN.md)：进程恢复、在线升级与硬盘/RAID 管理。
5. [桌面式 WebPanel](webpanel.zh-CN.md)：桌面交互、内置应用与前端契约。
6. [路线图](roadmap.zh-CN.md)：实施顺序、依赖与验收门槛。
7. [TODO](../TODO.md)：使用相同里程碑编号的英文开发清单。
8. [M0 实验](m0.zh-CN.md)：复现命令、双语决策、证据与已接受的功能范围。

9. [M1 后端](m1.zh-CN.md)：构建、本地引导、HTTPS CLI、服务生命周期及限制。
10. [M2 身份与文件核心](m2.zh-CN.md)：授权、存储域、传输与恢复、配额及原生监控。

## 已确定方向

- 在现有 Windows 或 Linux 宿主上部署的软件，后端优先。
- 使用 C++20 和 xmake，PACE 负责网络与协程执行。
- 尽量采用原生协议服务器，不强制依赖 Samba 或系统 NFS 服务。
- 密码学原语使用成熟库，不自行设计密码算法。
- 不同协议共用身份、策略与存储核心。
- 管理、协议、存储域、监控、插件、升级与特权操作使用受监督的独立进程。
- 在线组件升级，以及基于原生提供者的硬盘/RAID 管理。
- 独立开发桌面式 WebPanel，通过公开后端契约访问服务。
- README 和 TODO 使用英文；README 与 docs 同时维护简体中文版。

其余细节为建议默认方案。涉及协议兼容性、数据持久性或公开接口的调整，应记录设计决策并更新验收条件。

## 依据与术语

M0 在[依赖锁文件](../dependencies.lock.json)中固定 PACE `d3842473b2bea63e291eb25fe44f610cbd49b02e`。获取时校验已提交源码内容，不依赖相邻仓库修改过的 `xmake.lua`。参见[基线决策](decisions/0001-m0-baseline.zh-CN.md)与[实测证据](evidence/README.zh-CN.md)。

“目标”表示规划范围；“原型”表示实验；“支持”必须对应已通过并记录的宿主、客户端与特性矩阵；“不可用”表示当前宿主无法提供该能力，不能将其显示成健康的零值。

相关设计处附有规范和上游文档链接。引用规范不代表 tauCloud 已兼容该规范。标为建议的决策属于项目选择，而不是上游要求。

11. [M3 WebDAV](m3.md) · [M3 中文](m3.zh-CN.md) · [Evidence / 验证](evidence/m3/README.md)

12. [M4 FTP/FTPS](m4.md) · [M4 中文](m4.zh-CN.md) · [Evidence / 验证](evidence/m4/README.md)

13. [M5 SMB2](m5.md) · [M5 中文](m5.zh-CN.md) · [Evidence / 验证](evidence/m5/README.md)

14. [M6 SMB3](m6.md) · [M6 中文](m6.zh-CN.md) · [Evidence / 验证](evidence/m6/README.md)

- [M7 NFS experimental profile / NFS 实验配置](m7.zh-CN.md) — M7a/M7b 选定配置和原生客户端已验收，排除项保持明确。
