# ADR 0001 — 可复现的 M0 基线

[English](0001-m0-baseline.md) · [M0 指南](../m0.zh-CN.md)

状态：2026-10-29 接受用于实验，不启用生产服务。

## 决策与理由

采用 C++20 与 xmake 3.1.1（`3ba37a0` 构建），确切版本记录在 [`toolchains.lock.json`](../../toolchains.lock.json)。Linux 为 Ubuntu 24.04.4 x86-64、GCC 13.3.0 / Clang 18.1.3、参考 WSL2 内核 6.18.40.1 和 ext4。Windows 为 Windows 11 25H2 26200.9457、MSVC 工具集 14.51.36231、SDK 10.0.26100.0 和 NTFS。Windows 构建显式指定工具集和 SDK。这是已测环境记录，不是不可变虚拟机镜像，也不代表所有补丁版本行为相同。

PACE 固定为已调研的 `d3842473b2bea63e291eb25fe44f610cbd49b02e`，不跟随上游 HEAD。`scripts/fetch_pace.py` 获取该 Git 对象，对导出树的全部文件校验内容 SHA-256。离线模式只读取仓库的已提交对象，忽略工作区修改。构建不依赖 `../PACE`；相邻仓库已修改的 `xmake.lua` 不会被复制或更改。已有导出内容不匹配锁文件时拒绝构建；构建不会隐式下载依赖。

M0 xmake 适配层编译 PACE 原样的三个 runtime 源文件。直接包含上游完整工程会引入全局选项并默认构建其测试/示例，因此选择显式适配。此次运行时实验不启用 HTTP/TLS/net 目标；以后接入须扩展锁文件和适配层。

## 组件与构建边界

| 组件 | 允许的依赖 / 所有者 |
| --- | --- |
| `core` | 标准库、ID、错误与配置 |
| `runtime` | `core`、`pace_runtime`；有界任务和上下文交接 |
| `platform`、`storage` | 原生调用与运行时契约；不包含协议编解码 |
| `metadata`、`identity`、`policy` | 每个权威服务独占数据库写入；协议进程不直接访问 SQL |
| `ipc`、`supervisor` | 版本化服务客户端和平台进程/传输适配 |
| `protocols/*`、`api` | PACE 网络模块和 IPC 客户端；不互相依赖协议实现 |
| `updates`、`storage_admin` | 持久化任务和类型化 helper 调用；不提供通用特权命令代理 |

当前 tauCloud 选项为 `m0`（默认启用）、`sanitizers`（Linux ASan/UBSan）；目标为 `pace_runtime`、`taucloud_m0_runtime`、`taucloud_m0_filesystem`。生产进程目标由 M1 创建，不添加空服务占位或前端依赖。

上游选项保留给上游工程：`cxxstandard`、`sanitizers`、`profiling`、`http1`、`websocket`、`tls`、`dns`、`quic`、`http2`、`http3`、`tests`、`examples`、`benchmarks`、`components`、`scaling`、`protocol_benchmarks`。适配层不会隐式传递它们；未来第一方协议开关使用 `taucloud_` 前缀。

## 依赖、许可证与安全

| 依赖 | M0 用途 | 许可证 / 边界 |
| --- | --- | --- |
| tauCloud | 自有实验代码 | 仓库 GPLv3 文本，不额外声称 “or later” |
| 固定提交的 PACE | C++ 运行时链接 | MIT，导出/分发保留 LICENSE |
| 标准库与 SDK | 平台执行 | 对应 GCC runtime exception、LLVM exception、Microsoft SDK 条款 |
| Python 3.12.3 / 3.13.3 | 仅开发测试 | PSF；不对 IPC 消息执行 pickle 反序列化 |
| Python SQLite 3.45.1 / 3.49.1 | 临时更新日志 | Public domain；单所有者、synchronous FULL |
| OpenSSL CLI 3.0.13 / 3.2.3 | 临时 Ed25519 签名、Linux NT 哈希向量 | Apache-2.0；子进程依赖，不是生产 TLS 选型 |
| Windows CNG | Windows NT 哈希实验 | 系统密码学提供者；MD4 仅用于 NTLM 注册 |
| Impacket 0.12.0 | 独立 Linux SMB 客户端 | Apache-2.0；可选隔离测试环境 |
| smbprotocol 1.15.0 / pyspnego 0.12.4 | 含 Windows 的独立 SMB 客户端 | MIT；可选隔离测试环境 |

可选测试客户端的传递依赖版本固定于 `experiments/m0/*requirements.txt`，不进入后端依赖，也不是生产安全版本建议。复现仍依赖可信包源和工具二进制，不是全部采用哈希锁定的离线供应链。分发测试环境前需审查传递依赖声明和安全更新。生产 TLS、凭据保险库和相关库版本由 M1/M5 单独评审，不能因上游存在默认值就启用可选依赖。

拒绝依赖相邻脏构建、把系统 SMB 守护进程替换为产品实现、或以交叉编译冒充 Windows 实测。证据与剩余限制见 [M0](../m0.zh-CN.md)。
