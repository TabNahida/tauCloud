# 原生协议服务器规划

[English](protocols.md) · [文档](README.zh-CN.md)

状态：下表描述生产目标；当前有界后端预览见 [M3](m3.zh-CN.md)、[M4](m4.zh-CN.md) 和 [M5](m5.zh-CN.md)。[M0 回环 SMB 实验](m0.zh-CN.md)是可丢弃的协议子集，不是已支持的服务器。

## 1. 实现原则

协议分帧、解析、协商、会话状态和文件操作映射主要使用 C++20 基于 PACE 构建。按需复用成熟 TLS、密码学和认证提供者，但这不意味着必须启动独立的操作系统协议服务。认证库须先验证非阻塞集成、许可证和 Windows/Linux 行为，再决定采用；决策中应写明哪些层仍由项目自研。

Samba 和成熟 NFS/WebDAV 服务器提供独立行为参照与测试对端，不是必需的文件服务后端。未来若提供可选的系统服务管理适配器，必须与原生协议支持分别说明。

每个协议家族在独立工作进程运行；FTP 与 FTPS 共用工作进程，WebDAV 与管理 API 分离。所有监听器通过经过认证的本地 IPC 调用共同文件服务契约。协议崩溃不能终止其他协议或管理进程。协议重启可以断开该协议的客户端，锁与会话须按恢复契约保留或失效。不能在各协议内另建权限或配额系统。协议专属凭据与网络语义仍需显式转换，不能将一种登录机制直接复用到全部协议。

## 2. 范围矩阵

| 协议 | 初始实施里程碑 | 后续目标 | 初期排除项 |
| --- | --- | --- | --- |
| WebDAV | M3：HTTPS 文件访问与经过验证的 Class 1 配置 | 合规测试后的 Class 2 锁支持 | CalDAV、CardDAV、版本控制扩展 |
| FTP/FTPS | M4：被动传输与显式 TLS | 按客户端需求增加兼容功能 | 匿名访问、FXP、主动模式、隐式 FTPS |
| SMB | M5：签名 SMB 2.1，可选 2.0.2 兼容 | M6：3.0、3.0.2、3.1.1 | SMB1、AD 域控制器、RDMA、QUIC、集群 |
| NFS | M7a：TCP 上的 v4.1 | M7b：v3 兼容及其相关服务 | v2，初期不含 v4.0/v4.2，以及 pNFS、RDMA |

每个声明支持的版本都必须实现其必需行为。能够挂载、读写的演示只是原型，不是合规证明。可选能力必须如实协商；缺少必需操作时不能发布对应协议配置。

## 3. WebDAV

实现所选 RFC 4918 合规等级要求的 HTTP 方法以及属性和集合行为，包括 `OPTIONS`、`GET`、`HEAD`、`PUT`、`DELETE`、`MKCOL`、`COPY`、`MOVE`、`PROPFIND` 和 `PROPPATCH`。持久化 dead properties。限制 XML 大小与深度，禁用外部实体，限制递归遍历。处理 multistatus、条件请求、覆盖规则和命名空间转义。验证后才声明 Class 1；Class 2 另需通过 `LOCK`/`UNLOCK` 语义测试。[RFC 4918](https://www.rfc-editor.org/info/rfc4918/)

项目门槛包括 PACE 流式集成、有界内存大文件传输、范围读取与续传、取消清理和凭据隔离。启用跨协议可写前，其他 tauCloud 写入者也必须检查 DAV 锁。文档应说明锁范围、过期、token 所有权和重启策略。

使用 Windows Explorer、macOS Finder 与 Linux DAV 客户端测试，记录系统和客户端版本及其认证、TLS 限制。若客户端不兼容，公开限制，不为兼容单个客户端而降低所有部署的要求。

## 4. FTP 与 FTPS

基于 PACE 分别实现控制与数据状态机。支持认证后的目录列表、二进制传输、上传下载、重命名与删除、目录创建、续传偏移以及被动协商（`PASV`/`EPSV`）。提供机器可读列表与能力发现。声明支持的传输类型，对不支持的类型准确报错。[RFC 959](https://www.rfc-editor.org/info/rfc959/)、[RFC 3659](https://www.rfc-editor.org/info/rfc3659/)

显式 FTPS 增加 `AUTH TLS`、`PBSZ` 以及 `PROT P` 保护的数据连接。正常配置要求凭据与文件内容均加密。[RFC 4217](https://www.rfc-editor.org/info/rfc4217/)

明文 FTP 是单独开启的兼容选项，配置中明确提示。限定被动端口范围，验证发布地址和数据连接对端关联，防止反弹与劫持。定义 NAT 配置、空闲超时、中断清理与安全续传语义。控制与数据 TLS 会话需要经过测试的绑定策略。

在两种宿主上使用 FileZilla、curl 及另一独立 FTP 客户端测试，覆盖并发会话、部分上传、TLS 失败和被动端口耗尽。

## 5. SMB

### 方言与交付顺序

| 方言 | 编码 | 计划策略 |
| --- | --- | --- |
| 2.0.2 | `0x0202` | 共享 SMB2 实现后提供显式旧版本兼容配置 |
| 2.1 | `0x0210` | 首个带签名的 SMB 互操作目标，初期仅限受限评估 |
| 3.0 | `0x0300` | 增加该方言必需行为与经过测试的加密 |
| 3.0.2 | `0x0302` | 独立验证方言专属行为 |
| 3.1.1 | `0x0311` | 协商、完整性与密码学验证后作为现代默认目标 |

方言值依据 [Microsoft MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8)。顺序属于项目交付决策。不支持 SMB1。不能仅因为解析器识别某个编号就协商该方言。

实现共享 SMB2 分帧与 compound 解析、credit 记账、会话建立、tree connect、创建与打开、读写、目录查询、信息操作、flush/close、锁、取消与错误映射。为每个启用方言实现要求的签名和密钥派生。开放 SMB3 和 3.1.1 前分别完成加密与预认证完整性要求。解析有界，检查全部偏移、长度、ID 与 compound 链。

通过 SPNEGO 和认证提供者边界实现认证。规划本地账户 NTLMv2 互操作及独立 SMB 凭据注册，不能假定 Argon2 密码验证值可以响应 NTLM 挑战。Kerberos 和域集成属于后续工作，不是本地账户里程碑前提。见[凭据设计](security.zh-CN.md)。

Windows 共享模式、delete-on-close、大小写、Unicode 文件名、属性和安全描述符需要在 Linux 上显式映射。客户端体验可能需要最小的已认证 `IPC$`、命名管道和 RPC 共享枚举能力，需独立限定范围并测试。不宣称实现完整 Windows 服务器或目录服务。

可选 leases/oplocks、durable handles、multichannel、变更通知和高级复制操作都需要独立决策与测试。恢复和失效机制未完成前，不声明可选缓存或重连能力。每个方言的必需行为单独审查，排除项不能违背选定规范要求。

测试 Windows Explorer 与命令行访问、Linux 内核 CIFS 挂载和 `smbclient`，以及 macOS SMB。使用适用的 Samba torture 用例与报文分析。验收包括签名传输、拒绝篡改或降级、权限撤销、并发打开、锁冲突、打开期间的重命名或删除、重连、磁盘满和重启恢复。一个客户端通过不代表广泛 SMB 兼容。

## 6. NFS

当前实现见 [M7 实验子集](m7.zh-CN.md)。下列完整 M7a/M7b 门槛仍未完成，预览不发布完整 NFS 兼容性承诺。

在 PACE TCP 上实现 ONC RPC/XDR 层，包括有界 record 拼装、数组检查、请求身份与认证分发。NFSv4.1 是主要目标，NFSv3 是独立的后续兼容路线。实现 v4.1 不要求先实现 v4.0。[RFC 8881](https://www.rfc-editor.org/rfc/rfc8881.html)

v4.1 需要设计稳定文件句柄、导出命名空间、COMPOUND 操作、session/slot、重放处理、state ID、open/lock 所有权、lease、恢复宽限期与 reclaim 行为。持久化服务器重启语义所需状态。初期在规范允许时拒绝可选 delegation/layout。完成必需操作验证后才能标记兼容。

v3 需要实现必需文件操作、stable/unstable 写入和 COMMIT 语义、重启 verifier 变化与重复请求处理。MOUNT/rpcbind 发现、NLM/NSM 锁与恢复属于兼容配置的一部分；仅提供 2049 端口读写演示不足以交付。优先使用 TCP，初期 v3 配置不包含 UDP。[RFC 1813](https://www.rfc-editor.org/info/rfc1813/)

NFS 身份通过导出策略和显式 UID/GID 或 principal 映射处理。AUTH_SYS 信任客户端提供的身份，只适用于显式配置的可信网络，并启用 root squash 和导出限制。RPCSEC_GSS/Kerberos 是后续经过认证的多用户配置。不能把 AUTH_SYS 等同于 tauCloud 密码会话。

用户态原生 NFS 服务器面向 Linux 与 Windows，不依赖 Windows Server NFS 角色，但 Windows 仍需要验证文件 ID、权限与锁映射。客户端支持是另一个问题：微软原生 Windows NFS 客户端列出的版本是 v2/v3，不能假设它能测试首个 v4.1 目标。[Microsoft NFS 概述](https://learn.microsoft.com/en-us/windows-server/storage/nfs/nfs-overview)

v4.1 使用 Linux 客户端；v3 使用 Linux/macOS 与适用的 Windows 客户端。运行适用的 NFS 合规套件与文件系统压力用例，覆盖重传、服务器重启、文件替换、过期句柄、锁 reclaim、重复变更和磁盘满。在文档声明的存储持久性范围内，崩溃不能丢失已确认的稳定写入。

## 7. 共同发布门槛

声明协议配置受支持前，记录宿主系统与文件系统、客户端版本、协商协议、认证、加密、限制和已知偏差。覆盖畸形输入 fuzz、路径穿越与授权测试、资源耗尽、大于内存的文件传输、连接中断和混合客户端并发。

测试数据必须可丢弃。默认诊断不记录文件内容；报文捕获可能包含凭据或文件数据，必须受控处理。性能结果应记录硬件、存储与缓存条件、加密设置和负载，不能未经测量就宣称 Windows 与 Linux 性能相同。

已有服务可能占用 SMB 445、NFS 2049 或 FTP 21。检测冲突，不自动关闭宿主服务。非标准端口并非对所有客户端透明；需要独立宿主地址或管理员主动调整配置时，应明确报告。
