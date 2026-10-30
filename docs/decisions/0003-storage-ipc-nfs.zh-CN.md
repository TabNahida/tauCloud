# ADR 0003 — 文件系统、IPC、恢复与 NFS 状态

M7 实验配置的原生句柄重开方式由 [ADR 0010](0010-nfs-preview.zh-CN.md)补充；完整兼容性门槛仍未完成。

[English](0003-storage-ipc-nfs.md)

状态：接受作为 M1/M2 实施依据，保留下列明确发布门槛。

## 文件系统契约

Linux 必须使用相对根目录句柄的 `openat2`，设置 `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`，不回退为字符串前缀判断。Windows 使用句柄相对的 `NtCreateFile`，打开而不穿越 reparse point，并拒绝 reparse tag 和硬链接。M0 Windows 实验仅接受单个文件名；M2 完成逐段解析并以祖先句柄阻止重命名后，才能启用嵌套路径。双方拒绝路径穿越、歧义分隔符和备用数据流。宿主管理员不在该约束边界内。

临时实验验证 ext4/NTFS 的硬/软链接拒绝、重命名和重新打开后的身份一致、删除后的打开对象存活、大小写行为和原生 flush 成功。Linux 还覆盖恶意软链接替换竞态；Windows 测试目录位于 NTFS，即使源码来自 WSL 共享。Linux 的文件与目录 `fsync` 和 Windows 文件 `FlushFileBuffers` 分开记录；实验不能证明断电持久性、NTFS 目录项持久性、跨卷原子性、Unicode 冲突策略、挂载竞态或 inode 重用安全。NTFS 目录持久性须在 M2 单独确认，不能假设 POSIX fsync 可移植。

`(device,inode)` / `(volume serial,128-bit FileId)` 仅标识当前对象，不是永久授权。应用对象 ID 使用存储域所有者持久化的随机 UUID，记录原生 incarnation/恢复依据，删除时保留墓碑且不重用应用 ID。不能证明代次或 incarnation 时失效句柄。重命名不产生新对象 ID；宿主外部修改需要协调。仅按 inode 映射不能发布 NFS 持久句柄。

## 本地传输与进程所有权

Linux 选择私有目录中的 Unix socket 并校验 peer credential；Windows 选择限制到服务 SID 的 ACL 命名管道。PACE 的 Windows WSAPoll 无法等待管道句柄，需 overlapped I/O 适配层，以有界完成队列返回所属上下文；Linux 使用 reactor 上的非阻塞 Unix 描述符。M1 实现这些适配器前，控制 IPC 可放入专用有界阻塞线程，不能无限阻塞事件循环。M0 的 Python `AF_UNIX` / `AF_PIPE` 证明传输与恢复可行，不代表生产适配或 ACL 已完成。

帧包含版本、请求 ID、期限、调用者/资源和代次。M0 使用有界字节消息、JSON 而非 pickle、每连接随机挑战、HMAC 对端持有证明和绑定请求的认证响应。生产启动凭据分别发给各服务，策略签名密钥不能共享给协议工作进程。实验配置同时持有两种密钥，仅存在于临时目录；面向不可信本地用户前必须校验系统身份并测试 ACL。不提供未认证的任意命令通道。

每存储域一个锁文件保证单所有者。故障后退役旧代次，终止/回收进程并排空或标记不确定写入，再授予新所有者。M1 事务化持久分配代次；M0 由测试输入显式分配。接管须使用新挑战并匹配实例随机值、代次和活进程 PID，不能只信 PID 文件；生产还需校验可执行文件和系统进程创建时间。两种传输均测试新的接管进程、工作进程被杀/重启、同级流量持续、旧授权、租约过期、错误密钥、不兼容版本和重复所有者。M0 为串行服务；生产多路复用、队列饱和及停止/取消 RPC 属于 M1。

Docker 使用批准的 Unix socket / Windows 命名管道，经同样有界调度适配器访问，或显式配置的双向认证 TLS。不开放任意守护进程路由。M0 仅选择传输架构；真实引擎清单、API 协商、hijacked stream、权限和 WSL/Windows 路径转换仍属 M8，不能由 IPC 测试推导为已完成。

## NFS 持久状态

不透明句柄包含格式版本、export UUID、object UUID、incarnation 和带密钥认证码；若与 v3 共用，完整编码须落在 v3 的 64 字节限制内，采用固定宽度字段及 16 字节 MAC。export 删除、对象删除/重用或身份无法证明时返回 STALE。存储工作进程代次只用于内部隔离；普通重启不能自动使原本可证明的 NFS 持久句柄失效。原生稳定句柄重新打开（Linux exportfs handle、Windows file-ID open）须使用受限权限和根归属校验，否则声明该文件系统不适用。路径无法解决外部重命名后的持久句柄。

存储域状态所有者保存 export/object 映射和 incarnation 墓碑。NFS 状态所有者保存客户端/open/lock owner、session、slot 序列、最后请求摘要/结果、租约 epoch、恢复 grace 和 reclaim 资格。成功的非幂等操作在确认前持久化结果/replay 状态；不确定操作协调完成前不能复用 slot。有界缓存响应，无法保留 replay 时返回协议定义的重试错误。重启从持久状态恢复 grace，拒绝无关客户端 reclaim；策略不可用不能无限续租。NFSv3 丢失不稳定数据后更新 reboot write verifier，COMMIT 只确认真正完成的持久写入。

AUTH_SYS 按 export 配置把数字 UID/GID 映射为 tauCloud 主体，UID 0 root-squash 到显式配置的匿名身份，拒绝未映射/过期授权并限制附加组数。它是明确启用的可信网络配置，客户端数字身份不是密码认证。Windows 使用相同应用映射，不能默认等同于 SID。Kerberos/principal 映射是后续独立配置。稳定句柄重用/重启、replay/reclaim 和写入持久性均为各文件系统的 M7 发布门槛。
