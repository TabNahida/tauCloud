# ADR 0004 — 原生存储、验证更新与 SMB 可行性

[English](0004-storage-updates-smb.md)

状态：接受。用户于 2026-10-29 取消 M0 的 445 端口门槛，以功能互操作证据验收。

## 磁盘与 RAID 管理

选择 Linux 内核 MD，通过类型化 `mdadm` 操作管理；Windows 选择 Storage Spaces 的类型化 PowerShell/CIM 适配器。先验证双成员镜像，不包含校验 RAID 或硬件控制器管理。M8b 临时测试镜像必须记录提供者版本；M0 不安装提供者或操作磁盘。

夹具为独立可丢弃虚拟机：三个新建的 2 GiB 数据盘（两个成员及一个替换盘）、独立系统/状态盘和快照。Linux 可补充仅由新建稀疏文件支持的 loop 设备；Windows 使用该虚拟机内专用 VHDX。创建/挂载须有仅列出测试文件及稳定原生磁盘 ID 的清单，不能因盘符、枚举序号或空分区表就判断可销毁。先验证原生镜像创建、单成员丢失、替换、重建、检查、重启协调及清理，再验证代表性硬件。

预览返回提供者/版本、拓扑修订/哈希、稳定设备 ID、布局、擦除范围、受影响共享/任务/容器、预计停机和不可逆步骤。确认绑定管理员身份、完整计划摘要、一次性随机值及五分钟有效期。串行变更前重新枚举拓扑；身份变化、新消费者、系统/状态盘均使确认失效。特权 helper 仅接受允许列表中的类型化操作和精确 ID，不接受用户 shell 文本。变更前静默受影响所有者，获取与更新共用的维护锁；尽可能在提交前记录原生操作/任务身份。超时/重启后查询原生提供者，不盲目重复创建/格式化。取消仅停止未来步骤，已不可逆操作明确报告；恢复状态包括待协调、降级及需管理员处理。

## 更新契约与实验

`updates.py` 创建临时 Ed25519 密钥，签名 manifest，用独立配置的公钥验证，并校验载荷摘要、组件/版本/序号/路径及 IPC 版本范围，再并排暂存版本。SQLite FULL 事务记录活动版本指针和状态日志，文件刷新后才切换指针。子进程在五个状态边界不执行清理直接退出；重启协调到旧版或验证后的新版。测试损坏签名/载荷、危险路径、不兼容 IPC、健康检查失败及新写入 epoch 后禁止自动回滚。独立 IPC 工作进程还验证接受 v1/v2、拒绝 v3。

载荷和健康检查是夹具，不是真实安装。公钥轮换、跨安装防降级计数、helper 交接、schema 迁移、supervisor 重认父进程及系统断电持久性仍属 M8c，不能由杀进程实验推导。真实更新须排空、隔离旧存储所有者、让新代次获得独占所有权，并认证就绪后提交。新 schema/数据已产生写入时禁止自动元数据回滚，报告 recovery-required 并保留两版本及备份。不作通用零停机承诺。

## SMB 实验与凭据边界

`smb.py` 校验公开 MS-NLMP NTOWFv2、proof、session key 向量及 SMB 2.1 签名 CREATE。NT 哈希注册在 Linux 实验中调用 OpenSSL legacy MD4，在 Windows 调用 CNG。管理密码 verifier 明确独立，不能用于 NTLM challenge。生产 SMB 注册须显式启用，由身份服务持有，使用宿主秘密存储加密、审计并独立撤销。NT 哈希等价于密码秘密，不能写入日志或普通控制数据库备份。

`smb_interop.py` 是自编、仅监听回环地址的协议子集：强制签名的 SMB 2.1 协商、有界 SPNEGO/NTLMv2 会话、单个测试共享、签名打开/关闭及篡改拒绝。独立客户端提供线协议验证；实验服务端不导入客户端库实现。它不是未来的 C++/PACE 服务，也不是通用 SMB 支持；MIC/channel binding、凭据保险库、durable handle、锁、compound、共享枚举及完整文件操作均由 M5 验收。不得连接真实账号或暴露给外部网络；凭据使用 Microsoft 公开示例。

Windows 实测：系统 SMB 由 PID 4 占用 445 通配监听。只读宿主探针尝试独占绑定并测试临时回环替代端口，不禁用服务、不修改防火墙或删除共享。Windows 原生 SMB 无法改动 TCP 监听端口。Windows 11 24H2+ 客户端可显式映射替代 TCP 端口，但不代表所有客户端兼容。因此标准端口部署仍需要独立可丢弃 Windows 宿主/虚拟机、管理员批准的服务配置和真实原生客户端验证，不在用户现用宿主执行；用户已明确同意该部署实验不作为 M0 门槛。首个可用后端仍为 M3 WebDAV，Windows 原生 SMB 支持明确受此门槛约束。

来源：[NTOWFv2 示例](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26)、[SMB 签名校验](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5b570c0b-0854-4324-8fb5-d410692dde3e)、[Microsoft 替代端口部署说明](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports?tabs=powershell)。
