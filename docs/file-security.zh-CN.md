# 共享文件安全描述符

Full SMB/NFS 扩展已增加文件服务统一执行的持久 DACL。访问必须同时通过空间/共享授权和文件权限检查；Linux 与 Windows 使用相同服务语义，不修改主机 NTFS/POSIX 属主。宿主直接访问不在此权限边界内。

SMB 支持查询/设置 owner、group、DACL，以及 CREATE SecD 初始描述符。检查 READ_CONTROL、WRITE_DAC、WRITE_OWNER，区分 NULL/空 DACL，按 ACE 顺序处理允许/拒绝、通用权限、OWNER RIGHTS 和所有者隐含权限。MAXIMUM_ALLOWED、MxAc 与应用授权和只读约束相交。父目录可通过 DELETE_CHILD 和 LIST_DIRECTORY 提供 DELETE、READ_ATTRIBUTES；新建对象先检查父目录添加权限，初始句柄获得请求权限，后续打开受继承 DACL 限制。

实现对象/容器继承、仅继承、禁止继续传播、CREATOR OWNER/GROUP 和传统/自动继承标志。SET 不会隐式递归重写已有子对象；新对象继承创建时的描述符。SecD 在创建前验证所有权、偏移、长度和总大小，支持 protected DACL。旧句柄保留已授予权限，应用策略撤销仍会关闭句柄。请求发现认证会话失效后，服务先清理该会话的全部文件句柄与锁，再发出等待锁的失败响应；重新登录不依赖旧连接断开。

描述符按原生对象代次保存，重命名和重启后保持，替换对象获得新描述符。文件数据库升级至 schema 6，schema 5 迁移前保存 `file*.pre-v6.db`。备份接受 schema 6；把文件字节复制成新的原生对象不会自动重建其描述符。

用户名和组名映射为稳定服务 SID，算法见[英文说明](file-security.md)。身份服务把当前组成员关系签入短期授权，不信任客户端传来的 SID 身份。默认所有者只可设为自身 SID；组只可设为所属服务组或保留原组。管理 API 的管理员身份不等于 Windows 恢复/审计特权。请求 ACCESS_SYSTEM_SECURITY 的打开操作返回 STATUS_PRIVILEGE_NOT_HELD，允许原生 ACL 工具退回仅修改 DACL；普通句柄仍不能读写 SACL。未保存描述符的旧对象保留既有共享权限语义，新对象以创建者为所有者。

NFSv3 读写/命名空间操作、NFSv4 OPEN/ACCESS、core/WebDAV/FTP 文件操作均检查同一 DACL。NFS 修改 mode/属主需要相应文件权限；ACCESS 与导出权限相交。分阶段上传在发布前再次检查权限并保留目标描述符；复制检查每个来源及被覆盖的后代，私有分阶段复制目录也传递继承权限。DAV 对不存在的 URL 执行 LOCK 时，检查父目录添加权限并持久化新资源的继承描述符。NFS 的 mode/UID/GID 现从共享描述符派生，chmod 会真正改变所有协议后续访问的权限。

NFSv4 已支持 `acl`/`aclsupport` 的允许/拒绝 ACE，覆盖 GETATTR、VERIFY/NVERIFY、READDIR、SETATTR 和创建。READ_ACL/WRITE_ACL 分别检查；同时修改 mode 和 ACL 时先应用 mode；仅设置 ACL 时重新计算低九位 mode。目录继承保留特殊主体，普通 acl 属性按 RFC 清除继承来源标志；无效 ACL 在创建或截断前拒绝。上限为 1024 个 ACE、64 KiB 属性/描述符。audit/alarm、单独 dacl/sacl、完整所有权和域映射仍待完成。

主体支持 OWNER@、GROUP@、EVERYONE@、导出映射中的 `用户名@taucloud`/`组名@taucloud`；无法命名的 SMB SID 使用 `sid-十六进制SID@taucloud` 往返。GROUP@ 随所属组修改和子对象继承更新。AUTH_SYS 只使用已验证且实际提交的组，root squash 清空组，不能靠未提交的数据库成员关系取得文件权限。NFS 按 RFC 允许读取具有执行权限的普通文件，SMB 仍按原始 ACL 检查。旧对象的有效访问保持不变，回报 mode 改为反映真实 DACL。

独立 NFS/SMB 客户端新增测试覆盖多用户拒绝、组身份、mode/ACL 同步、错误输入无副作用、继承、大 ACL、跨协议和重启；Actions 同时加入 Linux 内核挂载后的原生 chmod、nfs4_getfacl/nfs4_setfacl 验收。

SMB 共享可设置 `access_based_enumeration:true`，按 DACL 隐藏无完整读取权限的目录项，并宣告对应 TREE_CONNECT 标志。默认关闭。无论是否隐藏，直接打开都检查权限。

独立客户端测试覆盖迁移、权限拒绝、畸形描述符、所有权边界、组撤销、继承、SecD、重命名/重启、对象替换及跨协议绕过，已接入 GCC、Clang ASan+UBSan 和 MSVC Actions。显式授予测试账号恢复所有者权限后，未修改 Samba `smb2.acls` 完整 14 项已在本地通过，包括 SDFLAGSVSCHOWN。保留原来无特权的 13 项回归及历史失败证据；新增全部套件与独立所有权测试已接入 Actions，远程验收待完成。见[本地证据](evidence/pre-m8/smb-owner-local.json)。

Windows Server 2025 原生加密 SMB 重定向器已通过 PowerShell Get-Acl/Set-Acl 验收：SID/DACL 回读、拒绝写入但允许读取、恢复权限及删除文件。这仅验证普通 DACL，不代表 SACL 或特权所有权已实现。

完整 SMB/NFS 验收仍开放：完整备份恢复特权、SACL/审计/条件 ACE、域身份映射、Windows Kerberos/RPCSEC_GSS 接受端、完整 NFS 权限、原生安全编辑器、流/链接、lease/durable/replay/multichannel、delegation/callback 等尚待完成。详见 [TODO](../TODO.md) 和[英文技术说明](file-security.md)。

NFS 的完整 12 位 mode 已实现。`mode_set_masked` 仅供 SETATTR 使用，不能与 mode 同时设置；只修改高三位时不会重写 DACL。setgid 目录向新对象传递组，向新目录传递 setgid；显式设置 setgid 需要调用者属于对应组；设置 setuid 还要求调用者是对象所有者，单独授予 WRITE_ACL 不足以越过此限制。sticky 目录的删除、重命名和覆盖同时受父目录/目标所有者限制，NFS、SMB、core、DAV、FTP 共用此检查；已接受的 SMB 删除意图保留原授权直到回收。

普通文件数据写入、截断和所有权修改会清除 setuid/setgid，分阶段上传在发布前清除目标复制过来的位。为防止部分写入失败后仍保留 set-ID 内容，清除发生在可能修改数据的原生操作前。主机文件权限仍不改变，服务也不执行客户端文件。新增独立 mode 测试及 Linux 原生 chmod/继承验收已接入 Actions。

管理员可用 `POST /api/v1/smb-owner-authority` 显式配置按用户、按空间的所有权授权，例如 `{"id":"restore-alice","username":"alice","space":"team","mode":"restore"}`。模式为 `none`、`take`、`restore`；更新需携带 `update:true` 和完整字段。同一用户/空间只能有一条记录，查询和修改要求管理员身份。修改被审计并撤销现有句柄，授权只签入 SMB 请求，不会自动授予空间写权限。

`take` 可绕过 DACL 取得 WRITE_OWNER，但只能把所有者设为自身。`restore` 允许 SET_INFO/CREATE SecD 使用任意合法 owner/group SID；SET_INFO 仍要求句柄具有 WRITE_OWNER，只有 FILE_OPEN_FOR_BACKUP_INTENT 打开可为恢复操作绕过此 DACL 权限，普通打开和 MxAc 保持原 DACL 权限。SecD 的 CREATOR OWNER/GROUP 继承使用恢复后的身份，选中的空 owner/group 在任何字段修改前被拒绝。

这仅实现明确范围内的所有权权限，不等于完整 Windows SeBackupPrivilege/SeRestorePrivilege：不会授予数据、WRITE_DAC、SACL 权限，也不能绕过只读共享或跨空间授权。独立测试覆盖配置权限、取得/恢复差异、备份意图、SID 校验、创建继承、撤销和重启持久化。
