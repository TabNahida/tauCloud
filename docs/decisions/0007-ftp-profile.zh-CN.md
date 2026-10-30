# ADR 0007 — 有界 FTP/FTPS 与数据会话归属

[English](0007-ftp-profile.md)

状态：M4 后端预览已实现，FileZilla 互操作验收仍未完成。

## 背景与决定

FTP 控制命令和数据使用不同连接，仅比较来源 IP 无法证明受保护的数据连接属于特定已认证控制连接。锁定版本的 PACE TLS API 未暴露所需的会话恢复检查。

采用独立 `taucloud_ftp` 进程与 PACE TCP/协程，在项目内使用小型 OpenSSL memory BIO 适配器完成显式 TLS 升级与恢复检查，不修改锁定依赖。每条控制连接使用独立 SSL 上下文、会话 ID 上下文、缓存和 ticket 密钥；受保护数据连接必须来源 IP 相同且会话恢复成功。全新或其他控制连接的会话在打开传输文件句柄前被拒绝。TLS 1.2/1.3 由 OpenSSL 实现。默认显式 TLS，明文需停服修改配置；不支持主动模式、FXP、匿名或 TLS 降级。

虚拟共享路径映射到已有短时身份授权和文件权威服务。FTP 暂不加入混合写协议组合。上传暂存、刷新、原子发布；FTPS 要求认证 EOF；REST STOR 复制前缀并在提交时复核 ETag。撤权后的签名授权只能用于清理。进程所有权锁配合各文件域的认证恢复，只回收 FTP 句柄与未发布暂存；正在提交的任务沿用日志语义，core 持久任务与其他协议进程继续运行。

## 影响

- 客户端必须在数据连接上复用 TLS 会话。自动测试在标准 Python FTP 实现上显式传入 `SSLSession`；未适配的 `FTP_TLS` 不会自行传入。已测试的 curl 构建可成功复用。
- 输入 TLS 截断视为上传失败。合法 EOF 后回送关闭通知为尽力而为：curl 可能已经关闭 TCP；不能因此把已发布文件误报为传输失败。
- 明文 FIN 无法认证预期长度。文件只支持二进制，TYPE A 可用于列表，不能隐式转换文件内容。
- REST 基于已发布文件续传，隐形 FTP 半成品被丢弃；续传替换后缀，提交前复核源版本。
- 未知长度上传保守预留最多 1 GiB 或剩余配额。当前本地预览以明确的内存、连接、时间预算限定兼容范围和慢速传输。
- FileZilla 单独验收前不声明兼容。见[证据](../evidence/m4/README.md)与[协议限制](../m4.zh-CN.md)。

依据：[RFC 4217](https://www.rfc-editor.org/rfc/rfc4217)、[RFC 3659](https://www.rfc-editor.org/rfc/rfc3659)、[RFC 2428](https://www.rfc-editor.org/rfc/rfc2428)。
