# ADR 0002 — 执行、资源预算与 HTTP 流式接口

[English](0002-execution-http.md)

状态：接受 M0 契约，HTTP 流式实现仍属于 M3。

C++ `bounded_executor` 同时按未完成任务数和字节数准入，预算包含等待 PACE 执行的完成回调。成功准入的预留贯穿排队、执行和回调投递；被丢弃的回调也通过 RAII 释放预留。投递期间保持上下文存活，不捕获借用的协程句柄；调用方需让事件循环运行至已接收回调排空。错误作为结果返回所属上下文；拒绝准入不触发回调。运行中取消是协作式的，不能撤销写入。排队任务开始前检查超时；无法在排空期限内返回的内核 I/O 由监督者隔离并终止所属进程。

关闭顺序：停止监听和新准入；请求取消；在监督线程加入阻塞线程，同时保持 reactor 可用；排空回调；刷新必须持久化的状态；最后停止并加入 PACE。上下文失败时记录未投递结果，不通过悬空指针回调。M1 明确协程生命周期前先采用回调桥接。

[`budgets.json`](../../experiments/m0/budgets.json) 固定基于实测 24 逻辑 CPU、197226000 KiB Linux 参考主机的初始准入策略。每连接两个 64 KiB 传输块，加 128 KiB 控制/编解码状态，总计 256 KiB；全局 256 连接最多预留 64 MiB。每工作进程四个阻塞线程、64 个未完成任务、16 MiB 阻塞工作预留、64 连接、32 个控制调用；全局进一步限制 256 任务、八个工作进程。每进程 RSS 硬上限 512 MiB，总计 4 GiB，实际 RSS 强制执行属于 M1。排队 2 秒、握手 10 秒、IPC 5 秒、传输无进展 30 秒、授权租约 15 秒、优雅排空 15 秒、隔离进程终止 30 秒。实验使用更小预算，确保可确定性触发过载。

这些是保守容量上限，不是吞吐实测结论。两种宿主的内存和存储不同，建议的 4 CPU / 8 GiB 最低配置仍需 M2 负载验证。全局和局部预算同时生效；不能通过增加工作进程规避全局限制。内核 socket/TLS 缓冲和进程开销计入 RSS，不计入上述有效载荷公式。

## 拟议 PACE 接口

```cpp
// 契约草案，不是已经实现的 PACE API。
task<request_head> read_head(header_limits, deadline);
task<body_reader> admit_body(body_budget, stop_token);
task<chunk_lease> body_reader::read(); // 仅经校验的 EOF 返回空块
task<void> write_head(response_head);
task<void> write_body(async_producer, stop_token);
// async_producer 返回 task<chunk_lease>，lease 析构归还额度。
```

`read_head` 校验头部大小、消息分帧、重复长度和 transfer-encoding 歧义，不消费请求体。tauCloud 在 `admit_body` 前认证、检查授权/配额并预留容量。授权且准入成功后才发送 `100 Continue`；拒绝请求返回最终 401/403/413/429，并关闭连接，不无限排空请求体。不支持的 Expect 返回 417。客户端提前发送数据时，准入前最多接收有界 socket 窗口。当前请求体完成或连接关闭前不解析下一个流水线请求。

前一个 lease 释放后 `read()` 才推进。Content-Length 和 chunked 都受累计字节/期限限制，trailer 单独受头部预算限制。响应生产者可等待文件/IPC 和 socket 背压，但不能阻塞 PACE 上下文或组装整文件字符串。断开连接取消双向操作并释放预留；部分写入须由文件服务协调后才能确定结果。range 使用 64 位，非法范围、EOF 和短读均明确区分。

PACE 上游负责通用增量解析、异步生产者和 `100-continue`；tauCloud 负责认证、配额、文件服务适配和取消策略。当前固定的 PACE 仍缓冲请求体、使用同步响应生产者并拒绝 Expect，不能包装现有接口后声称已实现流式。M3 启用 WebDAV 前须在两种宿主验证未授权提前发送请求体、分块边界、慢速读写、超内存文件、断线、内存上限和优雅关闭。
