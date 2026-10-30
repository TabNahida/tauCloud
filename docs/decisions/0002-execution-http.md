# ADR 0002 — Execution, budgets and HTTP streaming

[简体中文](0002-execution-http.zh-CN.md)

Status: accepted M0 contracts. HTTP streaming implementation remains M3.

The C++ `bounded_executor` proves admission by outstanding jobs **and bytes**, including results waiting on the PACE queue. Successful admission transfers one reservation through queued work, active work and completion delivery. RAII also releases discarded callbacks. The context is held while posting; callbacks contain no borrowed coroutine handle. The caller keeps its reactor running until accepted completions drain. Completion errors are values on the owner context; rejected admission never calls the callback. Running cancellation is cooperative and cannot undo a write. Queued expiry is checked before work starts; a supervisor fences/kills a process whose native I/O cannot return within its drain budget.

Shutdown order: stop listeners and new admissions; request cancellation; join blocking threads from the supervisor thread while reactors remain available; drain completions; flush required metadata; then stop and join PACE. A failed context causes undelivered results to be counted, not posted through freed pointers. This callback prototype avoids adding an unsafe coroutine awaiter before M1 lifetime ownership is defined.

[`budgets.json`](../../experiments/m0/budgets.json) fixes the initial admission policy on the observed 24-CPU / 197226000-KiB Linux reference host. A connection owns at most two 64-KiB transfer chunks plus 128 KiB control/codec state (256 KiB total); 256 global connections reserve at most 64 MiB. A worker has four blocking threads, 64 outstanding jobs, 16 MiB blocking reservations, 64 connections and 32 control calls; global admission further limits jobs to 256 and workers to eight. Per-worker RSS hard limit is 512 MiB, aggregate 4 GiB; actual RSS enforcement belongs to M1. Queue wait is 2 seconds, handshake 10 seconds, IPC 5 seconds, transfer inactivity 30 seconds, policy leases 15 seconds, drain 15 seconds and fenced-worker termination 30 seconds. The experiment intentionally uses smaller limits to make overload deterministic.

These are conservative caps, not measured throughput claims. Linux/Windows memory and storage differ; the proposed 4-CPU/8-GiB minimum needs M2 load validation. Global and per-owner budgets both apply; callers cannot bypass global reservations by creating more workers. Native socket/TLS buffers and process overhead count toward RSS, outside the transfer-payload arithmetic.

## Proposed PACE-facing interface

```cpp
// Contract sketch, not an implemented PACE API.
task<request_head> read_head(header_limits, deadline);
task<body_reader> admit_body(body_budget, stop_token);
task<chunk_lease> body_reader::read(); // empty only at validated EOF
task<void> write_head(response_head);
task<void> write_body(async_producer, stop_token);
// async_producer: task<chunk_lease>(); leases release credits on destruction.
```

`read_head` validates bounded headers, framing and duplicate length/transfer-encoding ambiguity without consuming the body. tauCloud authenticates, checks grant/quota and reserves transfer capacity before `admit_body`. For an authorized `Expect: 100-continue`, send `100` only after admission; unauthorized requests receive the final 401/403/413/429 response and close without draining an unbounded body. Unsupported expectations receive 417. Clients may send data early: only the bounded socket receive window is allowed until admission. Pipelining cannot begin the next request before the current body is consumed or the connection is closed.

`read()` advances only when the previous lease is released. Content-Length and chunked bodies share cumulative byte/deadline limits; trailers have their own header budget. A response producer suspends for file/IPC work and socket backpressure; it never blocks the PACE owner or builds a whole-file string. Disconnect cancels both directions and releases reservations; partial writes remain uncertain until the file service reconciles them. Ranges are 64-bit; malformed ranges, EOF and short reads are explicit outcomes.

PACE upstream owns generic incremental parsing, async producers and `100-continue`; tauCloud owns authorization, quotas, file-service adapters and cancellation policy. The pinned PACE currently buffers request bodies, has a synchronous response producer and rejects `Expect`; do not wrap that API and claim streaming. M3 must test unauthorized early body, chunk boundaries, slow readers/writers, >RAM transfers, disconnect, bounded memory and graceful stop on both hosts before WebDAV activation.
