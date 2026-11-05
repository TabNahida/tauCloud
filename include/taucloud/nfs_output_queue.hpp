#pragma once
#include <taucloud/nfs.hpp>
#include <algorithm>
#include <array>
#include <deque>
#include <optional>

namespace tc::nfs_detail {
struct outgoing_record {
  std::string packet;
  uint64_t completion = 0;
  bool callback = false;
  std::weak_ptr<callback_delivery> delivery{};
};

// Reactor-owned. The active frame stays charged until its write completes;
// choosing another frame can never interleave a partial RPC record.
class output_queue {
  std::array<std::deque<outgoing_record>, 2> waiting_;
  std::array<size_t, 2> bytes_{};
  std::array<unsigned, 2> count_{};
  std::optional<outgoing_record> active_;
  unsigned burst_ = 0;
public:
  output_queue() = default;
  output_queue(const output_queue &) = delete;
  output_queue &operator=(const output_queue &) = delete;
  bool push(outgoing_record record) {
    auto kind = unsigned(record.callback);
    auto byte_limit = (record.callback ? 1 : 4) * max_record;
    if (record.packet.empty() || record.packet.size() > max_record ||
        count_[kind] >= (record.callback ? 4u : 16u) ||
        record.packet.size() > byte_limit - bytes_[kind]) return false;
    auto size = record.packet.size();
    waiting_[kind].push_back(std::move(record));
    bytes_[kind] += size; ++count_[kind];
    return true;
  }
  bool empty() const { return count_[0] + count_[1] == 0; }
  const outgoing_record &start() {
    require(!active_ && !empty(), "invalid_output_state");
    bool callback = !waiting_[1].empty() && (waiting_[0].empty() || burst_ < 4);
    auto &queue = waiting_[unsigned(callback)];
    active_.emplace(std::move(queue.front())); queue.pop_front();
    burst_ = callback ? std::min(4u, burst_ + 1) : 0;
    return *active_;
  }
  uint64_t finish() {
    require(active_.has_value(), "invalid_output_state");
    auto kind = unsigned(active_->callback);
    bytes_[kind] -= active_->packet.size(); --count_[kind];
    auto completion = active_->completion;
    active_.reset();
    return completion;
  }
  template<class Complete> void drain(Complete complete) {
    if (active_) complete(finish());
    while (!empty()) { start(); complete(finish()); }
    burst_ = 0;
  }
};
} // namespace tc::nfs_detail
