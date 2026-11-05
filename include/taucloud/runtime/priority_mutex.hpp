#pragma once
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <utility>

namespace taucloud {
// Prefer pending control work, but admit ordinary work after at most four
// consecutive priority holders. Running work is never preempted.
class priority_mutex {
    mutable std::mutex state_;
    std::condition_variable changed_;
    unsigned normal_ = 0, priority_ = 0, burst_ = 0;
    bool held_ = false;
    void acquire(bool priority) {
        std::unique_lock lock(state_);
        auto &waiting = priority ? priority_ : normal_;
        ++waiting;
        try {
            changed_.wait(lock, [&] {
                return !held_ && (priority ? !normal_ || burst_ < 4 : !priority_ || burst_ >= 4);
            });
        } catch (...) {
            --waiting; changed_.notify_all(); throw;
        }
        --waiting;
        held_ = true;
        burst_ = priority ? std::min(4u, burst_ + 1) : 0;
    }
public:
    class entry {
        priority_mutex &owner_;
    public:
        entry(priority_mutex &owner, bool priority) : owner_(owner) { owner_.acquire(priority); }
        entry(const entry &) = delete;
        entry &operator=(const entry &) = delete;
        ~entry() { owner_.unlock(); }
    };
    [[nodiscard]] entry enter(bool priority) { return entry(*this, priority); }
    void lock() { acquire(false); }
    void unlock() {
        std::lock_guard lock(state_);
        held_ = false;
        changed_.notify_all();
    }
    // Bounded dispatch diagnostics; this never waits for the current holder.
    std::pair<unsigned, unsigned> pending() const {
        std::lock_guard lock(state_);
        return {normal_, priority_};
    }
};
} // namespace taucloud
