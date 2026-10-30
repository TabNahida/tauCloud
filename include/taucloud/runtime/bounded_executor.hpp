#pragma once
#include <pace/io_context.hpp>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <vector>

namespace taucloud {
// M0 callback bridge. The owner must drain completions before stopping its loop.
// Captures/buffers must fit the declared reservation; no unbounded payload capture.
class bounded_executor {
public:
    using clock = std::chrono::steady_clock;
    enum class status { completed, cancelled, expired, failed };
    struct result { status state; std::exception_ptr error{}; };
    using work = std::function<void(std::stop_token)>;
    using completion = std::function<void(result)>;
    struct ticket {
        std::stop_source cancellation;
        void cancel() { cancellation.request_stop(); }
    };
private:
    struct job {
        std::shared_ptr<pace::io_context> owner;
        work run;
        completion done;
        std::stop_source cancellation;
        clock::time_point deadline;
        std::size_t bytes;
    };
    struct state {
        std::mutex mutex;
        std::condition_variable wake;
        std::deque<job> queue;
        bool closing = false;
        std::size_t outstanding = 0, bytes = 0, undelivered = 0;
    };
    std::shared_ptr<state> state_ = std::make_shared<state>();
    std::stop_source shutdown_;
    std::vector<std::jthread> workers_;
    std::size_t max_jobs_, max_bytes_;
    static void release(const std::shared_ptr<state>& s, std::size_t bytes) {
        std::lock_guard lock(s->mutex);
        --s->outstanding;
        s->bytes -= bytes;
    }
    struct reservation {
        std::shared_ptr<state> owner;
        std::size_t bytes;
        bool delivered = false;
        reservation(std::shared_ptr<state> s, std::size_t size) : owner(std::move(s)), bytes(size) {}
        ~reservation() {
            release(owner, bytes);
            if (!delivered) {
                std::lock_guard lock(owner->mutex);
                ++owner->undelivered;
            }
        }
    };
    void worker() {
        for (;;) {
            job item;
            {
                std::unique_lock lock(state_->mutex);
                state_->wake.wait(lock, [&] { return state_->closing || !state_->queue.empty(); });
                if (state_->queue.empty()) return;
                item = std::move(state_->queue.front());
                state_->queue.pop_front();
            }
            // stop_callback is scoped to this job and propagates pool shutdown.
            std::stop_callback stop(shutdown_.get_token(), [source = item.cancellation]() mutable { source.request_stop(); });
            result outcome{status::completed};
            if (item.cancellation.stop_requested()) outcome.state = status::cancelled;
            else if (clock::now() >= item.deadline) outcome.state = status::expired;
            else {
                try { item.run(item.cancellation.get_token()); }
                catch (...) { outcome = {status::failed, std::current_exception()}; }
                // A returned write may already have committed, even if cancelled.
                // Never relabel that success as an operation safe to replay.
            }
            const auto bytes = item.bytes;
            std::shared_ptr<reservation> admitted;
            try {
                admitted = std::make_shared<reservation>(state_, bytes);
                item.owner->post([admitted, done = std::move(item.done), outcome] {
                    admitted->delivered = true;
                    done(outcome);
                });
            } catch (...) {
                if (!admitted) {
                    release(state_, bytes);
                    std::lock_guard lock(state_->mutex);
                    ++state_->undelivered;
                }
            }
        }
    }
public:
    bounded_executor(std::size_t threads, std::size_t jobs, std::size_t bytes)
        : max_jobs_(jobs), max_bytes_(bytes) {
        if (!threads || !jobs || !bytes) throw std::invalid_argument("zero executor budget");
        try {
            for (std::size_t i = 0; i < threads; ++i) workers_.emplace_back([this] { worker(); });
        } catch (...) { shutdown(); throw; }
    }
    bounded_executor(const bounded_executor&) = delete;
    bounded_executor& operator=(const bounded_executor&) = delete;
    ~bounded_executor() { shutdown(); }

    // Rejection does not allocate a queue entry or invoke the completion.
    bool submit(std::shared_ptr<pace::io_context> owner, std::size_t bytes,
                clock::time_point deadline, work run, completion done, ticket& out) {
        std::lock_guard lock(state_->mutex);
        if (!owner || !run || !done || state_->closing || state_->outstanding >= max_jobs_ ||
            bytes > max_bytes_ - state_->bytes) return false;
        ticket next;
        state_->queue.push_back({std::move(owner), std::move(run), std::move(done), next.cancellation, deadline, bytes});
        out = next;
        ++state_->outstanding;
        state_->bytes += bytes;
        state_->wake.notify_one();
        return true;
    }
    // Call from the supervising thread, not a PACE callback or blocking worker.
    // Kernel I/O cannot be forcibly cancelled; supervisor process deadlines fence hangs.
    void shutdown() {
        {
            std::lock_guard lock(state_->mutex);
            state_->closing = true;
        }
        shutdown_.request_stop();
        state_->wake.notify_all();
        workers_.clear();
    }
    std::size_t outstanding() const { std::lock_guard lock(state_->mutex); return state_->outstanding; }
    std::size_t undelivered() const { std::lock_guard lock(state_->mutex); return state_->undelivered; }
};
} // namespace taucloud
