#include <taucloud/runtime/bounded_executor.hpp>
#include <atomic>
#include <future>
#include <iostream>

using namespace std::chrono_literals;
using executor = taucloud::bounded_executor;
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }

int main() try {
    auto io = std::make_shared<pace::io_context>();
    executor pool(1, 4, 4096);
    std::promise<void> started, unblock;
    auto barrier = unblock.get_future().share();
    executor::ticket first, cancelled, expired, failing, rejected;
    unsigned completions = 0, failures = 0, cancellations = 0, expirations = 0;
    bool affine = true;
    auto done = [&](executor::result result) {
        affine = affine && pace::io_context::current() == io.get();
        failures += result.state == executor::status::failed && result.error != nullptr;
        cancellations += result.state == executor::status::cancelled;
        expirations += result.state == executor::status::expired;
        if (++completions == 4) io->stop();
    };
    auto deadline = executor::clock::now() + 5s;
    require(pool.submit(io, 1024, deadline, [&](auto) { started.set_value(); barrier.wait(); }, done, first), "first admission");
    started.get_future().wait();
    require(pool.submit(io, 1024, deadline, [](auto) { throw std::runtime_error("cancelled job ran"); }, done, cancelled), "cancel admission");
    cancelled.cancel();
    require(pool.submit(io, 1024, executor::clock::now() - 1s, [](auto) { throw std::runtime_error("expired job ran"); }, done, expired), "expiry admission");
    require(pool.submit(io, 1024, deadline, [](auto) { throw std::runtime_error("expected"); }, done, failing), "failure admission");
    require(!pool.submit(io, 1, deadline, [](auto) {}, done, rejected), "job/byte limit bypass");
    unblock.set_value();
    // Force completions to accumulate while the reactor is not running. Capacity
    // must remain reserved through callback delivery, not just through disk work.
    pool.shutdown();
    require(pool.outstanding() == 4, "posted completions escaped budget");
    io->run();
    require(affine && completions == 4 && cancellations >= 1, "completion affinity/cancellation");
    require(pool.outstanding() == 0, "reservation leak");
    require(!pool.submit(io, 1, deadline, [](auto) {}, done, rejected), "accepted after close");

    // Deterministic expiry and exception tests without shutdown cancellation.
    auto loop = std::make_shared<pace::io_context>();
    executor second(1, 2, 128);
    unsigned seen = 0;
    auto check = [&](executor::result result) {
        failures += result.state == executor::status::failed && result.error != nullptr;
        expirations += result.state == executor::status::expired;
        if (++seen == 2) loop->stop();
    };
    require(!second.submit(loop, 129, deadline, [](auto) {}, check, rejected), "byte limit bypass");
    require(second.submit(loop, 64, executor::clock::now() - 1s, [](auto) {}, check, expired), "expiry");
    require(second.submit(loop, 64, deadline, [](auto) { throw std::runtime_error("expected"); }, check, failing), "exception");
    loop->run(); second.shutdown();
    require(failures >= 1 && expirations >= 1 && second.outstanding() == 0, "expiry/exception accounting");

    // Running cancellation and a responsive owner while blocking work is active.
    auto active = std::make_shared<pace::io_context>();
    executor third(1, 1, 1);
    std::promise<void> running;
    bool cooperative = false, responsive = false;
    executor::ticket running_ticket;
    require(third.submit(active, 1, deadline, [&](std::stop_token stop) {
        running.set_value();
        while (!stop.stop_requested()) std::this_thread::sleep_for(1ms);
        cooperative = true;
    }, [&](auto result) { require(result.state == executor::status::completed, "false rollback claim"); active->stop(); }, running_ticket), "running admission");
    running.get_future().wait();
    active->post([&] { responsive = true; running_ticket.cancel(); });
    active->run(); third.shutdown();
    require(cooperative && responsive, "blocked owner or cancellation lost");

    auto stopped = std::make_shared<pace::io_context>();
    stopped->stop(); stopped->run();
    executor fourth(1, 1, 1);
    require(fourth.submit(stopped, 1, deadline, [](auto) {}, [](auto) {}, rejected), "stopped probe admission");
    fourth.shutdown();
    require(fourth.outstanding() == 0 && fourth.undelivered() == 1, "stopped-owner cleanup");
    auto abandoned = std::make_shared<pace::io_context>();
    executor fifth(1, 1, 1);
    require(fifth.submit(abandoned, 1, deadline, [](auto) {}, [](auto) {}, rejected), "abandoned admission");
    fifth.shutdown();
    abandoned.reset(); // A discarded queued callback must release its reservation.
    require(fifth.outstanding() == 0 && fifth.undelivered() == 1, "abandoned-owner cleanup");
    std::cout << "{\"probe\":\"runtime\",\"status\":\"passed\",\"checks\":13}\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n'; return 1;
}
