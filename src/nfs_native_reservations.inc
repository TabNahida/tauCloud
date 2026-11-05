// Called only with reply_mutex held. Every channel operation is nonblocking;
// protocol workers wait for these jobs only after releasing that mutex.
struct native_hold_state { uint64_t token = 0; };
struct native_job {
  enum class kind { reserve, refresh, finish } operation;
  std::shared_ptr<native_hold_state> hold;
  bool renew = false, done = false;
  std::string failure;
  enum class phase { start, completing, reserving, inspecting } step = phase::start;
};
struct reservation_route {
  uint64_t client;
  int64_t expires;
  std::unique_ptr<native_delegation_reservation_channel> channel;
  bool failed = false, authenticating = true, published = false, probing = false, retiring = false;
  int64_t next_probe = 0;
  int64_t protected_until = 0, recall_until = 0;
  static int64_t clock() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
  }
  uint32_t revoked = 0;
  std::deque<std::shared_ptr<native_job>> queued;
  std::shared_ptr<native_job> active;
  reservation_route(uint64_t c, int64_t expiry, const json &capability)
      : client(c), expires(expiry), channel(std::make_unique<native_delegation_reservation_channel>(
          capability, native_delegation_reservation_channel::mode::nonblocking)) {}
  void lost() noexcept {
    // A previously acknowledged terminal cutoff is not an owner crash while
    // protection is owed. Unknown or still-reserved protection remains fatal.
    if (protected_until && clock() >= protected_until &&
        (recall_until || (now() >= expires && !active && queued.empty())))
      revoked = recall_until ? 10087 : 10011;
    failed = true; channel.reset();
    if (active) { active->failure = "delegation_owner_lost"; active->done = true; active.reset(); }
    for (auto &job : queued) { job->failure = "delegation_owner_lost"; job->done = true; }
    queued.clear();
  }
  void observe(const json &snapshot) {
    next_probe = clock() + 250;
    protected_until = snapshot.at("protected_until_ms");
    recall_until = snapshot.at("recall_deadline_ms");
    if (!snapshot.at("held").get<bool>()) revoked = snapshot.at("state") == "expired" ? 10011 : 10087;
  }
  std::shared_ptr<native_job> submit(native_job::kind kind, const std::shared_ptr<native_hold_state> &hold,
                                      bool renew = false) {
    require(!failed, "delegation_owner_lost");
    require(queued.size() + bool(active) < 96, "operation_limit");
    auto job = std::make_shared<native_job>(native_job{kind, hold, renew});
    queued.push_back(job); return job;
  }
  void finish() { active->done = true; active.reset(); }
  void choose() {
    // Completion/cancellation frees native capacity before new reservations.
    // Never overtake an earlier job belonging to the same hold.
    auto selected = queued.begin();
    for (auto it = queued.begin(); it != queued.end(); ++it)
      if ((*it)->operation == native_job::kind::finish &&
          std::none_of(queued.begin(), it, [&](const auto &j) { return j->hold == (*it)->hold; })) {
        selected = it; break;
      }
    active = *selected; queued.erase(selected);
  }
  void pump() noexcept {
    if (failed) return;
    try {
      if (!channel->alive()) { lost(); return; }
      if (authenticating) {
        auto ack = channel->poll(); if (!ack) return;
        observe(*ack); authenticating = false;
      }
      if (probing) {
        auto ack = channel->poll(); if (!ack) return;
        observe(*ack); probing = false;
      }
      // Limit work per route, even if every ACK is immediately available.
      for (unsigned budget = 0; budget < 8; ++budget) {
        if (!active) {
          if (queued.empty()) {
            if (!revoked && clock() >= next_probe) { channel->begin_inspect(); probing = true; }
            return;
          }
          choose();
        }
        auto &job = *active;
        if (job.step == native_job::phase::start) {
          if (revoked) { job.hold->token = 0; finish(); continue; }
          if (job.operation == native_job::kind::reserve) {
            channel->begin_reserve(); job.step = native_job::phase::reserving;
          } else if (!job.hold->token) {
            if (job.operation == native_job::kind::refresh) { lost(); return; }
            finish(); continue;
          } else {
            auto token = std::exchange(job.hold->token, 0);
            channel->begin_complete(token, job.operation == native_job::kind::refresh || job.renew);
            job.step = native_job::phase::completing;
          }
        }
        std::optional<json> ack;
        try { ack = channel->poll(); }
        catch (const error &e) {
          auto failure = std::string_view(e.what());
          if (failure == "stale_handle" && job.step == native_job::phase::reserving) {
            channel->begin_inspect(); job.step = native_job::phase::inspecting; continue;
          }
          if (failure == "operation_limit" && job.operation == native_job::kind::reserve) {
            job.failure = "operation_limit"; finish(); continue;
          }
          throw;
        }
        if (!ack) return;
        observe(*ack);
        if (job.step == native_job::phase::inspecting) {
          if (!revoked) {
            if (job.operation != native_job::kind::reserve) { lost(); return; }
            job.failure = "stale_handle";
          }
          finish();
        } else if (job.step == native_job::phase::reserving) {
          job.hold->token = ack->at("reservation").get<uint64_t>(); finish();
        } else if (job.operation == native_job::kind::refresh && !revoked) {
          channel->begin_reserve(); job.step = native_job::phase::reserving;
        } else finish();
      }
    } catch (...) { lost(); }
  }
};
struct native_ticket {
  std::shared_ptr<reservation_route> route;
  std::shared_ptr<native_job> job;
};
struct native_request_hold {
  std::shared_ptr<reservation_route> route;
  std::shared_ptr<native_hold_state> state = std::make_shared<native_hold_state>();
  native_ticket initial, finishing;
  explicit native_request_hold(std::shared_ptr<reservation_route> r) : route(std::move(r)) {
    initial = {route, route->submit(native_job::kind::reserve, state)};
  }
  native_request_hold(const native_request_hold &) = delete;
  native_ticket refresh() {
    require(!finishing.job, "cancelled");
    return {route, route->submit(native_job::kind::refresh, state)};
  }
  native_ticket finish(bool renew) noexcept {
    if (!finishing.job) {
      try { finishing = {route, route->submit(native_job::kind::finish, state, renew)}; }
      catch (...) { route->lost(); }
    }
    return finishing;
  }
  ~native_request_hold() { finish(false); }
};
