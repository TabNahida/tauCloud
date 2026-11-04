#pragma once
#include <taucloud/files.hpp>

namespace tc {
// A private, descriptor-capability channel to a separate native guard owner.
// Closing this object detaches, rather than releasing active delegations.
// Accepted renewals extend retention; callers must await acknowledgment before
// extending network state. Expiry/release drops the guard.
// Protocol reclaim and authorization remain the caller's responsibility.
class native_delegation_owner {
  struct impl;
  std::unique_ptr<impl> impl_;
public:
  native_delegation_owner();
  ~native_delegation_owner();
  native_delegation_owner(const native_delegation_owner &) = delete;
  uint64_t acquire(const native_file &, int64_t period_ms, int64_t remaining_ms,
                   bool write = false);
  json inspect(uint64_t id);
  void renew(uint64_t id, int64_t remaining_ms);
  void recall(uint64_t id);
  void release(uint64_t id);
  // Must be called before application startup (including ordinary invocation),
  // registering helper support before an owner can spawn this executable.
  // Returns -1 for ordinary invocation.
  static int entry(int argc, char **argv);
};
} // namespace tc
