#pragma once
#include <taucloud/files.hpp>

namespace tc {
// A private, descriptor-capability channel to a separate native guard owner.
// Closing this object detaches, rather than releasing active delegations.
// Accepted renewals extend retention; callers must await acknowledgment before
// extending network state. Expiry/release drops the guard.
// Protocol reclaim and authorization remain the caller's responsibility.
class native_delegation_reservation_channel;
class native_delegation_owner {
  friend class native_delegation_reservation_channel;
  struct impl;
  std::unique_ptr<impl> impl_;
public:
  native_delegation_owner();
  ~native_delegation_owner();
  native_delegation_owner(const native_delegation_owner &) = delete;
  uint64_t acquire(const native_file &, int64_t period_ms, int64_t remaining_ms,
                   bool write = false);
  json inspect(uint64_t id);
  // Returns acknowledged absolute monotonic lease/recall/protection deadlines.
  json renew(uint64_t id, int64_t remaining_ms);
  // Unique, bounded in-flight reservations. Completion grants a full lease;
  // cancellation grants none. Neither can postpone a fixed recall deadline.
  json reserve(uint64_t id);
  // Private same-host capability for a separate controller. It only observes
  // and reserves this delegation; it cannot acquire/release guards or do IO.
  json reservation_capability(uint64_t id);
  json complete(uint64_t id, uint64_t reservation, bool renew_lease);
  void recall(uint64_t id);
  void release(uint64_t id);
  // Diagnostics only; use a pidfd/verified process identity for signaling.
  int64_t process_id() const;
  // Must be called before application startup (including ordinary invocation),
  // registering helper support before an owner can spawn this executable.
  // Returns -1 for ordinary invocation.
  static int entry(int argc, char **argv);
};
// A separately connected, delegation-bound channel, independent of the file
// worker's execution queue and primary owner channel. Do not expose capabilities
// on the NFS wire. Losing this channel conservatively completes its own tokens.
class native_delegation_reservation_channel {
  struct impl;
  std::unique_ptr<impl> impl_;
public:
  explicit native_delegation_reservation_channel(const json &capability);
  ~native_delegation_reservation_channel();
  native_delegation_reservation_channel(const native_delegation_reservation_channel &) = delete;
  json inspect();
  json reserve();
  json complete(uint64_t reservation, bool renew_lease);
};
} // namespace tc
