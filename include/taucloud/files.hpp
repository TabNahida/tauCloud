#pragma once
#include <taucloud/core.hpp>
namespace tc {
constexpr size_t file_chunk_size = 128 * 1024;
constexpr size_t ipc_frame_size = 512 * 1024;
std::string encode_bytes(std::string_view bytes);
std::string decode_bytes(std::string_view hex);
std::string path_fold(const std::string &);
void portable_path(const std::string &path, bool internal = false);
bool file_role(std::string_view role);
const std::vector<std::string> &file_roles();
class native_watch;
class native_cache_guard;
class native_delegation_owner;
// Every traversal is relative to a pinned directory handle. No path-based fallback.
class native_file {
  friend class native_watch;
  friend class native_cache_guard;
  friend class native_delegation_owner;
  struct impl;
  std::unique_ptr<impl> impl_;
  native_file open_impl(const std::string &, bool, bool, bool, bool, bool = false) const;
  std::unique_ptr<native_cache_guard> cache_guard_impl(bool, bool, bool = true) const;

public:
  native_file();
  ~native_file();
  native_file(native_file &&) noexcept;
  native_file &operator=(native_file &&) noexcept;
  // Share an already-confined descriptor, retaining access after unlink.
  native_file retain() const;
  bool writable() const;
  std::unique_ptr<native_watch> watch(bool recursive, uint32_t filter) const;
  // Kernel-enforced data-cache exclusion. Returns null if the requested
  // guarantee cannot be established; callers must then decline caching.
  // This alone does not coordinate namespace/handle caching or SMB leases.
  std::unique_ptr<native_cache_guard> cache_guard(bool write_cache) const;
  // Linux 6.19+ delegation: data and namespace/attribute conflict retention.
  // No ordinary-lease fallback. Does not survive the last descriptor's close
  // or certify NFS recovery. Unsupported kernels/platforms return null.
  std::unique_ptr<native_cache_guard> delegation_guard(bool write_cache) const;
  // Private namespace links preserve an open incarnation across process death.
  // Ordinary opens continue to reject all hard links.
  native_file pin(const native_file &directory, const std::string &name) const;
  native_file open_pin(const std::string &name, const std::string &object) const;
  bool matches_pin(const std::string &path, const std::string &object) const;
  static native_file root(const fs::path &path);
  native_file open(const std::string &path, bool directory = false, bool create = false,
                   bool write = false) const;
  // Confined namespace observation, without opening a file for data access or
  // breaking its native data-cache guard. Never returns a usable IO handle.
  json metadata(const std::string &path, bool directory = false) const;
  json info(bool change_stamp = false) const;
  // Filesystems without native incarnation evidence are ineligible for persistent NFS handles.
  std::string stable_identity() const;
  // Persistent SMB FILE_OBJECTID_BUFFER; absent unless explicitly created.
  // Metadata remains bound to this native incarnation across host renames.
  std::optional<std::string> object_identifier(bool create = false) const;
  // Internal enumeration avoids Linux atime updates where ownership permits.
  // Client-requested directory reads retain their native access behavior.
  std::vector<json> list(bool preserve_access = false) const;
  std::string read(uint64_t offset, size_t count) const;
  size_t write(uint64_t offset, std::string_view bytes);
  void truncate(uint64_t size);
  void allocate(uint64_t size);
  void set_times(std::optional<uint64_t> accessed_ns, std::optional<uint64_t> modified_ns);
  void flush() const;
  void rename(const std::string &from, const std::string &to, bool replace = false,
              bool directory = false, const native_file *source = nullptr) const;
  void remove(const std::string &path, bool directory = false,
              const std::string &pinned_object = "") const;
};
class native_cache_guard {
  struct impl;
  std::unique_ptr<impl> impl_;
  friend class native_file;
  native_cache_guard();
public:
  ~native_cache_guard();
  // A break allows the protocol owner to flush/invalidate before release().
  // Linux may force the lease off after its system-wide break timeout; callers
  // must recall clients within that deadline. Windows RW waits for release.
  bool breaking() const;
  void release();
};
// A bounded, nonblocking native directory notification stream. Paths are
// relative to a pinned directory; overflow requires client enumeration.
class native_watch {
  struct impl;
  std::unique_ptr<impl> impl_;
  friend class native_file;
  native_watch();
public:
  ~native_watch();
  json poll();
};
json inspect_root(const fs::path &path);
#ifdef TAUCLOUD_TEST_IO
void test_write_budget(int64_t bytes);
#endif
json system_inventory(const call_context &ctx);
class file_store {
  struct impl;
  std::unique_ptr<impl> impl_;

public:
  file_store(const config &, std::string role, std::string generation);
  ~file_store();
  // Fence expired cache owners even when no protocol request arrives.
  void maintain();
  json dispatch(const std::string &, const json &, const call_context &);
};
} // namespace tc
