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
// Every traversal is relative to a pinned directory handle. No path-based fallback.
class native_file {
  struct impl;
  std::unique_ptr<impl> impl_;
  native_file open_impl(const std::string &, bool, bool, bool, bool) const;

public:
  native_file();
  ~native_file();
  native_file(native_file &&) noexcept;
  native_file &operator=(native_file &&) noexcept;
  // Share an already-confined descriptor, retaining access after unlink.
  native_file retain() const;
  // Private namespace links preserve an open incarnation across process death.
  // Ordinary opens continue to reject all hard links.
  native_file pin(const native_file &directory, const std::string &name) const;
  native_file open_pin(const std::string &name, const std::string &object) const;
  bool matches_pin(const std::string &path, const std::string &object) const;
  static native_file root(const fs::path &path);
  native_file open(const std::string &path, bool directory = false, bool create = false,
                   bool write = false) const;
  json info(bool change_stamp = false) const;
  // Filesystems without native incarnation evidence are ineligible for persistent NFS handles.
  std::string stable_identity() const;
  std::vector<json> list() const;
  std::string read(uint64_t offset, size_t count) const;
  size_t write(uint64_t offset, std::string_view bytes);
  void truncate(uint64_t size);
  void allocate(uint64_t size);
  void set_times(std::optional<uint64_t> accessed_ns, std::optional<uint64_t> modified_ns);
  void flush() const;
  void rename(const std::string &from, const std::string &to, bool replace = false,
              bool directory = false) const;
  void remove(const std::string &path, bool directory = false,
              const std::string &pinned_object = "") const;
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
  json dispatch(const std::string &, const json &, const call_context &);
};
} // namespace tc
