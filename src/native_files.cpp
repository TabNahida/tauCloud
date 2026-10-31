#include <taucloud/files.hpp>
#include <algorithm>
#include <cstring>
#include <limits>
#include <utf8proc.h>
#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/falloc.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif
namespace tc {
#ifdef TAUCLOUD_TEST_IO
static std::atomic<int64_t> write_budget = -1;
void test_write_budget(int64_t bytes) { write_budget = bytes; }
#endif
std::string encode_bytes(std::string_view input) {
  std::string out;
  out.reserve(input.size() * 2);
  for (unsigned char c : input) {
    out += "0123456789abcdef"[c >> 4];
    out += "0123456789abcdef"[c & 15];
  }
  return out;
}
std::string decode_bytes(std::string_view input) {
  require(input.size() % 2 == 0 && input.size() <= file_chunk_size * 2, "invalid_request");
  std::string out(input.size() / 2, '\0');
  auto nibble = [](char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    throw error("invalid_request");
  };
  for (size_t i = 0; i < out.size(); ++i)
    out[i] = static_cast<char>((nibble(input[i * 2]) << 4) | nibble(input[i * 2 + 1]));
  return out;
}
bool file_role(std::string_view role) {
  return role == "file" || role == "file_1" || role == "file_2" || role == "file_3";
}
const std::vector<std::string> &file_roles() {
  static const std::vector<std::string> value = {"file", "file_1", "file_2", "file_3"};
  return value;
}
std::string unicode_map(const std::string &value, bool fold) {
  utf8proc_uint8_t *result = nullptr;
  auto flags = static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPOSE |
                                              (fold ? UTF8PROC_CASEFOLD : 0));
  auto n = utf8proc_map(reinterpret_cast<const utf8proc_uint8_t *>(value.data()), value.size(),
                        &result, flags);
  require(n >= 0, "unsupported_name");
  std::string out(reinterpret_cast<char *>(result), static_cast<size_t>(n));
  free(result);
  return out;
}
std::string path_fold(const std::string &value) { return unicode_map(value, true); }
#ifdef _WIN32
static std::wstring wide_name(const std::string &value) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), nullptr, 0);
  require(n > 0, "unsupported_name");
  std::wstring out(n, 0);
  require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), out.data(), n) == n,
          "unsupported_name");
  return out;
}
static std::string narrow_name(const std::wstring &value) {
  int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  require(n > 0, "unsupported_name");
  std::string out(n, 0);
  require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), out.data(), n, nullptr, nullptr) == n,
          "unsupported_name");
  return out;
}
#endif
void portable_path(const std::string &path, bool internal) {
  require(!path.empty() && path.size() <= 1024, "invalid_path");
  require(unicode_map(path, false) == path, "unsupported_name");
  size_t start = 0;
  while (start < path.size()) {
    auto end = path.find('/', start);
    if (end == std::string::npos)
      end = path.size();
    auto part = path.substr(start, end - start);
    require(!part.empty() && part.size() <= 120 && part != "." && part != ".." &&
                part.back() != '.' && part.back() != ' ',
            "invalid_path");
    for (unsigned char c : part)
      require(c >= 32 && c != 127 &&
                  std::string_view("\\:*?\"<>|").find(static_cast<char>(c)) ==
                      std::string_view::npos,
              "unsupported_name");
    auto folded = path_fold(part);
    require(internal || !folded.starts_with(".tc-"), "reserved_name");
    auto base = folded.substr(0, folded.find('.'));
    require(base != "con" && base != "prn" && base != "aux" && base != "nul" &&
                !(base.size() == 4 && (base.starts_with("com") || base.starts_with("lpt")) &&
                  base[3] >= '1' && base[3] <= '9'),
            "reserved_name");
    require(end != path.size() - 1 || path.back() != '/', "invalid_path");
    start = end + 1;
  }
}
static void native_error() {
#ifdef _WIN32
  auto code = GetLastError();
  if (code == ERROR_DISK_FULL || code == ERROR_HANDLE_DISK_FULL)
    throw error("disk_full");
  if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
    throw error("not_found");
  if (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS)
    throw error("already_exists");
  if (code == ERROR_ACCESS_DENIED)
    throw error("permission_denied");
  if (code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION)
    throw error("locked");
#else
  if (errno == ENOSPC || errno == EDQUOT)
    throw error("disk_full");
  if (errno == ENOENT)
    throw error("not_found");
  if (errno == EEXIST)
    throw error("already_exists");
  if (errno == EACCES || errno == EPERM)
    throw error("permission_denied");
  if (errno == EXDEV)
    throw error("cross_volume");
  if (errno == ELOOP || errno == ENOTDIR)
    throw error("unsafe_path");
#endif
  throw error("io_error");
}
namespace {
struct resource {
#ifdef _WIN32
  HANDLE handle = INVALID_HANDLE_VALUE;
  ~resource() {
    if (handle != INVALID_HANDLE_VALUE)
      CloseHandle(handle);
  }
#else
  int handle = -1;
  ~resource() {
    if (handle >= 0)
      ::close(handle);
  }
#endif
};
} // namespace
struct native_file::impl {
  std::shared_ptr<resource> file = std::make_shared<resource>();
  std::vector<std::shared_ptr<resource>> parents;
#ifdef _WIN32
  std::wstring leaf;
#endif
  bool allow_unlinked = false;
  bool private_pin = false;
};
native_file::native_file() : impl_(std::make_unique<impl>()) {}
native_file::~native_file() = default;
native_file::native_file(native_file &&) noexcept = default;
native_file &native_file::operator=(native_file &&) noexcept = default;
native_file native_file::retain() const {
  info();
  native_file result;
  *result.impl_ = *impl_;
  result.impl_->allow_unlinked = true;
  return result;
}
std::string native_file::stable_identity() const {
#ifdef _WIN32
  // NTFS file IDs contain the MFT sequence, and are verified on the pinned handle.
  wchar_t filesystem[32]{};
  require(GetVolumeInformationByHandleW(impl_->file->handle, nullptr, 0, nullptr, nullptr,
                                       nullptr, filesystem, 32) &&
              std::wstring(filesystem) == L"NTFS", "stable_handles_unavailable");
  return info().at("object").get<std::string>();
#else
  alignas(file_handle) unsigned char storage[sizeof(file_handle) + 128]{};
  auto *h = reinterpret_cast<file_handle *>(storage);
  h->handle_bytes = 128;
  int mount_id = 0;
  require(name_to_handle_at(impl_->file->handle, "", h, &mount_id, AT_EMPTY_PATH) == 0 &&
              h->handle_bytes > 0 && h->handle_bytes <= 128, "stable_handles_unavailable");
  return info().at("object").get<std::string>() + ":" + std::to_string(h->handle_type) + ":" +
         encode_bytes(std::string_view(reinterpret_cast<char *>(h->f_handle), h->handle_bytes));
#endif
}
json native_file::info(bool change_stamp) const {
#ifdef _WIN32
  FILE_ID_INFO id{};
  BY_HANDLE_FILE_INFORMATION meta{};
  if (!GetFileInformationByHandleEx(impl_->file->handle, FileIdInfo, &id, sizeof(id)) ||
      !GetFileInformationByHandle(impl_->file->handle, &meta))
    native_error();
  require(!(meta.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "unsafe_path");
  bool directory = (meta.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  require(directory || meta.nNumberOfLinks == 1 ||
              (impl_->private_pin && meta.nNumberOfLinks == 2) ||
              (impl_->allow_unlinked && meta.nNumberOfLinks == 0), "hardlink_denied");
  json result = {
      {"object",
       std::to_string(id.VolumeSerialNumber) + ":" +
           encode_bytes(std::string_view(reinterpret_cast<char *>(id.FileId.Identifier), 16)) +
           ":" +
           std::to_string((uint64_t(meta.ftCreationTime.dwHighDateTime) << 32) |
                          meta.ftCreationTime.dwLowDateTime)},
      {"volume", std::to_string(id.VolumeSerialNumber)},
      {"directory", directory},
      {"created_ns",
       ((uint64_t(meta.ftCreationTime.dwHighDateTime) << 32) | meta.ftCreationTime.dwLowDateTime) *
               100 -
           uint64_t(116444736000000000) * 100},
      {"accessed_ns", ((uint64_t(meta.ftLastAccessTime.dwHighDateTime) << 32) |
                       meta.ftLastAccessTime.dwLowDateTime) *
                              100 -
                          uint64_t(116444736000000000) * 100},
      {"modified_ns", ((uint64_t(meta.ftLastWriteTime.dwHighDateTime) << 32) |
                       meta.ftLastWriteTime.dwLowDateTime) *
                              100 -
                          uint64_t(116444736000000000) * 100},
      {"size", (uint64_t(meta.nFileSizeHigh) << 32) | meta.nFileSizeLow}};
  FILE_STANDARD_INFO storage{};
  if (!GetFileInformationByHandleEx(impl_->file->handle, FileStandardInfo, &storage,
                                    sizeof(storage)))
    native_error();
  result["allocated"] = directory ? uint64_t(0) : uint64_t(storage.AllocationSize.QuadPart);
  if (change_stamp) {
    FILE_BASIC_INFO basic{};
    if (!GetFileInformationByHandleEx(impl_->file->handle, FileBasicInfo, &basic, sizeof(basic)))
      native_error();
    result["changed_ns"] = (uint64_t(basic.ChangeTime.QuadPart) - 116444736000000000ull) * 100;
  }
  return result;
#else
  struct stat s {};
  if (fstat(impl_->file->handle, &s) != 0)
    native_error();
  require(S_ISDIR(s.st_mode) || S_ISREG(s.st_mode), "unsafe_path");
  require(S_ISDIR(s.st_mode) || s.st_nlink == 1 ||
              (impl_->private_pin && s.st_nlink == 2) ||
              (impl_->allow_unlinked && s.st_nlink == 0), "hardlink_denied");
  struct statx sx {};
  require(statx(impl_->file->handle, "", AT_EMPTY_PATH, STATX_BTIME, &sx) == 0 &&
              (sx.stx_mask & STATX_BTIME),
          "stable_identity_unavailable");
  json result = {{"object", std::to_string(s.st_dev) + ":" + std::to_string(s.st_ino) + ":" +
                                std::to_string(sx.stx_btime.tv_sec) + ":" +
                                std::to_string(sx.stx_btime.tv_nsec)},
                 {"volume", std::to_string(s.st_dev)},
                 {"directory", S_ISDIR(s.st_mode)},
                 {"created_ns", int64_t(sx.stx_btime.tv_sec) * 1000000000 + sx.stx_btime.tv_nsec},
                 {"accessed_ns", int64_t(s.st_atim.tv_sec) * 1000000000 + s.st_atim.tv_nsec},
                 {"modified_ns", int64_t(s.st_mtim.tv_sec) * 1000000000 + s.st_mtim.tv_nsec},
                 {"size", s.st_size}};
  result["allocated"] = S_ISDIR(s.st_mode) ? uint64_t(0) : uint64_t(s.st_blocks) * 512;
  if (change_stamp)
    result["changed_ns"] = int64_t(s.st_ctim.tv_sec) * 1000000000 + s.st_ctim.tv_nsec;
  return result;
#endif
}
native_file native_file::root(const fs::path &path) {
  require(path.is_absolute(), "invalid_path");
  native_file result;
#ifdef _WIN32
  require(path.has_root_name() && path.root_name().wstring().size() == 2, "unsupported_root");
  auto base = path.root_path();
  result.impl_->file->handle = CreateFileW(
      base.c_str(), GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (result.impl_->file->handle == INVALID_HANDLE_VALUE)
    native_error();
  for (auto &part : path.relative_path()) {
    require(part != L"." && part != L"..", "invalid_path");
    // Root registration permits native Unicode directory names. File names use the portable
    // profile.
    using nt_open = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                      PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    auto open =
        reinterpret_cast<nt_open>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    require(open, "not_supported");
    std::wstring name = part.wstring();
    UNICODE_STRING u{static_cast<USHORT>(name.size() * 2), static_cast<USHORT>(name.size() * 2),
                     name.data()};
    OBJECT_ATTRIBUTES a{};
    InitializeObjectAttributes(&a, &u, OBJ_CASE_INSENSITIVE, result.impl_->file->handle, nullptr);
    IO_STATUS_BLOCK io{};
    native_file next;
    auto code = open(&next.impl_->file->handle, GENERIC_READ | SYNCHRONIZE, &a, &io, nullptr, 0,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, 1, 0x00200000 | 0x20 | 1, nullptr, 0);
    if (code < 0) {
      auto convert = reinterpret_cast<ULONG(WINAPI *)(NTSTATUS)>(
          GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
      auto saved = convert(code);
      log("native", "open_failed", std::to_string(saved));
      SetLastError(saved);
      native_error();
    }
    next.info();
    next.impl_->leaf = name;
    next.impl_->parents = result.impl_->parents;
    next.impl_->parents.push_back(result.impl_->file);
    result = std::move(next);
  }
#else
  int base = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(base >= 0, "io_error");
  open_how how{};
  how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
  auto relative = path.relative_path().string();
  int fd = static_cast<int>(
      syscall(SYS_openat2, base, relative.empty() ? "." : relative.c_str(), &how, sizeof(how)));
  int saved = errno;
  ::close(base);
  errno = saved;
  if (fd < 0)
    native_error();
  result.impl_->file->handle = fd;
#endif
  require(result.info().at("directory"), "invalid_root");
  return result;
}
native_file native_file::open(const std::string &path, bool directory, bool create,
                              bool write_access) const {
  return open_impl(path, directory, create, write_access, false);
}
native_file native_file::open_impl(const std::string &path, bool directory, bool create,
                                   bool write_access, bool pin) const {
  portable_path(path, true);
  native_file result;
  result.impl_->private_pin = pin;
#ifdef _WIN32
  auto parent = impl_->file;
  result.impl_->parents = impl_->parents;
  size_t start = 0;
  for (;;) {
    size_t end = path.find('/', start);
    bool last = end == std::string::npos;
    auto part = path.substr(start, end - start);
    std::wstring name = wide_name(part);
    using nt_open = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                      PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    auto open =
        reinterpret_cast<nt_open>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    require(open, "not_supported");
    bool dir = !last || directory;
    UNICODE_STRING u{static_cast<USHORT>(name.size() * 2), static_cast<USHORT>(name.size() * 2),
                     name.data()};
    OBJECT_ATTRIBUTES a{};
    InitializeObjectAttributes(&a, &u, OBJ_CASE_INSENSITIVE, parent->handle, nullptr);
    IO_STATUS_BLOCK io{};
    auto next = std::make_shared<resource>();
    ACCESS_MASK rights = GENERIC_READ | SYNCHRONIZE;
    if (last && write_access)
      rights |= GENERIC_WRITE | DELETE;
    auto code = open(&next->handle, rights, &a, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | (dir ? 0 : FILE_SHARE_DELETE),
                     last && create ? 2 : 1, 0x00200000 | 0x20 | (dir ? 1 : 0x40), nullptr, 0);
    if (code < 0) {
      auto convert = reinterpret_cast<ULONG(WINAPI *)(NTSTATUS)>(
          GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
      SetLastError(convert(code));
      native_error();
    }
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(next->handle, FileAttributeTagInfo, &tag, sizeof(tag)))
      native_error();
    require(!(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "unsafe_path");
    result.impl_->parents.push_back(parent);
    parent = next;
    if (last) {
      result.impl_->file = next;
      result.impl_->leaf = name;
      break;
    }
    start = end + 1;
  }
#else
  if (directory && create) {
    auto slash = path.rfind('/');
    native_file parent;
    int dir = impl_->file->handle;
    auto name = path;
    if (slash != std::string::npos) {
      parent = open(path.substr(0, slash), true);
      dir = parent.impl_->file->handle;
      name = path.substr(slash + 1);
    }
    if (mkdirat(dir, name.c_str(), 0700) != 0)
      native_error();
  }
  open_how how{};
  how.flags = O_CLOEXEC | O_NOFOLLOW |
              (directory ? O_RDONLY | O_DIRECTORY : (write_access ? O_RDWR : O_RDONLY));
  if (create && !directory) {
    how.flags |= O_CREAT | O_EXCL;
    how.mode = 0600;
  }
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
  result.impl_->file->handle =
      static_cast<int>(syscall(SYS_openat2, impl_->file->handle, path.c_str(), &how, sizeof(how)));
  if (result.impl_->file->handle < 0)
    native_error();
  result.impl_->parents = impl_->parents;
  result.impl_->parents.push_back(impl_->file);
#endif
  auto value = result.info();
  require(value.at("directory") == directory && value.at("volume") == info().at("volume"),
          "unsafe_path");
  return result;
}
static void pin_name(const std::string &name) {
  require(name.size() == 40 && name.starts_with(".tc-nfs-") &&
      std::all_of(name.begin() + 8, name.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
      }), "invalid_path");
}
native_file native_file::open_pin(const std::string &name, const std::string &object) const {
  pin_name(name);
  auto result = open_impl(name, false, false, true, true);
  require(result.info().at("object") == object, "object_replaced");
  return result;
}
bool native_file::matches_pin(const std::string &path, const std::string &object) const {
  try { return open_impl(path, false, false, false, true).info().at("object") == object; }
  catch (const error &e) {
    auto code = std::string_view(e.what());
    if (code == "not_found" || code == "unsafe_path" || code == "hardlink_denied" ||
        code == "is_directory") return false;
    throw;
  }
}
native_file native_file::pin(const native_file &directory, const std::string &name) const {
  pin_name(name);
  auto before = info();
  require(!before.at("directory").get<bool>() && directory.info().at("directory") &&
      directory.info().at("volume") == before.at("volume"), "unsafe_path");
#ifdef _WIN32
  auto wide = wide_name(name);
  // FILE_LINK_INFORMATION has the same layout as FILE_RENAME_INFORMATION.
  std::vector<char> buffer(sizeof(FILE_RENAME_INFO) + wide.size() * sizeof(wchar_t));
  auto *link = reinterpret_cast<FILE_RENAME_INFO *>(buffer.data());
  link->ReplaceIfExists = FALSE;
  link->RootDirectory = directory.impl_->file->handle;
  link->FileNameLength = static_cast<DWORD>(wide.size() * 2);
  memcpy(link->FileName, wide.data(), wide.size() * 2);
  using nt_set = NTSTATUS(NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
  auto set = reinterpret_cast<nt_set>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
  require(set, "not_supported");
  IO_STATUS_BLOCK io{};
  auto code = set(impl_->file->handle, &io, link, static_cast<ULONG>(buffer.size()),
                  static_cast<FILE_INFORMATION_CLASS>(11));
  if (code < 0) {
    auto convert = reinterpret_cast<ULONG(WINAPI *)(NTSTATUS)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
    SetLastError(convert(code)); native_error();
  }
#else
  // Follow only this process's pinned descriptor, never the old pathname.
  auto source = "/proc/self/fd/" + std::to_string(impl_->file->handle);
  if (linkat(AT_FDCWD, source.c_str(), directory.impl_->file->handle, name.c_str(),
              AT_SYMLINK_FOLLOW) != 0) native_error();
#endif
  auto result = directory.open_pin(name, before.at("object"));
  result.flush();
  directory.flush();
  return result;
}
std::vector<json> native_file::list() const {
  require(info().at("directory"), "invalid_path");
  std::vector<json> result;
#ifdef _WIN32
  std::vector<char> buffer(65536);
  bool first = true;
  for (;;) {
    BOOL ok = GetFileInformationByHandleEx(
        impl_->file->handle, first ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
        buffer.data(), static_cast<DWORD>(buffer.size()));
    first = false;
    if (!ok) {
      if (GetLastError() == ERROR_NO_MORE_FILES)
        break;
      native_error();
    }
    auto *entry = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(buffer.data());
    for (;;) {
      std::wstring wide(entry->FileName, entry->FileNameLength / 2);
      auto name = narrow_name(wide);
      if (name != "." && name != "..") {
        require(result.size() < 4096, "directory_limit");
        result.push_back({{"name", name},
                          {"directory", bool(entry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)}});
      }
      if (!entry->NextEntryOffset)
        break;
      entry = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(reinterpret_cast<char *>(entry) +
                                                        entry->NextEntryOffset);
    }
  }
#else
  int fd = openat(impl_->file->handle, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    native_error();
  DIR *stream = fdopendir(fd);
  if (!stream) {
    ::close(fd);
    native_error();
  }
  try {
    while (auto *entry = readdir(stream)) {
      std::string name = entry->d_name;
      if (name == "." || name == "..")
        continue;
      require(result.size() < 4096, "directory_limit");
      struct stat s {};
      if (fstatat(impl_->file->handle, name.c_str(), &s, AT_SYMLINK_NOFOLLOW) != 0)
        native_error();
      require(!S_ISLNK(s.st_mode), "unsafe_path");
      result.push_back({{"name", name}, {"directory", S_ISDIR(s.st_mode)}});
    }
  } catch (...) {
    closedir(stream);
    throw;
  }
  closedir(stream);
#endif
  return result;
}
std::string native_file::read(uint64_t offset, size_t count) const {
  require(count <= file_chunk_size && offset <= uint64_t(INT64_MAX) - count, "invalid_offset");
  info();
  std::string result(count, '\0');
#ifdef _WIN32
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(offset);
  DWORD size = 0;
  if (!SetFilePointerEx(impl_->file->handle, position, nullptr, FILE_BEGIN) ||
      !ReadFile(impl_->file->handle, result.data(), static_cast<DWORD>(count), &size, nullptr))
    native_error();
  result.resize(size);
#else
  ssize_t size;
  do {
    size = pread(impl_->file->handle, result.data(), count, static_cast<off_t>(offset));
  } while (size < 0 && errno == EINTR);
  if (size < 0)
    native_error();
  result.resize(static_cast<size_t>(size));
#endif
  return result;
}
size_t native_file::write(uint64_t offset, std::string_view data) {
  require(data.size() <= file_chunk_size && offset <= uint64_t(INT64_MAX) - data.size(),
          "invalid_offset");
  info();
#ifdef TAUCLOUD_TEST_IO
  if (write_budget >= 0) {
    require(write_budget != 0, "disk_full");
    data = data.substr(0, std::min<size_t>(data.size(), static_cast<size_t>(write_budget.load())));
    write_budget -= static_cast<int64_t>(data.size());
  }
#endif
#ifdef _WIN32
  if (offset > info().at("size").get<uint64_t>() + file_chunk_size) {
    DWORD returned = 0;
    if (!DeviceIoControl(impl_->file->handle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned,
                         nullptr))
      native_error();
  }
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(offset);
  DWORD size = 0;
  if (!SetFilePointerEx(impl_->file->handle, position, nullptr, FILE_BEGIN) ||
      !WriteFile(impl_->file->handle, data.data(), static_cast<DWORD>(data.size()), &size, nullptr))
    native_error();
  return size;
#else
  ssize_t size;
  do {
    size = pwrite(impl_->file->handle, data.data(), data.size(), static_cast<off_t>(offset));
  } while (size < 0 && errno == EINTR);
  if (size < 0)
    native_error();
  return static_cast<size_t>(size);
#endif
}
void native_file::truncate(uint64_t size) {
  require(size <= uint64_t(INT64_MAX), "invalid_offset");
#ifdef _WIN32
  FILE_END_OF_FILE_INFO value{};
  value.EndOfFile.QuadPart = static_cast<LONGLONG>(size);
  if (!SetFileInformationByHandle(impl_->file->handle, FileEndOfFileInfo, &value, sizeof(value)))
    native_error();
#else
  if (ftruncate(impl_->file->handle, static_cast<off_t>(size)) != 0)
    native_error();
#endif
}
void native_file::allocate(uint64_t size) {
  require(size <= uint64_t(INT64_MAX), "invalid_offset");
#ifdef _WIN32
  FILE_ALLOCATION_INFO value{};
  value.AllocationSize.QuadPart = static_cast<LONGLONG>(size);
#ifdef TAUCLOUD_TEST_IO
  require(!size || write_budget != 0, "disk_full");
#endif
  if (!SetFileInformationByHandle(impl_->file->handle, FileAllocationInfo, &value, sizeof(value)))
    native_error();
#else
  struct statvfs volume {};
  if (fstatvfs(impl_->file->handle, &volume) != 0)
    native_error();
  uint64_t unit = volume.f_frsize;
  require(unit > 0 && unit <= 1024 * 1024, "not_supported");
  auto aligned = [&](uint64_t value) {
    require(value <= uint64_t(INT64_MAX) - unit, "invalid_offset");
    return (value + unit - 1) / unit * unit;
  };
  auto target = aligned(size), current = info().at("size").get<uint64_t>();
  // Linux hole punching ignores preallocation past EOF. Same-size truncation
  // frees that tail without discarding data. When shrinking EOF, allocate first
  // so an allocation failure cannot discard the existing suffix.
  if (target >= current)
    truncate(current);
#ifdef TAUCLOUD_TEST_IO
  require(!target || write_budget != 0, "disk_full");
#endif
  if (target &&
      fallocate(impl_->file->handle, FALLOC_FL_KEEP_SIZE, 0, static_cast<off_t>(target)) != 0)
    native_error();
  if (target < current)
    truncate(target);
#endif
}
void native_file::flush() const {
#ifdef _WIN32
  if (!FlushFileBuffers(impl_->file->handle)) {
    auto saved = GetLastError();
    if (info().at("directory") && saved == ERROR_ACCESS_DENIED)
      return;
    SetLastError(saved);
    log("native", "flush_failed", std::to_string(saved));
    native_error();
  }
#else
  if (fsync(impl_->file->handle) != 0)
    native_error();
#endif
}
void native_file::set_times(std::optional<uint64_t> accessed, std::optional<uint64_t> modified) {
  for (auto value : {accessed, modified})
    require(!value || *value <= uint64_t(INT64_MAX), "invalid_timestamp");
#ifdef _WIN32
  resource attributes;
  if (info().at("directory").get<bool>()) {
    // ReOpenFile rejects directory metadata handles on supported Windows hosts.
    // Our original directory and all its parents deny DELETE, pinning the name.
    // Reopen only that component beneath the retained parent; verify the native
    // identity before changing attributes. Never resolve an absolute pathname.
    require(!impl_->parents.empty() && !impl_->leaf.empty(), "not_supported");
    using nt_open = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    auto open = reinterpret_cast<nt_open>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    require(open, "not_supported");
    UNICODE_STRING name{static_cast<USHORT>(impl_->leaf.size() * 2),
                        static_cast<USHORT>(impl_->leaf.size() * 2), impl_->leaf.data()};
    OBJECT_ATTRIBUTES object{};
    InitializeObjectAttributes(&object, &name, OBJ_CASE_INSENSITIVE, impl_->parents.back()->handle, nullptr);
    IO_STATUS_BLOCK io{};
    auto status = open(&attributes.handle, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                       &object, &io, nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       1, 0x00200000 | 0x20 | 1, nullptr, 0);
    if (status < 0) {
      auto convert = reinterpret_cast<ULONG(WINAPI *)(NTSTATUS)>(
          GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
      SetLastError(convert(status));native_error();
    }
    BY_HANDLE_FILE_INFORMATION before{}, after{};
    if (!GetFileInformationByHandle(impl_->file->handle, &before) ||
        !GetFileInformationByHandle(attributes.handle, &after)) native_error();
    require((after.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(after.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
                before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow,
            "object_replaced");
  } else {
    attributes.handle = ReOpenFile(impl_->file->handle, FILE_WRITE_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   FILE_FLAG_BACKUP_SEMANTICS);
  }
  auto handle = attributes.handle;
  if (handle == INVALID_HANDLE_VALUE) {
    auto saved = GetLastError();
    log("native", "reopen_attributes_failed", std::to_string(saved));
    SetLastError(saved);
    native_error();
  }
  auto convert = [](uint64_t ns) {
    auto ticks = ns / 100 + uint64_t(116444736000000000);
    return FILETIME{DWORD(ticks), DWORD(ticks >> 32)};
  };
  auto a = convert(accessed.value_or(0)), m = convert(modified.value_or(0));
  bool ok = SetFileTime(handle, nullptr, accessed ? &a : nullptr, modified ? &m : nullptr);
  auto saved = GetLastError();
  SetLastError(saved);
  if (!ok) {
    log("native", "set_times_failed", std::to_string(saved));
    SetLastError(saved);
    native_error();
  }
#else
  timespec values[2]{};
  size_t i = 0;
  for (auto value : {accessed, modified}) {
    values[i].tv_sec = value ? time_t(*value / 1000000000) : 0;
    values[i++].tv_nsec = value ? long(*value % 1000000000) : UTIME_OMIT;
  }
  if (futimens(impl_->file->handle, values) != 0) native_error();
#endif
}
void native_file::rename(const std::string &from, const std::string &to, bool replace,
                         bool directory) const {
#ifndef _WIN32
  (void)directory;
#endif
  portable_path(from, true);
  portable_path(to, true);
  auto split = [&](const std::string &value) {
    auto pos = value.rfind('/');
    return std::pair{pos == std::string::npos ? std::string() : value.substr(0, pos),
                     pos == std::string::npos ? value : value.substr(pos + 1)};
  };
  auto [fromdir, fromname] = split(from);
  auto [todir, toname] = split(to);
  native_file source_parent, target_parent;
  auto a = impl_->file, b = impl_->file;
  if (!fromdir.empty()) {
    source_parent = open(fromdir, true);
    a = source_parent.impl_->file;
  }
  if (!todir.empty()) {
    target_parent = open(todir, true);
    b = target_parent.impl_->file;
  }
#ifdef _WIN32
  auto source = open(from, directory, false, true);
  std::wstring wide = wide_name(toname);
  std::vector<char> buffer(sizeof(FILE_RENAME_INFO) + wide.size() * sizeof(wchar_t));
  auto *rename = reinterpret_cast<FILE_RENAME_INFO *>(buffer.data());
  // Preserve outstanding descriptors to a replaced file (NFS OPEN). Legacy
  // FileRenameInformation rejects this even when every handle shares DELETE.
  uint32_t flags = replace ? 3u : 0u; // REPLACE_IF_EXISTS | POSIX_SEMANTICS
  memcpy(buffer.data(), &flags, sizeof(flags));
  rename->RootDirectory = b->handle;
  rename->FileNameLength = static_cast<DWORD>(wide.size() * 2);
  memcpy(rename->FileName, wide.data(), wide.size() * 2);
  using nt_set = NTSTATUS(NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
  auto set = reinterpret_cast<nt_set>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
  require(set, "not_supported");
  IO_STATUS_BLOCK io{};
  auto code =
      set(source.impl_->file->handle, &io, rename, static_cast<ULONG>(buffer.size()),
          static_cast<FILE_INFORMATION_CLASS>(65)); // FileRenameInformationEx, confined RootDirectory.
  if (code < 0) {
    auto convert = reinterpret_cast<ULONG(WINAPI *)(NTSTATUS)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
    SetLastError(convert(code));
    native_error();
  }
#else
  if (syscall(SYS_renameat2, a->handle, fromname.c_str(), b->handle, toname.c_str(),
              replace ? 0 : 1) != 0)
    native_error();
  if (fsync(a->handle) != 0 || fsync(b->handle) != 0)
    native_error();
#endif
}
void native_file::remove(const std::string &path, bool directory,
                         const std::string &pinned_object) const {
  portable_path(path, true);
#ifdef _WIN32
  auto file = open_impl(path, directory, false, true, !pinned_object.empty());
  require(pinned_object.empty() || (!directory && file.info().at("object") == pinned_object),
          "object_replaced");
  FILE_DISPOSITION_INFO value{TRUE};
  if (!SetFileInformationByHandle(file.impl_->file->handle, FileDispositionInfo, &value,
                                  sizeof(value)))
    native_error();
#else
  if (!pinned_object.empty()) {
    auto file = open_impl(path, false, false, false, true);
    require(!directory && file.info().at("object") == pinned_object, "object_replaced");
  }
  auto slash = path.rfind('/');
  native_file parent;
  int dir = impl_->file->handle;
  auto name = path;
  if (slash != std::string::npos) {
    parent = open(path.substr(0, slash), true);
    dir = parent.impl_->file->handle;
    name = path.substr(slash + 1);
  }
  if (unlinkat(dir, name.c_str(), directory ? AT_REMOVEDIR : 0) != 0)
    native_error();
  if (fsync(dir) != 0)
    native_error();
#endif
}
json inspect_root(const fs::path &path) {
  auto root = native_file::root(path);
  auto result = root.info();
  result["path"] = fs::absolute(path).lexically_normal().string();
  return result;
}
} // namespace tc
