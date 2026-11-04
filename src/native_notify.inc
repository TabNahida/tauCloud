// Native notifications remain tied to the pinned directory, including rename.
struct native_watch::impl {
  native_file root;
  bool recursive = false, overflow = false, deleted = false, coverage_lost = false;
  uint32_t filter = 0;
#ifdef _WIN32
  HANDLE directory = INVALID_HANDLE_VALUE;
  OVERLAPPED operation{};
  alignas(DWORD) unsigned char buffer[65536]{};
  bool pending = false;
  void arm() {
    ResetEvent(operation.hEvent);
    require(ReadDirectoryChangesW(directory, buffer, sizeof(buffer), recursive,
                (filter & 0x1ff) ? (filter & 0x1ff) : FILE_NOTIFY_CHANGE_FILE_NAME, nullptr, &operation, nullptr),
            "notify_unavailable");
    pending = true;
  }
  ~impl() {
    if (directory != INVALID_HANDLE_VALUE) {
      if (pending) {
        CancelIoEx(directory, &operation);
        DWORD transferred;
        GetOverlappedResult(directory, &operation, &transferred, TRUE);
      }
      CloseHandle(directory);
    }
    if (operation.hEvent) CloseHandle(operation.hEvent);
  }
#else
  int fd = -1;
  struct watched {
    native_file directory;
    std::string path;
    std::map<std::string, struct stat> entries;
  };
  inline static std::atomic<unsigned> pinned = 0;
  std::map<int, watched> directories;
  void add(native_file directory, const std::string &path) {
    if (pinned.fetch_add(1) >= 96) { --pinned; coverage_lost = true; return; }
    auto proc = "/proc/self/fd/" + std::to_string(directory.impl_->file->handle);
    auto wd = inotify_add_watch(fd, proc.c_str(), IN_ONLYDIR | IN_CREATE | IN_DELETE |
        IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY | IN_ATTRIB | IN_ACCESS | IN_DELETE_SELF);
    if (wd < 0) { --pinned; coverage_lost = true; return; }
    if (directories.contains(wd)) --pinned;
    directories.insert_or_assign(wd, watched{std::move(directory), path, {}});
    try {
      for (const auto &entry : directories.at(wd).directory.list()) {
        auto name = entry.at("name").get<std::string>();
        if (name.starts_with(".tc-")) continue;
        portable_path(name);
        struct stat baseline{};
        if (fstatat(directories.at(wd).directory.impl_->file->handle, name.c_str(),
                    &baseline, AT_SYMLINK_NOFOLLOW) == 0)
          directories.at(wd).entries.emplace(name, baseline);
        if (!recursive || !entry.at("directory").get<bool>()) continue;
        auto child = directories.at(wd).directory.open(name, true);
        add(std::move(child), path.empty() ? name : path + "/" + name);
      }
    } catch (...) { coverage_lost = true; }
  }
  void erase(int wd) {
    inotify_rm_watch(fd, wd);
    if (directories.erase(wd)) --pinned;
  }
  ~impl() { pinned -= directories.size(); if (fd >= 0) ::close(fd); }
#endif
};
native_watch::native_watch() : impl_(std::make_unique<impl>()) {}
native_watch::~native_watch() = default;
std::unique_ptr<native_watch> native_file::watch(bool recursive, uint32_t filter) const {
  require(info().at("directory").get<bool>(), "not_directory");
  auto result = std::unique_ptr<native_watch>(new native_watch);
  auto &w = *result->impl_;
  w.root = retain(); w.recursive = recursive; w.filter = filter & 0xfff;
#ifdef _WIN32
  // ReOpenFile rejects the directory handles opened by NtCreateFile above.
  // The retained parent pins this component against rename/replacement. Reopen
  // it asynchronously relative to that parent and verify the native identity.
  if (!impl_->parents.empty() && !impl_->leaf.empty()) {
    using nt_open = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    auto open = reinterpret_cast<nt_open>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    require(open, "notify_unavailable");
    UNICODE_STRING name{static_cast<USHORT>(impl_->leaf.size() * 2),
                        static_cast<USHORT>(impl_->leaf.size() * 2), impl_->leaf.data()};
    OBJECT_ATTRIBUTES object{};
    InitializeObjectAttributes(&object, &name, OBJ_CASE_INSENSITIVE, impl_->parents.back()->handle, nullptr);
    IO_STATUS_BLOCK io{};
    auto status = open(&w.directory, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                       &object, &io, nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       1, 0x00200000 | 1, nullptr, 0); // OPEN_REPARSE_POINT, DIRECTORY_FILE; async.
    if (status < 0) {
      log("native", "notify_open_failed", std::to_string(static_cast<uint32_t>(status)));
      throw error("notify_unavailable");
    }
    BY_HANDLE_FILE_INFORMATION before{}, after{};
    require(GetFileInformationByHandle(impl_->file->handle, &before) &&
                GetFileInformationByHandle(w.directory, &after), "notify_unavailable");
    require((after.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(after.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
                before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow,
            "object_replaced");
  } else {
    w.directory = ReOpenFile(impl_->file->handle, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED);
  }
  require(w.directory != INVALID_HANDLE_VALUE, "notify_unavailable");
  w.operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  require(w.operation.hEvent != nullptr, "notify_unavailable");
  w.arm();
#else
  w.fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
  require(w.fd >= 0, "notify_unavailable");
  w.add(retain(), "");
#endif
  return result;
}
json native_watch::poll() {
  auto &w = *impl_;
  w.overflow |= w.coverage_lost;
  json events = json::array();
  size_t bytes = 0;
  auto event = [&](std::string name, unsigned action, uint32_t mask) {
    if (!(w.filter & mask) || w.overflow) return;
    // Internal staging/pin names are not part of the exported namespace.
    for (size_t at = 0; at < name.size();) {
      auto end = name.find('/', at);
      if (name.substr(at, end == std::string::npos ? end : end - at).starts_with(".tc-")) return;
      if (end == std::string::npos) break;
      at = end + 1;
    }
    bytes += name.size();
    if (events.size() >= 1024 || bytes > 65536) { w.overflow = true; return; }
    events.push_back({{"name", name}, {"action", action}});
  };
#ifdef _WIN32
  DWORD count = 0;
  if (w.pending && GetOverlappedResult(w.directory, &w.operation, &count, FALSE)) {
    w.pending = false;
    if (!count) w.overflow = true;
    size_t at = 0;
    while (at < count) {
      auto *entry = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(w.buffer + at);
      if (count - at < 12 || entry->FileNameLength > count - at - 12 || entry->FileNameLength % 2) {
        w.overflow = true; break;
      }
      auto name = narrow_name(std::wstring(entry->FileName, entry->FileNameLength / 2));
      std::replace(name.begin(), name.end(), '\\', '/');
      event(name, entry->Action, w.filter);
      if (!entry->NextEntryOffset) break;
      if (entry->NextEntryOffset < 12 || entry->NextEntryOffset > count - at) { w.overflow = true; break; }
      at += entry->NextEntryOffset;
    }
    w.arm();
  } else if (w.pending) {
    auto error = GetLastError();
    if (error != ERROR_IO_INCOMPLETE) {
      w.pending = false;
      if (error == ERROR_NOTIFY_ENUM_DIR) { w.overflow = true; w.arm(); }
      else w.deleted = true;
    }
  }
#else
  struct move { std::string name; uint32_t mask; bool directory; };
  std::map<uint32_t, move> removed;
  alignas(inotify_event) char buffer[65536];
  size_t batches = 0;
  while (++batches <= 16) {
    auto count = ::read(w.fd, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR) { --batches; continue; }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
    if (count <= 0) { w.overflow = true; break; }
    for (size_t at = 0; at < static_cast<size_t>(count);) {
      auto *entry = reinterpret_cast<inotify_event *>(buffer + at);
      if (sizeof(inotify_event) > count - at || entry->len > count - at - sizeof(inotify_event)) {
        w.overflow = true; break;
      }
      at += sizeof(inotify_event) + entry->len;
      if (entry->mask & IN_Q_OVERFLOW) { w.overflow = true; continue; }
      auto found = w.directories.find(entry->wd);
      if (found == w.directories.end()) continue;
      if (entry->mask & IN_DELETE_SELF) {
        if (found->second.path.empty()) w.deleted = true;
      }
      if (entry->mask & IN_IGNORED) { w.directories.erase(found); --impl::pinned; continue; }
      if (!entry->len) continue;
      auto name = std::string(entry->name, strnlen(entry->name, entry->len));
      if (name.empty() || name.starts_with(".tc-")) continue;
      try { portable_path(name); } catch (...) { w.overflow = true; continue; }
      auto &snapshots = found->second.entries;
      auto previous_stat = snapshots.find(name);
      struct stat current{};
      bool exists = fstatat(found->second.directory.impl_->file->handle, name.c_str(),
                            &current, AT_SYMLINK_NOFOLLOW) == 0;
      uint32_t changed = 0;
      if (exists && previous_stat != snapshots.end()) {
        const auto &old = previous_stat->second;
        if (old.st_ino != current.st_ino || old.st_dev != current.st_dev) {
          // A pathname was replaced before its queued event was inspected.
          w.overflow = true;
        } else {
          if (old.st_size != current.st_size) changed |= 8;
          if (old.st_mtim.tv_sec != current.st_mtim.tv_sec || old.st_mtim.tv_nsec != current.st_mtim.tv_nsec) changed |= 16;
          if (old.st_atim.tv_sec != current.st_atim.tv_sec || old.st_atim.tv_nsec != current.st_atim.tv_nsec) changed |= 32;
          if (old.st_mode != current.st_mode || old.st_uid != current.st_uid || old.st_gid != current.st_gid) changed |= 256;
        }
      }
      if (entry->mask & (IN_DELETE | IN_MOVED_FROM)) snapshots.erase(name);
      else if (exists) {
        if (snapshots.size() >= 4096 && previous_stat == snapshots.end()) w.coverage_lost = true;
        else {
          snapshots[name] = current;
          // CREATE and a subsequent WRITE may be read in the same batch; do
          // not lose the growth just because fstat already sees the write.
          if ((entry->mask & IN_CREATE) && S_ISREG(current.st_mode)) snapshots[name].st_size = 0;
        }
      }
      auto relative = found->second.path.empty() ? name : found->second.path + "/" + name;
      bool directory = entry->mask & IN_ISDIR;
      uint32_t mask = directory ? 2 : 1;
      if (entry->mask & IN_MOVED_FROM) {
        removed[entry->cookie] = {relative, mask, directory};
      } else if (entry->mask & IN_MOVED_TO) {
        auto previous = removed.find(entry->cookie);
        if (previous != removed.end()) {
          event(previous->second.name, 4, previous->second.mask); event(relative, 5, mask);
          if (directory)
            for (auto &[wd, item] : w.directories)
              if (item.path == previous->second.name || item.path.starts_with(previous->second.name + "/"))
                item.path = relative + item.path.substr(previous->second.name.size());
          removed.erase(previous);
        } else event(relative, 1, mask);
      } else if (entry->mask & IN_CREATE) event(relative, 1, mask);
      else if (entry->mask & IN_DELETE) event(relative, 2, mask);
      if (entry->mask & IN_MODIFY) changed |= 16;
      if (entry->mask & (IN_MODIFY | IN_ATTRIB | IN_ACCESS)) event(relative, 3, changed);
      if (w.recursive && directory && (entry->mask & (IN_CREATE | IN_MOVED_TO))) {
        bool present = false;
        for (const auto &[wd, item] : w.directories) present |= item.path == relative;
        if (!present) {
          try {
            auto child = w.root.open(relative, true);
            // inotify is not recursive: changes before installation must cause
            // a rescan instead of silently disappearing from a watched tree.
            if (!child.list().empty()) w.overflow = true;
            w.add(std::move(child), relative);
          } catch (...) { w.coverage_lost = true; }
        }
      }
    }
  }
  for (const auto &[cookie, item] : removed) {
    if (item.directory) {
      // Queued events from a moved-out child must not expose its new namespace.
      for (auto it = events.begin(); it != events.end();) {
        auto name = it->at("name").get<std::string>();
        if (name.starts_with(item.name + "/")) it = events.erase(it);
        else ++it;
      }
      // Stop observing a subtree moved outside the exported directory.
      std::vector<int> remove;
      for (const auto &[wd, entry] : w.directories)
        if (entry.path == item.name || entry.path.starts_with(item.name + "/")) remove.push_back(wd);
      for (auto wd : remove) w.erase(wd);
    }
    event(item.name, 2, item.mask);
  }
  if (batches > 16) w.overflow = true;
#endif
  w.overflow = w.filter && (w.overflow || w.coverage_lost);
  json result = {{"events", w.overflow ? json::array() : events},
                 {"overflow", w.overflow}, {"deleted", w.deleted}};
  w.overflow = false;
  return result;
}
