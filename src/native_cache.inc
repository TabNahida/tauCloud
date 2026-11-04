// Kernel data-cache exclusion, independent of any network protocol. Linux
// leases and Windows RW oplocks delay conflicting native data access. Linux
// leases do not protect namespace/handle caching and have a kernel break timeout.
struct native_cache_guard::impl {
  std::shared_ptr<resource> file;
  bool write = false, active = false;
#ifdef _WIN32
  native_operation notification;
  REQUEST_OPLOCK_INPUT_BUFFER request{};
  REQUEST_OPLOCK_OUTPUT_BUFFER output{};
#endif
};
native_cache_guard::native_cache_guard() : impl_(std::make_unique<impl>()) {}
native_cache_guard::~native_cache_guard() {
  try { release(); }
  catch (...) {
    // Never leave a hidden lease held by another retained reference after an
    // unexpected release failure. Invalidating that descriptor fails closed.
#ifdef _WIN32
    if (impl_->file && impl_->file->handle != INVALID_HANDLE_VALUE) {
      CloseHandle(impl_->file->handle);
      impl_->file->handle = INVALID_HANDLE_VALUE;
      // Closing cancels any outstanding IRP. Its output/OVERLAPPED storage
      // must still survive until the kernel has finished touching it.
      if (impl_->active)
        WaitForSingleObject(impl_->notification.value.hEvent, INFINITE);
      impl_->file->cache_owned = false;
    }
#else
    if (impl_->file && impl_->file->handle >= 0) {
      ::close(impl_->file->handle);
      impl_->file->handle = -1;
      impl_->file->cache_owned = false;
    }
#endif
  }
}
std::unique_ptr<native_cache_guard> native_file::cache_guard(bool write_cache) const {
  if (info().at("directory")) return nullptr;
#ifdef _WIN32
  // Native R/RH breaks on writes are advisory: they do not wait for an ACK.
  // Only RW currently satisfies this primitive's data-exclusion guarantee.
  // RW describes the kernel exclusion, not the caller's data-access rights.
  // A read-only protocol open still needs writes delayed until invalidation.
  if (!write_cache) return nullptr;
#else
  // SIGIO is reserved only when no application handler owns it. No signal
  // handler touches file state: F_GETLEASE reports the requested break target.
  static std::once_flag setup;
  static bool available = false;
  std::call_once(setup, [] {
    struct sigaction old{};
    if (sigaction(SIGIO, nullptr, &old) != 0 ||
        (old.sa_handler != SIG_DFL && old.sa_handler != SIG_IGN)) return;
    struct sigaction ignored{};
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    available = sigaction(SIGIO, &ignored, nullptr) == 0;
  });
  struct sigaction current{};
  if (!available || sigaction(SIGIO, nullptr, &current) != 0 || current.sa_handler != SIG_IGN)
    return nullptr;
#endif
  auto file = impl_->file;
  auto result = std::unique_ptr<native_cache_guard>(new native_cache_guard());
  if (file->cache_owned.exchange(true)) return nullptr;
  auto &guard = *result->impl_;
  guard.file = file;
  guard.write = write_cache;
#ifdef _WIN32
  if (!file->overlapped) {
    // ReOpenFile retains the native incarnation, including after rename; it
    // never resolves the old pathname. Replace the shared synchronous file
    // description before requesting RW, which requires sole data access.
    auto async = ReOpenFile(file->handle, file->access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OVERLAPPED);
    if (async == INVALID_HANDLE_VALUE) { file->cache_owned = false; return nullptr; }
    CloseHandle(file->handle);
    file->handle = async;
    file->overlapped = true;
  }
  guard.request.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
  guard.request.StructureLength = sizeof(guard.request);
  guard.request.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE;
  guard.request.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
  auto immediate = DeviceIoControl(file->handle, FSCTL_REQUEST_OPLOCK,
      &guard.request, sizeof(guard.request), &guard.output, sizeof(guard.output), nullptr,
      &guard.notification.value);
  if (immediate || GetLastError() != ERROR_IO_PENDING) {
    file->cache_owned = false;
    return nullptr;
  }
#else
  int rc;
  do { rc = fcntl(file->handle, F_SETLEASE, write_cache ? F_WRLCK : F_RDLCK); }
  while (rc < 0 && errno == EINTR);
  if (rc < 0) {
    file->cache_owned = false;
    return nullptr; // Conflicting opens, permissions or unsupported filesystem.
  }
#endif
  guard.active = true;
  return result;
}
bool native_cache_guard::breaking() const {
#ifdef _WIN32
  if (impl_->active) {
    DWORD size = 0;
    if (GetOverlappedResult(impl_->file->handle, &impl_->notification.value, &size, FALSE))
      return true;
    return GetLastError() != ERROR_IO_INCOMPLETE;
  }
#else
  if (impl_->active) {
    int level;
    do { level = fcntl(impl_->file->handle, F_GETLEASE); } while (level < 0 && errno == EINTR);
    if (level < 0) native_error();
    return level != (impl_->write ? F_WRLCK : F_RDLCK);
  }
#endif
  return false;
}
void native_cache_guard::release() {
  if (!impl_->active) return;
#ifdef _WIN32
  DWORD size = 0;
  auto file = impl_->file->handle;
  auto &notification = impl_->notification.value;
  auto completed = GetOverlappedResult(file, &notification, &size, FALSE);
  auto code = completed ? ERROR_SUCCESS : GetLastError();
  if (!completed && code == ERROR_IO_INCOMPLETE) {
    // A voluntary release cancels only this IRP, never another file request.
    // A concurrent break can win the cancellation race and still need an ACK.
    CancelIoEx(file, &notification);
    completed = GetOverlappedResult(file, &notification, &size, TRUE);
    code = completed ? ERROR_SUCCESS : GetLastError();
  }
  if (!completed && code != ERROR_OPERATION_ABORTED) {
    SetLastError(code); native_error();
  }
  if (completed && (impl_->output.Flags & REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED)) {
    REQUEST_OPLOCK_INPUT_BUFFER ack{};
    ack.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    ack.StructureLength = sizeof(ack);
    ack.Flags = REQUEST_OPLOCK_INPUT_FLAG_ACK; // RequestedOplockLevel = NONE.
    REQUEST_OPLOCK_OUTPUT_BUFFER output{};
    native_operation operation;
    operation.finish(file, DeviceIoControl(file, FSCTL_REQUEST_OPLOCK,
        &ack, sizeof(ack), &output, sizeof(output), nullptr, &operation.value));
  }
#else
  int rc;
  do { rc = fcntl(impl_->file->handle, F_SETLEASE, F_UNLCK); } while (rc < 0 && errno == EINTR);
  if (rc < 0) native_error();
#endif
  impl_->active = false;
  impl_->file->cache_owned = false;
}
