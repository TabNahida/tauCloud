#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#else
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct fixture {
    fs::path path;
    fixture() {
        for (unsigned i = 0; i < 100; ++i) {
            path = fs::temp_directory_path() / ("taucloud-m0-" + std::to_string(std::random_device{}()));
            if (fs::create_directory(path)) return;
        }
        throw std::runtime_error("cannot create disposable fixture");
    }
    ~fixture() { std::error_code ignored; fs::remove_all(path, ignored); }
};
void validate(const std::string& path) {
    require(!path.empty() && path[0] != '/', "absolute or empty path");
    require(path.find('\\') == std::string::npos && path.find(':') == std::string::npos &&
            path.find('\0') == std::string::npos, "ambiguous path");
    std::size_t start = 0;
    for (;;) {
        const auto end = path.find('/', start);
        const auto part = path.substr(start, end - start);
        require(!part.empty() && part != "." && part != "..", "traversal");
        if (end == std::string::npos) break;
        start = end + 1;
    }
}
#ifdef _WIN32
struct handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    handle(const handle&) = delete;
};
using native_open = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
HANDLE confined(HANDLE root, const std::string& name) {
    validate(name);
    // Probe only single-component ASCII paths. M2 must add segment walking,
    // Unicode policy and locked ancestor handles before exposing nested paths.
    require(name.find('/') == std::string::npos, "nested paths not enabled in Windows M0 probe");
    std::wstring wide(name.begin(), name.end());
    UNICODE_STRING unicode{};
    unicode.Buffer = wide.data();
    unicode.Length = static_cast<USHORT>(wide.size() * sizeof(wchar_t));
    unicode.MaximumLength = unicode.Length;
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &unicode, OBJ_CASE_INSENSITIVE, root, nullptr);
    IO_STATUS_BLOCK status{};
    HANDLE result = INVALID_HANDLE_VALUE;
    auto open = reinterpret_cast<native_open>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    require(open != nullptr, "NtCreateFile unavailable");
    const NTSTATUS code = open(&result, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &attributes, &status, nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        1 /* FILE_OPEN */, 0x00200000 /* FILE_OPEN_REPARSE_POINT */ |
        0x40 /* FILE_NON_DIRECTORY_FILE */ | 0x20 /* FILE_SYNCHRONOUS_IO_NONALERT */, nullptr, 0);
    require(code >= 0, "relative native open failed");
    FILE_ATTRIBUTE_TAG_INFO tag{};
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandleEx(result, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !GetFileInformationByHandle(result, &info) || info.nNumberOfLinks != 1) {
        CloseHandle(result); throw std::runtime_error("reparse point or hardlink refused");
    }
    return result;
}
FILE_ID_INFO identity(HANDLE file) {
    FILE_ID_INFO id{};
    require(GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)), "file ID");
    return id;
}
#else
struct handle {
    int value = -1;
    explicit handle(int fd = -1) : value(fd) {}
    ~handle() { if (value >= 0) ::close(value); }
    handle(const handle&) = delete;
};
int confined(int root, const std::string& name) {
    validate(name);
    open_how how{};
    how.flags = O_RDWR | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    int result = static_cast<int>(syscall(SYS_openat2, root, name.c_str(), &how, sizeof(how)));
    require(result >= 0, "confined open failed (openat2 required; no unsafe fallback)");
    struct stat info{};
    if (fstat(result, &info) || info.st_nlink != 1 || !S_ISREG(info.st_mode)) {
        ::close(result); throw std::runtime_error("hardlink or nonregular file refused");
    }
    return result;
}
#endif

int main() try {
    fixture temp;
    const auto root = temp.path / "root";
    fs::create_directory(root);
    std::ofstream(root / "file") << "inside";
    std::ofstream(temp.path / "outside") << "secret";
    unsigned rejected = 0;
#ifdef _WIN32
    handle directory(CreateFileW(root.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(directory.value != INVALID_HANDLE_VALUE, "root handle");
#else
    handle directory(::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    require(directory.value >= 0, "root handle");
#endif
    for (const auto* path : {"../outside", "/outside", "file:stream", "a\\b", "./file", "", "a//b"}) {
        try { handle invalid(confined(directory.value, path)); }
        catch (const std::exception&) { ++rejected; }
    }
    require(rejected == 7, "unsafe path accepted");
    fs::create_hard_link(temp.path / "outside", root / "hardlink");
    bool hardlink = false;
    try { handle invalid(confined(directory.value, "hardlink")); }
    catch (const std::exception&) { hardlink = true; }
    require(hardlink, "external hardlink accepted");
    std::error_code link_error;
    fs::create_symlink(temp.path / "outside", root / "link", link_error);
    if (!link_error) {
        bool link = false;
        try { handle invalid(confined(directory.value, "link")); }
        catch (const std::exception&) { link = true; }
        require(link, "external symlink accepted");
    }
    handle file(confined(directory.value, "file"));
    bool case_sensitive = !fs::exists(root / "FILE");
#ifdef _WIN32
    const auto before = identity(file.value);
    require(FlushFileBuffers(file.value), "file flush");
    fs::rename(root / "file", root / "renamed");
    const auto after = identity(file.value);
    require(before.VolumeSerialNumber == after.VolumeSerialNumber &&
        memcmp(before.FileId.Identifier, after.FileId.Identifier, 16) == 0, "ID changed across rename");
    handle renamed(confined(directory.value, "renamed"));
    const auto reopened = identity(renamed.value);
    require(memcmp(before.FileId.Identifier, reopened.FileId.Identifier, 16) == 0, "reopen ID mismatch");
    fs::remove(root / "renamed");
    char data[6]{}; DWORD count = 0;
    require(ReadFile(file.value, data, sizeof(data), &count, nullptr) && count == 6 &&
        std::string(data, 6) == "inside", "delete-while-open lost object");
    const char* platform = "windows";
#else
    struct stat before{}, after{}, reopened{};
    require(fstat(file.value, &before) == 0 && fsync(file.value) == 0, "stat/flush");
    fs::rename(root / "file", root / "renamed");
    require(fstat(file.value, &after) == 0 && before.st_ino == after.st_ino && before.st_dev == after.st_dev, "ID changed across rename");
    handle renamed(confined(directory.value, "renamed"));
    require(fstat(renamed.value, &reopened) == 0 && before.st_ino == reopened.st_ino, "reopen ID mismatch");
    fs::remove(root / "renamed");
    require(fsync(directory.value) == 0, "directory flush");
    char data[6]{};
    require(pread(file.value, data, sizeof(data), 0) == 6 && std::string(data, 6) == "inside", "unlink-while-open lost object");
    // Concurrent name replacement must never follow the hostile link.
    fs::create_directory(root / "race");
    std::atomic<bool> stop{false};
    std::jthread attacker([&] {
        while (!stop) {
            std::error_code ignored;
            fs::remove(root / "race" / "entry", ignored);
            fs::create_symlink(temp.path / "outside", root / "race" / "entry", ignored);
        }
    });
    bool escaped = false;
    for (unsigned i = 0; i < 1000; ++i) {
        try { handle escaped_file(confined(directory.value, "race/entry")); escaped = true; }
        catch (const std::exception&) {}
    }
    stop = true; attacker.join();
    require(!escaped, "symlink race escaped root");
    const char* platform = "linux";
#endif
    std::cout << "{\"probe\":\"filesystem\",\"status\":\"passed\",\"host\":\"" << platform
              << "\",\"case_sensitive\":" << (case_sensitive ? "true" : "false")
              << ",\"symlink_test\":\"" << (link_error ? "unavailable" : "passed")
              << "\",\"power_loss_durability\":\"not_tested\"}\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n'; return 1;
}
