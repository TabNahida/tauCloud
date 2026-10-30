#include <taucloud/files.hpp>
#include <fstream>
#include <sstream>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <psapi.h>
#include <winioctl.h>
#else
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace tc {
json system_inventory(const call_context &ctx) {
  ctx.check();
  json out = {{"observed_at", now()}, {"status", "available"}};
  json volumes = json::array(), network = json::array(), disks = json::array();
#ifdef _WIN32
  MEMORYSTATUSEX memory{};
  memory.dwLength = sizeof(memory);
  require(GlobalMemoryStatusEx(&memory), "inventory_unavailable");
  SYSTEM_INFO system{};
  GetSystemInfo(&system);
  FILETIME idle, kernel, user;
  require(GetSystemTimes(&idle, &kernel, &user), "inventory_unavailable");
  auto ticks = [](FILETIME t) { return (uint64_t(t.dwHighDateTime) << 32) | t.dwLowDateTime; };
  out["memory"] = {{"total", memory.ullTotalPhys}, {"available", memory.ullAvailPhys}};
  out["cpu"] = {{"logical", system.dwNumberOfProcessors},
                {"idle_ticks", ticks(idle)},
                {"total_ticks", ticks(kernel) + ticks(user)},
                {"ticks_per_second", 10000000}};
  out["uptime_ms"] = GetTickCount64();
  PMIB_IF_TABLE2 table = nullptr;
  if (GetIfTable2(&table) == NO_ERROR) {
    for (ULONG i = 0; i < std::min<ULONG>(table->NumEntries, 128); ++i) {
      auto &row = table->Table[i];
      network.push_back(
          {{"id", row.InterfaceIndex}, {"received", row.InOctets}, {"sent", row.OutOctets}});
    }
    FreeMibTable(table);
  }
  wchar_t drives[1024];
  auto length = GetLogicalDriveStringsW(1024, drives);
  require(length > 0 && length < 1024, "inventory_unavailable");
  for (auto *drive = drives; *drive; drive += wcslen(drive) + 1) {
    ctx.check();
    if (GetDriveTypeW(drive) != DRIVE_FIXED)
      continue;
    wchar_t guid[MAX_PATH]{};
    ULARGE_INTEGER free, total, available;
    bool stable = GetVolumeNameForVolumeMountPointW(drive, guid, MAX_PATH);
    auto mount = fs::path(drive).string();
    json volume = {{"mount", mount}, {"identity_status", stable ? "available" : "unavailable"}};
    if (stable)
      volume["stable_id"] = fs::path(guid).string();
    if (GetDiskFreeSpaceExW(drive, &available, &total, &free)) {
      volume["status"] = "available";
      volume["total"] = total.QuadPart;
      volume["available"] = available.QuadPart;
    } else
      volume["status"] =
          GetLastError() == ERROR_ACCESS_DENIED ? "permission_denied" : "unavailable";
    volumes.push_back(volume);
  }
  // Read-only queries. A provider may require elevated read access; report that result
  // instead of elevating the monitor or treating absence of telemetry as good health.
  for (unsigned index = 0; index < 32; ++index) {
    ctx.check();
    auto path = L"\\\\.\\PhysicalDrive" + std::to_wstring(index);
    HANDLE disk = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (disk == INVALID_HANDLE_VALUE) {
      auto code = GetLastError();
      if (code == ERROR_ACCESS_DENIED)
        disks.push_back({{"device", index},
                         {"identity_status", "permission_denied"},
                         {"health", {{"status", "permission_denied"}, {"observed_at", now()}}}});
      continue;
    }
    json d = {{"device", index},
              {"identity_status", "unavailable"},
              {"health", {{"status", "unavailable"}, {"observed_at", now()}}}};
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    alignas(STORAGE_DEVICE_DESCRIPTOR) char buffer[4096]{};
    DWORD returned = 0;
    if (DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer,
                        sizeof(buffer), &returned, nullptr) &&
        returned >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
      auto *descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR *>(buffer);
      auto offset = descriptor->SerialNumberOffset;
      if (offset > 0 && offset < returned) {
        auto end = static_cast<const char *>(memchr(buffer + offset, 0, returned - offset));
        if (end && end > buffer + offset) {
          d["stable_id"] = std::string(buffer + offset, static_cast<size_t>(end - buffer - offset));
          d["identity_kind"] = "device_serial";
          d["identity_status"] = "available";
        }
      }
    }
    STORAGE_PREDICT_FAILURE prediction{};
    if (DeviceIoControl(disk, IOCTL_STORAGE_PREDICT_FAILURE, nullptr, 0, &prediction,
                        sizeof(prediction), &returned, nullptr))
      d["health"] = {{"status", "available"},
                     {"predicts_failure", bool(prediction.PredictFailure)},
                     {"provider", "storage_predict_failure"},
                     {"observed_at", now()}};
    else {
      d["health"]["status"] =
          GetLastError() == ERROR_ACCESS_DENIED ? "permission_denied" : "unavailable";
      d["health"]["reason"] = "native_query_not_available";
    }
    CloseHandle(disk);
    disks.push_back(d);
  }
#else
  struct sysinfo memory {};
  require(sysinfo(&memory) == 0, "inventory_unavailable");
  out["memory"] = {{"total", uint64_t(memory.totalram) * memory.mem_unit},
                   {"available", uint64_t(memory.freeram) * memory.mem_unit}};
  out["uptime_ms"] = int64_t(memory.uptime) * 1000;
  {
    std::ifstream f("/proc/meminfo");
    std::string key;
    uint64_t value;
    std::string unit;
    while (f >> key >> value >> unit)
      if (key == "MemAvailable:")
        out["memory"]["available"] = value * 1024;
  }
  {
    std::ifstream f("/proc/stat");
    std::string line;
    std::getline(f, line);
    std::istringstream row(line);
    std::string label;
    row >> label;
    uint64_t v = 0, total = 0, idle = 0;
    int n = 0;
    while (row >> v) {
      if (n < 8)
        total += v;
      if (n == 3 || n == 4)
        idle += v;
      ++n;
    }
    out["cpu"] = {{"logical", sysconf(_SC_NPROCESSORS_ONLN)},
                  {"idle_ticks", idle},
                  {"total_ticks", total},
                  {"ticks_per_second", sysconf(_SC_CLK_TCK)}};
  }
  {
    std::ifstream f("/proc/net/dev");
    std::string line;
    while (std::getline(f, line) && network.size() < 128) {
      auto colon = line.find(':');
      if (colon == std::string::npos)
        continue;
      std::istringstream row(line.substr(colon + 1));
      uint64_t received, sent, ignored;
      row >> received;
      for (int i = 0; i < 7; ++i)
        row >> ignored;
      row >> sent;
      network.push_back({{"id", line.substr(0, colon)}, {"received", received}, {"sent", sent}});
    }
  }
  {
    std::ifstream f("/proc/self/mounts");
    std::string device, mount, type, opts, rest;
    while (f >> device >> mount >> type >> opts && volumes.size() < 128) {
      std::getline(f, rest);
      ctx.check();
      if (!device.starts_with("/dev/"))
        continue;
      json v = {{"mount", mount}, {"filesystem", type}, {"identity_status", "unavailable"}};
      std::error_code ec;
      auto capacity = fs::space(mount, ec);
      if (!ec) {
        v["status"] = "available";
        v["total"] = capacity.capacity;
        v["available"] = capacity.available;
      } else
        v["status"] = ec == std::errc::permission_denied ? "permission_denied" : "unavailable";
      if (fs::exists("/dev/disk/by-uuid", ec)) {
        size_t count = 0;
        for (auto &entry : fs::directory_iterator("/dev/disk/by-uuid", ec)) {
          if (++count > 128)
            break;
          if (fs::equivalent(entry.path(), device, ec)) {
            v["stable_id"] = entry.path().filename().string();
            v["identity_status"] = "available";
            break;
          }
        }
      }
      volumes.push_back(v);
    }
  }
  {
    std::error_code ec;
    size_t count = 0;
    for (auto &entry : fs::directory_iterator("/sys/class/block", ec)) {
      if (++count > 64)
        break;
      ctx.check();
      auto name = entry.path().filename().string();
      if (name.starts_with("loop") || name.starts_with("ram"))
        continue;
      json d = {{"device", name},
                {"identity_status", "unavailable"},
                {"health",
                 {{"status", "unavailable"},
                  {"reason", "no_readable_disk_sensor"},
                  {"observed_at", now()}}}};
      for (auto file : {"wwid", "device/wwid", "device/serial"}) {
        std::ifstream f(entry.path() / file);
        std::string id;
        if (std::getline(f, id) && !id.empty() && id.size() <= 256) {
          d["stable_id"] = id;
          d["identity_status"] = "available";
          break;
        }
      }
      auto hwmon = entry.path() / "device/hwmon";
      if (fs::exists(hwmon, ec)) {
        size_t sensors = 0;
        for (auto &sensor : fs::directory_iterator(hwmon, ec)) {
          if (++sensors > 4)
            break;
          std::ifstream f(sensor.path() / "temp1_input");
          int64_t temperature;
          if (f >> temperature) {
            d["health"] = {{"status", "available"},
                           {"temperature_celsius", temperature / 1000.0},
                           {"observed_at", now()},
                           {"overall_health", "unavailable"}};
            break;
          }
          if (errno == EACCES)
            d["health"]["status"] = "permission_denied";
        }
      }
      disks.push_back(d);
    }
  }
#endif
  ctx.check();
  for (auto &disk : disks)
    if (disk["health"]["status"] == "available" &&
        now() - disk["health"]["observed_at"].get<int64_t>() > 2000)
      disk["health"]["status"] = "stale";
  out["network"] = network;
  out["volumes"] = volumes;
  out["disks"] = disks;
  out["collection_limit_ms"] = 4000;
  return out;
}
} // namespace tc
