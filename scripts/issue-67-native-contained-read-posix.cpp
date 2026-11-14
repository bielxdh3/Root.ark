// #67 / PR #298: Linux ext4 LAB ONLY. No production integration or authority.
// Root fingerprint must arrive from a trusted, externally retained root lease.
// An open fd protects the inode, not its directory name from concurrent rename.
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {
struct Fd {
  int fd = -1;
  explicit Fd(int value = -1) : fd(value) {}
  ~Fd() { if (fd >= 0) ::close(fd); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
  Fd& operator=(Fd&& other) noexcept {
    if (this != &other) {
      if (fd >= 0) ::close(fd);
      fd = std::exchange(other.fd, -1);
    }
    return *this;
  }
};
struct Entry {
  Fd lease;
  struct stat identity{};
  std::string component;
  Entry(Fd&& file, const struct stat& metadata, std::string name)
      : lease(std::move(file)), identity(metadata), component(std::move(name)) {}
};
bool safeSegments(const std::string& path, bool absolute, std::vector<std::string>& out) {
  if (path.empty() || (path.front() == '/') != absolute) return false;
  const std::size_t start = absolute ? 1U : 0U;
  if (absolute && path == "/") return true;
  std::size_t at = start;
  while (at < path.size()) {
    const std::size_t end = path.find('/', at);
    const std::string part = path.substr(at, end == std::string::npos ? end : end - at);
    if (part.empty() || part == "." || part == ".." || part.size() > 255) return false;
    for (const unsigned char c : part)
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
          || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return false;
    out.push_back(part);
    if (end == std::string::npos) return true;
    at = end + 1;
  }
  return false;
}
bool identityEqual(const struct stat& a, const struct stat& b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino
      && (a.st_mode & S_IFMT) == (b.st_mode & S_IFMT);
}
std::string fingerprint(const struct stat& info) {
  std::ostringstream output;
  output << std::hex << std::setfill('0') << std::setw(16)
         << static_cast<std::uint64_t>(info.st_dev) << std::setw(16)
         << static_cast<std::uint64_t>(info.st_ino);
  return output.str();
}
int beneathOpen(int parent, const std::string& segment, bool directory) {
  struct open_how how{};
  how.flags = static_cast<std::uint64_t>(O_CLOEXEC | O_NOFOLLOW
      | (directory ? (O_PATH | O_DIRECTORY) : (O_RDONLY | O_NONBLOCK)));
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
      | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
  return static_cast<int>(::syscall(SYS_openat2, parent, segment.c_str(), &how, sizeof(how)));
}
bool validChain(const std::vector<Entry>& entries) {
  for (std::size_t i = 0; i < entries.size(); ++i) {
    struct stat actual{};
    if (::fstat(entries[i].lease.fd, &actual) != 0
        || !identityEqual(actual, entries[i].identity)) return false;
    if (i == 0) continue;
    struct stat located{};
    if (::fstatat(entries[i - 1].lease.fd, entries[i].component.c_str(),
        &located, AT_SYMLINK_NOFOLLOW) != 0
        || !identityEqual(located, entries[i].identity)) return false;
  }
  return true;
}
bool readHeld(int fd, std::string& bytes) {
  struct stat before{};
  if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
      || before.st_nlink != 1 || before.st_uid != ::geteuid()
      || (before.st_mode & (S_IWGRP | S_IWOTH)) != 0
      || before.st_size < 0 || before.st_size > 65536) return false;
  bytes.resize(static_cast<std::size_t>(before.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto received = ::read(fd, &bytes[offset], bytes.size() - offset);
    if (received <= 0) return false;
    offset += static_cast<std::size_t>(received);
  }
  char extra = 0;
  if (::read(fd, &extra, 1) != 0) return false;
  struct stat after{};
  return ::fstat(fd, &after) == 0 && identityEqual(before, after)
      && before.st_nlink == after.st_nlink && before.st_size == after.st_size
      && before.st_mode == after.st_mode && before.st_uid == after.st_uid
      && before.st_mtim.tv_sec == after.st_mtim.tv_sec
      && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec
      && before.st_ctim.tv_sec == after.st_ctim.tv_sec
      && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}
std::string base64(const std::string& bytes) {
  constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string output;
  output.reserve(((bytes.size() + 2) / 3) * 4);
  for (std::size_t i = 0; i < bytes.size(); i += 3) {
    const auto a = static_cast<unsigned char>(bytes[i]);
    const auto b = i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0;
    const auto c = i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0;
    output.push_back(alphabet[a >> 2]);
    output.push_back(alphabet[((a & 3) << 4) | (b >> 4)]);
    output.push_back(i + 1 < bytes.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=');
    output.push_back(i + 2 < bytes.size() ? alphabet[c & 63] : '=');
  }
  return output;
}
bool walk(const std::string& root, const std::string* relative,
    const std::string* expected, unsigned holdMs, std::string& rootId,
    std::string& payload) {
  std::vector<std::string> rootParts;
  std::vector<std::string> fileParts;
  if (!safeSegments(root, true, rootParts)
      || (relative && !safeSegments(*relative, false, fileParts))) return false;
  std::vector<Entry> leases;
  leases.reserve(1 + rootParts.size() + fileParts.size());
  Fd slash(::open("/", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  struct stat slashInfo{};
  if (slash.fd < 0 || ::fstat(slash.fd, &slashInfo) != 0) return false;
  leases.emplace_back(std::move(slash), slashInfo, "");
  const auto append = [&](const std::string& part, bool directory) {
    Fd child(beneathOpen(leases.back().lease.fd, part, directory));
    struct stat metadata{};
    if (child.fd < 0 || ::fstat(child.fd, &metadata) != 0
        || ((metadata.st_mode & S_IFMT) != (directory ? S_IFDIR : S_IFREG))
        || metadata.st_dev != slashInfo.st_dev) return false;
    leases.emplace_back(std::move(child), metadata, part);
    return true;
  };
  for (const auto& part : rootParts) if (!append(part, true)) return false;
  rootId = fingerprint(leases.back().identity);
  if (expected && *expected != rootId) return false;
  for (std::size_t i = 0; i < fileParts.size(); ++i)
    if (!append(fileParts[i], i + 1 != fileParts.size())) return false;
  if (!validChain(leases)) return false;
  if (relative && (fileParts.empty() || (leases.back().identity.st_mode & S_IFMT) != S_IFREG))
    return false;
  if (holdMs != 0) {
    std::fputs("READY\n", stderr);
    std::fflush(stderr);
    ::usleep(static_cast<useconds_t>(holdMs) * 1000);
  }
  if (!validChain(leases)) return false;
  if (relative && !readHeld(leases.back().lease.fd, payload)) return false;
  return validChain(leases);
}
}  // namespace

int main(int argc, char** argv) {
  const bool probe = argc == 3 && std::strcmp(argv[1], "--fingerprint") == 0;
  const bool reading = (argc == 5 || argc == 7)
      && std::strcmp(argv[1], "--read") == 0;
  if (!probe && !reading) return 2;
  unsigned holdMs = 0;
  if (reading && argc == 7) {
    if (std::strcmp(argv[5], "--hold-ms") != 0) return 2;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(argv[6], &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 5000) return 2;
    holdMs = static_cast<unsigned>(parsed);
  }
  const std::string relative = reading ? argv[3] : "";
  const std::string expected = reading ? argv[4] : "";
  if (reading && (expected.size() != 32 || expected.find_first_not_of("0123456789abcdef") != std::string::npos)) return 2;
  std::string id;
  std::string contents;
  const bool ok = walk(argv[2], reading ? &relative : nullptr,
      reading ? &expected : nullptr, holdMs, id, contents);
  if (!ok) {
    std::puts("{\"ok\":false}");
    return 4;
  }
  if (probe) std::printf("{\"ok\":true,\"rootId\":\"%s\"}\n", id.c_str());
  else std::printf("{\"ok\":true,\"contained\":true,\"bytes\":%zu,\"payloadBase64\":\"%s\"}\n",
      contents.size(), base64(contents).c_str());
  return 0;
}
