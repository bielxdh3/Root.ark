// PR298 / Issue67 POSIX EXT4 LAB ONLY. Not called by production.
// Physical second-process name swap versus retained source FD+directory FD.
// A syscall primitive is NOT RootSession/owner-A custody or release authority.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
struct Fd {
  int fd = -1;
  explicit Fd(int n = -1) : fd(n) {}
  ~Fd() { if (fd >= 0) ::close(fd); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
};
[[noreturn]] void die(const char* stage) {
  std::fprintf(stderr, "NATIVE_FD_LAB_FAIL %s errno=%d\n", stage, errno);
  std::exit(1);
}
void require(bool yes, const char* stage) {
  if (!yes) die(stage);
}
bool sameInode(const struct stat& a, const struct stat& b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
std::string bytes(int fd) {
  std::string data;
  char buf[256];
  for (;;) {
    const auto n = ::read(fd, buf, sizeof(buf));
    if (n < 0) die("read");
    if (n == 0) break;
    data.append(buf, static_cast<size_t>(n));
    if (data.size() > 1024) die("oversize");
  }
  return data;
}
void put(int dir, const char* name, const char* content) {
  Fd fd(::openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  require(fd.fd >= 0, "new-test-file");
  require(::write(fd.fd, content, std::strlen(content)) ==
    static_cast<ssize_t>(std::strlen(content)), "write");
  require(::fsync(fd.fd) == 0, "fsync-file");
}
bool linkHeldNoReplace(int src, int dir, const char* newName) {
  // Linux native inode-reference link. AT_EMPTY_PATH normally requires
  // CAP_DAC_READ_SEARCH. Unprivileged fallback is procfs's kernel-owned
  // descriptor symlink followed by linkat, NOT a mutable source pathname.
  if (::linkat(src, "", dir, newName, AT_EMPTY_PATH) == 0) return true;
  if (errno != ENOENT && errno != EPERM && errno != EACCES && errno != EINVAL)
    return false;
  char procfd[64];
  std::snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", src);
  return ::linkat(AT_FDCWD, procfd, dir, newName, AT_SYMLINK_FOLLOW) == 0;
}
} // namespace

int main() {
  const char* base = std::getenv("TMPDIR");
  if (!base || base[0] != '/') die("real-ext4-TMPDIR-required");
  std::string templatePath = std::string(base) + "/rootark67-w21-native-fd-XXXXXX";
  require(::mkdtemp(templatePath.data()) != nullptr, "mkdtemp");
  Fd directory(::open(templatePath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  require(directory.fd >= 0, "directory");
  struct stat fsinfo{};
  require(::fstat(directory.fd, &fsinfo) == 0 && S_ISDIR(fsinfo.st_mode), "dir-fstat");
  put(directory.fd, "source", "ORIGINAL VERIFIED BYTES");
  Fd source(::openat(directory.fd, "source", O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
  require(source.fd >= 0, "source-fd");
  struct stat before{};
  require(::fstat(source.fd, &before) == 0 && S_ISREG(before.st_mode)
    && before.st_nlink == 1 && before.st_dev == fsinfo.st_dev, "source-identity");

  int notify[2], ack[2], release[2];
  require(::pipe(notify) == 0 && ::pipe(ack) == 0 && ::pipe(release) == 0, "pipe");
  const pid_t child = ::fork();
  require(child >= 0, "fork");
  if (child == 0) {
    ::close(notify[1]); ::close(ack[0]); ::close(release[1]);
    char start;
    if (::read(notify[0], &start, 1) != 1) _exit(10);
    if (::renameat(directory.fd, "source", directory.fd, "source.retained") != 0) _exit(11);
    Fd foreign(::openat(directory.fd, "source",
      O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (foreign.fd < 0) _exit(12);
    const char* attackerBytes = "FOREIGN SECOND-PROCESS BYTES";
    if (::write(foreign.fd, attackerBytes, std::strlen(attackerBytes)) !=
        static_cast<ssize_t>(std::strlen(attackerBytes))) _exit(13);
    if (::fsync(foreign.fd) != 0 || ::write(ack[1], "1", 1) != 1) _exit(14);
    char done;
    if (::read(release[0], &done, 1) != 1) _exit(15);
    _exit(0);
  }
  ::close(notify[0]); ::close(ack[1]); ::close(release[0]);
  require(child != ::getpid() && ::write(notify[1], "1", 1) == 1, "child-pid");
  char ready;
  require(::read(ack[0], &ready, 1) == 1, "child-swapped-ack");
  struct stat nowNamed{}, retained{};
  require(::fstatat(directory.fd, "source", &nowNamed, AT_SYMLINK_NOFOLLOW) == 0
    && ::fstatat(directory.fd, "source.retained", &retained, AT_SYMLINK_NOFOLLOW) == 0,
    "source-swapped");
  require(!sameInode(before, nowNamed) && sameInode(before, retained),
    "swapped-physical-proof");
  // No mutable old name is used for the source: only source.fd and dir.fd.
  require(linkHeldNoReplace(source.fd, directory.fd, "published"), "link-held-no-replace");
  struct stat published{};
  require(::fstatat(directory.fd, "published", &published, AT_SYMLINK_NOFOLLOW) == 0
    && sameInode(published, before) && !sameInode(published, nowNamed),
    "published-must-be-original-held-inode");
  Fd publishedFd(::openat(directory.fd, "published", O_RDONLY | O_NOFOLLOW));
  require(publishedFd.fd >= 0 && bytes(publishedFd.fd) == "ORIGINAL VERIFIED BYTES",
    "published-bytes");
  Fd foreignFd(::openat(directory.fd, "source", O_RDONLY | O_NOFOLLOW));
  require(foreignFd.fd >= 0 && bytes(foreignFd.fd) == "FOREIGN SECOND-PROCESS BYTES",
    "foreign-preserved");
  // Destination exists: a second attempt must not clobber it.
  errno = 0;
  require(!linkHeldNoReplace(source.fd, directory.fd, "published") && errno == EEXIST,
    "no-replace-EEXIST");
  require(::fsync(directory.fd) == 0, "fsync-dir");
  require(::write(release[1], "1", 1) == 1, "release-attacker");
  int status;
  require(::waitpid(child, &status, 0) == child && WIFEXITED(status)
    && WEXITSTATUS(status) == 0, "attacker-exit");
  std::puts("POSIX_NATIVE_FD_LINK_LAB_PASS secondProcess=true originalHeld=true noReplace=true foreignPreserved=true");
  // Only the lab's own synthetic files are removed, after child exits.
  const char* names[] = {"source", "source.retained", "published"};
  for (const char* name : names) require(::unlinkat(directory.fd, name, 0) == 0, "lab-cleanup");
  require(::rmdir(templatePath.c_str()) == 0, "lab-rmdir");
}
