// Linux/ext4 LAB ONLY. No production caller or cleanup protocol uses this binary.
// Node passes already-open regular source and destination directory as FDs 3/4.
// The source pathname is deliberately unavailable to this process.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr int kSource = 3;
constexpr int kDestinationDir = 4;

int failure(const char* action, int code, int error) {
  std::fprintf(stderr, "ERROR action=%s errno=%d message=%s published=%d\n",
               action, error, std::strerror(error), code == 85 ? 1 : 0);
  return code;
}

bool safeName(const std::string& name) {
  if (name.empty() || name.size() > 255 || name == "." || name == "..") return false;
  for (char ch : name) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') continue;
    return false;
  }
  return true;
}

bool waitForGate() {
  if (std::fputs("READY\n", stdout) == EOF || std::fflush(stdout) != 0) return false;
  char byte = 0;
  ssize_t count;
  do { count = read(STDIN_FILENO, &byte, 1); } while (count < 0 && errno == EINTR);
  return count == 1 && byte == 'G';
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2 || !safeName(argv[1])) {
    std::fputs("ERROR invalid destination basename\n", stderr);
    return 2;
  }
  struct stat source{};
  struct stat destination{};
  if (fstat(kSource, &source) != 0) return failure("source-fstat", 20, errno);
  if (fstat(kDestinationDir, &destination) != 0) return failure("dir-fstat", 20, errno);
  if (!S_ISREG(source.st_mode) || !S_ISDIR(destination.st_mode) ||
      source.st_dev != destination.st_dev) {
    std::fputs("ERROR source must be regular and on same filesystem as held directory\n", stderr);
    return 20;
  }
  // A durable source is required before the no-replace directory entry exists.
  if (fsync(kSource) != 0) return failure("source-fsync", 21, errno);
  if (!waitForGate()) {
    std::fputs("ERROR gate not released\n", stderr);
    return 22;
  }

  // AT_EMPTY_PATH binds the link to the retained inode, even if an adversary
  // moves/replaces its former pathname. On Linux this often needs
  // CAP_DAC_READ_SEARCH for an already-linked file (unlike O_TMPFILE).
  const char* method = "AT_EMPTY_PATH";
  int emptyPathErrno = 0;
  if (linkat(kSource, "", kDestinationDir, argv[1], AT_EMPTY_PATH) != 0) {
    const int firstError = errno;
    emptyPathErrno = firstError;
    if (firstError == EEXIST) return failure("no-replace", 17, firstError);
    if (firstError != EPERM && firstError != EACCES && firstError != ENOENT &&
        firstError != EINVAL && firstError != EOPNOTSUPP) {
      return failure("linkat-empty-path", 23, firstError);
    }
    // Linux procfs magic link names the same open file DESCRIPTION, not the
    // mutable source pathname. AT_SYMLINK_FOLLOW resolves the kernel FD link.
    // This compatibility route requires trusted procfs mounted at /proc.
    method = "PROC_SELF_FD";
    if (linkat(AT_FDCWD, "/proc/self/fd/3", kDestinationDir, argv[1],
               AT_SYMLINK_FOLLOW) != 0) {
      const int secondError = errno;
      return failure(secondError == EEXIST ? "no-replace" : "linkat-proc-fd",
                     secondError == EEXIST ? 17 : 24, secondError);
    }
  }

  // The directory entry exists now, but a failed checkpoint must be returned
  // as 'published, durability unknown'. NEVER unlink by a now-uncertain name.
  if (fsync(kDestinationDir) != 0) return failure("destination-dir-fsync", 85, errno);
  std::printf("PUBLISHED mode=%s at_empty_path_errno=%d source_dev=%llu source_ino=%llu\n",
              method, emptyPathErrno,
              static_cast<unsigned long long>(source.st_dev),
              static_cast<unsigned long long>(source.st_ino));
  return 0;
}
