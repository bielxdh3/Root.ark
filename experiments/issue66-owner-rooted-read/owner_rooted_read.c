// Read-only Linux ext4 experiment: root-owned sticky parent prevents a
// different unprivileged principal from replacing a test-owned leaf.
// This is NOT authenticated RootSession nor a durable writable recovery.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_openat2
#error "Linux openat2 required"
#endif

#define STRICT_RESOLVE (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)
#define OWNER_PREFIX "rootark-issue66-owner-"
#define MARKER_NAME "caf\303\251-\344\270\255-\360\237\230\200.txt"
#define MARKER_BYTES "TRUSTED_ROOT_CANARY_V1\n"

static void reject(void) {
  fputs("ROOTARK_OWNER_REJECTED\n", stderr);
  exit(41);
}

static void require(int success) {
  if (!success) reject();
}

static int open_strict(int parent, const char *name, uint64_t flags) {
  struct open_how how = {
    .flags = flags | O_CLOEXEC | O_NOFOLLOW,
    .resolve = STRICT_RESOLVE,
  };
  return (int)syscall(SYS_openat2, parent, name, &how, sizeof(how));
}

static int valid_leaf(const char *leaf) {
  const size_t prefix = strlen(OWNER_PREFIX);
  if (!leaf || strlen(leaf) != prefix + 16 || strncmp(leaf, OWNER_PREFIX, prefix) != 0)
    return 0;
  for (size_t i = prefix; i < prefix + 16; ++i) {
    if (!((leaf[i] >= '0' && leaf[i] <= '9') || (leaf[i] >= 'a' && leaf[i] <= 'f')))
      return 0;
  }
  return 1;
}

static struct stat require_dir(int fd, uid_t owner, mode_t mode) {
  struct stat info;
  require(fd >= 0 && fstat(fd, &info) == 0 && S_ISDIR(info.st_mode));
  require(info.st_uid == owner && (info.st_mode & 01777) == mode && info.st_ino != 0);
  return info;
}

static void verify_one_utf8_entry(int directory) {
  int copy = dup(directory);
  require(copy >= 0);
  DIR *listing = fdopendir(copy);
  require(listing != NULL);
  size_t count = 0;
  errno = 0;
  for (struct dirent *entry; (entry = readdir(listing)) != NULL;) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      errno = 0;
      continue;
    }
    require(strcmp(entry->d_name, MARKER_NAME) == 0 && ++count <= 1);
    errno = 0;
  }
  require(errno == 0 && count == 1 && closedir(listing) == 0);
}

static void verify_marker(int directory, dev_t device) {
  int fd = open_strict(directory, MARKER_NAME, O_RDONLY);
  require(fd >= 0);
  struct stat info;
  require(fstat(fd, &info) == 0 && S_ISREG(info.st_mode)
    && info.st_uid == 0 && (info.st_mode & 0777) == 0444
    && info.st_dev == device && info.st_nlink == 1);
  char buffer[sizeof(MARKER_BYTES) + 16];
  size_t received = 0;
  for (;;) {
    require(received < sizeof(buffer));
    ssize_t n = read(fd, buffer + received, sizeof(buffer) - received);
    if (n < 0 && errno == EINTR) continue;
    require(n >= 0);
    if (n == 0) break;
    received += (size_t)n;
  }
  require(received == strlen(MARKER_BYTES)
    && memcmp(buffer, MARKER_BYTES, received) == 0);
  require(close(fd) == 0);
}

int main(int argc, char **argv) {
  require(argc == 2 && valid_leaf(argv[1]));
  // Open parent strictly beneath the local filesystem root: neither a JS
  // pathname nor a mutable same-UID HOME can choose the trust anchor.
  int root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  require(root >= 0);
  int parent = open_strict(root, "var/tmp", O_RDONLY | O_DIRECTORY);
  require(close(root) == 0);
  struct stat parent_info = require_dir(parent, 0, 01777);
  struct statfs filesystem;
  require(fstatfs(parent, &filesystem) == 0 && filesystem.f_type == EXT4_SUPER_MAGIC);
  int owned = open_strict(parent, argv[1], O_RDONLY | O_DIRECTORY);
  struct stat owned_info = require_dir(owned, 0, 0555);
  require(owned_info.st_dev == parent_info.st_dev);
  verify_one_utf8_entry(owned);
  verify_marker(owned, owned_info.st_dev);
  struct stat held_after;
  require(fstat(owned, &held_after) == 0 && held_after.st_dev == owned_info.st_dev
    && held_after.st_ino == owned_info.st_ino && held_after.st_uid == 0
    && (held_after.st_mode & 0777) == 0555);
  require(close(owned) == 0 && close(parent) == 0);
  puts("ROOTARK_OWNER_V1 fs=EXT4 parent=ROOT_STICKY root=ROOT_OWNED marker=READ_ONLY fd=PINNED");
  return 0;
}
