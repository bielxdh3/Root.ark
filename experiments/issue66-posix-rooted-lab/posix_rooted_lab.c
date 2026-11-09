// Issue #66 W3. Linux-only opt-in physical test, NOT a trusted root/session.
// Compile to an outside-checkout disposable location. Retain all test fixtures.
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
#error "Linux openat2 syscall required"
#endif
#ifndef SYS_renameat2
#error "Linux renameat2 syscall required"
#endif

#define STRICT_RESOLVE (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)
#define BULK_COUNT 16385u
#define ROOT_PREFIX "rootark-w3-posix-"
#define UTF8_FILE "caf\303\251-\344\270\255-\360\237\230\200.bin"
#define UTF8_SUFFIX "-\303\251-\344\270\255.dat"
#define OWNED_TEXT "ORIGINAL_MARKER_CONTENT"
#define FOREIGN_TEXT "FOREIGN_MARKER_CONTENT"

static void reject(void) {
  static const char error[] = "ROOTARK_POSIX_REJECTED\n";
  ssize_t ignored = write(STDERR_FILENO, error, sizeof(error) - 1);
  (void)ignored;
  _exit(41);
}

static void require(int condition) {
  if (!condition) reject();
}

static int open_beneath(int parent, const char *name, uint64_t flags, uint64_t mode) {
  struct open_how how = {
    .flags = flags | O_CLOEXEC | O_NOFOLLOW,
    .mode = mode,
    .resolve = STRICT_RESOLVE,
  };
  // No openat(), open(), realpath(), or pathname fallback on syscall failure.
  int fd = (int)syscall(SYS_openat2, parent, name, &how, sizeof(how));
  if (fd < 0) reject();
  return fd;
}

static int rename_noreplace(int parent, const char *from, const char *to) {
  return (int)syscall(SYS_renameat2, parent, from, parent, to, RENAME_NOREPLACE);
}

static void move_noreplace(int parent, const char *from, const char *to) {
  if (rename_noreplace(parent, from, to) != 0) reject();
  if (fsync(parent) != 0) reject();
}

static void verify_directory(int fd) {
  struct stat st;
  require(fstat(fd, &st) == 0 && S_ISDIR(st.st_mode));
}

static void verify_ext4(int fd) {
  struct statfs stat;
  require(fstatfs(fd, &stat) == 0 && (unsigned long)stat.f_type == EXT4_SUPER_MAGIC);
}

static int same_object(int left, int right) {
  struct stat a, b;
  require(fstat(left, &a) == 0 && fstat(right, &b) == 0);
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static void verify_leaf(const char *name) {
  size_t prefix = strlen(ROOT_PREFIX);
  size_t length = strlen(name);
  require(length >= prefix + 6 && length <= 100 &&
          strncmp(name, ROOT_PREFIX, prefix) == 0);
  for (size_t i = prefix; i < length; ++i) {
    unsigned char c = (unsigned char)name[i];
    require((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-');
  }
}

static uint64_t hash_buffer(const unsigned char *bytes, size_t length) {
  uint64_t h = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < length; ++i) {
    h ^= bytes[i];
    h *= UINT64_C(1099511628211);
  }
  return h;
}

static uint64_t hash_file(int parent, const char *leaf) {
  int fd = open_beneath(parent, leaf, O_RDONLY, 0);
  unsigned char bytes[4096];
  uint64_t h = UINT64_C(14695981039346656037);
  size_t total = 0;
  for (;;) {
    ssize_t n = read(fd, bytes, sizeof(bytes));
    if (n < 0) reject();
    if (n == 0) break;
    total += (size_t)n;
    require(total <= sizeof(bytes));
    for (ssize_t i = 0; i < n; ++i) {
      h ^= bytes[i];
      h *= UINT64_C(1099511628211);
    }
  }
  require(close(fd) == 0);
  return h;
}

static void write_file(int parent, const char *leaf, const char *value, int sync) {
  int fd = open_beneath(parent, leaf, O_WRONLY | O_CREAT | O_EXCL, 0600);
  size_t length = strlen(value), written = 0;
  while (written < length) {
    ssize_t n = write(fd, value + written, length - written);
    if (n <= 0) reject();
    written += (size_t)n;
  }
  if (sync && fsync(fd) != 0) reject();
  require(close(fd) == 0);
}

static void verify_empty_directory(int root) {
  int copy = dup(root);
  if (copy < 0) reject();
  DIR *d = fdopendir(copy);
  if (!d) reject();
  errno = 0;
  for (struct dirent *e; (e = readdir(d)) != NULL;) {
    if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
      reject();
    errno = 0;
  }
  require(errno == 0 && closedir(d) == 0);
}

static void assert_no_symlink_escape(int dirfd) {
  require(symlinkat("owned.marker", dirfd, "symlink-alias") == 0);
  struct open_how how = {
    .flags = O_RDONLY | O_CLOEXEC,
    .resolve = STRICT_RESOLVE,
  };
  errno = 0;
  int bad = (int)syscall(SYS_openat2, dirfd, "symlink-alias", &how, sizeof(how));
  require(bad == -1 && errno == ELOOP);
  errno = 0;
  bad = (int)syscall(SYS_openat2, dirfd, "../escape", &how, sizeof(how));
  require(bad == -1 && errno == EXDEV);
}

static void run_core(int scratchfd) {
  require(mkdirat(scratchfd, "held", 0700) == 0);
  int heldfd = open_beneath(scratchfd, "held", O_RDONLY | O_DIRECTORY, 0);
  DIR *held = fdopendir(heldfd); // dirfd(held) IS heldfd, never a new path open.
  if (!held) reject();
  const int pinned = dirfd(held);
  require(pinned == heldfd);
  verify_directory(pinned);
  write_file(pinned, "owned.marker", OWNED_TEXT, 1);
  write_file(pinned, UTF8_FILE, "UNICODE_BYTES", 1);
  assert_no_symlink_escape(pinned);
  require(fsync(pinned) == 0 && fsync(scratchfd) == 0);

  // Adversarial namespace sequence: A (held original) -> B (replacement)
  // -> A (restored original). All names are relative to the scratch dirfd.
  move_noreplace(scratchfd, "held", "parked");
  require(mkdirat(scratchfd, "held", 0700) == 0);
  int foreign = open_beneath(scratchfd, "held", O_RDONLY | O_DIRECTORY, 0);
  require(!same_object(pinned, foreign));
  write_file(foreign, "owned.marker", FOREIGN_TEXT, 1);
  write_file(foreign, "foreign.marker", FOREIGN_TEXT, 1);
  require(fsync(foreign) == 0 && fsync(scratchfd) == 0);

  const uint64_t originalHash = hash_buffer((const unsigned char *)OWNED_TEXT, strlen(OWNED_TEXT));
  const uint64_t foreignHash = hash_buffer((const unsigned char *)FOREIGN_TEXT, strlen(FOREIGN_TEXT));
  require(hash_file(pinned, "owned.marker") == originalHash);
  require(hash_file(foreign, "owned.marker") == foreignHash);
  int moved = open_beneath(scratchfd, "parked", O_RDONLY | O_DIRECTORY, 0);
  require(same_object(pinned, moved));
  require(close(moved) == 0);

  // Collision must fail WITHOUT overwriting the replacement's marker.
  errno = 0;
  require(rename_noreplace(scratchfd, "parked", "held") == -1 && errno == EEXIST);
  require(hash_file(foreign, "foreign.marker") == foreignHash);
  move_noreplace(scratchfd, "held", "foreign-parked");
  move_noreplace(scratchfd, "parked", "held");
  int restored = open_beneath(scratchfd, "held", O_RDONLY | O_DIRECTORY, 0);
  require(same_object(pinned, restored) && !same_object(foreign, restored));
  require(hash_file(pinned, "owned.marker") == originalHash);
  require(hash_file(restored, UTF8_FILE) ==
          hash_buffer((const unsigned char *)"UNICODE_BYTES", strlen("UNICODE_BYTES")));
  require(hash_file(foreign, "foreign.marker") == foreignHash);

  // Enumerate the exact original held descriptor after two namespace changes.
  rewinddir(held);
  int foundOwned = 0, foundUnicode = 0, foundLink = 0, count = 0;
  errno = 0;
  for (struct dirent *e; (e = readdir(held)) != NULL;) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
    ++count;
    foundOwned += strcmp(e->d_name, "owned.marker") == 0;
    foundUnicode += strcmp(e->d_name, UTF8_FILE) == 0;
    foundLink += strcmp(e->d_name, "symlink-alias") == 0;
    errno = 0;
  }
  require(errno == 0 && count == 3 && foundOwned == 1 &&
          foundUnicode == 1 && foundLink == 1);

  // The only deletion is this just-created, fixed-name disposable file.
  write_file(pinned, "disposable.delete", "OWNED", 1);
  require(unlinkat(pinned, "disposable.delete", 0) == 0);
  struct open_how how = {.flags = O_RDONLY | O_CLOEXEC, .resolve = STRICT_RESOLVE};
  errno = 0;
  require(syscall(SYS_openat2, pinned, "disposable.delete", &how, sizeof(how)) == -1 &&
          errno == ENOENT);
  require(fsync(pinned) == 0 && fsync(scratchfd) == 0);
  require(close(restored) == 0 && close(foreign) == 0 && closedir(held) == 0);
  puts("ROOTARK_POSIX_V1 stage=CORE fs=EXT4 parent=INDEPENDENT_FD openat2=STRICT aba=PASS noReplace=PASS marker=PASS unicode=PASS unlink=PASS fsync=PASS");
}

static void run_bulk(int scratchfd) {
  require(mkdirat(scratchfd, "bulk", 0700) == 0);
  int fd = open_beneath(scratchfd, "bulk", O_RDONLY | O_DIRECTORY, 0);
  DIR *d = fdopendir(fd);
  if (!d) reject();
  require(dirfd(d) == fd);
  for (size_t i = 0; i < BULK_COUNT; ++i) {
    char leaf[80];
    int length = snprintf(leaf, sizeof(leaf), "entry-%05zu" UTF8_SUFFIX, i);
    require(length > 0 && (size_t)length < sizeof(leaf));
    int file = open_beneath(dirfd(d), leaf, O_WRONLY | O_CREAT | O_EXCL, 0600);
    require(write(file, "x", 1) == 1 && close(file) == 0);
  }
  require(fsync(dirfd(d)) == 0 && fsync(scratchfd) == 0);
  // Streaming; no array of 16,385 names; native DIR owns the SAME fd.
  rewinddir(d);
  size_t count = 0;
  errno = 0;
  for (struct dirent *e; (e = readdir(d)) != NULL;) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
    require(strncmp(e->d_name, "entry-", 6) == 0);
    size_t size = strlen(e->d_name);
    const size_t suffix = strlen(UTF8_SUFFIX);
    require(size > suffix && strcmp(e->d_name + size - suffix, UTF8_SUFFIX) == 0);
    ++count;
    require(count <= BULK_COUNT);
    errno = 0;
  }
  require(errno == 0 && count == BULK_COUNT && closedir(d) == 0);
  puts("ROOTARK_POSIX_V1 stage=BULK fs=EXT4 entries=16385 enumeration=SAME_FD unicode=PASS fsync=PASS");
}

int main(int argc, char **argv) {
  if (argc != 4 || getenv("ROOTARK_ISSUE66_POSIX_LAB") == NULL ||
      strcmp(getenv("ROOTARK_ISSUE66_POSIX_LAB"), "1") != 0) reject();
  const char *home = getenv("HOME");
  require(home && argv[1][0] == '/' && strcmp(home, argv[1]) == 0);
  require(strcmp(argv[3], "core") == 0 || strcmp(argv[3], "bulk") == 0);
  verify_leaf(argv[2]);
  // Trust boundary: / is a kernel namespace anchor. Traversal into HOME is
  // restricted, but is NOT an independently attested application trust root.
  int namespacefd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (namespacefd < 0) reject();
  int parent = open_beneath(namespacefd, argv[1] + 1, O_RDONLY | O_DIRECTORY, 0);
  verify_directory(parent);
  verify_ext4(parent);
  int scratch = open_beneath(parent, argv[2], O_RDONLY | O_DIRECTORY, 0);
  verify_directory(scratch);
  verify_ext4(scratch);
  verify_empty_directory(scratch);
  if (strcmp(argv[3], "core") == 0) run_core(scratch);
  else run_bulk(scratch);
  require(close(scratch) == 0 && close(parent) == 0 && close(namespacefd) == 0);
  return 0;
}
