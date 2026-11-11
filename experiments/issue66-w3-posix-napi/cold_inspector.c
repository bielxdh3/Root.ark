// Issue #66: new-process ext4 cold-phase inspector for disposable W3 labs.
// Read-only, nonauthorizing. No path or identifier from this helper can open
// the production RootSession; it does not own the home ancestor independently.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SYS_openat2
#error "Linux openat2 required"
#endif

#define RESOLVE_FLAGS (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)
#define STAGE ".rootark-w3-staged-v1"
#define PREPARE ".rootark-w3-journal-v1"
#define ORIGINAL_ID ".rootark-w3-prepared-id-v2"
#define PUBLISHED ".rootark-w3-committed-v1"
#define COMMIT ".rootark-w3-commit-marker-v1"
#define STAGE_BYTES "STAGED_ROOT_CANARY_V1"
#define PREPARE_BYTES "PREPARED_V1"
#define COMMIT_BYTES "COMMITTED_V1"

typedef struct {
  int exists;
  struct stat stat;
  size_t length;
  char bytes[160];
} observed_leaf;

static int open_child(int parent, const char *name, unsigned flags) {
  struct open_how how = {
    .flags = flags | O_CLOEXEC | O_NOFOLLOW,
    .resolve = RESOLVE_FLAGS,
  };
  return (int)syscall(SYS_openat2, parent, name, &how, sizeof(how));
}

static int same_version(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino != 0 &&
    a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
    a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
    a->st_size == b->st_size &&
    a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
    a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
    a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
    a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int plain_dir(int fd, int protected_mode) {
  struct stat st;
  struct statfs fs;
  return fd >= 0 && fstat(fd, &st) == 0 &&
    S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
    (!protected_mode || (st.st_mode & 0777) == 0700) &&
    fstatfs(fd, &fs) == 0 && fs.f_type == EXT4_SUPER_MAGIC;
}

// Every leaf is opened once for its own bytes, stat'ed before and after the
// exact bounded positional read, then separately checked against its current
// name to reject ordinary same-UID rebinding. This cannot defeat ABA by a
// writer who still owns the parent; only an independent custodian can do so.
static int inspect_leaf(int dir, const char *name, observed_leaf *leaf) {
  memset(leaf, 0, sizeof(*leaf));
  int fd = open_child(dir, name, O_RDONLY | O_NONBLOCK);
  if (fd < 0) return errno == ENOENT;
  struct stat before, after, named;
  int okay = 0;
  int by_name = -1;
  if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_ino == 0 || before.st_uid != geteuid() ||
      before.st_nlink < 1 || before.st_nlink > 2 ||
      before.st_size < 0 || before.st_size >= (off_t)sizeof(leaf->bytes))
    goto done;
  ssize_t count = pread(fd, leaf->bytes, sizeof(leaf->bytes), 0);
  // Native C string operations otherwise treat `COMMITTED_V1\0FOREIGN` as
  // the legitimate COMMIT prefix. All five fixed markers are ASCII-only;
  // embedded NUL is never a valid control-file byte.
  if (count != before.st_size || memchr(leaf->bytes, 0, (size_t)count) != NULL ||
      fstat(fd, &after) != 0 ||
      !same_version(&before, &after)) goto done;
  by_name = open_child(dir, name, O_RDONLY | O_NONBLOCK);
  if (by_name < 0 || fstat(by_name, &named) != 0 ||
      !same_version(&before, &named)) goto done;
  leaf->bytes[(size_t)count] = 0;
  leaf->length = (size_t)count;
  leaf->stat = before;
  leaf->exists = 1;
  okay = 1;
done:
  if (by_name >= 0 && close(by_name) != 0) okay = 0;
  if (close(fd) != 0) okay = 0;
  return okay;
}

static int bytes_equal(const observed_leaf *leaf, const char *expected) {
  size_t expected_length = strlen(expected);
  return leaf->exists && leaf->length == expected_length &&
    memcmp(leaf->bytes, expected, expected_length) == 0;
}

static int exact_leaf(const observed_leaf *leaf, const char *expected) {
  return leaf->stat.st_nlink == 1 && bytes_equal(leaf, expected);
}

static int child_same(int parent, const char *name, int original) {
  struct stat expected, current;
  int opened = open_child(parent, name, O_RDONLY | O_DIRECTORY);
  int okay = opened >= 0 && fstat(original, &expected) == 0 &&
    fstat(opened, &current) == 0 && same_version(&expected, &current);
  if (opened >= 0 && close(opened) != 0) okay = 0;
  return okay;
}

static const char *inspect(int home, const char *fixture_name) {
  int parent = -1, held = -1;
  const char *phase = NULL;
  observed_leaf prepare, identity, stage, published, commit;
  struct stat root_stat, parent_stat, held_stat;
  parent = open_child(home, fixture_name, O_RDONLY | O_DIRECTORY);
  if (!plain_dir(parent, 1) || fstat(parent, &parent_stat) != 0)
    goto done;
  held = open_child(parent, "held", O_RDONLY | O_DIRECTORY);
  if (!plain_dir(held, 1) || fstat(held, &root_stat) != 0 ||
      !inspect_leaf(held, PREPARE, &prepare) ||
      !inspect_leaf(held, ORIGINAL_ID, &identity) ||
      !inspect_leaf(held, STAGE, &stage) ||
      !inspect_leaf(held, PUBLISHED, &published) ||
      !inspect_leaf(held, COMMIT, &commit)) goto done;
  if (!exact_leaf(&prepare, PREPARE_BYTES) || !identity.exists ||
      identity.stat.st_nlink != 1 ||
      (stage.exists && !bytes_equal(&stage, STAGE_BYTES)) ||
      (published.exists && !bytes_equal(&published, STAGE_BYTES)) ||
      (commit.exists && !exact_leaf(&commit, COMMIT_BYTES))) goto done;

  // The PREPARE sidecar was originally fsynced by the native writer. It pins
  // original directory and stage IDs for cold *observations*, not signatures.
  // Reject syntax aliases and trailing bytes by exact re-encoding.
  uintmax_t root_dev, root_ino, file_dev, file_ino;
  char canonical[160];
  int consumed = 0;
  if (sscanf(identity.bytes, "PREPARED_ID_V2:%jx:%jx:%jx:%jx\n%n",
             &root_dev, &root_ino, &file_dev, &file_ino, &consumed) != 4 ||
      consumed == 0 ||
      snprintf(canonical, sizeof(canonical),
        "PREPARED_ID_V2:%jx:%jx:%jx:%jx\n",
        root_dev, root_ino, file_dev, file_ino) < 1 ||
      identity.length != strlen(canonical) ||
      memcmp(identity.bytes, canonical, identity.length) != 0 ||
      root_dev != (uintmax_t)root_stat.st_dev ||
      root_ino != (uintmax_t)root_stat.st_ino ||
      file_dev != (uintmax_t)root_stat.st_dev || file_ino == 0)
    goto done;

  if (stage.exists &&
      (stage.stat.st_dev != (dev_t)file_dev ||
       stage.stat.st_ino != (ino_t)file_ino || stage.stat.st_nlink != 1))
    goto done;
  if (published.exists &&
      (published.stat.st_dev != (dev_t)file_dev ||
       published.stat.st_ino != (ino_t)file_ino ||
       published.stat.st_nlink != 1 || stage.exists))
    goto done;

  if (!published.exists && !commit.exists) phase = "PREPARED_ONLY";
  else if (published.exists && !commit.exists) phase = "PUBLISHED_NO_COMMIT";
  else if (published.exists && commit.exists) phase = "COMMIT_OBSERVED";

  if (fstat(held, &held_stat) != 0 ||
      !same_version(&root_stat, &held_stat) ||
      !child_same(parent, "held", held) ||
      !child_same(home, fixture_name, parent)) phase = NULL;
done:
  if (held >= 0 && close(held) != 0) phase = NULL;
  if (parent >= 0 && close(parent) != 0) phase = NULL;
  return phase;
}

int main(int argc, char **argv) {
  const char *flag = getenv("ROOTARK_ISSUE66_W3_COLD_INSPECT_LAB");
  if (!flag || strcmp(flag, "1") != 0 || argc != 2 ||
      strlen(argv[1]) != 32) goto denied;
  for (size_t i = 0; i < 32; ++i)
    if (!((argv[1][i] >= '0' && argv[1][i] <= '9') ||
          (argv[1][i] >= 'a' && argv[1][i] <= 'f'))) goto denied;

  struct passwd pw_storage, *pw = NULL;
  char password_buffer[16384];
  if (getpwuid_r(geteuid(), &pw_storage, password_buffer,
                 sizeof(password_buffer), &pw) != 0 ||
      !pw || !pw->pw_dir || pw->pw_dir[0] != '/' || pw->pw_dir[1] == 0)
    goto denied;
  int system_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (system_root < 0) goto denied;
  int home = open_child(system_root, pw->pw_dir + 1, O_RDONLY | O_DIRECTORY);
  (void)close(system_root);
  if (!plain_dir(home, 0)) {
    if (home >= 0) (void)close(home);
    goto denied;
  }
  char fixture_name[80];
  int n = snprintf(fixture_name, sizeof(fixture_name),
                   ".rootark-w3-napi-%s", argv[1]);
  const char *phase = n > 0 && (size_t)n < sizeof(fixture_name)
    ? inspect(home, fixture_name) : NULL;
  if (close(home) != 0) phase = NULL;
  if (!phase) goto denied;
  printf("ROOTARK_W3_COLD_INSPECT phase=%s authority=LAB_ONLY_NO_GO\n", phase);
  return 0;
denied:
  fputs("ROOTARK_W3_COLD_INSPECT_REJECTED\n", stderr);
  return 41;
}
