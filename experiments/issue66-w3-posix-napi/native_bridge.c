// Issue #66 W3: throwaway Linux Node 22 N-API bridge, NOT RootSession.
// No JS-provided path, fd, object, or flag can become native root authority.
#define _GNU_SOURCE
#include <node_api.h>
#include <dirent.h>
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
#ifndef SYS_renameat2
#error "Linux renameat2 required"
#endif
#ifndef SYS_getrandom
#error "Linux getrandom required"
#endif

#define RESOLVE_FLAGS (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)
#define UNICODE_LEAF "caf\303\251-\344\270\255-\360\237\230\200.bin"
#define TRUSTED_BYTES "TRUSTED_ORIGINAL"
#define FOREIGN_BYTES "FOREIGN_ORIGINAL"
#define STAGE_PROOF ".rootark-w3-staged-v1"
#define JOURNAL_PROOF ".rootark-w3-journal-v1"
#define IDENTITY_PROOF ".rootark-w3-prepared-id-v2"
#define PUBLISHED_PROOF ".rootark-w3-committed-v1"
#define COMMIT_PROOF ".rootark-w3-commit-marker-v1"
#define STAGE_PAYLOAD "STAGED_ROOT_CANARY_V1"
#define JOURNAL_PAYLOAD "PREPARED_V1"
#define COMMIT_PAYLOAD "COMMITTED_V1"
#define ANCESTOR_LIMIT 32

typedef struct {
  int fd;
  dev_t dev;
  ino_t ino;
  uid_t uid;
  mode_t mode; // initial permissions and special bits, never a grant to write
  char name[256]; // empty only for the retained '/' anchor
} retained_ancestor;

typedef struct {
  int active;
  int parentfd; // borrowed from the last retained_ancestor entry
  size_t ancestor_count;
  retained_ancestor ancestors[ANCESTOR_LIMIT];
  int staged_fd; // original exclusive inode, retained until session close
  int journal_fd; // original exclusive PREPARE inode, retained through COMMIT
  struct stat journal_initial; // version pinned after original PREPARE fsync
  int journal_version_pinned;
  int identity_fd; // PREPARE binds the native held dirfd and stage inode IDs
  struct stat identity_initial;
  char identity_payload[160]; // persisted bytes, NOT an independent signature
  int identity_version_pinned;
  int txn_anonymous; // opt-in O_TMPFILE stage, never a product recovery mode
  DIR *held;
  int phase;
  int stream_active;
  int stream_done;
  int seeded;
  int raw_seeded;
  int txn_phase; // 0=empty, 1=prepared, 2=published, 3=indeterminate
  char token[33];
} lab_session;

// The callback descriptor, rather than the N-API instance-data slot, owns
// this addon's private per-environment session. The slot can be overwritten
// by another set_instance_data call and must never carry our authority.
static lab_session *session_for(napi_env env, napi_callback_info info) {
  void *private_data = NULL;
  size_t argc = 0;
  if (napi_get_cb_info(env, info, &argc, NULL, NULL, &private_data) != napi_ok)
    return NULL;
  return (lab_session *)private_data;
}

static napi_value fail(napi_env env, const char *message) {
  (void)napi_throw_error(env, NULL, message);
  return NULL;
}

static napi_value result_text(napi_env env, const char *value) {
  napi_value out;
  if (napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &out) != napi_ok)
    return fail(env, "NATIVE_API_FAILED");
  return out;
}

static int args_of(napi_env env, napi_callback_info info, size_t required,
                   napi_value *argv) {
  size_t argc = 3;
  return napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok &&
         argc == required;
}

static int fd_openat2(int base, const char *leaf, uint64_t access, uint64_t mode) {
  struct open_how how = {
    .flags = access | O_CLOEXEC | O_NOFOLLOW,
    .mode = mode,
    .resolve = RESOLVE_FLAGS,
  };
  return (int)syscall(SYS_openat2, base, leaf, &how, sizeof(how));
}

static int object_is(int a, int b) {
  struct stat x, y;
  return a >= 0 && b >= 0 && fstat(a, &x) == 0 && fstat(b, &y) == 0 &&
         x.st_dev == y.st_dev && x.st_ino == y.st_ino;
}

static int plain_directory(int fd, int mode_protected);

static int retain_child_directory(lab_session *session, int base, const char *name) {
  size_t length = strlen(name);
  if (session->ancestor_count >= ANCESTOR_LIMIT || length < 1 || length > 255 ||
      strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return -1;
  int child = fd_openat2(base, name, O_RDONLY | O_DIRECTORY, 0);
  if (child < 0) return -1;
  struct stat st;
  if (fstat(child, &st) != 0 || !S_ISDIR(st.st_mode)) {
    (void)close(child);
    return -1;
  }
  retained_ancestor *entry = &session->ancestors[session->ancestor_count++];
  entry->fd = child;
  entry->dev = st.st_dev;
  entry->ino = st.st_ino;
  entry->uid = st.st_uid;
  entry->mode = st.st_mode & 07777;
  memcpy(entry->name, name, length + 1);
  return child;
}

// Live observation only. These opened ancestors belong to this process and
// cannot prove same-UID exclusion, ABA resistance, or cold-path authority.
static int still_original_ancestors(lab_session *session) {
  if (!session || !session->active || session->ancestor_count < 3 ||
      !session->held || session->parentfd !=
        session->ancestors[session->ancestor_count - 1].fd) return 0;
  for (size_t i = 0; i < session->ancestor_count; ++i) {
    retained_ancestor *current = &session->ancestors[i];
    struct stat st;
    if (current->fd < 0 || fstat(current->fd, &st) != 0 ||
        !S_ISDIR(st.st_mode) || st.st_dev != current->dev ||
        st.st_ino != current->ino || st.st_uid != current->uid ||
        (st.st_mode & 07777) != current->mode) return 0;
    if (i == 0) continue; // '/' is an untrusted process namespace anchor.
    int reopened = fd_openat2(session->ancestors[i - 1].fd,
                              current->name, O_RDONLY | O_DIRECTORY, 0);
    int same = reopened >= 0 && object_is(reopened, current->fd);
    if (reopened >= 0 && close(reopened) != 0) same = 0;
    if (!same) return 0;
  }
  // Same inode identity alone is insufficient: another same-UID process may
  // chmod the private 0700 parent to 0777 without renaming any component.
  if (!plain_directory(session->parentfd, 1)) return 0;
  int held = dirfd(session->held);
  int reopened = fd_openat2(session->parentfd, "held", O_RDONLY | O_DIRECTORY, 0);
  int same = reopened >= 0 && object_is(reopened, held) &&
             plain_directory(held, 1);
  if (reopened >= 0 && close(reopened) != 0) same = 0;
  return same;
}

static int plain_directory(int fd, int mode_protected) {
  struct stat st;
  struct statfs fs;
  return fd >= 0 && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
         st.st_uid == geteuid() &&
         (!mode_protected || (st.st_mode & 0777) == 0700) &&
         fstatfs(fd, &fs) == 0 && fs.f_type == EXT4_SUPER_MAGIC;
}

static int random_hex(char *destination, size_t bytes) {
  uint8_t raw[16];
  static const char digits[] = "0123456789abcdef";
  if (bytes > sizeof(raw)) return 0;
  size_t got = 0;
  while (got < bytes) {
    ssize_t n = syscall(SYS_getrandom, raw + got, bytes - got, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return 0;
    got += (size_t)n;
  }
  for (size_t i = 0; i < bytes; ++i) {
    destination[i * 2] = digits[raw[i] >> 4];
    destination[i * 2 + 1] = digits[raw[i] & 15];
  }
  destination[bytes * 2] = 0;
  memset(raw, 0, sizeof(raw));
  return 1;
}

static int write_owned(int dirfd, const char *name, const char *content) {
  int fd = fd_openat2(dirfd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) return 0;
  size_t size = strlen(content);
  ssize_t count = write(fd, content, size);
  int okay = count == (ssize_t)size && fsync(fd) == 0;
  if (close(fd) != 0) okay = 0;
  return okay;
}

static int create_open_proof(int dirfd, const char *name, const char *payload) {
  int fd = fd_openat2(dirfd, name, O_RDWR | O_CREAT | O_EXCL, 0600);
  if (fd < 0) return -1;
  size_t size = strlen(payload);
  if (write(fd, payload, size) != (ssize_t)size || fsync(fd) != 0) {
    (void)close(fd);
    return -1;
  }
  return fd;
}
static int create_open_stage(int dirfd) {
  return create_open_proof(dirfd, STAGE_PROOF, STAGE_PAYLOAD);
}

static int create_anonymous_stage(int dirfd) {
  // ext4 O_TMPFILE has no visible stage pathname. O_EXCL must NOT be set:
  // Linux otherwise forbids linking this anonymous inode into the directory.
  int fd = openat(dirfd, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0) return -1;
  size_t size = strlen(STAGE_PAYLOAD);
  if (write(fd, STAGE_PAYLOAD, size) != (ssize_t)size || fsync(fd) != 0) {
    (void)close(fd);
    return -1;
  }
  return fd;
}

static int opened_stage_equals(int fd, int anonymous) {
  if (fd < 0) return 0;
  struct stat st;
  char bytes[64];
  size_t size = strlen(STAGE_PAYLOAD);
  ssize_t got = pread(fd, bytes, sizeof(bytes), 0);
  return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
         st.st_size == (off_t)size &&
         st.st_nlink == (anonymous ? 0 : 1) &&
         got == (ssize_t)size && memcmp(bytes, STAGE_PAYLOAD, size) == 0;
}

static int same_prepare_version(const struct stat *before, const struct stat *after) {
  return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
         before->st_uid == after->st_uid && before->st_mode == after->st_mode &&
         before->st_nlink == after->st_nlink && before->st_size == after->st_size &&
         before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
         before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
         before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
         before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static int opened_prepare_equals(int fd, const struct stat *initial) {
  if (fd < 0) return 0;
  struct stat st;
  char bytes[64];
  size_t size = strlen(JOURNAL_PAYLOAD);
  ssize_t got = pread(fd, bytes, sizeof(bytes), 0);
  return fstat(fd, &st) == 0 && same_prepare_version(initial, &st) &&
         S_ISREG(st.st_mode) &&
         st.st_size == (off_t)size && st.st_nlink == 1 &&
         got == (ssize_t)size && memcmp(bytes, JOURNAL_PAYLOAD, size) == 0;
}

static int opened_identity_equals(int fd, const struct stat *initial,
                                  const char *expected) {
  if (fd < 0 || !expected) return 0;
  struct stat st;
  char bytes[160];
  size_t size = strlen(expected);
  if (size >= sizeof(bytes)) return 0;
  ssize_t got = pread(fd, bytes, sizeof(bytes), 0);
  return fstat(fd, &st) == 0 && same_prepare_version(initial, &st) &&
         S_ISREG(st.st_mode) && st.st_size == (off_t)size &&
         st.st_nlink == 1 && got == (ssize_t)size &&
         memcmp(bytes, expected, size) == 0;
}

static int still_original_identity(lab_session *session, int dirfd) {
  if (!session->identity_version_pinned ||
      !opened_identity_equals(session->identity_fd,
                              &session->identity_initial,
                              session->identity_payload)) return 0;
  int current = fd_openat2(dirfd, IDENTITY_PROOF, O_RDONLY | O_NONBLOCK, 0);
  int okay = current >= 0 && object_is(current, session->identity_fd) &&
             opened_identity_equals(current, &session->identity_initial,
                                    session->identity_payload);
  if (current >= 0 && close(current) != 0) okay = 0;
  return okay;
}

static int marker_equals(int dirfd, const char *name, const char *expected) {
  // Never block a helper before fstat if a same-UID fixture writer installs
  // a FIFO. A non-regular descriptor fails the held-file check below.
  int fd = fd_openat2(dirfd, name, O_RDONLY | O_NONBLOCK, 0);
  if (fd < 0) return 0;
  struct stat st;
  char bytes[64];
  ssize_t n = read(fd, bytes, sizeof(bytes));
  int okay = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
             st.st_nlink == 1 && n == (ssize_t)strlen(expected) &&
             memcmp(bytes, expected, strlen(expected)) == 0;
  if (close(fd) != 0) okay = 0;
  return okay;
}

static int rename_no_replace(int parent, const char *from, const char *to) {
  return syscall(SYS_renameat2, parent, from, parent, to, RENAME_NOREPLACE) == 0 &&
         fsync(parent) == 0;
}

static int valid_token(napi_env env, napi_callback_info info, napi_value value) {
  lab_session *session = session_for(env, info);
  napi_valuetype t;
  if (!session || !session->active ||
      napi_typeof(env, value, &t) != napi_ok || t != napi_string)
    return 0;
  size_t size = 0;
  if (napi_get_value_string_utf8(env, value, NULL, 0, &size) != napi_ok ||
      size != 32) return 0;
  char text[34];
  size_t used;
  if (napi_get_value_string_utf8(env, value, text, sizeof(text), &used) != napi_ok ||
      used != 32 || text[32] != 0) return 0;
  unsigned diff = 0;
  for (size_t i = 0; i < 33; ++i)
    diff |= (unsigned)(unsigned char)(text[i] ^ session->token[i]);
  return diff == 0;
}

static int leaf_name(napi_env env, napi_value value, char out[256]) {
  napi_valuetype t;
  size_t bytes;
  if (napi_typeof(env, value, &t) != napi_ok || t != napi_string ||
      napi_get_value_string_utf8(env, value, NULL, 0, &bytes) != napi_ok ||
      bytes < 1 || bytes >= 255) return 0;
  size_t used;
  if (napi_get_value_string_utf8(env, value, out, 256, &used) != napi_ok ||
      used != bytes || strlen(out) != bytes ||
      strcmp(out, ".") == 0 || strcmp(out, "..") == 0) return 0;
  for (size_t i = 0; i < bytes; ++i) {
    if (out[i] == '/' || out[i] == '\\') return 0;
  }
  return 1;
}

static void release_handles(lab_session *session) {
  if (!session) return;
  if (session->staged_fd >= 0) {
    (void)close(session->staged_fd);
    session->staged_fd = -1;
  }
  if (session->journal_fd >= 0) {
    (void)close(session->journal_fd);
    session->journal_fd = -1;
  }
  if (session->identity_fd >= 0) {
    (void)close(session->identity_fd);
    session->identity_fd = -1;
  }
  if (session->held) {
    (void)closedir(session->held);
    session->held = NULL;
  }
  for (size_t i = session->ancestor_count; i > 0; --i)
    (void)close(session->ancestors[i - 1].fd);
  session->ancestor_count = 0;
  session->parentfd = -1;
  session->active = 0;
  session->phase = 0;
  session->stream_active = 0;
  session->stream_done = 0;
  session->seeded = 0;
  session->raw_seeded = 0;
  session->txn_phase = 0;
  session->txn_anonymous = 0;
  session->journal_version_pinned = 0;
  session->identity_version_pinned = 0;
  memset(&session->journal_initial, 0, sizeof(session->journal_initial));
  memset(&session->identity_initial, 0, sizeof(session->identity_initial));
  memset(session->identity_payload, 0, sizeof(session->identity_payload));
  memset(session->token, 0, sizeof(session->token));
}

static void cleanup(void *data) {
  lab_session *session = (lab_session *)data;
  release_handles(session); // handles only; never unlink or recursively clean.
  free(session);
}

static napi_value authority(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 0, argv)) return fail(env, "NATIVE_ARGUMENT_REJECTED");
  return result_text(env, "LAB_ONLY_NO_GO");
}

static napi_value open_test_session(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 0, argv)) return fail(env, "NATIVE_ARGUMENT_REJECTED");
  lab_session *session = session_for(env, info);
  if (!session || session->active || getenv("ROOTARK_ISSUE66_W3_NAPI_LAB") == NULL ||
      strcmp(getenv("ROOTARK_ISSUE66_W3_NAPI_LAB"), "1") != 0)
    return fail(env, "NATIVE_TEST_DISABLED");
  // POSIX passwd HOME is not independently attested authority. The newly
  // created 0700 parent and all subsequent handles are strictly test-owned.
  // getpwuid() returns process-shared static storage. Per-worker native
  // acquisitions must never race while reading the passwd HOME path.
  struct passwd passwd_entry, *pw = NULL;
  char passwd_buffer[16384];
  if (getpwuid_r(geteuid(), &passwd_entry, passwd_buffer,
                 sizeof(passwd_buffer), &pw) != 0 ||
      !pw || !pw->pw_dir || pw->pw_dir[0] != '/' ||
      pw->pw_dir[1] == 0) return fail(env, "NATIVE_PARENT_UNVERIFIED");
  int root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root < 0) return fail(env, "NATIVE_PARENT_UNVERIFIED");
  struct stat root_stat;
  if (fstat(root, &root_stat) != 0 || !S_ISDIR(root_stat.st_mode)) {
    (void)close(root);
    return fail(env, "NATIVE_PARENT_UNVERIFIED");
  }
  session->ancestors[0].fd = root;
  session->ancestors[0].dev = root_stat.st_dev;
  session->ancestors[0].ino = root_stat.st_ino;
  session->ancestors[0].uid = root_stat.st_uid;
  session->ancestors[0].mode = root_stat.st_mode & 07777;
  session->ancestors[0].name[0] = 0;
  session->ancestor_count = 1;
  // Walk passwd HOME one literal path segment at a time. A single multi-
  // component openat2 here would leave intermediate ancestors unretained.
  int home = root;
  const char *part = pw->pw_dir + 1;
  while (*part) {
    const char *slash = strchr(part, '/');
    size_t length = slash ? (size_t)(slash - part) : strlen(part);
    if (length == 0 || length > 255 || (slash && slash[1] == 0)) {
      release_handles(session);
      return fail(env, "NATIVE_PARENT_UNVERIFIED");
    }
    char segment[256];
    memcpy(segment, part, length);
    segment[length] = 0;
    home = retain_child_directory(session, home, segment);
    if (home < 0) {
      release_handles(session);
      return fail(env, "NATIVE_PARENT_UNVERIFIED");
    }
    if (!slash) break;
    part = slash + 1;
  }
  if (!plain_directory(home, 0)) {
    release_handles(session);
    return fail(env, "NATIVE_PARENT_UNVERIFIED");
  }
  // Two independent CSPRNG draws: a visible HOME directory suffix must not
  // disclose the native bearer token to another same-UID directory enumerator.
  char directory_id[33], token[33];
  if (!random_hex(directory_id, 16) || !random_hex(token, 16) ||
      strcmp(directory_id, token) == 0) {
    release_handles(session);
    return fail(env, "NATIVE_RANDOM_FAILED");
  }
  char parent_name[80];
  (void)snprintf(parent_name, sizeof(parent_name), ".rootark-w3-napi-%s", directory_id);
  if (mkdirat(home, parent_name, 0700) != 0) {
    release_handles(session);
    return fail(env, "NATIVE_PARENT_UNVERIFIED");
  }
  int parent = retain_child_directory(session, home, parent_name);
  if (!plain_directory(parent, 1)) {
    release_handles(session);
    return fail(env, "NATIVE_PARENT_UNVERIFIED");
  }
  session->parentfd = parent;
  if (mkdirat(parent, "held", 0700) != 0) {
    release_handles(session);
    return fail(env, "NATIVE_FIXTURE_FAILED");
  }
  int original = fd_openat2(parent, "held", O_RDONLY | O_DIRECTORY, 0);
  DIR *dir = original < 0 ? NULL : fdopendir(original);
  if (!dir) {
    if (original >= 0) (void)close(original);
    release_handles(session);
    return fail(env, "NATIVE_FIXTURE_FAILED");
  }
  session->held = dir;
  int heldfd = dirfd(dir);
  if (!plain_directory(heldfd, 1) ||
      !write_owned(heldfd, "original.bin", TRUSTED_BYTES) ||
      !write_owned(heldfd, UNICODE_LEAF, "UNICODE") ||
      symlinkat("original.bin", heldfd, "alias") != 0 ||
      fsync(heldfd) != 0 || fsync(parent) != 0) {
    release_handles(session);
    return fail(env, "NATIVE_FIXTURE_FAILED");
  }
  session->staged_fd = -1;
  session->journal_fd = -1;
  session->identity_fd = -1;
  session->phase = 0;
  session->stream_active = 0;
  session->stream_done = 0;
  session->seeded = 0;
  session->raw_seeded = 0;
  session->txn_phase = 0;
  session->txn_anonymous = 0;
  memcpy(session->token, token, sizeof(session->token));
  session->active = 1;
  return result_text(env, token);
}

static napi_value enumerate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  lab_session *session = session_for(env, info);
  if (session->stream_active) return fail(env, "NATIVE_STREAM_BUSY");
  int fd = dirfd(session->held);
  if (!plain_directory(fd, 1)) return fail(env, "NATIVE_FD_INVALID");
  rewinddir(session->held);
  napi_value array;
  if (napi_create_array(env, &array) != napi_ok) return fail(env, "NATIVE_API_FAILED");
  uint32_t count = 0;
  errno = 0;
  for (struct dirent *entry; (entry = readdir(session->held)) != NULL;) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (++count > 16) return fail(env, "NATIVE_ENUM_LIMIT"); // no 16,385 claim
    napi_value name;
    if (napi_create_string_utf8(env, entry->d_name, NAPI_AUTO_LENGTH, &name) != napi_ok ||
        napi_set_element(env, array, count - 1, name) != napi_ok)
      return fail(env, "NATIVE_API_FAILED");
    errno = 0;
  }
  if (errno != 0) return fail(env, "NATIVE_ENUM_FAILED");
  return array;
}

// Test-only fixed-count native file creation under the *retained* held dirfd.
// This is intentionally NOT an independently authorized production writer.
// A same-UID actor still owns the test parent and can mutate its ancestry.
static napi_value seed_many(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  // This 16,385-inode stress operation is deliberately retained for audit.
  // The N-API boundary itself must require explicit opt-in: a JS test skip
  // alone cannot stop another lab caller from seeding thousands of files.
  const char *stress = getenv("ROOTARK_ISSUE66_W3_STREAM_STRESS");
  if (!stress || strcmp(stress, "1") != 0)
    return fail(env, "NATIVE_STRESS_DISABLED");
  lab_session *session = session_for(env, info);
  const int directory = dirfd(session->held);
  if (session->phase != 0 || session->seeded || !plain_directory(directory, 1))
    return fail(env, "NATIVE_SEED_DENIED");
  session->seeded = 1;
  for (unsigned i = 0; i < 16385; ++i) {
    char name[32];
    if (snprintf(name, sizeof(name), "entry-%05u.bin", i) < 0)
      return fail(env, "NATIVE_SEED_FAILED");
    int file = fd_openat2(directory, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (file < 0) return fail(env, "NATIVE_SEED_FAILED");
    int okay = write(file, "x", 1) == 1 && fsync(file) == 0;
    if (close(file) != 0) okay = 0;
    if (!okay) return fail(env, "NATIVE_SEED_FAILED");
  }
  if (fsync(directory) != 0) return fail(env, "NATIVE_SEED_FAILED");
  return result_text(env, "LAB_SEEDED_16385");
}

// A legal POSIX leaf need not be valid UTF-8. Keep it as raw bytes through
// native creation and enumeration rather than replacing 0xff with U+FFFD.
static napi_value seed_raw_byte_name(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  lab_session *session = session_for(env, info);
  int directory = dirfd(session->held);
  if (session->phase != 0 || session->raw_seeded || !plain_directory(directory, 1))
    return fail(env, "NATIVE_SEED_DENIED");
  session->raw_seeded = 1;
  const char raw_name[] = { 'r', 'a', 'w', '-', (char)0xff, '.', 'b', 'i', 'n', 0 };
  if (!write_owned(directory, raw_name, "x") || fsync(directory) != 0)
    return fail(env, "NATIVE_SEED_FAILED");
  return result_text(env, "LAB_SEEDED_RAW_NAME");
}

static napi_value begin_stream(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  lab_session *session = session_for(env, info);
  if (!plain_directory(dirfd(session->held), 1))
    return fail(env, "NATIVE_FD_INVALID");
  rewinddir(session->held);
  session->stream_active = 1;
  session->stream_done = 0;
  return result_text(env, "LAB_STREAM_READY");
}

// The native cursor advances on the same held DIR* across invocations.
// Names are copied as exact bytes, without lossy UTF-8 normalization.
// Every page is bounded to 64 names, independent of directory size.
static napi_value next_stream_page(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  lab_session *session = session_for(env, info);
  if (!session->stream_active || !plain_directory(dirfd(session->held), 1))
    return fail(env, "NATIVE_STREAM_NOT_READY");
  napi_value result, array;
  if (napi_create_object(env, &result) != napi_ok ||
      napi_create_array(env, &array) != napi_ok)
    return fail(env, "NATIVE_API_FAILED");
  uint32_t count = 0;
  while (count < 64 && !session->stream_done) {
    errno = 0;
    struct dirent *entry = readdir(session->held);
    if (!entry) {
      if (errno != 0) return fail(env, "NATIVE_ENUM_FAILED");
      session->stream_done = 1;
      break;
    }
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    size_t length = strlen(entry->d_name);
    if (length == 0 || length > 255)
      return fail(env, "NATIVE_ENUM_FAILED");
    napi_value name;
    if (napi_create_buffer_copy(env, length, entry->d_name, NULL, &name) != napi_ok ||
        napi_set_element(env, array, count, name) != napi_ok)
      return fail(env, "NATIVE_API_FAILED");
    ++count;
  }
  if (!plain_directory(dirfd(session->held), 1))
    return fail(env, "NATIVE_FD_INVALID");
  napi_value done;
  if (napi_get_boolean(env, session->stream_done != 0, &done) != napi_ok ||
      napi_set_named_property(env, result, "names", array) != napi_ok ||
      napi_set_named_property(env, result, "done", done) != napi_ok)
    return fail(env, "NATIVE_API_FAILED");
  return result;
}

static napi_value native_read(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 2, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  lab_session *session = session_for(env, info);
  char leaf[256];
  if (!leaf_name(env, argv[1], leaf))
    return fail(env, "NATIVE_LEAF_REJECTED");
  int file = fd_openat2(dirfd(session->held), leaf, O_RDONLY | O_NONBLOCK, 0);
  if (file < 0) return fail(env, "NATIVE_OPEN_DENIED");
  struct stat st;
  if (fstat(file, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
      st.st_size < 0 || st.st_size > 4096) {
    (void)close(file);
    return fail(env, "NATIVE_OPEN_DENIED");
  }
  size_t size = (size_t)st.st_size;
  char content[4096];
  size_t off = 0;
  while (off < size) {
    if (off >= sizeof(content)) {
      (void)close(file);
      return fail(env, "NATIVE_READ_FAILED");
    }
    size_t amount = sizeof(content) - off;
    if (amount > size - off) amount = size - off;
    ssize_t n = read(file, content + off, amount);
    if (n <= 0) {
      (void)close(file);
      return fail(env, "NATIVE_READ_FAILED");
    }
    off += (size_t)n;
  }
  if (close(file) != 0) return fail(env, "NATIVE_READ_FAILED");
  napi_value result;
  if (napi_create_buffer_copy(env, size, content, NULL, &result) != napi_ok)
    return fail(env, "NATIVE_API_FAILED");
  return result;
}

// Fixed-name transactional rehearsal only. It exercises real fd-relative
// exclusive stage, fsync, journal and no-overwrite publication, but the lab
// parent is SAME-UID writable and lacks an independent monotonic custodian.
// Never export these methods as product RootSession authority.
static int txn_lab_enabled(void) {
  const char *flag = getenv("ROOTARK_ISSUE66_W3_TXN_LAB");
  return flag && strcmp(flag, "1") == 0;
}

static napi_value stage_proof(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  if (!txn_lab_enabled()) return fail(env, "NATIVE_TXN_TEST_DISABLED");
  lab_session *session = session_for(env, info);
  int held = dirfd(session->held);
  if (session->txn_phase != 0 || !plain_directory(held, 1))
    return fail(env, "NATIVE_TXN_PHASE_REJECTED");
  if (!still_original_ancestors(session)) {
    session->txn_phase = 3;
    return fail(env, "NATIVE_ANCESTOR_CHANGED");
  }
  // Any uncertain failure permanently blocks this lab session's transaction
  // rather than permitting a blind second admission after partial writes.
  session->txn_phase = 3;
  const char *anon = getenv("ROOTARK_ISSUE66_W3_ANON_LAB");
  session->txn_anonymous = anon && strcmp(anon, "1") == 0;
  session->staged_fd = session->txn_anonymous
    ? create_anonymous_stage(held) : create_open_stage(held);
  struct stat held_stat, original_stage;
  int n = session->staged_fd < 0 ? -1 :
    (fstat(held, &held_stat) == 0 && fstat(session->staged_fd, &original_stage) == 0
      ? snprintf(session->identity_payload, sizeof(session->identity_payload),
                 "PREPARED_ID_V2:%jx:%jx:%jx:%jx:%c\n",
                 (uintmax_t)held_stat.st_dev, (uintmax_t)held_stat.st_ino,
                 (uintmax_t)original_stage.st_dev, (uintmax_t)original_stage.st_ino,
                 session->txn_anonymous ? 'A' : 'N')
      : -1);
  if (n < 1 || (size_t)n >= sizeof(session->identity_payload) ||
      !S_ISDIR(held_stat.st_mode) || !S_ISREG(original_stage.st_mode) ||
      original_stage.st_ino == 0 || fsync(held) != 0 ||
      (session->journal_fd =
        create_open_proof(held, JOURNAL_PROOF, JOURNAL_PAYLOAD)) < 0 ||
      fstat(session->journal_fd, &session->journal_initial) != 0 ||
      fsync(held) != 0)
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  // A deterministic new-process crash can separate an already fsynced
  // PREPARE from its identity sidecar. On cold admission the native inspector
  // must reject this torn transaction, never guess the missing FileId.
  const char *early_exit = getenv("ROOTARK_ISSUE66_W3_HARD_EXIT_BEFORE_ID_PROOF");
  if (early_exit && strcmp(early_exit, "1") == 0) _exit(75);
  if ((session->identity_fd = create_open_proof(held, IDENTITY_PROOF,
                                               session->identity_payload)) < 0 ||
      fstat(session->identity_fd, &session->identity_initial) != 0 ||
      fsync(held) != 0)
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  session->journal_version_pinned = 1;
  session->identity_version_pinned = 1;
  session->txn_phase = 1;
  return result_text(env, "LAB_TXN_PREPARED");
}

static napi_value publish_proof(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  if (!txn_lab_enabled()) return fail(env, "NATIVE_TXN_TEST_DISABLED");
  lab_session *session = session_for(env, info);
  int held = dirfd(session->held);
  if (session->txn_phase != 1 || !plain_directory(held, 1))
    return fail(env, "NATIVE_TXN_PHASE_REJECTED");
  if (!still_original_ancestors(session)) {
    session->txn_phase = 3;
    return fail(env, "NATIVE_ANCESTOR_CHANGED");
  }
  int stage_identity_matches = opened_stage_equals(session->staged_fd,
                                                    session->txn_anonymous);
  if (!session->txn_anonymous) {
    int current = fd_openat2(held, STAGE_PROOF, O_RDONLY | O_NONBLOCK, 0);
    stage_identity_matches = stage_identity_matches && current >= 0 &&
                             object_is(current, session->staged_fd);
    if (current >= 0 && close(current) != 0) stage_identity_matches = 0;
    stage_identity_matches = stage_identity_matches &&
                             marker_equals(held, STAGE_PROOF, STAGE_PAYLOAD);
  }
  // PREPARE bytes are insufficient: a same-UID writer could park the journal
  // and install an identical payload in a DIFFERENT inode. Reopen relative to
  // the held parent only to compare it with the ORIGINAL journal FD, which
  // remains open until session cleanup. Never promote the new path occupant.
  int current_journal = fd_openat2(held, JOURNAL_PROOF,
                                    O_RDONLY | O_NONBLOCK, 0);
  int journal_identity_matches = session->journal_version_pinned &&
                                 opened_prepare_equals(session->journal_fd,
                                                       &session->journal_initial) &&
                                 current_journal >= 0 &&
                                 object_is(current_journal, session->journal_fd) &&
                                 opened_prepare_equals(current_journal,
                                                       &session->journal_initial);
  if (current_journal >= 0 && close(current_journal) != 0)
    journal_identity_matches = 0;
  if (!stage_identity_matches || !journal_identity_matches ||
      !still_original_identity(session, held)) {
    session->txn_phase = 3;
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  }
  // Publish from the ORIGINAL retained inode, not the mutable stage name.
  // /proc/self/fd is kernel-owned; AT_SYMLINK_FOLLOW dereferences this exact
  // opened descriptor while linkat supplies atomic no-replace destination.
  // Visible stages keep their second hardlink rather than delete a mutable
  // name. Anonymous O_TMPFILE stages instead have nlink=0 before publication
  // and nlink=1 afterwards, with no unsafe cleanup or second visible name.
  // Neither version authorizes production or cold required-v2 replay.
  char opened_source[64];
  int written = snprintf(opened_source, sizeof(opened_source),
                         "/proc/self/fd/%d", session->staged_fd);
  if (written < 1 || (size_t)written >= sizeof(opened_source)) {
    session->txn_phase = 3;
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  }
  // An explicitly opted-in deterministic physical adversary changes the
  // original stage pathname AFTER all source identity checks but BEFORE the
  // native link. It must not redirect the source: linkat below resolves only
  // the privately retained opened FD. This is NOT a concurrent writer test.
  const char *rebind = getenv("ROOTARK_ISSUE66_W3_REBIND_AFTER_CHECK");
  if (!session->txn_anonymous && rebind && strcmp(rebind, "1") == 0) {
    if (syscall(SYS_renameat2, held, STAGE_PROOF, held,
                ".rootark-w3-postcheck-parked", RENAME_NOREPLACE) != 0 ||
        !write_owned(held, STAGE_PROOF, STAGE_PAYLOAD)) {
      session->txn_phase = 3;
      return fail(env, "NATIVE_TXN_INDETERMINATE");
    }
  }
  errno = 0;
  if (linkat(AT_FDCWD, opened_source,
             held, PUBLISHED_PROOF, AT_SYMLINK_FOLLOW) != 0) {
    session->txn_phase = 3;
    if (errno == EEXIST) return fail(env, "NATIVE_TXN_NO_REPLACE_CONFLICT");
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  }
  session->txn_phase = 3;
  if (fsync(held) != 0)
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  // A checked PREPARE name is mutable under a SAME-UID lab writer. Check the
  // original inode version and current name again AFTER the publication and
  // its directory fsync, before emitting COMMIT. This catches deterministic
  // post-link swaps; only an independently protected parent can eliminate
  // the remaining last-check -> COMMIT window in a production custodian.
  const char *late = getenv("ROOTARK_ISSUE66_W3_JOURNAL_REBIND_AFTER_LINK");
  if (late && strcmp(late, "1") == 0) {
    if (syscall(SYS_renameat2, held, JOURNAL_PROOF, held,
                ".rootark-w3-afterlink-original-prepare", RENAME_NOREPLACE) != 0 ||
        !write_owned(held, JOURNAL_PROOF, JOURNAL_PAYLOAD))
      return fail(env, "NATIVE_TXN_INDETERMINATE");
  }
  current_journal = fd_openat2(held, JOURNAL_PROOF, O_RDONLY | O_NONBLOCK, 0);
  journal_identity_matches = session->journal_version_pinned &&
                             opened_prepare_equals(session->journal_fd,
                                                   &session->journal_initial) &&
                             current_journal >= 0 &&
                             object_is(current_journal, session->journal_fd) &&
                             opened_prepare_equals(current_journal,
                                                   &session->journal_initial);
  if (current_journal >= 0 && close(current_journal) != 0)
    journal_identity_matches = 0;
  if (!journal_identity_matches || !still_original_identity(session, held))
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  // Deterministic lab-only attack after the durable link, before COMMIT.
  // This performs the same rename/replacement that a same-UID writer can do;
  // it does not simulate independently protected custody or a real race.
  const char *ancestor_rebind =
    getenv("ROOTARK_ISSUE66_W3_ANCESTOR_REBIND_AFTER_LINK");
  if (ancestor_rebind && strcmp(ancestor_rebind, "1") == 0) {
    retained_ancestor *parent_entry =
      &session->ancestors[session->ancestor_count - 1];
    int home_fd = session->ancestors[session->ancestor_count - 2].fd;
    char parked_name[128];
    int n = snprintf(parked_name, sizeof(parked_name), "%s-afterlink-parked",
                     parent_entry->name);
    if (n < 1 || (size_t)n >= sizeof(parked_name) ||
        !rename_no_replace(home_fd, parent_entry->name, parked_name) ||
        mkdirat(home_fd, parent_entry->name, 0700) != 0)
      return fail(env, "NATIVE_TXN_INDETERMINATE");
    int replacement = fd_openat2(home_fd, parent_entry->name,
                                  O_RDONLY | O_DIRECTORY, 0);
    int okay = replacement >= 0 && mkdirat(replacement, "held", 0700) == 0 &&
               fsync(replacement) == 0 && fsync(home_fd) == 0;
    if (replacement >= 0 && close(replacement) != 0) okay = 0;
    if (!okay) return fail(env, "NATIVE_TXN_INDETERMINATE");
  }
  // Physical hard-exit in an explicitly opted-in child process ONLY. The
  // destination has passed linkat+directory fsync but COMMIT has not been
  // created. No native cold replay may treat PREPARED as COMMITTED.
  const char *hard_exit = getenv("ROOTARK_ISSUE66_W3_HARD_EXIT_POST_LINK");
  const char *hard_exit_named =
    getenv("ROOTARK_ISSUE66_W3_HARD_EXIT_POST_LINK_NAMED");
  if ((session->txn_anonymous && hard_exit && strcmp(hard_exit, "1") == 0) ||
      (!session->txn_anonymous && hard_exit_named &&
       strcmp(hard_exit_named, "1") == 0))
    _exit(73);
  // Recheck the live chain AFTER link+fsync and just before COMMIT. There is
  // still a race until commit without an independently protected custodian.
  if (!still_original_ancestors(session))
    return fail(env, "NATIVE_ANCESTOR_CHANGED");
  if (!write_owned(held, COMMIT_PROOF, COMMIT_PAYLOAD) || fsync(held) != 0)
    return fail(env, "NATIVE_TXN_INDETERMINATE");
  session->txn_phase = 2;
  return result_text(env, "LAB_TXN_COMMITTED");
}

static napi_value swap_to_foreign(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  lab_session *session = session_for(env, info);
  if (session->phase != 0) return fail(env, "NATIVE_PHASE_REJECTED");
  int parent = session->parentfd;
  if (!rename_no_replace(parent, "held", "parked") ||
      mkdirat(parent, "held", 0700) != 0)
    return fail(env, "NATIVE_RENAME_FAILED");
  int foreign = fd_openat2(parent, "held", O_RDONLY | O_DIRECTORY, 0);
  int original = dirfd(session->held);
  int okay = plain_directory(foreign, 1) && !object_is(foreign, original) &&
             write_owned(foreign, "original.bin", FOREIGN_BYTES) &&
             marker_equals(original, "original.bin", TRUSTED_BYTES) &&
             marker_equals(foreign, "original.bin", FOREIGN_BYTES) &&
             fsync(foreign) == 0 && fsync(parent) == 0;
  if (foreign >= 0 && close(foreign) != 0) okay = 0;
  if (!okay) return fail(env, "NATIVE_RENAME_FAILED");
  session->phase = 1;
  return result_text(env, "HELD_ORIGINAL_FOREIGN_AT_NAME");
}

static napi_value restore_original(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  lab_session *session = session_for(env, info);
  if (session->phase != 1) return fail(env, "NATIVE_PHASE_REJECTED");
  int parent = session->parentfd;
  if (!rename_no_replace(parent, "held", "foreign-parked") ||
      !rename_no_replace(parent, "parked", "held"))
    return fail(env, "NATIVE_RENAME_FAILED");
  int restored = fd_openat2(parent, "held", O_RDONLY | O_DIRECTORY, 0);
  int foreign = fd_openat2(parent, "foreign-parked", O_RDONLY | O_DIRECTORY, 0);
  int okay = object_is(dirfd(session->held), restored) &&
             !object_is(dirfd(session->held), foreign) &&
             marker_equals(restored, "original.bin", TRUSTED_BYTES) &&
             marker_equals(foreign, "original.bin", FOREIGN_BYTES);
  if (restored >= 0 && close(restored) != 0) okay = 0;
  if (foreign >= 0 && close(foreign) != 0) okay = 0;
  if (!okay) return fail(env, "NATIVE_RENAME_FAILED");
  session->phase = 2;
  return result_text(env, "ORIGINAL_RESTORED_FOREIGN_RETAINED");
}

static napi_value probe_existing_mount(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 0, argv)) return fail(env, "NATIVE_ARGUMENT_REJECTED");
  int base = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (base < 0) return fail(env, "NATIVE_MOUNT_PROBE_UNVERIFIED");
  errno = 0;
  int cross = fd_openat2(base, "proc", O_PATH | O_DIRECTORY, 0);
  int err = errno;
  if (cross >= 0) (void)close(cross);
  (void)close(base);
  if (cross != -1 || err != EXDEV) return fail(env, "NATIVE_MOUNT_PROBE_UNVERIFIED");
  return result_text(env, "NO_XDEV_DENIED");
}

static napi_value close_test_session(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (!args_of(env, info, 1, argv) || !valid_token(env, info, argv[0]))
    return fail(env, "NATIVE_TOKEN_REJECTED");
  release_handles(session_for(env, info));
  return result_text(env, "CLOSED_NO_AUTHORITY");
}

static napi_value init(napi_env env, napi_value exports) {
  lab_session *session = calloc(1, sizeof(*session));
  if (!session) return fail(env, "NATIVE_API_FAILED");
  session->parentfd = -1;
  session->staged_fd = -1;
  session->journal_fd = -1;
  session->identity_fd = -1;
  if (napi_add_env_cleanup_hook(env, cleanup, session) != napi_ok) {
    free(session);
    return fail(env, "NATIVE_API_FAILED");
  }
  napi_property_descriptor methods[] = {
    {"authority", NULL, authority, NULL, NULL, NULL, napi_default, session},
    {"openTestSession", NULL, open_test_session, NULL, NULL, NULL, napi_default, session},
    {"enumerate", NULL, enumerate, NULL, NULL, NULL, napi_default, session},
    {"seedMany", NULL, seed_many, NULL, NULL, NULL, napi_default, session},
    {"seedRawByteName", NULL, seed_raw_byte_name, NULL, NULL, NULL, napi_default, session},
    {"beginStream", NULL, begin_stream, NULL, NULL, NULL, napi_default, session},
    {"nextStreamPage", NULL, next_stream_page, NULL, NULL, NULL, napi_default, session},
    {"read", NULL, native_read, NULL, NULL, NULL, napi_default, session},
    {"stageProof", NULL, stage_proof, NULL, NULL, NULL, napi_default, session},
    {"publishProof", NULL, publish_proof, NULL, NULL, NULL, napi_default, session},
    {"swapToForeign", NULL, swap_to_foreign, NULL, NULL, NULL, napi_default, session},
    {"restoreOriginal", NULL, restore_original, NULL, NULL, NULL, napi_default, session},
    {"probeExistingMount", NULL, probe_existing_mount, NULL, NULL, NULL, napi_default, session},
    {"closeTestSession", NULL, close_test_session, NULL, NULL, NULL, napi_default, session},
  };
  if (napi_define_properties(env, exports, sizeof(methods)/sizeof(methods[0]),
                             methods) != napi_ok) {
    // If removal unexpectedly fails, the environment still owns the hook:
    // let it free this state later rather than risk a double free here.
    if (napi_remove_env_cleanup_hook(env, cleanup, session) == napi_ok)
      cleanup(session);
    return fail(env, "NATIVE_API_FAILED");
  }
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
