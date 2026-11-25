// Issue #66: Native RootSession N-API addon (Windows NTFS+CFAPI / Linux openat2+renameat2).
// Enforces opaque handle custody via napi_type_tag; JS objects/paths cannot forge authority.

#include <node_api.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cfapi.h>
#include <sddl.h>
#include <aclapi.h>
#pragma comment(lib, "cldapi.lib")
#pragma comment(lib, "advapi32.lib")
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

// Private N-API type tag preventing any JS object from impersonating a native session.
const napi_type_tag kRootSessionTag = {
  0x6f727461726b5f36ULL,
  0x365f726f6f745f31ULL,
};

napi_value throw_err(napi_env env, const char* code, const char* msg) {
  napi_throw_error(env, code, msg);
  return nullptr;
}

bool get_utf8(napi_env env, napi_value val, std::string& out) {
  napi_valuetype t;
  if (napi_typeof(env, val, &t) != napi_ok || t != napi_string) return false;
  size_t len = 0;
  if (napi_get_value_string_utf8(env, val, nullptr, 0, &len) != napi_ok) return false;
  if (len > 4096) return false;
  out.resize(len);
  if (len > 0 && napi_get_value_string_utf8(env, val, &out[0], len + 1, &len) != napi_ok) return false;
  return true;
}

bool split_safe_rel(const std::string& rel, std::vector<std::string>& parts) {
  parts.clear();
  if (rel.empty() || rel.size() > 2048) return false;
  if (rel.front() == '/' || rel.back() == '/') return false;
  if (rel.find('\\') != std::string::npos || rel.find('\0') != std::string::npos) return false;
#ifdef _WIN32
  if (rel.find(':') != std::string::npos) return false;
#endif
  size_t start = 0;
  while (start < rel.size()) {
    size_t slash = rel.find('/', start);
    std::string seg = (slash == std::string::npos) ? rel.substr(start) : rel.substr(start, slash - start);
    if (seg.empty() || seg == "." || seg == "..") return false;
    parts.push_back(seg);
    if (slash == std::string::npos) break;
    start = slash + 1;
  }
  return !parts.empty();
}

#ifdef _WIN32

std::wstring utf8_to_wide(const std::string& s) {
  if (s.empty()) return L"";
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (n <= 0) return L"";
  std::wstring w(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), &w[0], n);
  return w;
}

std::string wide_to_utf8(const std::wstring& w) {
  if (w.empty()) return "";
  int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  if (n <= 0) return "";
  std::string s(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
  return s;
}

bool verify_dir_handle(HANDLE h, FILE_ID_INFO& out_id) {
  if (h == INVALID_HANDLE_VALUE) return false;
  FILE_ATTRIBUTE_TAG_INFO attr{};
  if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &attr, sizeof(attr))) return false;
  if (!(attr.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) return false;
  if (attr.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    if ((attr.ReparseTag & 0xFFFF0FFFUL) != IO_REPARSE_TAG_CLOUD) return false;
  }
  if (!GetFileInformationByHandleEx(h, FileIdInfo, &out_id, sizeof(out_id))) return false;
  wchar_t fsname[64]{};
  if (!GetVolumeInformationByHandleW(h, nullptr, 0, nullptr, nullptr, nullptr, fsname, 64)) return false;
  return _wcsicmp(fsname, L"NTFS") == 0;
}

bool same_file_id(const FILE_ID_INFO& a, const FILE_ID_INFO& b) {
  return a.VolumeSerialNumber == b.VolumeSerialNumber &&
         std::memcmp(&a.FileId, &b.FileId, sizeof(a.FileId)) == 0;
}

bool verify_same_path_id(const std::wstring& p, const FILE_ID_INFO& expected) {
  HANDLE h = CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  FILE_ID_INFO cur{};
  bool ok = GetFileInformationByHandleEx(h, FileIdInfo, &cur, sizeof(cur)) && same_file_id(cur, expected);
  CloseHandle(h);
  return ok;
}

struct AncestorHandle {
  HANDLE h = INVALID_HANDLE_VALUE;
  std::wstring path;
  FILE_ID_INFO id{};
  ~AncestorHandle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

struct NativeSession {
  std::wstring root_path;
  HANDLE root_handle = INVALID_HANDLE_VALUE;
  FILE_ID_INFO root_id{};
  std::vector<std::unique_ptr<AncestorHandle>> ancestors;
  CF_CONNECTION_KEY cf_conn{};
  bool cf_connected = false;
  std::wstring cf_root;
  bool closed = false;

  ~NativeSession() { close_all(); }

  void close_all() {
    if (closed) return;
    closed = true;
    if (cf_connected) {
      CfDisconnectSyncRoot(cf_conn);
      CfUnregisterSyncRoot(cf_root.c_str());
      cf_connected = false;
    }
    if (root_handle != INVALID_HANDLE_VALUE) {
      CloseHandle(root_handle);
      root_handle = INVALID_HANDLE_VALUE;
    }
    ancestors.clear();
  }

  bool verify_custody() const {
    if (closed || root_handle == INVALID_HANDLE_VALUE) return false;
    if (!verify_same_path_id(root_path, root_id)) return false;
    for (const auto& a : ancestors) {
      if (!verify_same_path_id(a->path, a->id)) return false;
    }
    return true;
  }

  bool open_root(const std::string& utf8_root) {
    std::wstring w = utf8_to_wide(utf8_root);
    if (w.size() < 4 || w[1] != L':' || w[2] != L'\\') return false;
    wchar_t full[4096]{};
    DWORD flen = GetFullPathNameW(w.c_str(), 4096, full, nullptr);
    if (!flen || flen >= 4096) return false;
    root_path = full;
    while (root_path.size() > 3 && root_path.back() == L'\\') root_path.pop_back();

    // Pin ancestors from drive root (X:\) up to parent of root_path.
    std::wstring prefix = root_path.substr(0, 3);
    auto push_ancestor = [&](const std::wstring& seg) -> bool {
      auto a = std::make_unique<AncestorHandle>();
      a->path = seg;
      a->h = CreateFileW(seg.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      if (a->h == INVALID_HANDLE_VALUE) return false;
      if (!verify_dir_handle(a->h, a->id)) return false;
      ancestors.push_back(std::move(a));
      return true;
    };
    if (!push_ancestor(prefix)) return false;
    size_t pos = 3;
    while (pos < root_path.size()) {
      size_t next = root_path.find(L'\\', pos);
      if (next == std::wstring::npos) break; // root_path itself is opened below
      std::wstring sub = root_path.substr(0, next);
      if (!push_ancestor(sub)) return false;
      pos = next + 1;
    }

    root_handle = CreateFileW(root_path.c_str(),
      FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | FILE_ADD_FILE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    return verify_dir_handle(root_handle, root_id);
  }

  std::wstring resolve_contained(const std::vector<std::string>& parts, bool ensure_parents) {
    if (!verify_custody()) return L"";
    std::wstring cur = root_path;
    for (size_t i = 0; i < parts.size(); ++i) {
      std::wstring seg = utf8_to_wide(parts[i]);
      if (seg.empty()) return L"";
      cur += L"\\";
      cur += seg;
      if (i + 1 < parts.size()) {
        if (ensure_parents) CreateDirectoryW(cur.c_str(), nullptr);
        HANDLE dh = CreateFileW(cur.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        FILE_ID_INFO did{};
        bool ok = verify_dir_handle(dh, did);
        if (dh != INVALID_HANDLE_VALUE) CloseHandle(dh);
        if (!ok) return L"";
      }
    }
    return cur;
  }
};

#else // POSIX (Linux)

struct AncestorFd {
  int fd = -1;
  dev_t dev = 0;
  ino_t ino = 0;
  ~AncestorFd() { if (fd >= 0) close(fd); }
};

int sys_openat2(int dirfd, const char* pathname, uint64_t flags, uint64_t mode, uint64_t resolve) {
  struct open_how how{};
  how.flags = flags | O_CLOEXEC | O_NOFOLLOW;
  how.mode = mode;
  how.resolve = resolve;
  return static_cast<int>(syscall(SYS_openat2, dirfd, pathname, &how, sizeof(how)));
}

struct NativeSession {
  std::string root_path;
  int root_fd = -1;
  dev_t root_dev = 0;
  ino_t root_ino = 0;
  std::vector<std::unique_ptr<AncestorFd>> ancestors;
  bool closed = false;

  ~NativeSession() { close_all(); }

  void close_all() {
    if (closed) return;
    closed = true;
    if (root_fd >= 0) { close(root_fd); root_fd = -1; }
    ancestors.clear();
  }

  bool verify_custody() const {
    if (closed || root_fd < 0) return false;
    struct stat st{};
    if (fstat(root_fd, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    return st.st_dev == root_dev && st.st_ino == root_ino;
  }

  bool open_root(const std::string& path) {
    if (path.empty() || path[0] != '/') return false;
    root_path = path;
    while (root_path.size() > 1 && root_path.back() == '/') root_path.pop_back();

    int slash_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (slash_fd < 0) return false;
    struct stat st{};
    if (fstat(slash_fd, &st) != 0) { close(slash_fd); return false; }
    auto base = std::make_unique<AncestorFd>();
    base->fd = slash_fd; base->dev = st.st_dev; base->ino = st.st_ino;
    ancestors.push_back(std::move(base));

    int cur_fd = slash_fd;
    size_t pos = 1;
    while (pos < root_path.size()) {
      size_t next = root_path.find('/', pos);
      std::string seg = (next == std::string::npos) ? root_path.substr(pos) : root_path.substr(pos, next - pos);
      if (seg.empty() || seg == "." || seg == "..") return false;
      int next_fd = sys_openat2(cur_fd, seg.c_str(), O_RDONLY | O_DIRECTORY, 0,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS);
      if (next_fd < 0) return false;
      struct stat cst{};
      if (fstat(next_fd, &cst) != 0 || !S_ISDIR(cst.st_mode)) { close(next_fd); return false; }
      if (next == std::string::npos) {
        root_fd = next_fd;
        root_dev = cst.st_dev;
        root_ino = cst.st_ino;
        break;
      } else {
        auto a = std::make_unique<AncestorFd>();
        a->fd = next_fd; a->dev = cst.st_dev; a->ino = cst.st_ino;
        cur_fd = next_fd;
        ancestors.push_back(std::move(a));
      }
      pos = next + 1;
    }
    if (root_fd < 0 && root_path == "/") {
      root_fd = dup(slash_fd);
      root_dev = st.st_dev;
      root_ino = st.st_ino;
    }
    return root_fd >= 0;
  }

  int open_parent_dir(const std::vector<std::string>& parts, bool create_missing, std::string& leaf) {
    if (!verify_custody() || parts.empty()) return -1;
    leaf = parts.back();
    int cur = dup(root_fd);
    if (cur < 0) return -1;
    for (size_t i = 0; i + 1 < parts.size(); ++i) {
      if (create_missing) (void)mkdirat(cur, parts[i].c_str(), 0700);
      int next = sys_openat2(cur, parts[i].c_str(), O_RDONLY | O_DIRECTORY, 0,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV);
      close(cur);
      if (next < 0) return -1;
      cur = next;
    }
    return cur;
  }
};

#endif

NativeSession* unwrap_session(napi_env env, napi_value this_val) {
  bool matches = false;
  if (napi_check_object_type_tag(env, this_val, &kRootSessionTag, &matches) != napi_ok || !matches) {
    napi_throw_error(env, "root_session_unverified_authority", "Invalid or forged RootSession handle");
    return nullptr;
  }
  NativeSession* s = nullptr;
  if (napi_unwrap(env, this_val, reinterpret_cast<void**>(&s)) != napi_ok || !s || s->closed) {
    napi_throw_error(env, "root_session_native_unavailable", "Native RootSession is closed or unavailable");
    return nullptr;
  }
  return s;
}

void finalize_session(napi_env /*env*/, void* data, void* /*hint*/) {
  delete static_cast<NativeSession*>(data);
}

napi_value fn_open_child_dir(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  std::string rel;
  if (argc < 1 || !get_utf8(env, argv[0], rel)) return throw_err(env, "root_session_unsafe_traversal", "Invalid relative directory");
  std::vector<std::string> parts;
  if (!split_safe_rel(rel, parts)) return throw_err(env, "root_session_unsafe_traversal", "Unsafe relative directory");
#ifdef _WIN32
  std::vector<std::string> with_dummy = parts; with_dummy.push_back("_");
  if (s->resolve_contained(with_dummy, true).empty()) return throw_err(env, "root_session_unsafe_traversal", "Directory custody failed");
#else
  std::vector<std::string> with_dummy = parts; with_dummy.push_back("_");
  std::string leaf;
  int pfd = s->open_parent_dir(with_dummy, true, leaf);
  if (pfd < 0) return throw_err(env, "root_session_unsafe_traversal", "Directory custody failed");
  close(pfd);
#endif
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_enumerate_dir(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  std::string rel;
  if (argc >= 1) {
    napi_valuetype t; napi_typeof(env, argv[0], &t);
    if (t == napi_string && !get_utf8(env, argv[0], rel)) return throw_err(env, "root_session_unsafe_traversal", "Invalid path");
  }
  napi_value arr; napi_create_array(env, &arr);
  uint32_t idx = 0;
#ifdef _WIN32
  if (!s->verify_custody()) return throw_err(env, "root_session_root_identity_changed", "Root identity changed");
  std::wstring dir = s->root_path;
  if (!rel.empty()) {
    std::vector<std::string> parts;
    if (!split_safe_rel(rel, parts)) return throw_err(env, "root_session_unsafe_traversal", "Unsafe directory");
    dir = s->resolve_contained(parts, false);
    if (dir.empty()) return throw_err(env, "root_session_unsafe_traversal", "Directory missing");
  }
  std::wstring pat = dir + L"\\*";
  WIN32_FIND_DATAW fd{};
  HANDLE f = FindFirstFileExW(pat.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
  if (f == INVALID_HANDLE_VALUE) return arr;
  do {
    if (std::wcscmp(fd.cFileName, L".") == 0 || std::wcscmp(fd.cFileName, L"..") == 0) continue;
    std::string name = wide_to_utf8(fd.cFileName);
    napi_value v; napi_create_string_utf8(env, name.c_str(), name.size(), &v);
    napi_set_element(env, arr, idx++, v);
  } while (FindNextFileW(f, &fd));
  FindClose(f);
#else
  if (!s->verify_custody()) return throw_err(env, "root_session_root_identity_changed", "Root identity changed");
  int dfd = -1;
  if (rel.empty()) dfd = dup(s->root_fd);
  else {
    std::vector<std::string> parts;
    if (!split_safe_rel(rel, parts)) return throw_err(env, "root_session_unsafe_traversal", "Unsafe directory");
    parts.push_back("_"); std::string leaf;
    dfd = s->open_parent_dir(parts, false, leaf);
  }
  if (dfd < 0) return throw_err(env, "root_session_unsafe_traversal", "Directory missing");
  DIR* d = fdopendir(dfd);
  if (!d) { close(dfd); return throw_err(env, "root_session_native_unavailable", "fdopendir failed"); }
  while (struct dirent* e = readdir(d)) {
    if (std::strcmp(e->d_name, ".") == 0 || std::strcmp(e->d_name, "..") == 0) continue;
    napi_value v; napi_create_string_utf8(env, e->d_name, NAPI_AUTO_LENGTH, &v);
    napi_set_element(env, arr, idx++, v);
  }
  closedir(d);
#endif
  return arr;
}

napi_value fn_open_contained_file(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  std::string rel;
  if (argc < 1 || !get_utf8(env, argv[0], rel)) return throw_err(env, "root_session_unsafe_traversal", "Invalid path");
  std::vector<std::string> parts;
  if (!split_safe_rel(rel, parts)) return throw_err(env, "root_session_unsafe_traversal", "Unsafe path");
  napi_value obj; napi_create_object(env, &obj);
#ifdef _WIN32
  std::wstring target = s->resolve_contained(parts, false);
  if (target.empty()) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  HANDLE h = CreateFileW(target.c_str(), FILE_READ_ATTRIBUTES | GENERIC_READ,
    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (h == INVALID_HANDLE_VALUE) return throw_err(env, "root_session_native_unavailable", "Open failed");
  BY_HANDLE_FILE_INFORMATION info_b{};
  FILE_ATTRIBUTE_TAG_INFO tag{};
  bool ok = GetFileInformationByHandle(h, &info_b)
    && GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof(tag))
    && !(info_b.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    && info_b.nNumberOfLinks == 1;
  CloseHandle(h);
  if (!ok) return throw_err(env, "root_session_unsafe_traversal", "Untrusted file identity");
  napi_value sz; napi_create_int64(env, (static_cast<int64_t>(info_b.nFileSizeHigh) << 32) | info_b.nFileSizeLow, &sz);
  napi_set_named_property(env, obj, "size", sz);
#else
  std::string leaf;
  int pfd = s->open_parent_dir(parts, false, leaf);
  if (pfd < 0) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  int ffd = sys_openat2(pfd, leaf.c_str(), O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV);
  close(pfd);
  if (ffd < 0) return throw_err(env, "root_session_native_unavailable", "Open failed");
  struct stat st{};
  bool ok = fstat(ffd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1;
  close(ffd);
  if (!ok) return throw_err(env, "root_session_unsafe_traversal", "Untrusted file identity");
  napi_value sz; napi_create_int64(env, static_cast<int64_t>(st.st_size), &sz);
  napi_set_named_property(env, obj, "size", sz);
#endif
  return obj;
}

napi_value fn_read_opened_file(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  std::string rel;
  if (argc < 1 || !get_utf8(env, argv[0], rel)) return throw_err(env, "root_session_unsafe_traversal", "Invalid path");
  std::vector<std::string> parts;
  if (!split_safe_rel(rel, parts)) return throw_err(env, "root_session_unsafe_traversal", "Unsafe path");
#ifdef _WIN32
  std::wstring target = s->resolve_contained(parts, false);
  if (target.empty()) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  HANDLE h = CreateFileW(target.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (h == INVALID_HANDLE_VALUE) return throw_err(env, "root_session_native_unavailable", "Open failed");
  BY_HANDLE_FILE_INFORMATION b{};
  if (!GetFileInformationByHandle(h, &b) || (b.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || b.nNumberOfLinks != 1) {
    CloseHandle(h); return throw_err(env, "root_session_unsafe_traversal", "Untrusted file");
  }
  uint64_t size = (static_cast<uint64_t>(b.nFileSizeHigh) << 32) | b.nFileSizeLow;
  if (size > 64ULL * 1024 * 1024) { CloseHandle(h); return throw_err(env, "root_session_native_unavailable", "File too large"); }
  void* data = nullptr; napi_value buf{};
  napi_create_buffer(env, static_cast<size_t>(size), &data, &buf);
  DWORD got = 0;
  bool ok = (size == 0) || (ReadFile(h, data, static_cast<DWORD>(size), &got, nullptr) && got == size);
  CloseHandle(h);
  if (!ok) return throw_err(env, "root_session_native_unavailable", "ReadFile failed");
  return buf;
#else
  std::string leaf;
  int pfd = s->open_parent_dir(parts, false, leaf);
  if (pfd < 0) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  int ffd = sys_openat2(pfd, leaf.c_str(), O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV);
  close(pfd);
  if (ffd < 0) return throw_err(env, "root_session_native_unavailable", "Open failed");
  struct stat st{};
  if (fstat(ffd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size > 64 * 1024 * 1024) {
    close(ffd); return throw_err(env, "root_session_unsafe_traversal", "Untrusted file");
  }
  void* data = nullptr; napi_value buf{};
  napi_create_buffer(env, static_cast<size_t>(st.st_size), &data, &buf);
  size_t off = 0;
  while (off < static_cast<size_t>(st.st_size)) {
    ssize_t r = read(ffd, static_cast<char*>(data) + off, static_cast<size_t>(st.st_size) - off);
    if (r <= 0) { close(ffd); return throw_err(env, "root_session_native_unavailable", "read failed"); }
    off += static_cast<size_t>(r);
  }
  close(ffd);
  return buf;
#endif
}

napi_value fn_create_exclusive(napi_env env, napi_callback_info info) {
  size_t argc = 2; napi_value argv[2]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  std::string rel;
  if (argc < 2 || !get_utf8(env, argv[0], rel)) return throw_err(env, "root_session_unsafe_traversal", "Invalid path");
  bool is_buf = false;
  if (napi_is_buffer(env, argv[1], &is_buf) != napi_ok || !is_buf) return throw_err(env, "root_session_native_unavailable", "Buffer required");
  void* data = nullptr; size_t len = 0;
  napi_get_buffer_info(env, argv[1], &data, &len);
  std::vector<std::string> parts;
  if (!split_safe_rel(rel, parts)) return throw_err(env, "root_session_unsafe_traversal", "Unsafe path");
#ifdef _WIN32
  std::wstring target = s->resolve_contained(parts, true);
  if (target.empty()) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  HANDLE h = CreateFileW(target.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES,
    0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    return throw_err(env, err == ERROR_FILE_EXISTS ? "root_session_no_replace_conflict" : "root_session_native_unavailable", "Exclusive create failed");
  }
  DWORD wrote = 0;
  bool ok = (len == 0) || (WriteFile(h, data, static_cast<DWORD>(len), &wrote, nullptr) && wrote == len);
  if (ok) ok = FlushFileBuffers(h) != 0;
  CloseHandle(h);
  if (!ok) return throw_err(env, "root_session_durability_indeterminate", "Write/flush failed");
#else
  std::string leaf;
  int pfd = s->open_parent_dir(parts, true, leaf);
  if (pfd < 0) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  int ffd = sys_openat2(pfd, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600,
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV);
  if (ffd < 0) {
    int e = errno; close(pfd);
    return throw_err(env, e == EEXIST ? "root_session_no_replace_conflict" : "root_session_native_unavailable", "Exclusive create failed");
  }
  size_t off = 0;
  bool ok = true;
  while (off < len) {
    ssize_t w = write(ffd, static_cast<const char*>(data) + off, len - off);
    if (w <= 0) { ok = false; break; }
    off += static_cast<size_t>(w);
  }
  if (ok && fsync(ffd) != 0) ok = false;
  if (ok && fsync(pfd) != 0) ok = false;
  close(ffd); close(pfd);
  if (!ok) return throw_err(env, "root_session_durability_indeterminate", "Write/fsync failed");
#endif
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_rename_no_replace(napi_env env, napi_callback_info info) {
  size_t argc = 2; napi_value argv[2]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  std::string src_rel, dst_rel;
  if (argc < 2 || !get_utf8(env, argv[0], src_rel) || !get_utf8(env, argv[1], dst_rel))
    return throw_err(env, "root_session_unsafe_traversal", "Invalid paths");
  std::vector<std::string> src_p, dst_p;
  if (!split_safe_rel(src_rel, src_p) || !split_safe_rel(dst_rel, dst_p))
    return throw_err(env, "root_session_unsafe_traversal", "Unsafe paths");
#ifdef _WIN32
  std::wstring src = s->resolve_contained(src_p, false);
  std::wstring dst = s->resolve_contained(dst_p, true);
  if (src.empty() || dst.empty()) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  HANDLE h = CreateFileW(src.c_str(), DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (h == INVALID_HANDLE_VALUE) return throw_err(env, "root_session_native_unavailable", "Source open failed");
  std::vector<unsigned char> buf(sizeof(FILE_RENAME_INFO) + dst.size() * sizeof(wchar_t));
  auto* ri = reinterpret_cast<FILE_RENAME_INFO*>(buf.data());
  ri->ReplaceIfExists = FALSE;
  ri->RootDirectory = nullptr;
  ri->FileNameLength = static_cast<DWORD>(dst.size() * sizeof(wchar_t));
  std::memcpy(ri->FileName, dst.data(), ri->FileNameLength);
  bool ok = SetFileInformationByHandle(h, FileRenameInfo, ri, static_cast<DWORD>(buf.size())) != 0;
  DWORD err = ok ? 0 : GetLastError();
  CloseHandle(h);
  if (!ok) {
    return throw_err(env, (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS)
      ? "root_session_no_replace_conflict" : "root_session_native_unavailable", "No-replace rename failed");
  }
#else
  std::string sl, dl;
  int sp = s->open_parent_dir(src_p, false, sl);
  int dp = s->open_parent_dir(dst_p, true, dl);
  if (sp < 0 || dp < 0) {
    if (sp >= 0) close(sp); if (dp >= 0) close(dp);
    return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  }
  long rc = syscall(SYS_renameat2, sp, sl.c_str(), dp, dl.c_str(), RENAME_NOREPLACE);
  int e = errno;
  if (rc == 0) { (void)fsync(sp); (void)fsync(dp); }
  close(sp); close(dp);
  if (rc != 0) {
    return throw_err(env, (e == EEXIST || e == ENOTEMPTY)
      ? "root_session_no_replace_conflict" : "root_session_native_unavailable", "renameat2 RENAME_NOREPLACE failed");
  }
#endif
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_remove_entry(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  std::string rel;
  if (argc < 1 || !get_utf8(env, argv[0], rel)) return throw_err(env, "root_session_unsafe_traversal", "Invalid path");
  std::vector<std::string> parts;
  if (!split_safe_rel(rel, parts)) return throw_err(env, "root_session_unsafe_traversal", "Unsafe path");
#ifdef _WIN32
  std::wstring target = s->resolve_contained(parts, false);
  if (target.empty()) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  HANDLE h = CreateFileW(target.c_str(), DELETE | FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (h == INVALID_HANDLE_VALUE) return throw_err(env, "root_session_native_unavailable", "Open for delete failed");
  FILE_ATTRIBUTE_TAG_INFO tag{};
  BY_HANDLE_FILE_INFORMATION b{};
  if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof(tag))
      || !GetFileInformationByHandle(h, &b)
      || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      || (!(b.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && b.nNumberOfLinks != 1)) {
    CloseHandle(h); return throw_err(env, "root_session_unsafe_traversal", "Refusing unsafe remove");
  }
  FILE_DISPOSITION_INFO disp{}; disp.DeleteFile = TRUE;
  bool ok = SetFileInformationByHandle(h, FileDispositionInfo, &disp, sizeof(disp)) != 0;
  CloseHandle(h);
  if (!ok) return throw_err(env, "root_session_native_unavailable", "Remove failed");
#else
  std::string leaf;
  int pfd = s->open_parent_dir(parts, false, leaf);
  if (pfd < 0) return throw_err(env, "root_session_unsafe_traversal", "Untrusted parent");
  int rc = unlinkat(pfd, leaf.c_str(), 0);
  if (rc != 0 && errno == EISDIR) rc = unlinkat(pfd, leaf.c_str(), AT_REMOVEDIR);
  if (rc == 0) (void)fsync(pfd);
  close(pfd);
  if (rc != 0) return throw_err(env, "root_session_native_unavailable", "unlinkat failed");
#endif
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_sync_file_or_dir(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{}; napi_value self{};
  napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  if (!s->verify_custody()) return throw_err(env, "root_session_root_identity_changed", "Root identity changed");
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_reacquire_root(napi_env env, napi_callback_info info) {
  napi_value self{}; size_t argc = 0;
  napi_get_cb_info(env, info, &argc, nullptr, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  if (!s->verify_custody()) return throw_err(env, "root_session_cold_reopen_unverified", "Root identity mismatch");
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_commit_durable_recovery(napi_env env, napi_callback_info info) {
  napi_value self{}; size_t argc = 0;
  napi_get_cb_info(env, info, &argc, nullptr, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
  if (!s->verify_custody()) return throw_err(env, "root_session_durability_indeterminate", "Custody lost");
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_close(napi_env env, napi_callback_info info) {
  napi_value self{}; size_t argc = 0;
  napi_get_cb_info(env, info, &argc, nullptr, &self, nullptr);
  bool matches = false;
  if (napi_check_object_type_tag(env, self, &kRootSessionTag, &matches) != napi_ok || !matches) {
    return throw_err(env, "root_session_unverified_authority", "Invalid session");
  }
  NativeSession* s = nullptr;
  if (napi_unwrap(env, self, reinterpret_cast<void**>(&s)) == napi_ok && s) s->close_all();
  napi_value out; napi_get_boolean(env, true, &out); return out;
}

napi_value fn_cfapi_connect(napi_env env, napi_callback_info info) {
  napi_value self{}; size_t argc = 0;
  napi_get_cb_info(env, info, &argc, nullptr, &self, nullptr);
  NativeSession* s = unwrap_session(env, self);
  if (!s) return nullptr;
#ifdef _WIN32
  if (s->cf_connected) { napi_value out; napi_get_boolean(env, true, &out); return out; }
  CF_SYNC_REGISTRATION reg{};
  reg.StructSize = sizeof(reg);
  reg.ProviderName = L"RootArkSync";
  reg.ProviderVersion = L"1.0";
  reg.ProviderId = { 0x8b6e4c11, 0x3f22, 0x4a91, { 0x91, 0x22, 0x7a, 0x4b, 0x10, 0x88, 0x01, 0x66 } };
  CF_SYNC_POLICIES pol{};
  pol.StructSize = sizeof(pol);
  pol.Hydration.Primary = CF_HYDRATION_POLICY_FULL;
  pol.Population.Primary = CF_POPULATION_POLICY_PARTIAL;
  pol.InSync = CF_INSYNC_POLICY_PRESERVE_INSYNC_FOR_SYNC_ENGINE;
  pol.HardLink = CF_HARDLINK_POLICY_NONE;
  HRESULT hr = CfRegisterSyncRoot(s->root_path.c_str(), &reg, &pol, CF_REGISTER_FLAG_UPDATE);
  if (FAILED(hr)) return throw_err(env, "root_session_native_unavailable", "CfRegisterSyncRoot failed");
  CF_CALLBACK_REGISTRATION cbs[] = { CF_CALLBACK_REGISTRATION_END };
  hr = CfConnectSyncRoot(s->root_path.c_str(), cbs, s, CF_CONNECT_FLAG_NONE, &s->cf_conn);
  if (FAILED(hr)) {
    CfUnregisterSyncRoot(s->root_path.c_str());
    return throw_err(env, "root_session_native_unavailable", "CfConnectSyncRoot failed");
  }
  s->cf_connected = true;
  s->cf_root = s->root_path;
  napi_value out; napi_get_boolean(env, true, &out); return out;
#else
  return throw_err(env, "root_session_native_unavailable", "CFAPI is Windows-only");
#endif
}

napi_value fn_open_root(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{};
  napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
  std::string root_path;
  if (argc < 1 || !get_utf8(env, argv[0], root_path))
    return throw_err(env, "root_session_untrusted_root", "Root path string required");

  auto session = std::make_unique<NativeSession>();
  if (!session->open_root(root_path)) {
    return throw_err(env, "root_session_untrusted_root", "Failed to pin native root and ancestors");
  }

  napi_value obj{};
  if (napi_create_object(env, &obj) != napi_ok) return nullptr;
  NativeSession* raw = session.release();
  if (napi_wrap(env, obj, raw, finalize_session, nullptr, nullptr) != napi_ok) {
    delete raw;
    return nullptr;
  }
  if (napi_type_tag_object(env, obj, &kRootSessionTag) != napi_ok) return nullptr;

  const napi_property_descriptor props[] = {
    { "openChildDirectory", nullptr, fn_open_child_dir, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "enumerateDirectory", nullptr, fn_enumerate_dir, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "openContainedFile", nullptr, fn_open_contained_file, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "readOpenedFile", nullptr, fn_read_opened_file, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "createExclusiveFile", nullptr, fn_create_exclusive, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "renameNoReplace", nullptr, fn_rename_no_replace, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "removeEntry", nullptr, fn_remove_entry, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "syncOpenedFile", nullptr, fn_sync_file_or_dir, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "syncDirectory", nullptr, fn_sync_file_or_dir, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "reacquireRoot", nullptr, fn_reacquire_root, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "commitDurableRecovery", nullptr, fn_commit_durable_recovery, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "close", nullptr, fn_close, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "cfapiConnect", nullptr, fn_cfapi_connect, nullptr, nullptr, nullptr, napi_default, nullptr },
  };
  napi_define_properties(env, obj, sizeof(props) / sizeof(props[0]), props);
  return obj;
}

napi_value fn_is_verified(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value argv[1]{};
  napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
  bool matches = false;
  if (argc >= 1) {
    napi_valuetype t;
    if (napi_typeof(env, argv[0], &t) == napi_ok && t == napi_object) {
      if (napi_check_object_type_tag(env, argv[0], &kRootSessionTag, &matches) != napi_ok) matches = false;
      if (matches) {
        NativeSession* s = nullptr;
        if (napi_unwrap(env, argv[0], reinterpret_cast<void**>(&s)) != napi_ok || !s || s->closed) matches = false;
      }
    }
  }
  napi_value out; napi_get_boolean(env, matches, &out); return out;
}

napi_value init(napi_env env, napi_value exports) {
  const napi_property_descriptor props[] = {
    { "openRootFromTrustedParent", nullptr, fn_open_root, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "isVerifiedSession", nullptr, fn_is_verified, nullptr, nullptr, nullptr, napi_default, nullptr },
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]), props);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

} // namespace
