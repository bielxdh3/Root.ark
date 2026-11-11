// PR298 / Issue67: Windows NTFS LAB, not a production writer.
// Publish an already-open source HANDLE into an already-open destination
// directory HANDLE via FileLinkInfo/RootDirectory, with no replace and no
// pathname cleanup. A second process can move both original names after READY.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <utility>
#include <vector>

namespace {
using NtOpenFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
using NtSetInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK,
    PVOID, ULONG, FILE_INFORMATION_CLASS);
using RtlNtStatusToDosErrorFn = ULONG(NTAPI*)(NTSTATUS);
// FileLinkInformation (11), documented by the NT file-information contract.
// This layout is deliberately private to the isolated native LAB: Windows SDK
// 10.0.26100 exposes no Win32 FileLinkInfo / FILE_LINK_INFO in minwinbase.h.
struct LinkInformation {
  BOOLEAN replaceIfExists;
  HANDLE rootDirectory;
  ULONG nameLength;
  WCHAR name[1];
};
constexpr auto kFileLinkInformation = static_cast<FILE_INFORMATION_CLASS>(11);

class Handle {
 public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle() { if (valid()) CloseHandle(value_); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (valid()) CloseHandle(value_);
      value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
    }
    return *this;
  }
  bool valid() const { return value_ != INVALID_HANDLE_VALUE && value_ != nullptr; }
  HANDLE get() const { return value_; }
 private:
  HANDLE value_;
};

bool segment(const std::wstring& name) {
  if (name.empty() || name.size() > 200 || name == L"." || name == L"..") return false;
  if (name.back() == L'.' || name.back() == L' ') return false;
  for (wchar_t c : name) {
    if ((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
        (c >= L'0' && c <= L'9') || c == L'-' || c == L'_' || c == L'.') continue;
    return false;
  }
  const auto dot = name.find(L'.');
  std::wstring base = name.substr(0, dot);
  for (auto& c : base) if (c >= L'a' && c <= L'z') c -= L'a' - L'A';
  if (base == L"CON" || base == L"PRN" || base == L"AUX" || base == L"NUL") return false;
  if (base.size() == 4 && (base.substr(0, 3) == L"COM" || base.substr(0, 3) == L"LPT")
      && base[3] >= L'1' && base[3] <= L'9') return false;
  return true;
}

int fail(const char* stage, int exitCode, DWORD error, bool published = false) {
  std::fprintf(stderr, "ERROR stage=%s win32=%lu published=%d durability=%s\n",
      stage, static_cast<unsigned long>(error), published ? 1 : 0,
      published ? "unknown" : "none");
  return exitCode;
}

bool info(HANDLE handle, bool directory, FILE_ID_INFO& id) {
  FILE_STANDARD_INFO standard{};
  FILE_ATTRIBUTE_TAG_INFO attr{};
  if (!GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id))
      || !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard))
      || !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attr, sizeof(attr))) return false;
  return !standard.DeletePending &&
      ((attr.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
      (attr.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool same(const FILE_ID_INFO& a, const FILE_ID_INFO& b) {
  return a.VolumeSerialNumber == b.VolumeSerialNumber &&
      std::memcmp(a.FileId.Identifier, b.FileId.Identifier, sizeof(a.FileId.Identifier)) == 0;
}

bool openRelative(NtOpenFileFn ntOpen, HANDLE parent, const std::wstring& basename,
    Handle& result) {
  UNICODE_STRING name{};
  name.Buffer = const_cast<PWSTR>(basename.c_str());
  name.Length = static_cast<USHORT>(basename.length() * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  OBJECT_ATTRIBUTES attributes{};
  InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, parent, nullptr);
  IO_STATUS_BLOCK io{};
  HANDLE output = INVALID_HANDLE_VALUE;
  NTSTATUS status = ntOpen(&output, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes,
      &io, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT);
  if (status < 0 || output == INVALID_HANDLE_VALUE || output == nullptr) {
    std::fprintf(stderr, "RELATIVE_OPEN_NTSTATUS=0x%08lx\n", static_cast<unsigned long>(status));
    return false;
  }
  result = Handle(output);
  return true;
}

bool gate() {
  if (std::fputs("READY\n", stdout) == EOF || std::fflush(stdout) != 0) return false;
  return std::getchar() == 'G';
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc != 4 || !segment(argv[3])) return fail("invalid-basename", 2, ERROR_INVALID_NAME);
  const std::wstring src = argv[1];
  const std::wstring dir = argv[2];
  // Even the raw names are only allowed for the initial opens. After READY,
  // neither src nor dir is referenced by any native syscall.
  Handle file(CreateFileW(src.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE |
      FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!file.valid()) return fail("open-source", 20, GetLastError());
  Handle parent(CreateFileW(dir.c_str(), FILE_ADD_FILE | FILE_LIST_DIRECTORY |
      FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!parent.valid()) return fail("open-parent", 21, GetLastError());

  FILE_ID_INFO source{}, directory{};
  if (!info(file.get(), false, source) || !info(parent.get(), true, directory))
    return fail("fileid-or-attrs", 22, GetLastError());
  if (source.VolumeSerialNumber != directory.VolumeSerialNumber)
    return fail("cross-volume", 23, ERROR_NOT_SAME_DEVICE);
  wchar_t filesystem[64]{};
  if (!GetVolumeInformationByHandleW(parent.get(), nullptr, 0, nullptr,
          nullptr, nullptr, filesystem, 64) || _wcsicmp(filesystem, L"NTFS") != 0)
    return fail("filesystem-not-ntfs", 24, GetLastError());

  if (!FlushFileBuffers(file.get())) return fail("source-flush", 25, GetLastError());
  if (!gate()) return fail("gate", 26, ERROR_CANCELLED);
  FILE_ID_INFO sourceNow{}, directoryNow{};
  if (!info(file.get(), false, sourceNow) || !info(parent.get(), true, directoryNow)
      || !same(source, sourceNow) || !same(directory, directoryNow))
    return fail("held-identity-changed", 27, GetLastError());

  const DWORD nameSize = static_cast<DWORD>(std::wcslen(argv[3]) * sizeof(wchar_t));
  std::vector<BYTE> bytes(FIELD_OFFSET(LinkInformation, name) + nameSize);
  auto* link = reinterpret_cast<LinkInformation*>(bytes.data());
  std::memset(link, 0, bytes.size());
  link->replaceIfExists = FALSE;
  link->rootDirectory = parent.get();
  link->nameLength = nameSize;
  std::memcpy(link->name, argv[3], nameSize);
  auto* ntdll = GetModuleHandleW(L"ntdll.dll");
  auto* ntSet = ntdll ? reinterpret_cast<NtSetInformationFileFn>(
      GetProcAddress(ntdll, "NtSetInformationFile")) : nullptr;
  auto* toWin32 = ntdll ? reinterpret_cast<RtlNtStatusToDosErrorFn>(
      GetProcAddress(ntdll, "RtlNtStatusToDosError")) : nullptr;
  if (!ntSet || !toWin32) return fail("native-api-unavailable", 28, ERROR_PROC_NOT_FOUND);
  IO_STATUS_BLOCK setIo{};
  const NTSTATUS setStatus = ntSet(file.get(), &setIo, link,
      static_cast<ULONG>(bytes.size()), kFileLinkInformation);
  if (setStatus < 0) {
    const DWORD error = toWin32(setStatus);
    std::fprintf(stderr, "NATIVE_FILELINK_NTSTATUS=0x%08lx\n",
        static_cast<unsigned long>(setStatus));
    if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)
      return fail("no-replace", 17, error);
    return fail("ntset-filelink", 28, error);
  }

  // Query the published entry by native relative open against held parent,
  // NOT using a composed pathname that might now resolve into a decoy dir.
  auto* ntOpen = reinterpret_cast<NtOpenFileFn>(GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "NtOpenFile"));
  Handle published;
  if (!ntOpen || !openRelative(ntOpen, parent.get(), argv[3], published))
    return fail("relative-verify-unavailable", 85, GetLastError(), true);
  FILE_ID_INFO publishedId{};
  if (!info(published.get(), false, publishedId) || !same(publishedId, source))
    return fail("published-fileid-mismatch", 85, GetLastError(), true);

  // NTFS does not promise a portable directory FlushFileBuffers contract;
  // report an explicit ambiguous checkpoint instead of pretending durable ACK.
  // LAB-only fault injection proves that an ambiguous published state cannot
  // trigger cleanup through names after an adversary has replaced the source.
  wchar_t simulatedFailure[2]{};
  if (GetEnvironmentVariableW(L"ROOTARK_LAB_FORCE_PARENT_FLUSH_FAILURE",
          simulatedFailure, 2) == 1 && simulatedFailure[0] == L'1')
    return fail("simulated-parent-flush", 85, ERROR_WRITE_FAULT, true);
  if (!FlushFileBuffers(parent.get()))
    return fail("parent-flush", 85, GetLastError(), true);

  std::printf("PUBLISHED same_fileid=1 source_flush=ok parent_flush=ok\n");
  return 0;
}
