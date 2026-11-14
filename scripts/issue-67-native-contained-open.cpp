// #67 / PR #298: standalone, READ-ONLY, Windows NTFS containment experiment.
// Never use this as a rollback/no-clobber authorization. No production caller
// consumes the handles, and existing writable mappings are NOT fenced.
// A trusted caller must persist/pin the root FileIdInfo fingerprint externally.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cwchar>
#include <cwctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {
bool fail(const char* stage) {
  if (GetEnvironmentVariableA("ROOTARK_ISSUE67_DEBUG", nullptr, 0) != 0)
    std::fprintf(stderr, "native-contained-open failed at %s (win32=%lu)\n", stage, GetLastError());
  return false;
}

using NtCreateFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

class Handle {
 public:
  explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
  ~Handle() { if (valid()) CloseHandle(h_); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : h_(std::exchange(other.h_, INVALID_HANDLE_VALUE)) {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (valid()) CloseHandle(h_);
      h_ = std::exchange(other.h_, INVALID_HANDLE_VALUE);
    }
    return *this;
  }
  bool valid() const { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }
  HANDLE get() const { return h_; }
 private:
  HANDLE h_;
};

struct Opened {
  Handle handle;
  FILE_ID_INFO identity{};
  bool directory = false;
  Opened(Handle&& h, const FILE_ID_INFO& id, bool dir)
      : handle(std::move(h)), identity(id), directory(dir) {}
  Opened(Opened&&) noexcept = default;
  Opened& operator=(Opened&&) noexcept = default;
  Opened(const Opened&) = delete;
};

bool sameIdentity(const FILE_ID_INFO& left, const FILE_ID_INFO& right) {
  return left.VolumeSerialNumber == right.VolumeSerialNumber
      && std::memcmp(left.FileId.Identifier, right.FileId.Identifier, sizeof(left.FileId.Identifier)) == 0;
}

std::string fingerprint(const FILE_ID_INFO& id) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0') << std::setw(16) << id.VolumeSerialNumber;
  for (unsigned char byte : id.FileId.Identifier)
    stream << std::setw(2) << static_cast<unsigned>(byte);
  return stream.str();
}

bool validSegment(const std::wstring& part) {
  if (part.empty() || part == L"." || part == L".." || part.size() > 255
      || part.back() == L' ' || part.back() == L'.') return false;
  for (wchar_t c : part) {
    if (c < 32 || c == 127 || c == L'<' || c == L'>' || c == L':'
        || c == L'"' || c == L'/' || c == L'\\' || c == L'|'
        || c == L'?' || c == L'*') return false;
  }
  // Forbid Win32 device spellings, including names with ordinary extensions.
  const auto dot = part.find(L'.');
  std::wstring base = part.substr(0, dot);
  for (wchar_t& c : base) c = static_cast<wchar_t>(std::towupper(c));
  if (base == L"CON" || base == L"PRN" || base == L"AUX" || base == L"NUL"
      || base == L"CONIN$" || base == L"CONOUT$") return false;
  if (base.size() == 4 && (base.substr(0, 3) == L"COM" || base.substr(0, 3) == L"LPT")
      && base[3] >= L'1' && base[3] <= L'9') return false;
  return true;
}

bool components(const std::wstring& input, bool relative, std::vector<std::wstring>& out) {
  if (input.empty() || (!relative && input.size() < 3)) return false;
  // Only a drive-letter absolute root is supported; UNC, volume aliases,
  // NT object names, rooted-relative paths and drive-relative paths fail.
  if (!relative && (!std::iswalpha(input[0]) || input[1] != L':'
      || input[2] != L'\\')) return false;
  if (relative && (input[0] == L'\\' || input[0] == L'/' || input.find(L':') != std::wstring::npos))
    return false;
  const std::size_t start = relative ? 0 : 3;
  if (start == input.size()) return !relative;
  std::size_t pos = start;
  while (pos < input.size()) {
    const auto end = input.find(L'\\', pos);
    const auto finalEnd = end == std::wstring::npos ? input.size() : end;
    const auto part = input.substr(pos, finalEnd - pos);
    if (!validSegment(part)) return false;
    out.push_back(part);
    if (end == std::wstring::npos) return true;
    pos = end + 1;
  }
  return false; // no trailing separator or empty component
}

bool inspectHandle(HANDLE h, bool directory, FILE_ID_INFO& identity) {
  FILE_ATTRIBUTE_TAG_INFO tags{};
  FILE_STANDARD_INFO standard{};
  if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tags, sizeof(tags)))
    return fail("attribute-tag");
  if (!GetFileInformationByHandleEx(h, FileStandardInfo, &standard, sizeof(standard)))
    return fail("standard-info");
  if (!GetFileInformationByHandleEx(h, FileIdInfo, &identity, sizeof(identity)))
    return fail("fileid");
  if ((tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || ((tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory
      || standard.DeletePending || (directory && standard.NumberOfLinks == 0)
      || (!directory && standard.NumberOfLinks != 1)) return fail("attributes-or-links");
  return true;
}

bool appendOpened(std::vector<Opened>& chain, Handle&& handle, bool directory) {
  FILE_ID_INFO id{};
  if (!handle.valid() || !inspectHandle(handle.get(), directory, id)) return fail("append");
  // All opened nodes must be on the same NTFS volume as the drive root.
  if (!chain.empty() && id.VolumeSerialNumber != chain.front().identity.VolumeSerialNumber)
    return fail("volume-mismatch");
  chain.emplace_back(std::move(handle), id, directory);
  return true;
}

bool verifyChain(const std::vector<Opened>& chain) {
  for (const auto& node : chain) {
    FILE_ID_INFO now{};
    if (!inspectHandle(node.handle.get(), node.directory, now)
        || !sameIdentity(now, node.identity)) return false;
  }
  return true;
}

bool relativeOpen(NtCreateFileFn native, HANDLE parent, const std::wstring& part,
    bool directory, Handle& result) {
  if (!validSegment(part) || part.size() * sizeof(wchar_t) > USHRT_MAX) return false;
  UNICODE_STRING name{};
  name.Length = static_cast<USHORT>(part.size() * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  name.Buffer = const_cast<PWSTR>(part.c_str());
  OBJECT_ATTRIBUTES attributes{};
  // A single validated segment has no intermediate component to reparse.
  // FILE_OPEN_REPARSE_POINT opens the leaf reparse object itself for rejection.
  InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, parent, nullptr);
  IO_STATUS_BLOCK io{};
  HANDLE opened = INVALID_HANDLE_VALUE;
  const ACCESS_MASK access = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
      | (directory ? FILE_TRAVERSE : FILE_READ_DATA);
  // Missing FILE_SHARE_DELETE pins the entire ancestor chain against rename,
  // unlink and junction replacement. Missing FILE_SHARE_WRITE on the leaf
  // rejects open ordinary writers; it cannot fence pre-existing mapped views.
  const ULONG sharing = FILE_SHARE_READ | (directory ? FILE_SHARE_WRITE : 0);
  // FILE_DIRECTORY_FILE is incompatible with FILE_OPEN_REPARSE_POINT and
  // FILE_OPEN_NO_RECALL; the returned attributes independently enforce that
  // each intermediate object is a real, non-reparse directory.
  const ULONG options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
      | (directory ? 0 : (FILE_OPEN_NO_RECALL | FILE_NON_DIRECTORY_FILE));
  const NTSTATUS status = native(&opened, access, &attributes, &io, nullptr,
      FILE_ATTRIBUTE_NORMAL, sharing, FILE_OPEN, options, nullptr, 0);
  if (status < 0 || opened == INVALID_HANDLE_VALUE || opened == nullptr) {
    if (GetEnvironmentVariableA("ROOTARK_ISSUE67_DEBUG", nullptr, 0) != 0)
      std::fprintf(stderr, "ntcreate failed status=0x%08lx\n", static_cast<unsigned long>(status));
    return false;
  }
  result = Handle(opened);
  return true;
}

bool walk(NtCreateFileFn native, const std::wstring& root,
    const std::wstring* relative, const std::string* expectedRoot,
    unsigned holdMs, std::string& observedRoot) {
  std::vector<std::wstring> rootSegments;
  if (!components(root, false, rootSegments)) return fail("root-components");
  std::vector<std::wstring> leafSegments;
  if (relative && !components(*relative, true, leafSegments)) return fail("leaf-components");
  const std::wstring volumeRoot = root.substr(0, 3);
  std::vector<Opened> chain;
  chain.reserve(1 + rootSegments.size() + leafSegments.size());
  Handle volume(CreateFileW(volumeRoot.c_str(),
      FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!appendOpened(chain, std::move(volume), true)) return fail("volume-open");
  wchar_t filesystem[64]{};
  if (!GetVolumeInformationByHandleW(chain.front().handle.get(), nullptr, 0,
      nullptr, nullptr, nullptr, filesystem, 64)
      || _wcsicmp(filesystem, L"NTFS") != 0) return fail("filesystem");

  for (const auto& part : rootSegments) {
    Handle next;
    if (!relativeOpen(native, chain.back().handle.get(), part, true, next)
        || !appendOpened(chain, std::move(next), true)) return fail("root-segment");
  }
  observedRoot = fingerprint(chain.back().identity);
  if (expectedRoot && *expectedRoot != observedRoot) return fail("root-identity");
  for (std::size_t i = 0; i < leafSegments.size(); ++i) {
    const bool directory = i + 1 != leafSegments.size();
    Handle next;
    if (!relativeOpen(native, chain.back().handle.get(), leafSegments[i], directory, next)
        || !appendOpened(chain, std::move(next), directory)) return fail("leaf-segment");
  }
  if (!verifyChain(chain)) return fail("initial-verification");
  if (holdMs != 0) {
    // Only a disposable test synchronization signal. No path or content leak.
    std::fputs("READY\n", stderr);
    std::fflush(stderr);
    Sleep(holdMs);
  }
  return verifyChain(chain) || fail("final-verification");
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  if ((argc != 3 || std::wcscmp(argv[1], L"--fingerprint") != 0)
      && (argc != 5 && argc != 7)) return 2;
  const bool fingerprintOnly = std::wcscmp(argv[1], L"--fingerprint") == 0;
  if (!fingerprintOnly && std::wcscmp(argv[1], L"--open") != 0) return 2;
  unsigned holdMs = 0;
  if (!fingerprintOnly && argc == 7) {
    if (std::wcscmp(argv[5], L"--hold-ms") != 0) return 2;
    wchar_t* end = nullptr;
    const unsigned long value = std::wcstoul(argv[6], &end, 10);
    if (!end || *end != L'\0' || value == 0 || value > 5000) return 2;
    holdMs = static_cast<unsigned>(value);
  }
  const HMODULE module = GetModuleHandleW(L"ntdll.dll");
  const auto native = module
      ? reinterpret_cast<NtCreateFileFn>(GetProcAddress(module, "NtCreateFile"))
      : nullptr;
  if (!native) return 3;
  std::string observedRoot;
  std::string expected;
  if (!fingerprintOnly) {
    for (wchar_t c : std::wstring(argv[4])) {
      if (c > 127) return 2;
      expected.push_back(static_cast<char>(c));
    }
    if (expected.size() != 48) return 2;
    for (char c : expected)
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 2;
  }
  const std::wstring relative = fingerprintOnly ? L"" : std::wstring(argv[3]);
  const bool ok = walk(native, argv[2], fingerprintOnly ? nullptr : &relative,
      fingerprintOnly ? nullptr : &expected, holdMs, observedRoot);
  if (!ok) {
    std::puts("{\"ok\":false}");
    return 4;
  }
  if (fingerprintOnly) {
    std::printf("{\"ok\":true,\"rootId\":\"%s\"}\n", observedRoot.c_str());
  } else {
    std::puts("{\"ok\":true,\"contained\":true,\"fileContentRead\":false,\"fileWritten\":false}");
  }
  return 0;
}
