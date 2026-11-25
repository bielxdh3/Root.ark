#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

// Isolated research lab only. ProcessImageFileMapping (44) is an undocumented
// NT information class. Fail closed if the OS does not support it.
using QueryProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool mappedExecutableSectionsMatch(HANDLE pinned, HANDLE process, QueryProcess query) {
  static_assert(sizeof(void*) == 8, "lab is x64 only");
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(pinned, &size) || size.QuadPart <= 0 || size.QuadPart > 64 * 1024 * 1024) {
    std::printf("IMAGE_SECTION_FAILURE:SIZE\n");
    return false;
  }
  LARGE_INTEGER start{};
  if (!SetFilePointerEx(pinned, start, nullptr, FILE_BEGIN)) return false;
  std::vector<BYTE> raw(static_cast<size_t>(size.QuadPart));
  DWORD got = 0;
  if (!ReadFile(pinned, raw.data(), static_cast<DWORD>(raw.size()), &got, nullptr)
      || got != raw.size() || raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
  IMAGE_DOS_HEADER mz{};
  std::memcpy(&mz, raw.data(), sizeof(mz));
  if (mz.e_magic != IMAGE_DOS_SIGNATURE || mz.e_lfanew < sizeof(mz)
      || static_cast<size_t>(mz.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > raw.size()) return false;
  IMAGE_NT_HEADERS64 ntHeaders{};
  std::memcpy(&ntHeaders, raw.data() + mz.e_lfanew, sizeof(ntHeaders));
  const auto* nt = &ntHeaders;
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
      || nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)
      || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || nt->FileHeader.NumberOfSections == 0
      || nt->FileHeader.NumberOfSections > 96) return false;
  const size_t headerOffset = static_cast<size_t>(mz.e_lfanew) + sizeof(DWORD)
    + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
  if (headerOffset + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > raw.size()) return false;
  PROCESS_BASIC_INFORMATION info{};
  if (query(process, ProcessBasicInformation, &info, sizeof(info), nullptr) != 0
      || !info.PebBaseAddress) { std::printf("IMAGE_SECTION_FAILURE:PEB\n"); return false; }
  // PEB.ImageBaseAddress is at offset 0x10 on x64; no execution has resumed.
  PVOID imageBase = nullptr;
  SIZE_T count = 0;
  const BYTE* remotePeb = reinterpret_cast<const BYTE*>(info.PebBaseAddress);
  if (!ReadProcessMemory(process, remotePeb + 0x10, &imageBase, sizeof(imageBase), &count)
      || count != sizeof(imageBase) || !imageBase) {
    std::printf("IMAGE_SECTION_FAILURE:IMAGE_BASE error=%lu\n", GetLastError());
    return false;
  }
  const auto rvaToOffset = [&](DWORD rva, size_t span, size_t& out) -> bool {
    for (unsigned j = 0; j < nt->FileHeader.NumberOfSections; ++j) {
      IMAGE_SECTION_HEADER section{};
      std::memcpy(&section, raw.data() + headerOffset + j * sizeof(section), sizeof(section));
      if (rva < section.VirtualAddress) continue;
      const size_t offset = static_cast<size_t>(rva) - section.VirtualAddress;
      if (offset > section.SizeOfRawData || span > section.SizeOfRawData - offset) continue;
      if (section.PointerToRawData > raw.size()
          || offset > raw.size() - section.PointerToRawData
          || span > raw.size() - section.PointerToRawData - offset) return false;
      out = section.PointerToRawData + offset;
      return true;
    }
    return false;
  };
  const IMAGE_DATA_DIRECTORY reloc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  const ULONGLONG delta = reinterpret_cast<ULONGLONG>(imageBase) - nt->OptionalHeader.ImageBase;
  bool examined = false;
  for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    IMAGE_SECTION_HEADER section{};
    std::memcpy(&section, raw.data() + headerOffset + i * sizeof(section), sizeof(section));
    if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
    examined = true;
    const size_t span = std::min(section.Misc.VirtualSize, section.SizeOfRawData);
    if (span == 0 || section.PointerToRawData > raw.size()
        || span > raw.size() - section.PointerToRawData
        || section.VirtualAddress >= nt->OptionalHeader.SizeOfImage
        || span > nt->OptionalHeader.SizeOfImage - section.VirtualAddress) return false;
    std::vector<BYTE> expected(span);
    std::memcpy(expected.data(), raw.data() + section.PointerToRawData, span);
    if (delta != 0 && reloc.Size > 0) {
      size_t relocIndex = 0;
      while (relocIndex < reloc.Size) {
        if (reloc.Size - relocIndex < sizeof(IMAGE_BASE_RELOCATION)
            || reloc.VirtualAddress > UINT32_MAX - relocIndex) return false;
        size_t blockOffset = 0;
        if (!rvaToOffset(reloc.VirtualAddress + static_cast<DWORD>(relocIndex),
            sizeof(IMAGE_BASE_RELOCATION), blockOffset)) return false;
        IMAGE_BASE_RELOCATION header{};
        std::memcpy(&header, raw.data() + blockOffset, sizeof(header));
        if (header.SizeOfBlock < sizeof(header) || header.SizeOfBlock > reloc.Size - relocIndex
            || ((header.SizeOfBlock - sizeof(header)) % sizeof(WORD)) != 0
            || header.SizeOfBlock > 1'000'000) return false;
        size_t fullBlock = 0;
        if (!rvaToOffset(reloc.VirtualAddress + static_cast<DWORD>(relocIndex),
            header.SizeOfBlock, fullBlock)) return false;
        for (size_t pos = sizeof(header); pos < header.SizeOfBlock; pos += sizeof(WORD)) {
          WORD word = 0;
          std::memcpy(&word, raw.data() + fullBlock + pos, sizeof(word));
          if (header.VirtualAddress > UINT32_MAX - (word & 0x0fff)) return false;
          const DWORD relocRva = header.VirtualAddress + (word & 0x0fff);
          const WORD type = word >> 12;
          if (relocRva < section.VirtualAddress
              || static_cast<size_t>(relocRva - section.VirtualAddress) >= span) continue;
          if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
          if (type != IMAGE_REL_BASED_DIR64) return false;
          const size_t relative = relocRva - section.VirtualAddress;
          if (relative + sizeof(ULONGLONG) > span) return false;
          ULONGLONG before = 0;
          std::memcpy(&before, expected.data() + relative, sizeof(before));
          before += delta;
          std::memcpy(expected.data() + relative, &before, sizeof(before));
        }
        relocIndex += header.SizeOfBlock;
      }
    }
    std::vector<BYTE> mapped(span);
    count = 0;
    if (!ReadProcessMemory(process,
        reinterpret_cast<const BYTE*>(imageBase) + section.VirtualAddress,
        mapped.data(), mapped.size(), &count) || count != mapped.size()) {
      std::printf("IMAGE_SECTION_FAILURE:READ code=%lu size=%zu got=%zu\n",
        GetLastError(), mapped.size(), static_cast<size_t>(count));
      return false;
    }
    if (std::memcmp(mapped.data(), expected.data(), span) != 0) {
      size_t first = 0;
      for (; first < span; ++first) {
        if (mapped[first] != expected[first]) break;
      }
      std::printf("IMAGE_SECTION_FAILURE:BYTES section=%u offset=%zu raw=%02x mapped=%02x\n",
        i, first, expected[first], mapped[first]);
      return false;
    }
  }
  return examined;
}

int wmain(int argc, wchar_t** argv) {
  if (argc != 3) return 64;
  // This is NOT a general-purpose launcher. Only compare two immutable
  // OS-provided test binaries; never accept a caller-chosen executable.
  const bool expectedAllowed = _wcsicmp(argv[1], L"C:\\Windows\\System32\\whoami.exe") == 0
    || _wcsicmp(argv[1], L"C:\\Windows\\System32\\hostname.exe") == 0;
  if (!expectedAllowed || _wcsicmp(argv[2], L"C:\\Windows\\System32\\whoami.exe") != 0)
    return 64;
  HANDLE trusted = CreateFileW(argv[1], FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (trusted == INVALID_HANDLE_VALUE) {
    std::printf("OPEN_FAILED:%lu\n", GetLastError());
    return 65;
  }
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto query = ntdll ? reinterpret_cast<QueryProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess")) : nullptr;
  if (!query) { CloseHandle(trusted); return 66; }
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  std::wstring command = L"\"" + std::wstring(argv[2]) + L"\"";
  if (!CreateProcessW(argv[2], command.data(), nullptr, nullptr, FALSE,
      CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
    std::printf("CREATE_FAILED:%lu\n", GetLastError());
    CloseHandle(trusted);
    return 67;
  }
  // ProcessImageFileMapping compares the executable image's file object,
  // not path spelling or content read from a reopened pathname.
  const NTSTATUS status = query(pi.hProcess, static_cast<PROCESSINFOCLASS>(44),
    &trusted, sizeof(trusted), nullptr);
  std::printf("NTSTATUS:%08lx\n", static_cast<unsigned long>(status));
  int result = 68;
  if (status == 0) {
    const bool verified = mappedExecutableSectionsMatch(trusted, pi.hProcess, query);
    std::printf("EXECUTABLE_SECTIONS_MATCH:%d\n", verified ? 1 : 0);
    // Probe only: NEVER ResumeThread. No argv can authorize execution.
    result = verified ? 0 : 71;
  }
  TerminateProcess(pi.hProcess, 1);
  WaitForSingleObject(pi.hProcess, 1000);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  CloseHandle(trusted);
  return result;
}
