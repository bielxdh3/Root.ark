#include "rootark-sync-windows-cfapi-root-policy.hpp"

int wmain(int argc, wchar_t** argv) {
  if (argc != 3 || (std::wcscmp(argv[1], L"--inspect") != 0
      && std::wcscmp(argv[1], L"--enumerate") != 0)) return 2;
  const bool enumerate = std::wcscmp(argv[1], L"--enumerate") == 0;
  DWORD platformBuild = 0;
  std::uint64_t count = 0;
  const bool accepted = inspect(argv[2], platformBuild, enumerate, &count);
  std::printf("{\"aclPreflightPassed\":%s,\"handleIdentityCaptured\":%s,"
    "\"platformBuild\":%lu,\"nativeEnumerationInformational\":%s,"
    "\"directoryEntriesEnumerated\":%llu,\"syncRootRegistered\":false,"
    "\"cloudDataBytesTransferred\":0}\n",
    accepted ? "true" : "false", accepted ? "true" : "false", platformBuild,
    enumerate && accepted ? "true" : "false",
    static_cast<unsigned long long>(accepted ? count : 0));
  return accepted ? 0 : 4;
}
