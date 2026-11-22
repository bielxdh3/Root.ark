#include "rootark-sync-windows-native-root-session.hpp"

int wmain(int argc, wchar_t** argv) {
  if (argc != 3 || (std::wcscmp(argv[1], L"--inspect") != 0
      && std::wcscmp(argv[1], L"--enumerate") != 0
      && std::wcscmp(argv[1], L"--native-session-inspect") != 0)) return 2;
  const bool enumerate = std::wcscmp(argv[1], L"--enumerate") == 0;
  const bool nativeSession = std::wcscmp(argv[1], L"--native-session-inspect") == 0;
  DWORD platformBuild = 0;
  std::uint64_t count = 0;
  HeldAncestors ancestors;
  HeldRoot nativeRoot;
  const bool acquired = !nativeSession || (ancestors.capture(argv[2])
    && nativeRoot.open(argv[2]) && ancestors.sameVolume(nativeRoot.id)
    && ancestors.samePaths() && nativeRoot.samePath(argv[2]));
  const bool accepted = acquired && inspect(argv[2], platformBuild, enumerate, &count)
    && (!nativeSession || (ancestors.samePaths() && nativeRoot.samePath(argv[2])));
  std::printf("{\"aclPreflightPassed\":%s,\"handleIdentityCaptured\":%s,"
    "\"platformBuild\":%lu,\"nativeEnumerationInformational\":%s,"
    "\"directoryEntriesEnumerated\":%llu,\"nativeRootSessionHeld\":%s,"
    "\"syncRootRegistered\":false,"
    "\"cloudDataBytesTransferred\":0}\n",
    accepted ? "true" : "false", accepted ? "true" : "false", platformBuild,
    enumerate && accepted ? "true" : "false",
    static_cast<unsigned long long>(accepted ? count : 0),
    nativeSession && accepted ? "true" : "false");
  return accepted ? 0 : 4;
}
