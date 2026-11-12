# Issue #66 — signed FOD bytes to native NTFS publisher (LAB only)

This experiment runs **real signed Ed25519 Sync v2 CREATE/UPDATE**, checks a
caller-selected path against the signed metadata, validates the independent
device public-key pin and live revocation policy provided by the test, and
decrypts the actual AES-256-GCM ciphertext before handing plaintext bytes via
bounded binary **stdin** to a separate Windows PowerShell process. Plaintext
never enters command-line arguments or environment variables. The C# P/Invoke code uses real
`NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory`, `FILE_CREATE`,
`FlushFileBuffers`, opened FileId and byte checks, and
`NtSetInformationFile(FileRenameInformation, ReplaceIfExists=FALSE)`.

It exercises a **positive local Files On-Demand materialization primitive**
for 1-byte and 4097-byte signed payloads, and an atomic destination collision
that preserves foreign bytes. The native reader hashes and compares bytes
from its original opened stage HANDLE before and after publish. Its committed
file is strictly `held/published.bin` inside a disposable NTFS test directory,
not a user-selected production path or registered sync root.

To run on real Windows NTFS with Node 22:

```powershell
$env:ROOTARK_ISSUE66_W37_FOD_LAB='1'
npm exec --offline --yes --package=node@22.23.5 -- node --test test/issue-66-w37-signed-fod-native.test.js
```

Test fixture directories are intentionally retained: a recursive pathname
cleanup could delete foreign objects after an ancestor swap. No production
method is exported from `sync-client`. The documented RootSession opener
still always throws and the existing CFAPI gate still fails all fetches.

**Missing security and product requirements:** independent original-A FileId
and all-ancestor enrollment *before first open*, other-operator root/ACL
custody, writer isolation, durable crash-recovery journal and independent
CURRENT floor, native-image provenance, real CFAPI
`CfRegisterSyncRoot/CfConnectSyncRoot/CfExecute` and FOD/pin/picker product
integration. The disposable local device pin is NOT an independent
custodian. This experiment proves native FILE_CREATE/no-replace only after a
test-owned native pin, and must never make `RootSession` available.

**LAB ONLY · ROOTSESSION OFF · PRODUCT/RELEASE NO-GO.**
# Additional same-SID concurrent-writer laboratory

The opt-in `FOD_EXTERNAL_COLLISION` mode starts a **separate Node 22
process** before launching the native publisher. Once the publisher's
retained scratch HANDLE creates its `publisher-ready.signal`, the separate
actor creates and fsyncs `held/published.bin` using `wx`, retains the
foreign descriptor during the attempted native rename, and creates a fsynced
`writer-ack.signal`. The W26 publisher independently checks the signal
content, foreign bytes/FileId, and exact NTSTATUS collision. It also
reopens the surviving stage by its **retained directory HANDLE**, checks its
FileId equals the original open source, and compares its SHA-256/bytes.

The actor is not an independent custodian, and the parent directory is still
writable by the same SID. This proves a bounded *post-pin, late-destination*
no-replace race on disposable NTFS, **not** original-A provenance, exclusion
of a persistent adversarial writer, CFAPI callbacks, durable PREPARE/COMMIT,
powercut recovery or permission to enable production FOD.
