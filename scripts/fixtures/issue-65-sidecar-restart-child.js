"use strict";

// Standalone stdin-driven fixture, intentionally outside test/: Node --test
// discovers .js files under test/support and would block on stdin at startup.
// Disposable second OS process: it has no writer, private key or parent memory.
// Its only authority is the separately supplied public administrator pinset.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { verifyPublishedSignedCatalogSidecars } =
  require("../../src/services/zk1CloudSignedCatalogSidecar");
const { Zk1ExternallyPinnedProviderDomains, spkiFingerprint } =
  require("../../src/services/zk1ExternallyPinnedProviderDomains");

async function main() {
  const wire = JSON.parse(fs.readFileSync(0, "utf8"));
  const scope = Object.fromEntries(Object.entries(wire.scope).map(([key, value]) =>
    [key, Buffer.from(value, "base64url")]));
  const signedCatalog = Object.fromEntries(Object.entries(wire.signedCatalog).map(([key, value]) =>
    [key, value && typeof value === "object" && Object.hasOwn(value, "binary")
      ? Buffer.from(value.binary, "base64url") : value]));
  const admins = wire.providers.map((target) => {
    const administratorPublicKey = crypto.createPublicKey({
      key: Buffer.from(target.adminSpki, "base64url"), format: "der", type: "spki",
    });
    return { provider: target.provider, trustDomainId: target.trustDomainId,
      administratorPublicKey,
      independentAdministratorSpkiSha256: spkiFingerprint(administratorPublicKey) };
  });
  const providerDomainPinset = new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: admins,
  });
  const readers = wire.providers.map((target) => ({
    provider: target.provider, expectedContext: target.expectedContext,
    pinnedDriveFileId: target.pinnedDriveFileId,
    domainAttestation: target.domainAttestation,
    cloudReader: {
      status: () => ({ provider: target.provider }), enabled: () => true,
      resolveInventoryContext: async () => target.expectedContext,
      zk1StorageNamespace: () => target.namespace,
      key: (folder, name, area) => `${target.provider}/${area}/${folder}/${name}`,
      async download(folder, name, destination, area, allowWrite, opts) {
        const source = path.join(wire.directory, target.provider, area, folder, name);
        if (!fs.existsSync(source) || !allowWrite()) return false;
        if (target.pinnedDriveFileId !== null) {
          assert.equal(opts.providerFileId, target.pinnedDriveFileId);
        }
        const data = fs.readFileSync(source);
        if (data.length > opts.maxBytes) return false;
        fs.writeFileSync(destination, data, { flag: "wx", mode: 0o600 });
        return true;
      },
    },
  }));
  const result = await verifyPublishedSignedCatalogSidecars({ scope,
    operationId: Buffer.from(wire.operationId, "base64url"), signedCatalog,
    readers, providerDomainPinset, minimumMatchingProviders: 2, deadlineMs: 3000,
    observationOnly: true });
  assert.equal(result.remoteDurabilityProven, false);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.coherentProviderIdentityQuorumProven, false);
  process.stdout.write(JSON.stringify({ matchingCount: result.matchingCount }));
}

main().catch((error) => {
  process.stderr.write(error.code || error.message || "child failed");
  process.exitCode = 1;
});
