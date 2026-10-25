"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  publishSignedCatalogSidecars, recoverSignedCatalogSidecar,
  verifyPublishedSignedCatalogSidecars,
} = require("../src/services/zk1CloudSignedCatalogSidecar");
const { Zk1ExternallyPinnedProviderDomains, signProviderDomainAttestation,
  spkiFingerprint } = require("../src/services/zk1ExternallyPinnedProviderDomains");

const b64 = (value) => Buffer.from(value).toString("base64url");
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const PROVIDERS = ["s3", "gdrive", "webdav"];

function durableFixture(directory) {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(6), keyring_id: crypto.randomBytes(16) };
  const operationId = crypto.randomBytes(16);
  const signedCatalog = { signedCommittedProof: crypto.randomBytes(50),
    signedSnapshot: crypto.randomBytes(64), snapshotNonce: crypto.randomBytes(32),
    committedProofChain: [], ownerCheckpoint: null,
    ownerHistoryCheckpoint: null, previousOwnerHistoryProof: null,
    expectedCiphertextRoot: crypto.randomBytes(32), chunkLengths: [15] };
  const admins = PROVIDERS.map((provider) => ({ provider,
    keys: crypto.generateKeyPairSync("ed25519"), trustDomainId: sha(provider + ":" + b64(operationId)) }));
  const pinset = new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: admins.map((admin) => ({
      provider: admin.provider, trustDomainId: admin.trustDomainId,
      administratorPublicKey: admin.keys.publicKey,
      independentAdministratorSpkiSha256: spkiFingerprint(admin.keys.publicKey),
    })),
  });
  const identities = {};
  const targets = admins.map((admin) => {
    const provider = admin.provider;
    const context = sha(provider + ":reader");
    const namespace = sha(provider + ":namespace");
    const pinnedDriveFileId = provider === "gdrive" ? "sidecar-drive-fixed-id" : null;
    identities[provider] = context;
    const object = (folder, name, area) => path.join(directory, provider, area, folder, name);
    const reader = {
      enabled: () => true, status: () => ({ provider }),
      zk1StorageNamespace: () => namespace,
      resolveInventoryContext: async () => identities[provider],
      key: (folder, name, area) => `${provider}/${area}/${folder}/${name}`,
      async upload(source, folder, name, area, options) {
        assert.equal(options.zk1BoundedBytes, fs.statSync(source).size);
        if (provider === "gdrive") assert.equal(options.providerFileId, pinnedDriveFileId);
        const target = object(folder, name, area);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(source, target);
        return { provider, key: this.key(folder, name, area),
          ...(provider === "gdrive" ? { id: pinnedDriveFileId } : {}) };
      },
      async download(folder, name, destination, area, allowWrite, options) {
        if (provider === "gdrive") assert.equal(options.providerFileId, pinnedDriveFileId);
        const source = object(folder, name, area);
        if (!fs.existsSync(source) || !allowWrite()) return false;
        const bytes = fs.readFileSync(source);
        if (bytes.length > options.maxBytes) return false;
        fs.writeFileSync(destination, bytes, { flag: "wx", mode: 0o600 });
        return true;
      },
    };
    const now = Math.floor(Date.now() / 1000);
    const domainAttestation = signProviderDomainAttestation({
      administratorPrivateKey: admin.keys.privateKey,
      statement: { schema: "rootark-zk1-provider-domain-attestation/v1",
        provider, trust_domain_id: admin.trustDomainId,
        namespace_sha256: namespace, principal_context_sha256: context,
        drive_file_id: pinnedDriveFileId,
        ...Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, b64(value)])),
        issued_at: now - 5, expires_at: now + 600 },
    });
    return { provider, cloudWriter: reader, cloudReader: reader,
      expectedContext: context, pinnedDriveFileId, domainAttestation,
      path: object, adminSpki: b64(admin.keys.publicKey.export({ type: "spki", format: "der" })),
      trustDomainId: admin.trustDomainId, namespace };
  });
  const writers = targets.map(({ provider, cloudWriter, expectedContext, pinnedDriveFileId,
    domainAttestation }) => ({ provider, cloudWriter, expectedContext,
    pinnedDriveFileId, domainAttestation }));
  const readers = targets.map(({ provider, cloudReader, expectedContext, pinnedDriveFileId,
    domainAttestation }) => ({ provider, cloudReader, expectedContext,
    pinnedDriveFileId, domainAttestation }));
  const publication = { scope, operationId, signedCatalog, writers,
    providerDomainPinset: pinset };
  const verification = { scope, operationId, signedCatalog, readers,
    providerDomainPinset: pinset, minimumMatchingProviders: 2, deadlineMs: 3000 };
  return { directory, scope, operationId, signedCatalog, pinset,
    targets, readers, identities, publication, verification };
}

test("readback is bound to the exact sidecar across process restart, provider corruption, and lost ACK", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-sidecar-reread-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  const fixture = durableFixture(directory);
  const ack = await publishSignedCatalogSidecars(fixture.publication);
  assert.equal(ack.status, "SIGNED_CATALOG_PUT_ACK_NONAUTHORITATIVE");
  assert.equal(ack.remoteDurabilityProven, false);
  const verified = await verifyPublishedSignedCatalogSidecars(fixture.verification);
  assert.equal(verified.status, "SIGNED_CATALOG_EXACT_REMOTE_REREAD");
  assert.equal(verified.readbackMatched, true);
  assert.equal(verified.remoteDurabilityProven, false);
  assert.equal(verified.authorizesIo, false);
  assert.equal(verified.matchingCount, 2);

  const childInput = {
    directory,
    scope: Object.fromEntries(Object.entries(fixture.scope).map(([key, value]) => [key, b64(value)])),
    operationId: b64(fixture.operationId),
    signedCatalog: Object.fromEntries(Object.entries(fixture.signedCatalog).map(([key, value]) =>
      [key, Buffer.isBuffer(value) ? { binary: b64(value) } : value])),
    providers: fixture.targets.map(({ provider, pinnedDriveFileId, expectedContext,
      domainAttestation, adminSpki, trustDomainId, namespace }) => ({ provider,
      pinnedDriveFileId, expectedContext, domainAttestation, adminSpki, trustDomainId, namespace })),
  };
  const child = spawnSync(process.execPath,
    [path.join(__dirname, "support", "issue-65-sidecar-restart-child.js")],
    { input: JSON.stringify(childInput), encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(child.stdout).matchingCount, 2);

  // Two providers can agree on a syntactically valid but different (older or
  // replaced) catalog. Their quorum cannot satisfy our retained digest.
  const competingCatalog = { ...fixture.signedCatalog,
    signedSnapshot: crypto.randomBytes(64) };
  await publishSignedCatalogSidecars({ ...fixture.publication,
    signedCatalog: competingCatalog, writers: fixture.publication.writers.slice(0, 2) });
  await assert.rejects(verifyPublishedSignedCatalogSidecars(fixture.verification),
    /ZK_SIGNED_CATALOG_SIDECAR_DENIED/,
    "two matching but wrong signed-wire payloads are not a valid exact readback");
  await publishSignedCatalogSidecars(fixture.publication);

  const second = fixture.targets[1].path;
  const catalogDir = path.join(directory, "gdrive", "uploads");
  const file = fs.readdirSync(catalogDir).flatMap((folder) =>
    fs.readdirSync(path.join(catalogDir, folder)).map((name) => second(folder, name, "uploads")))[0];
  const saved = fs.readFileSync(file);
  fs.writeFileSync(file, Buffer.from(saved).fill(0x13));
  const survivingQuorum = await verifyPublishedSignedCatalogSidecars(fixture.verification);
  assert.deepEqual(survivingQuorum.providers, ["s3", "webdav"],
    "a corrupt Drive copy cannot count, but independent S3+WebDAV should recover");
  await assert.rejects(verifyPublishedSignedCatalogSidecars({ ...fixture.verification,
    minimumMatchingProviders: 3 }), /ZK_SIGNED_CATALOG_SIDECAR_DENIED/,
  "two healthy providers cannot conceal a corrupted required third copy");
  fs.writeFileSync(file, saved);
  fs.rmSync(file);
  await assert.rejects(verifyPublishedSignedCatalogSidecars({ ...fixture.verification,
    minimumMatchingProviders: 3 }), /ZK_SIGNED_CATALOG_SIDECAR_DENIED/,
  "missing remote ciphertext cannot satisfy the configured three-provider quorum");
});

test("recovery refuses a provider whose pinned principal changes while another provider downloads", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-sidecar-principal-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  const fixture = durableFixture(directory);
  await publishSignedCatalogSidecars(fixture.publication);
  const second = fixture.readers[1];
  const read = second.cloudReader.download;
  second.cloudReader.download = async function (...args) {
    const result = await read.apply(this, args);
    fixture.identities.s3 = sha("rotated-principal-after-s3-get");
    return result;
  };
  await assert.rejects(recoverSignedCatalogSidecar({ scope: fixture.scope,
    operationId: fixture.operationId, readers: fixture.readers,
    providerDomainPinset: fixture.pinset, deadlineMs: 3000 }),
  /ZK_SIGNED_CATALOG_SIDECAR_DENIED/,
  "first provider must remain in its pinned principal through quorum completion");
});
