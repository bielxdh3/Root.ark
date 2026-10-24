"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Zk1ExternallyPinnedProviderDomains, signProviderDomainAttestation,
  spkiFingerprint } = require("../src/services/zk1ExternallyPinnedProviderDomains");
const { GRANT_FIELDS, STATE_FIELDS, GRANT_DOMAIN, STATUS_DOMAIN, POP_DOMAIN,
  verifyFreshOwnerDeviceRestoreAuthority } =
  require("../src/services/zk1FreshOwnerDeviceRestoreAuthority");

const random = (n) => crypto.randomBytes(n);
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const scope = () => ({ account_id: random(16), compartment_id: Buffer.from("tenant-alpha"),
  keyring_id: random(16) });

test("two branded cloud providers cannot claim independent custody with one native Ed25519 administrator", () => {
  const shared = crypto.generateKeyPairSync("ed25519");
  const unrelated = crypto.generateKeyPairSync("ed25519");
  const disguised = crypto.createPublicKey({
    key: shared.publicKey.export({ format: "der", type: "spki" }),
    type: "spki", format: "der",
  });
  const foreignSpki = unrelated.publicKey.export({ type: "spki", format: "der" });
  disguised.export = () => Buffer.from(foreignSpki);
  const domains = [
    { provider: "s3", trustDomainId: random(32).toString("hex"),
      administratorPublicKey: shared.publicKey,
      independentAdministratorSpkiSha256: spkiFingerprint(shared.publicKey) },
    { provider: "gdrive", trustDomainId: random(32).toString("hex"),
      administratorPublicKey: disguised,
      independentAdministratorSpkiSha256: crypto.createHash("sha256")
        .update(foreignSpki).digest("hex") },
  ];
  assert.throws(() => new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: domains,
  }), /ZK_PROVIDER_DOMAIN_UNVERIFIED/,
  "separate SPKI pins must represent separate actual signing authorities");
  assert.doesNotThrow(() => new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: [domains[0], { ...domains[1],
      administratorPublicKey: unrelated.publicKey }],
  }));
});

test("independently fixed admin signing keys bind distinct namespaces, contexts and custody domains", () => {
  const trusted = scope();
  const now = Math.floor(Date.now() / 1000);
  const labels = ["s3", "gdrive"];
  const operators = labels.map((provider) => ({
    provider, trustDomainId: random(32).toString("hex"),
    ...crypto.generateKeyPairSync("ed25519"),
  }));
  const pins = operators.map((admin) => ({
    provider: admin.provider, trustDomainId: admin.trustDomainId,
    administratorPublicKey: admin.publicKey,
    independentAdministratorSpkiSha256: spkiFingerprint(admin.publicKey),
  }));
  const policy = new Zk1ExternallyPinnedProviderDomains({ externallyPinnedDomains: pins });
  const targets = operators.map((admin, index) => {
    const namespaceIdentity = random(32).toString("hex");
    const expectedReaderContext = random(32).toString("hex");
    const pinnedDriveFileId = admin.provider === "gdrive" ? "independent-drive-object" : null;
    const statement = {
      schema: "rootark-zk1-provider-domain-attestation/v1",
      provider: admin.provider, trust_domain_id: admin.trustDomainId,
      namespace_sha256: namespaceIdentity, principal_context_sha256: expectedReaderContext,
      drive_file_id: pinnedDriveFileId,
      ...Object.fromEntries(Object.entries(trusted).map(([name, data]) => [name, b64(data)])),
      issued_at: now - 5, expires_at: now + 20,
    };
    return { provider: admin.provider, namespaceIdentity, expectedReaderContext,
      pinnedDriveFileId,
      domainAttestation: signProviderDomainAttestation({
        statement, administratorPrivateKey: admin.privateKey }),
      privateKey: admin.privateKey, index };
  });
  const signed = targets.map(({ privateKey: _unused, index: _ignored, ...target }) => target);
  const verify = (values = signed, at = now) =>
    policy.verify({ targets: values, scope: trusted, nowSeconds: at });
  assert.equal(verify().signedDomainsVerified, 2);
  assert.equal(verify().physicalIndependenceProven, false);
  assert.throws(() => verify(signed, now + 25), /ZK_PROVIDER_DOMAIN_UNVERIFIED/,
    "a signed certificate cannot be replayed after expiry");
  assert.throws(() => verify(signed.map((item, index) => index === 1
    ? { ...item, namespaceIdentity: signed[0].namespaceIdentity } : item)),
  /ZK_PROVIDER_DOMAIN_UNVERIFIED/, "namespace relabeling must not manufacture independent custody");
  assert.throws(() => verify(signed.map((item, index) => index === 1
    ? { ...item, expectedReaderContext: signed[0].expectedReaderContext } : item)),
  /ZK_PROVIDER_DOMAIN_UNVERIFIED/, "same principal context across two providers is one logical identity");
  assert.throws(() => verify(signed.map((item, index) => index === 1
    ? { ...item, domainAttestation: signed[0].domainAttestation } : item)),
  /ZK_PROVIDER_DOMAIN_UNVERIFIED/, "provider signed statement cannot be substituted");
  assert.throws(() => new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: [{ ...pins[0] }, { ...pins[1],
      independentAdministratorSpkiSha256: pins[0].independentAdministratorSpkiSha256 }],
  }), /ZK_PROVIDER_DOMAIN_UNVERIFIED/, "pinned administrator SPKI must match actual certificate");
  assert.throws(() => new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: [{ ...pins[0] }, { ...pins[1],
      trustDomainId: pins[0].trustDomainId }],
  }), /ZK_PROVIDER_DOMAIN_UNVERIFIED/, "cloned administration IDs never form two quorum members");
  assert.throws(() => new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: [{ ...pins[0] }, { ...pins[1],
      administratorPublicKey: pins[0].administratorPublicKey,
      independentAdministratorSpkiSha256: pins[0].independentAdministratorSpkiSha256 }],
  }), /ZK_PROVIDER_DOMAIN_UNVERIFIED/, "same signing key under two branded providers is denied");
  assert.throws(() => policy.verify({ targets: signed,
    scope: { ...trusted, keyring_id: random(16) }, nowSeconds: now }),
  /ZK_PROVIDER_DOMAIN_UNVERIFIED/, "signed scope cannot be rebound by caller");
});

test("fresh owner+device signed nonce binds current grant and rejects replay, expiry and revocation", async () => {
  const trusted = scope();
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const ownerPublic = await crypto.webcrypto.subtle.importKey("spki",
    ownerKeys.publicKey.export({ format: "der", type: "spki" }), "Ed25519", false, ["verify"]);
  const ownerHead = { revision: 7, digest: random(32), epoch: 3 };
  const op = { operation_id: random(16) };
  const signedFields = Object.fromEntries(Object.entries(trusted).map(([k, v]) => [k, b64(v)]));
  const grant = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...signedFields,
    device_id: "device-correct",
    authorization_key_id: b64(random(16)),
    authorization_public_key: b64(deviceKeys.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
    manifest_revision: 7, manifest_digest: b64(ownerHead.digest),
    current_epoch: 3, enrolled_epoch: 3, revoked_at_epoch: null };
  const ownerSign = (domain, fields, value) => b64(crypto.sign(null,
    Buffer.concat([domain, Buffer.from(JSON.stringify(
      Object.fromEntries(fields.map((k) => [k, value[k]]))))]), ownerKeys.privateKey));
  const signedGrant = { ...grant, signature: ownerSign(GRANT_DOMAIN, GRANT_FIELDS, grant) };
  let attack = null;
  let retained = null;
  const now = Math.floor(Date.now() / 1000);
  const fetch = async (challenge) => {
    const fields = { schema: "rootark-zk1-current-device-restore-state/v1",
      ...challenge.scope, device_id: challenge.deviceId,
      authorization_key_id: challenge.authorizationKeyId,
      operation_id: challenge.operationId,
      manifest_revision: challenge.manifestRevision,
      manifest_digest: challenge.manifestDigest,
      current_epoch: challenge.currentEpoch,
      state: attack === "revoked" ? "REVOKED" : "ACTIVE", nonce: challenge.nonce,
      issued_at: attack === "expired" ? now - 30
        : attack === "delayed" ? Math.floor(Date.now() / 1000) - 1 : now - 1,
      expires_at: attack === "expired" ? now - 20
        : attack === "delayed" ? Math.floor(Date.now() / 1000) + 1 : now + 9 };
    const signature = ownerSign(STATUS_DOMAIN, STATE_FIELDS, fields);
    const pop = Buffer.concat([POP_DOMAIN, Buffer.from(challenge.nonce, "base64url"),
      Buffer.from(challenge.operationId, "base64url"),
      Buffer.from(signedGrant.signature, "base64url")]);
    const answer = { state: { ...fields, signature },
      deviceProofOfPossession: b64(crypto.sign(null, pop, deviceKeys.privateKey)) };
    if (attack === "replay" && retained) return retained;
    if (!retained) retained = answer;
    if (attack === "delayed") await new Promise((resolve) => setTimeout(resolve, 2200));
    return answer;
  };
  const assertCurrent = () => verifyFreshOwnerDeviceRestoreAuthority({
    signedDeviceGrant: signedGrant, pinnedOwnerPublicKey: ownerPublic,
    fetchSignedCurrentDeviceState: fetch, scope: trusted, operation: op, ownerHead,
    nowSeconds: now,
  });
  assert.equal((await assertCurrent()).nonceBoundCurrentRevocationChecked, true);
  for (const mode of ["revoked", "expired", "replay"]) {
    attack = mode;
    await assert.rejects(assertCurrent(), /ZK_FRESH_RESTORE_DEVICE_UNVERIFIED/, mode);
  }
  attack = "delayed";
  await assert.rejects(verifyFreshOwnerDeviceRestoreAuthority({
    signedDeviceGrant: signedGrant, pinnedOwnerPublicKey: ownerPublic,
    fetchSignedCurrentDeviceState: fetch, scope: trusted, operation: op, ownerHead,
  }), /ZK_FRESH_RESTORE_DEVICE_UNVERIFIED/,
  "owner-signed ACTIVE must expire during a delayed provider response");
  attack = null;
  await assert.rejects(verifyFreshOwnerDeviceRestoreAuthority({
    signedDeviceGrant: { ...signedGrant, device_id: "cloned-device" },
    pinnedOwnerPublicKey: ownerPublic, fetchSignedCurrentDeviceState: fetch,
    scope: trusted, operation: op, ownerHead, nowSeconds: now,
  }), /ZK_FRESH_RESTORE_DEVICE_UNVERIFIED/);
  const signedRevokedGrant = { ...grant, revoked_at_epoch: 3 };
  await assert.rejects(verifyFreshOwnerDeviceRestoreAuthority({
    signedDeviceGrant: { ...signedRevokedGrant,
      signature: ownerSign(GRANT_DOMAIN, GRANT_FIELDS, signedRevokedGrant) },
    pinnedOwnerPublicKey: ownerPublic, fetchSignedCurrentDeviceState: fetch,
    scope: trusted, operation: op, ownerHead, nowSeconds: now,
  }), /ZK_FRESH_RESTORE_DEVICE_UNVERIFIED/);
});
