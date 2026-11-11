"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { canonicalJson } = require("../sync-client/rootark-sync-protocol");
const { DOMAIN, inspectSignedColdCommit } =
  require("../experiments/issue66-native-root-witness/verify-cold-proof");
const { openNativeRootSession } = require("../sync-client/rootark-sync-native-root-session-contract");

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const kp = () => crypto.generateKeyPairSync("ed25519");
const pub = (key) => key.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
const sign = (type, statement, key) => ({ statement,
  signature: crypto.sign(null, Buffer.from(DOMAIN + type + "\0" + canonicalJson(statement), "utf8"),
    key.privateKey).toString("base64url") });

test("#66 signed native cold witness reference rejects stale floors, swapped FileIds and incomplete COMMIT", async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-root-witness-"));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const originalName = path.join(directory, "published.bin");
  const parkedName = path.join(directory, "original-preserved.bin");
  const bytes = Buffer.from("SIGNED_NATIVE_ROOT_COLD_BYTES_V1");
  const original = await fsp.open(originalName, "wx+", 0o600);
  try { await original.writeFile(bytes); await original.sync(); }
  finally { await original.close(); }
  const openedPhysical = async () => {
    // Explicitly NOT a trusted native backend. We only prove that the
    // reference verifier rejects swapped physical evidence; this callback
    // cannot authorize RootSession or exclude a same-principal attacker.
    const held = await fsp.open(originalName,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    try {
      const before = await held.stat({ bigint: true });
      assert.equal(before.isFile(), true);
      assert.equal(before.nlink, 1n);
      const data = Buffer.alloc(bytes.length + 1);
      const { bytesRead } = await held.read(data, 0, data.length, 0);
      const after = await held.stat({ bigint: true });
      assert.equal(before.dev, after.dev);
      assert.equal(before.ino, after.ino);
      assert.equal(bytesRead, bytes.length);
      assert.deepEqual(data.subarray(0, bytesRead), bytes);
      return {
        phase: "COMMITTED", rootDigest, prepareDigest,
        commitDigest, fileId: sha(`${before.dev}:${before.ino}:${before.birthtimeNs}`),
      };
    } finally { await held.close(); }
  };
  const owner = kp(), witness = kp(), floor = kp();
  const scope = "issue66:disposable:local";
  const epoch = crypto.randomUUID();
  const rootDigest = sha("DISPOSABLE_ROOT_AND_ANCESTOR_CHAIN_NOT_TRUSTED");
  const prepareDigest = sha("PREPARED_LAB_V1");
  const commitDigest = sha("COMMITTED_LAB_V1");
  const originalPhysical = await openedPhysical();
  const provision = sign("owner", {
    type: "root-owner", version: 1, scope, rootDigest, epoch,
    initialSequence: 1, witnessSpki: pub(witness), floorSpki: pub(floor),
  }, owner);
  const expectedOwnerDigest = sha(DOMAIN + "provision\0" + canonicalJson(provision));
  let sequence = 7;
  let floorSequence = 7;
  let staleChallenge = false;
  let fakePhase = null;
  const args = {
    scope, expectedOwnerDigest, ownerProvision: provision,
    ownerSignerSpki: pub(owner), witnessSignerSpki: pub(witness), floorSignerSpki: pub(floor),
    async readPhysicalNative() {
      const physical = await openedPhysical();
      return fakePhase ? { ...physical, phase: fakePhase } : physical;
    },
    async currentSignedReadback(challenge) {
      const receiptNonce = staleChallenge ? "0".repeat(64) : challenge;
      return {
        witness: sign("witness", {
          type: "root-commit", version: 1, scope, rootDigest, epoch,
          sequence, phase: "COMMITTED", fileId: originalPhysical.fileId,
          prepareDigest, commitDigest, challenge: receiptNonce,
        }, witness),
        floor: sign("floor", {
          type: "root-floor", version: 1, scope, rootDigest, epoch,
          sequence: floorSequence, commitDigest, challenge: receiptNonce,
        }, floor),
      };
    },
  };
  const good = await inspectSignedColdCommit(args);
  assert.deepEqual(good, { status: "LAB_COLD_COMMIT_OBSERVED", sequence: 7,
    authorizesIo: false, authorizesReplay: false, rootSessionAvailable: false });
  assert.throws(() => openNativeRootSession(true, good),
    { code: "root_session_native_unavailable" });

  floorSequence = 8; // independent monotonic floor advanced; receipt stale
  await assert.rejects(inspectSignedColdCommit(args), { code: "root_session_unverified_authority" });
  floorSequence = 7;
  staleChallenge = true; // signed but not fresh CURRENT evidence
  await assert.rejects(inspectSignedColdCommit(args), { code: "root_session_unverified_authority" });
  staleChallenge = false;
  fakePhase = "PUBLISHED_NO_COMMIT";
  await assert.rejects(inspectSignedColdCommit(args), { code: "root_session_unverified_authority" });
  fakePhase = null;

  // After a verified COMMIT, a hostile same-user writer preserves the old
  // inode under another name and creates a different inode with EQUAL bytes.
  // The owner-signed root fingerprint and external floor are left intact.
  await fsp.rename(originalName, parkedName);
  const foreign = await fsp.open(originalName, "wx+", 0o600);
  try { await foreign.writeFile(bytes); await foreign.sync(); }
  finally { await foreign.close(); }
  const attackerPhysical = await openedPhysical();
  assert.notEqual(attackerPhysical.fileId, originalPhysical.fileId,
    "the test must physically substitute an unrelated opened inode");
  await assert.rejects(inspectSignedColdCommit(args), { code: "root_session_unverified_authority" });
  assert.deepEqual(await fsp.readFile(originalName), bytes);
  assert.deepEqual(await fsp.readFile(parkedName), bytes);

  const forged = { ...args, expectedOwnerDigest: "0".repeat(64) };
  await assert.rejects(inspectSignedColdCommit(forged), { code: "root_session_unverified_authority" });
  const duplicateSigners = { ...args, floorSignerSpki: pub(witness) };
  await assert.rejects(inspectSignedColdCommit(duplicateSigners), { code: "root_session_unverified_authority" });
  sequence = 1;
  floorSequence = 1;
  await assert.rejects(inspectSignedColdCommit(args), { code: "root_session_unverified_authority" },
    "a signed old file identity remains inadmissible after physical replacement");
});
