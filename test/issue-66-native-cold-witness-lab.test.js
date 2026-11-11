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
const wire = (object) => Buffer.from(canonicalJson(object), "utf8");
const sign = (type, statement, key) => ({ statement,
  signature: crypto.sign(null, Buffer.from(DOMAIN + type + "\0" + canonicalJson(statement), "utf8"),
    key.privateKey).toString("base64url") });

// Node's pathname hardlink source may be swapped by a same-principal writer.
// These lab-only checks cannot provide native atomic publication or RootSession.
const publicationMismatch = () => Object.assign(
  new Error("Published inode differs from the retained foreign hardlink"),
  { code: "lab_publication_identity_mismatch" });

const openPublishedLabNoFollow = async (name) => {
  let opened;
  try {
    opened = await fsp.open(name,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  } catch (error) {
    // POSIX O_NOFOLLOW rejects an entry hardlinked to a symlink with ELOOP.
    if (error?.code === "ELOOP") throw publicationMismatch();
    throw error;
  }
  try {
    // Supplementary lab check for platforms where O_NOFOLLOW is unavailable.
    // The namespace is not protected against concurrent same-principal writes.
    const entry = await fsp.lstat(name, { bigint: true });
    const held = await opened.stat({ bigint: true });
    if (!entry.isFile() || entry.isSymbolicLink() || !held.isFile()
      || entry.dev !== held.dev || entry.ino !== held.ino) throw publicationMismatch();
    return opened;
  } catch (error) {
    await opened.close();
    throw error;
  }
};

const assertHeldPublicationIdentity = async (foreign, published) => {
  const expected = await foreign.stat({ bigint: true });
  const actual = await published.stat({ bigint: true });
  if (!expected.isFile() || !actual.isFile()
    || expected.nlink !== 2n || actual.nlink !== 2n
    || expected.dev !== actual.dev || expected.ino !== actual.ino) throw publicationMismatch();
};

test("#66 signed native cold witness reference rejects stale floors, swapped FileIds and incomplete COMMIT", async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-root-witness-"));
  // Keep the disposable test-owned directory for forensic inspection. A
  // recursive pathname cleanup would be unsafe if a same-principal process
  // rebound the directory after the test; only an independent custodian may
  // later retire such evidence.
  const retainedHandles = [];
  t.after(async () => {
    for (const handle of retainedHandles.reverse()) await handle.close();
  });
  const originalName = path.join(directory, "published.bin");
  const parkedName = path.join(directory, "original-preserved.bin");
  const stagedForeignName = path.join(directory, "foreign-stage.bin");
  const bytes = Buffer.from("SIGNED_NATIVE_ROOT_COLD_BYTES_V1");
  const original = await fsp.open(originalName, "wx+", 0o600);
  retainedHandles.push(original);
  await original.writeFile(bytes);
  await original.sync();
  let publishedLinkCount = 1n;
  const openedPhysical = async () => {
    // Explicitly NOT a trusted native backend. We only prove that the
    // reference verifier rejects swapped physical evidence; this callback
    // cannot authorize RootSession or exclude a same-principal attacker.
    const held = await openPublishedLabNoFollow(originalName);
    try {
      const before = await held.stat({ bigint: true });
      assert.equal(before.isFile(), true);
      assert.equal(before.nlink, publishedLinkCount);
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
    scope, expectedOwnerDigest, ownerProvision: wire(provision),
    ownerSignerSpki: pub(owner), witnessSignerSpki: pub(witness), floorSignerSpki: pub(floor),
    async readPhysicalNative() {
      const physical = await openedPhysical();
      return wire(fakePhase ? { ...physical, phase: fakePhase } : physical);
    },
    async currentSignedReadback(challenge) {
      const receiptNonce = staleChallenge ? "0".repeat(64) : challenge;
      return wire({
        witness: sign("witness", {
          type: "root-commit", version: 1, scope, rootDigest, epoch,
          sequence, phase: "COMMITTED", fileId: originalPhysical.fileId,
          prepareDigest, commitDigest, challenge: receiptNonce,
        }, witness),
        floor: sign("floor", {
          type: "root-floor", version: 1, scope, rootDigest, epoch,
          sequence: floorSequence, commitDigest, challenge: receiptNonce,
        }, floor),
      });
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
  // Stage the foreign inode by exclusive creation BEFORE the rename. The
  // hardlink destination is no-replace, but its source pathname is mutable:
  // compare the published FD with the retained foreign FD after the link.
  const foreign = await fsp.open(stagedForeignName, "wx+", 0o600);
  retainedHandles.push(foreign);
  await foreign.writeFile(bytes);
  await foreign.sync();
  await fsp.rename(originalName, parkedName);
  await fsp.link(stagedForeignName, originalName);
  // Retain both hardlinks: unlink(stageName) could delete an attacker's newly
  // substituted pathname and would itself be an unauthorized filesystem act.
  publishedLinkCount = 2n;
  const published = await openPublishedLabNoFollow(originalName);
  retainedHandles.push(published);
  await assertHeldPublicationIdentity(foreign, published);
  const attackerPhysical = await openedPhysical();
  assert.notEqual(attackerPhysical.fileId, originalPhysical.fileId,
    "the test must physically substitute an unrelated opened inode");
  await assert.rejects(inspectSignedColdCommit(args), { code: "root_session_unverified_authority" });
  for (const [label, handle, expectedLinks] of [
    ["foreign", foreign, 2n], ["published", published, 2n],
    ["parked-original", original, 1n],
  ]) {
    const before = await handle.stat({ bigint: true });
    assert.equal(before.isFile(), true, `${label} must remain a held regular inode`);
    assert.equal(before.nlink, expectedLinks, `${label} must preserve its expected link count`);
    const content = Buffer.alloc(bytes.length + 1);
    const { bytesRead } = await handle.read(content, 0, content.length, 0);
    const after = await handle.stat({ bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(after.size, before.size);
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(bytesRead, bytes.length);
    assert.deepEqual(content.subarray(0, bytesRead), bytes,
      `${label} must retain exact original bytes despite hostile name replacement`);
  }
  const originalRetainedId = await original.stat({ bigint: true });
  const foreignRetainedId = await foreign.stat({ bigint: true });
  assert.notEqual(originalRetainedId.ino, foreignRetainedId.ino,
    "equal byte strings do not make two distinct retained OS inodes identical");

  const forged = { ...args, expectedOwnerDigest: "0".repeat(64) };
  await assert.rejects(inspectSignedColdCommit(forged), { code: "root_session_unverified_authority" });
  const duplicateSigners = { ...args, floorSignerSpki: pub(witness) };
  await assert.rejects(inspectSignedColdCommit(duplicateSigners), { code: "root_session_unverified_authority" });
  let unsafeAccessorCalled = false;
  const accessorProvision = { statement: provision.statement };
  Object.defineProperty(accessorProvision, "signature", { enumerable: true,
    get() { unsafeAccessorCalled = true; return provision.signature; } });
  await assert.rejects(inspectSignedColdCommit({ ...args, ownerProvision: accessorProvision }),
    { code: "root_session_unverified_authority" });
  assert.equal(unsafeAccessorCalled, false,
    "a caller-supplied object must be rejected before any getter or Proxy trap");
  await assert.rejects(inspectSignedColdCommit({ ...args,
    ownerProvision: wire({ ...provision, enormous: "A".repeat(1024 * 1024) }),
  }), { code: "root_session_unverified_authority" },
  "reject oversized serialized bytes before JSON parse or canonicalization");
  const numerous = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`j${i}`, i]));
  await assert.rejects(inspectSignedColdCommit({ ...args, ownerProvision: wire(numerous) }),
    { code: "root_session_unverified_authority" },
  "a prebounded byte input must not imply that arbitrarily many fields are acceptable");
  await assert.rejects(inspectSignedColdCommit({ ...args,
    ownerProvision: Buffer.from('{"statement":{}, "statement":{}, "signature":"x"}'),
  }), { code: "root_session_unverified_authority" },
  "duplicate keys and noncanonical byte framing cannot supply signed authority");
  let poisonedMethodCalled = false;
  const poisoned = Buffer.from(" ".repeat(8193));
  Object.defineProperty(poisoned, "length", { get() { return 1; } });
  Object.defineProperty(poisoned, "toString", { value() {
    poisonedMethodCalled = true;
    return wire(provision).toString("utf8");
  } });
  await assert.rejects(inspectSignedColdCommit({ ...args, ownerProvision: poisoned }),
    { code: "root_session_unverified_authority" },
    "intrinsic TypedArray byteLength must defeat a forged Buffer.length");
  assert.equal(poisonedMethodCalled, false,
    "the verifier must never invoke a caller-controlled Buffer.toString");
  const malformedUtf8 = Buffer.from('{"x":"ok"}');
  malformedUtf8[6] = 0xff;
  await assert.rejects(inspectSignedColdCommit({ ...args, ownerProvision: malformedUtf8 }),
    { code: "root_session_unverified_authority" },
    "invalid UTF-8 must fail, not normalize to a replacement character");
  sequence = 1;
  floorSequence = 1;
  await assert.rejects(inspectSignedColdCommit(args), { code: "root_session_unverified_authority" },
    "a signed old file identity remains inadmissible after physical replacement");
});

test("#66 stage-path swap rejects a published hardlink to an unheld foreign inode", async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-stage-swap-"));
  // Never delete an alias by pathname after a same-principal stage swap.
  const retained = [];
  t.after(async () => {
    for (const handle of retained.reverse()) await handle.close();
  });
  const stageName = path.join(directory, "foreign-stage.bin");
  const preservedName = path.join(directory, "foreign-preserved.bin");
  const publishedName = path.join(directory, "published.bin");
  const bytes = Buffer.from("EQUAL_CIPHERTEXT_IS_NOT_FILE_IDENTITY");
  const expected = await fsp.open(stageName, "wx+", 0o600);
  retained.push(expected);
  await expected.writeFile(bytes);
  await expected.sync();

  // Rebind the stage alias to a different same-user inode with identical bytes.
  await fsp.rename(stageName, preservedName);
  const injected = await fsp.open(stageName, "wx+", 0o600);
  retained.push(injected);
  await injected.writeFile(bytes);
  await injected.sync();
  await fsp.link(stageName, publishedName);
  const published = await openPublishedLabNoFollow(publishedName);
  retained.push(published);
  const originalId = await expected.stat({ bigint: true });
  const injectedId = await injected.stat({ bigint: true });
  assert.notDeepEqual([originalId.dev, originalId.ino], [injectedId.dev, injectedId.ino],
    "stage alias must be physically swapped to a distinct inode");
  await assert.rejects(assertHeldPublicationIdentity(expected, published),
    { code: "lab_publication_identity_mismatch" });
  for (const [label, handle, expectedLinks] of [
    ["retained-foreign", expected, 1n], ["hostile-injected", injected, 2n],
    ["published", published, 2n],
  ]) {
    const before = await handle.stat({ bigint: true });
    assert.equal(before.isFile(), true, `${label} must be an opened regular inode`);
    assert.equal(before.nlink, expectedLinks);
    const content = Buffer.alloc(bytes.length + 1);
    const { bytesRead } = await handle.read(content, 0, content.length, 0);
    const after = await handle.stat({ bigint: true });
    assert.deepEqual([after.dev, after.ino, after.size, after.mtimeNs, after.nlink],
      [before.dev, before.ino, before.size, before.mtimeNs, before.nlink]);
    assert.deepEqual(content.subarray(0, bytesRead), bytes,
      `${label} must have exact held inode bytes despite identical pathname payloads`);
  }
  assert.equal((await injected.stat({ bigint: true })).nlink, 2n,
    "both hostile stage and published hardlinks remain retained; no pathname unlink");
});

test("#66 POSIX stage-symlink substitution rejects a published symlink to retained equal bytes",
  { skip: process.platform === "win32" && "POSIX hardlinks preserve symlink inodes; Windows needs separate reparse validation" },
  async (t) => {
    const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-symlink-stage-"));
    const retained = [];
    t.after(async () => {
      for (const handle of retained.reverse()) await handle.close();
    });
    const stageName = path.join(directory, "foreign-stage.bin");
    const preservedName = path.join(directory, "foreign-preserved.bin");
    const publishedName = path.join(directory, "published.bin");
    const bytes = Buffer.from("SAME_BYTES_FROM_A_SYMLINK_ARE_NOT_A_HARDLINK");
    const foreign = await fsp.open(stageName, "wx+", 0o600);
    retained.push(foreign);
    await foreign.writeFile(bytes);
    await foreign.sync();
    await fsp.rename(stageName, preservedName);
    await fsp.symlink(preservedName, stageName);
    await fsp.link(stageName, publishedName);
    assert.equal((await fsp.lstat(publishedName)).isSymbolicLink(), true,
      "this physical attack requires the published directory entry to be a symlink");
    await assert.rejects(openPublishedLabNoFollow(publishedName),
      { code: "lab_publication_identity_mismatch" });
    const originalState = await foreign.stat({ bigint: true });
    assert.equal(originalState.nlink, 1n,
      "the original foreign inode was not given a second hardlink");
    const content = Buffer.alloc(bytes.length + 1);
    const { bytesRead } = await foreign.read(content, 0, content.length, 0);
    assert.deepEqual(content.subarray(0, bytesRead), bytes);
    const after = await foreign.stat({ bigint: true });
    assert.deepEqual([after.dev, after.ino, after.size, after.mtimeNs, after.nlink],
      [originalState.dev, originalState.ino, originalState.size, originalState.mtimeNs, 1n]);
  });
