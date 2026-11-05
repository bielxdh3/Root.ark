"use strict";

// A newly created SQLite pathname must never be re-adopted when its inode is
// replaced at close. A writable SQLite open would modify the substituted DB.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { Zk1SyncAtomicRetainedAnchorDevOff } =
  require("../src/services/zk1SyncAtomicRetainedAnchorDevOff");
const { Zk1SyncAtomicCasFloorLedgerDevOff, GENESIS, ANCHOR_DOMAIN } =
  require("../src/services/zk1SyncAtomicCasFloorLedgerDevOff");
const protocol = require("../sync-client/rootark-sync-protocol");

function fixture(t, prefix) {
  const directory = createPrivateAuthorityFixture(prefix);
  const filename = path.join(directory, "ledger.sqlite");
  const replacement = path.join(directory, "replacement.sqlite");
  const originallyCreated = path.join(directory, "original-created.sqlite");
  // No SQLite schema at all: a successful bootstrap into this distinct inode
  // is observable and proves that the pre-open path guard adopted the swap.
  fs.writeFileSync(replacement, Buffer.alloc(0), { flag: "wx", mode: 0o600 });
  const replacementIdentity = fs.statSync(replacement, { bigint: true });
  t.after(() => fs.rmSync(directory, { recursive: true, force: true,
    maxRetries: 10, retryDelay: 100 }));
  return { directory, filename, replacement, originallyCreated, replacementIdentity };
}

async function swapAfterExclusiveCreate(fixturePaths, action) {
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  let createdFd = null;
  let swapped = false;
  fs.openSync = function (filename, flags, ...rest) {
    const fd = originalOpen.call(fs, filename, flags, ...rest);
    if (filename === fixturePaths.filename && typeof flags === "number"
      && (flags & fs.constants.O_CREAT) && (flags & fs.constants.O_EXCL)) createdFd = fd;
    return fd;
  };
  fs.closeSync = function (fd) {
    originalClose.call(fs, fd);
    if (fd === createdFd && !swapped) {
      swapped = true;
      fs.renameSync(fixturePaths.filename, fixturePaths.originallyCreated);
      fs.renameSync(fixturePaths.replacement, fixturePaths.filename);
    }
  };
  try {
    await action();
    assert.equal(swapped, true, "must inject exactly at bootstrap descriptor close");
    const substituted = fs.statSync(fixturePaths.filename, { bigint: true });
    assert.equal(substituted.dev, fixturePaths.replacementIdentity.dev);
    assert.equal(substituted.ino, fixturePaths.replacementIdentity.ino);
    assert.equal(substituted.size, 0n,
      "substituted SQLite file must never receive the authority schema");
    assert.equal(fs.statSync(fixturePaths.originallyCreated, { bigint: true }).size, 0n,
      "the originally created inode must remain untouched after refusal");
  } finally {
    fs.openSync = originalOpen;
    fs.closeSync = originalClose;
  }
}

test("DEV-OFF retained anchor rejects replacement of newly created SQLite inode", async (t) => {
  const fixturePaths = fixture(t, "zk65-codeql-anchor-race-");
  const signer = crypto.generateKeyPairSync("ed25519");
  const scope = "race:anchor";
  await swapAfterExclusiveCreate(fixturePaths, async () => {
    assert.throws(() => {
      const anchor = new Zk1SyncAtomicRetainedAnchorDevOff({
        filename: fixturePaths.filename, bootstrapNew: true,
        signerPrivateKey: signer.privateKey,
        ownerBindings: [{ scope, accountId: crypto.randomUUID(),
          storeId: crypto.randomUUID() }],
        trustedMinimumHeads: [{ scope, sequence: 0, headHash: GENESIS }],
      });
      anchor.close();
    }, { code: "SYNC_ATOMIC_RETAINED_ANCHOR_DEV_OFF_DENIED" });
  });
});

test("DEV-OFF CAS floor rejects replacement of newly created SQLite inode", async (t) => {
  const fixturePaths = fixture(t, "zk65-codeql-cas-race-");
  const cas = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const anchor = crypto.generateKeyPairSync("ed25519");
  const scope = "race:cas";
  await swapAfterExclusiveCreate(fixturePaths, async () => {
    await assert.rejects(async () => {
      const ledger = await Zk1SyncAtomicCasFloorLedgerDevOff.open({
        filename: fixturePaths.filename, bootstrapNew: true,
        casPrivateKey: cas.privateKey, witnessPublicKey: witness.publicKey,
        anchorPublicKey: anchor.publicKey,
        ownerBindings: [{ scope, accountId: crypto.randomUUID(),
          storeId: crypto.randomUUID(), username: "owner", compartmentId: "private" }],
        physicalFence: { withCurrentRead: async () => { throw Error("unused"); } },
        retainedAnchor: {
          readSignedHead: async ({ scope: name, nonce }) => {
            const statement = { version: 1, scope: name, nonce, sequence: 0,
              headHash: GENESIS };
            return { statement, signature: crypto.sign(null,
              Buffer.from(ANCHOR_DOMAIN + protocol.canonicalJson(statement)),
              anchor.privateKey).toString("base64url") };
          },
          compareAndAdvance: async () => { throw Error("unused"); },
        },
      });
      ledger.close();
    }, { code: "SYNC_ATOMIC_CAS_DEV_OFF_UNVERIFIED" });
  });
});
