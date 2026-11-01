"use strict";

// Explicit DEV-OFF process boundary for the Sync v2 retained high-water.
// No physical witness, owner custody guarantee or protected ACK capability.
const crypto = require("node:crypto");
const net = require("node:net");
const path = require("node:path");
const { assertPrivateSqliteFile, assertPrivateSqliteAuthorityDirectory } =
  require("../src/services/zk1PrivateSqlitePath");
const { createAuthorityPinnedReader } =
  require("../src/services/zk1AuthorityPinnedFile");
const { verifyWindowsAuthorityFilePath } =
  require("../services/chunkUploadWindowsAcl");
const { Zk1SyncAtomicRetainedAnchorDevOff } =
  require("../src/services/zk1SyncAtomicRetainedAnchorDevOff");
const { createZk1SyncAtomicRetainedAnchorHttpsServerDevOff,
  createZk1SyncAtomicRetainedAnchorHttpsClientDevOff } =
  require("../src/services/zk1SyncAtomicRetainedAnchorHttpsDevOff");

function demand(ok) { if (!ok) throw Error("SYNC_RETAINED_OPERATOR_DEV_OFF_DENIED"); }
function exact(object, fields) {
  demand(object && typeof object === "object" && !Array.isArray(object)
    && Object.keys(object).length === fields.length
    && fields.every((field) => Object.hasOwn(object, field)));
}

function operatorConfiguration(file) {
  demand(typeof file === "string" && path.isAbsolute(file));
  const absolute = path.resolve(file);
  const directory = path.dirname(absolute);
  assertPrivateSqliteAuthorityDirectory(absolute);
  // A private parent directory does not necessarily protect a leaf file's
  // Windows DACL (e.g. a granted direct READ ACE with traverse bypass).
  // Reuse one native verifier while rechecking every separate file admission.
  const pinned = createAuthorityPinnedReader();
  try {
    const config = JSON.parse(pinned.read(absolute, 1024 * 1024).toString("utf8"));
    const fields = ["version", "host", "port", "database", "serverKey",
      "serverCert", "clientCa", "signerKey", "ownerBindings",
      "trustedMinimumHeads", "principals"];
    demand(config.version === 1 || config.version === 2);
    exact(config, config.version === 2 ? [...fields, "minimumFence"] : fields);
    demand(typeof config.host === "string"
      && net.isIP(config.host) !== 0
      && Number.isSafeInteger(config.port) && config.port >= 0
      && config.port <= 65535
      && (config.port !== 0 || process.env.NODE_ENV === "test"));
    const ownedFile = (name) => {
      demand(typeof name === "string" && /^[A-Za-z0-9._-]{1,100}$/.test(name)
        && name !== "." && name !== "..");
      return path.join(directory, name);
    };
    const dbFile = ownedFile(config.database);
    assertPrivateSqliteFile(dbFile);
    // SQLite is not a bounded small trust file, but its leaf write/delete
    // ACL still needs the native owner-only policy before WAL is opened.
    if (process.platform === "win32") verifyWindowsAuthorityFilePath(dbFile);
    const readPrivate = (name) => pinned.read(ownedFile(name), 1024 * 1024);
    const signerPrivateKey = crypto.createPrivateKey(readPrivate(config.signerKey));
    let minimumFence = null;
    if (config.version === 2) {
      const minimum = config.minimumFence;
      exact(minimum, ["hostname", "port", "servername",
        "pinnedServerFingerprint", "publicKeyFile", "caFile", "certFile", "keyFile"]);
      const minimumKey = crypto.createPublicKey(readPrivate(minimum.publicKeyFile));
      demand(minimumKey.asymmetricKeyType === "ed25519"
        && minimumKey.export({ type: "spki", format: "der" }).toString("hex")
          !== crypto.createPublicKey(signerPrivateKey)
            .export({ type: "spki", format: "der" }).toString("hex"));
      const client = createZk1SyncAtomicRetainedAnchorHttpsClientDevOff({
        hostname: minimum.hostname, port: minimum.port,
        servername: minimum.servername,
        pinnedServerFingerprint: minimum.pinnedServerFingerprint,
        ca: readPrivate(minimum.caFile), cert: readPrivate(minimum.certFile),
        key: readPrivate(minimum.keyFile), anchorPublicKey: minimumKey,
      });
      minimumFence = { publicKey: minimumKey,
        readSignedHead: client.readSignedHead,
        readSignedBindingHead: client.readSignedBindingHead,
        compareAndAdvance: client.compareAndAdvance };
    }
    return {
      config, dbFile, key: readPrivate(config.serverKey),
      cert: readPrivate(config.serverCert),
      ca: readPrivate(config.clientCa),
      signerPrivateKey, minimumFence,
    };
  } finally { pinned.stop(); }
}

async function main() {
  demand(["development", "test"].includes(process.env.NODE_ENV)
    && process.env.ROOTARK_SYNC_RETAINED_OPERATOR_DEV_OFF === "true"
    && process.argv.length === 3);
  const setup = operatorConfiguration(process.argv[2]);
  // No implicit bootstrap, secret key generation, floor reset or file repair.
  const anchor = new Zk1SyncAtomicRetainedAnchorDevOff({
    filename: setup.dbFile, bootstrapNew: false,
    ownerBindings: setup.config.ownerBindings,
    trustedMinimumHeads: setup.config.trustedMinimumHeads,
    signerPrivateKey: setup.signerPrivateKey,
    minimumFencePublicKey: setup.minimumFence?.publicKey || null,
  });
  let server;
  try {
    if (setup.minimumFence) {
      // Before advertising READY, reconcile every local scope with a fresh,
      // independently signed minimum. A restored SQLite prefix must not
      // briefly serve even a signed stale head during operator startup.
      for (const { scope } of setup.config.ownerBindings) {
        const nonce = crypto.randomBytes(32).toString("base64url");
        const remote = await setup.minimumFence.readSignedBindingHead({ scope, nonce });
        const local = anchor.readSignedBindingHead({ scope, nonce });
        demand(remote.statement.sequence === local.statement.sequence
          && remote.statement.headHash === local.statement.headHash
          && remote.statement.accountId === local.statement.accountId
          && remote.statement.storeId === local.statement.storeId);
      }
    }
    server = createZk1SyncAtomicRetainedAnchorHttpsServerDevOff({
      key: setup.key, cert: setup.cert, clientCa: setup.ca,
      anchor, principals: setup.config.principals,
      minimumFence: setup.minimumFence,
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(setup.config.port, setup.config.host, resolve);
    });
  } catch (error) {
    server?.close();
    anchor.close();
    throw error;
  }
  const ready = { kind: "SYNC_RETAINED_OPERATOR_DEV_READY",
    port: server.address().port };
  if (typeof process.send === "function") process.send(ready);
  else process.stdout.write(JSON.stringify(ready) + "\n");
  const close = () => server.close(() => {
    anchor.close();
    process.exitCode = 0;
  });
  process.once("SIGTERM", close);
  process.once("SIGINT", close);
}

main().catch(() => {
  process.stderr.write("SYNC_RETAINED_OPERATOR_DEV_OFF_DENIED\n");
  process.exitCode = 1;
});
