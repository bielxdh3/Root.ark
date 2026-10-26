"use strict";

// Exercise the actual private startup readers without starting CAS/floor
// listeners or provisioning a real remote authority. The source is loaded with
// inert service imports; node:fs and the pinned-file helper remain real.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Module = require("node:module");
const { execFileSync } = require("node:child_process");
const test = require("node:test");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

function privateRoot() {
  if (process.platform === "win32") {
    const folder = path.join(process.env.LOCALAPPDATA,
      `zk65-codeql-authority-${crypto.randomBytes(8).toString("hex")}`);
    ensureWindowsChunkUploadRoot(folder);
    return folder;
  }
  return fs.mkdtempSync(path.join(os.tmpdir(), "zk65-codeql-authority-"));
}

function loadReader(filename, readerName) {
  const sourceFile = require.resolve(`../src/services/${filename}`);
  const service = new Module(sourceFile, module);
  service.filename = sourceFile;
  service.paths = Module._nodeModulePaths(path.dirname(sourceFile));
  const realRequire = service.require.bind(service);
  service.require = (specifier) => {
    // Never initialize a signer, remote client, or database during a reader test.
    if (specifier.startsWith("./") && specifier !== "./zk1AuthorityPinnedFile") return {};
    return realRequire(specifier);
  };
  service._compile(`${fs.readFileSync(sourceFile, "utf8")}
    module.exports.__authorityReaderUnderTest = ${readerName};`, sourceFile);
  return service.exports.__authorityReaderUnderTest;
}

for (const [service, reader] of [
  ["zk1OpaqueCatalogCasService.js", "readBounded"],
  ["zk1OpaqueCatalogIndependentFloorService.js", "read"],
]) {
  test(`${service}: refuses a publicly readable operator Ed25519/TLS material path`, (t) => {
    const root = privateRoot();
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const filename = path.join(root, "authority-key.pem");
    fs.writeFileSync(filename, "fixture-only-secret-key", { mode: 0o600 });
    const read = loadReader(service, reader);
    assert.equal(read(filename).toString(), "fixture-only-secret-key",
      "private, genuine operator material must continue to load");
    if (process.platform === "win32") {
      execFileSync("icacls.exe", [filename, "/grant", "*S-1-5-32-545:R"],
        { windowsHide: true });
    } else {
      fs.chmodSync(filename, 0o644);
    }
    assert.throws(() => read(filename),
      /ZK_(?:OPAQUE_CAS_SERVICE_CONFIG_DENIED|OPAQUE_FLOOR_SERVICE_CONFIG_DENIED|AUTHORITY_FILE_UNTRUSTED)/,
      "a readable PEM must not be loaded before startup security validation");
  });

  test(`${service}: refuses a junction/symlink ancestor for a private signer`, (t) => {
    const root = privateRoot();
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const vault = path.join(root, "vault");
    if (process.platform === "win32") ensureWindowsChunkUploadRoot(vault);
    else fs.mkdirSync(vault, { mode: 0o700 });
    fs.writeFileSync(path.join(vault, "signer.pem"), "operator-only-signer", { mode: 0o600 });
    const redirected = path.join(root, "redirected");
    fs.symlinkSync(vault, redirected, process.platform === "win32" ? "junction" : "dir");
    const read = loadReader(service, reader);
    assert.throws(() => read(path.join(redirected, "signer.pem")),
      /ZK_(?:OPAQUE_CAS_SERVICE_CONFIG_DENIED|OPAQUE_FLOOR_SERVICE_CONFIG_DENIED|AUTHORITY_FILE_UNTRUSTED)/,
      "authority material must not be read across redirected ancestors");
  });
}
