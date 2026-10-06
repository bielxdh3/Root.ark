const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const unzipper = require("unzipper");
const { validateBackupArchive } = require("../services/restoreService");

const ROOT = path.resolve(__dirname, "..");

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function writeZip(target, entries) {
  const local = [];
  const central = [];
  let offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const bytes = Buffer.from(entry.bytes || "");
    const checksum = crc32(bytes);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x800, 6);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(bytes.length, 18);
    localHeader.writeUInt32LE(bytes.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    local.push(localHeader, name, bytes);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(entry.versionMadeBy ?? 0x0314, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x800, 8);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(bytes.length, 20);
    centralHeader.writeUInt32LE(bytes.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt32LE(entry.externalFileAttributes ?? 0x81a40000, 38);
    centralHeader.writeUInt32LE(offset, 42);
    central.push(centralHeader, name);
    offset += localHeader.length + name.length + bytes.length;
  }

  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  fs.writeFileSync(target, Buffer.concat([...local, centralBytes, end]));
}

function manifest(backupId = "fixture-backup") {
  return { name: "backup-manifest.json", bytes: JSON.stringify({ backup_id: backupId }) };
}

function state(target) {
  try {
    const stat = fs.lstatSync(target);
    if (stat.isFile()) return `file:${crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex")}`;
    return stat.isDirectory() ? `directory:${fs.readdirSync(target).sort().join(",")}` : "other";
  } catch (error) {
    if (error.code === "ENOENT") return "absent";
    throw error;
  }
}

test("hostile backup archives are rejected without side effects", async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-hostile-archive-"));
  t.after(() => fs.rmSync(sandbox, { recursive: true, force: true }));
  const outside = path.join(sandbox, "outside-sentinel.txt");
  const runtimeJson = path.join(sandbox, "runtime", "data", "state.json");
  const runtimeUpload = path.join(sandbox, "runtime", "uploads", "file.bin");
  const history = path.join(sandbox, "runtime", "data", "backup-history.json");
  for (const [target, bytes] of [[outside, "outside"], [runtimeJson, "json"], [runtimeUpload, "upload"], [history, "history"]]) {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, bytes);
  }
  const protectedPaths = [outside, runtimeJson, runtimeUpload, history, path.join(ROOT, "data", "backups"), path.join(ROOT, "data", "backup-history.json")];
  const before = protectedPaths.map(state);

  await t.test("valid control archive", async () => {
    const valid = path.join(sandbox, "valid.zip");
    writeZip(valid, [manifest(), { name: "data/config.json", bytes: "{}" }, { name: "uploads/folder/file.bin", bytes: Buffer.from([0, 1, 2, 255]) }]);
    const accepted = await validateBackupArchive({}, valid);
    assert.equal(accepted.manifest.backup_id, "fixture-backup");
  });

  const symlink = { name: "uploads/link", bytes: "../outside-sentinel.txt", versionMadeBy: 0x0314, externalFileAttributes: 0xa1ff0000 };
  const cases = [
    ["checksum mismatch", [manifest()], "Checksum do backup nao confere", { checksum: "0".repeat(64) }],
    ["POSIX traversal", [manifest(), { name: "data/../../outside.txt" }], "Path traversal bloqueado"],
    ["backslash traversal", [manifest(), { name: "data\\..\\outside.txt" }], "Path traversal bloqueado"],
    ["absolute POSIX path", [manifest(), { name: "/data/file.txt" }], "Caminho invalido no backup"],
    ["Windows drive path", [manifest(), { name: "C:\\data\\file.txt" }], "Caminho invalido no backup"],
    ["disallowed root", [manifest(), { name: "private/file.txt" }], "Entrada nao permitida no backup"],
    ["Unix symlink metadata", [manifest(), symlink], "Symlink bloqueado no backup"],
    ["nested backups", [manifest(), { name: "data/backups/copy.zip" }], "Entrada sensivel bloqueada no backup"],
    ["whole-restore coordinator control file", [manifest(), { name: "data/.rootark-restore-coordinator.json", bytes: "{}" }], "Entrada de controle bloqueada no backup"],
    ["active request lease control directory", [manifest(), { name: "data/.rootark-active-requests/active.json", bytes: "{}" }], "Entrada de controle bloqueada no backup"],
    ["restore restart acknowledgement control directory", [manifest(), { name: "data/.rootark-restore-restart-acks/transaction/instance.json", bytes: "{}" }], "Entrada de controle bloqueada no backup"],
    ["server master key", [manifest(), { name: "data/server-master.key" }], "Entrada sensivel bloqueada no backup"],
    ["environment file", [manifest(), { name: "data/.env" }], "Entrada sensivel bloqueada no backup"],
    ["missing manifest", [{ name: "data/config.json", bytes: "{}" }], "Manifest ausente no backup"],
    ["manifest without backup id", [manifest(null)], "Manifest invalido"],
    ["duplicate manifest", [manifest(), manifest("second")], "Entrada duplicada no backup"],
    ["exact duplicate", [manifest(), { name: "data/item.json" }, { name: "data/item.json" }], "Entrada duplicada no backup"],
    ["separator-normalized duplicate", [manifest(), { name: "uploads/folder/item.bin" }, { name: "uploads\\folder\\item.bin" }], "Entrada duplicada no backup"],
    ["case-insensitive duplicate", [manifest(), { name: "data/Item.json" }, { name: "data/item.json" }], "Entrada duplicada no backup"],
  ];

  for (const [name, entries, category, backup = {}] of cases) {
    await t.test(name, async () => {
      const archive = path.join(sandbox, `${name.replace(/\W+/g, "-")}.zip`);
      writeZip(archive, entries);
      if (name === "Unix symlink metadata") {
        const raw = (await unzipper.Open.file(archive)).files.find((entry) => entry.path === symlink.name);
        assert.equal(raw.versionMadeBy, 0x0314);
        assert.equal(raw.externalFileAttributes, 0xa1ff0000);
        assert.equal(raw.type, "File");
      }
      await assert.rejects(validateBackupArchive(backup, archive), (error) => error.message.startsWith(category));
      assert.equal(state(path.join(sandbox, "extracted")), "absent");
      assert.equal(state(path.join(sandbox, "runtime", "data", "backups", ".restore-tmp")), "absent");
      assert.deepEqual(protectedPaths.map(state), before);
    });
  }
});
