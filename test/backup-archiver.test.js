const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createRequire } = require("node:module");
const test = require("node:test");
const { ZipArchive } = require("archiver");
const unzipper = require("unzipper");

test("Archiver 8 creates a ZIP archive", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-archiver-"));
  const archivePath = path.join(tempDir, "backup.zip");
  try {
    await new Promise((resolve, reject) => {
      const output = fs.createWriteStream(archivePath);
      const archive = new ZipArchive({ zlib: { level: 9 } });
      output.on("close", resolve);
      output.on("error", reject);
      archive.on("error", reject);
      archive.pipe(output);
      archive.append("disposable", { name: "validation.txt" });
      archive.finalize();
    });
    assert.ok(fs.statSync(archivePath).size > 0);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("Archiver glob traversal works with a patched minimatch", async () => {
  const requireFromReaddirGlob = createRequire(require.resolve("readdir-glob", { paths: [require.resolve("archiver")] }));
  const minimatchVersion = requireFromReaddirGlob("minimatch/package.json").version;
  const [major, minor, patch] = minimatchVersion.split(".").map(Number);
  assert.ok(major > 11 || (major === 11 && (minor > 0 || patch >= 1)), `unsafe minimatch ${minimatchVersion}`);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-archiver-glob-"));
  const inputDir = path.join(tempDir, "input");
  const archivePath = path.join(tempDir, "filtered.zip");
  try {
    fs.mkdirSync(path.join(inputDir, "nested"), { recursive: true });
    fs.mkdirSync(path.join(inputDir, "skip"));
    fs.writeFileSync(path.join(inputDir, "root.txt"), "root");
    fs.writeFileSync(path.join(inputDir, "nested", "child.md"), "child");
    fs.writeFileSync(path.join(inputDir, "skip", "excluded.txt"), "excluded");
    await new Promise((resolve, reject) => {
      const output = fs.createWriteStream(archivePath);
      const archive = new ZipArchive({ zlib: { level: 9 } });
      output.on("close", resolve);
      output.on("error", reject);
      archive.on("error", reject);
      archive.pipe(output);
      archive.glob("**/*.{txt,md}", { cwd: inputDir, ignore: ["skip/**"] });
      archive.finalize();
    });
    const archive = await unzipper.Open.file(archivePath);
    const entries = archive.files.filter((entry) => entry.type !== "Directory").map((entry) => entry.path).sort();
    assert.deepEqual(entries, ["nested/child.md", "root.txt"]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
