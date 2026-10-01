"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const FIXTURE_MARKER = ".rootark-disposable-fixture";
const FIXTURE_MARKER_VALUE = "rootark-zk-inventory-fixture-v1";
const METADATA_FILE = "encrypted-files.json";
const MAX_METADATA_BYTES = 4 * 1024 * 1024;
const MAX_MARKER_BYTES = 64;
const MAX_RECORD_BYTES = 64 * 1024;
const MAX_RECORDS = 5000;
const MAX_JSON_DEPTH = 32;
const MAX_RECORD_FIELDS = 256;
const MAX_NESTED_FIELDS = 4096;
const MAX_ARRAY_ITEMS = 10000;
const MAX_JSON_TOKENS = 100000;
const SUPPORTED_LEGACY_MODES = new Set(["server-key", "user-key", "password", "dual"]);

const repositoryRoot = path.resolve(__dirname, "..");

function refuse(message) {
  const error = new Error(message);
  error.inventoryRefusal = true;
  throw error;
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function assertNoSymlinkComponents(targetPath) {
  const resolved = path.resolve(targetPath);
  const root = path.parse(resolved).root;
  let current = root;

  for (const component of resolved.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch {
      refuse("fixture path is unavailable");
    }
    if (stat.isSymbolicLink()) refuse("symlinks are not allowed");
  }

  return resolved;
}

function readRegularFile(filePath, maximumBytes) {
  let before;
  try {
    before = fs.lstatSync(filePath);
  } catch {
    refuse("required fixture file is unavailable");
  }
  if (before.isSymbolicLink() || !before.isFile()) refuse("fixture files must be regular files");
  if (before.size > maximumBytes) refuse("fixture file exceeds the size limit");

  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) {
      refuse("fixture file changed while opening");
    }

    const chunks = [];
    const chunk = Buffer.alloc(16 * 1024);
    let total = 0;
    while (true) {
      const remaining = maximumBytes + 1 - total;
      const amount = fs.readSync(descriptor, chunk, 0, Math.min(chunk.length, remaining), null);
      if (amount === 0) break;
      total += amount;
      if (total > maximumBytes) refuse("fixture file exceeds the size limit");
      chunks.push(Buffer.from(chunk.subarray(0, amount)));
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    if (error.inventoryRefusal) throw error;
    refuse("fixture file could not be read safely");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function utf8ByteLengthRange(text, start, end) {
  let bytes = 0;
  for (let index = start; index < end; index += 1) {
    const code = text.codePointAt(index);
    if (code > 0xffff) index += 1;
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code <= 0xffff) bytes += 3;
    else bytes += 4;
  }
  return bytes;
}

class LegacyMetadataScanner {
  constructor(buffer) {
    try {
      this.text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    } catch {
      refuse("legacy encryption metadata is not valid UTF-8");
    }
    this.index = 0;
    this.tokens = 0;
  }

  skipWhitespace() {
    while (/[\u0020\u0009\u000a\u000d]/.test(this.text[this.index] || "")) this.index += 1;
  }

  expect(character) {
    this.skipWhitespace();
    if (this.text[this.index] !== character) refuse("legacy encryption metadata is malformed");
    this.index += 1;
  }

  countToken() {
    this.tokens += 1;
    if (this.tokens > MAX_JSON_TOKENS) refuse("metadata token count exceeds the limit");
  }

  readString(decode) {
    this.skipWhitespace();
    const start = this.index;
    if (this.text[this.index] !== '"') refuse("legacy encryption metadata is malformed");
    this.index += 1;
    let hasEscape = false;

    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        this.countToken();
        const token = { start, end: this.index, hasEscape };
        if (decode) {
          try {
            token.value = JSON.parse(this.text.slice(start, this.index));
          } catch {
            refuse("legacy encryption metadata is malformed");
          }
        }
        return token;
      }
      if (code < 0x20) refuse("legacy encryption metadata is malformed");
      if (code === 0x5c) {
        hasEscape = true;
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === "u") {
          const hex = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) refuse("legacy encryption metadata is malformed");
          this.index += 5;
        } else if ('"\\/bfnrt'.includes(escape || "")) {
          this.index += 1;
        } else {
          refuse("legacy encryption metadata is malformed");
        }
      } else {
        this.index += 1;
      }
    }
    refuse("legacy encryption metadata is malformed");
  }

  readNumber() {
    this.skipWhitespace();
    const start = this.index;
    if (this.text[this.index] === "-") {
      this.index += 1;
      if (!/[0-9]/.test(this.text[this.index] || "")) refuse("legacy encryption metadata is malformed");
    }
    if (this.text[this.index] === "0") {
      this.index += 1;
    } else {
      if (!/[1-9]/.test(this.text[this.index] || "")) refuse("legacy encryption metadata is malformed");
      while (/[0-9]/.test(this.text[this.index] || "")) this.index += 1;
    }
    if (this.text[this.index] === ".") {
      this.index += 1;
      if (!/[0-9]/.test(this.text[this.index] || "")) refuse("legacy encryption metadata is malformed");
      while (/[0-9]/.test(this.text[this.index] || "")) this.index += 1;
    }
    if (this.text[this.index] === "e" || this.text[this.index] === "E") {
      this.index += 1;
      if (this.text[this.index] === "+" || this.text[this.index] === "-") this.index += 1;
      if (!/[0-9]/.test(this.text[this.index] || "")) refuse("legacy encryption metadata is malformed");
      while (/[0-9]/.test(this.text[this.index] || "")) this.index += 1;
    }
    if (this.index === start) refuse("legacy encryption metadata is malformed");
    this.countToken();
  }

  readLiteral(value) {
    this.skipWhitespace();
    if (this.text.slice(this.index, this.index + value.length) !== value) {
      refuse("legacy encryption metadata is malformed");
    }
    this.index += value.length;
    this.countToken();
  }

  readValue(depth) {
    this.skipWhitespace();
    if (depth > MAX_JSON_DEPTH) refuse("metadata nesting exceeds the limit");
    const character = this.text[this.index];
    if (character === '"') {
      this.readString(false);
      return;
    }
    if (character === "{") {
      this.readIgnoredObject(depth + 1);
      return;
    }
    if (character === "[") {
      this.readIgnoredArray(depth + 1);
      return;
    }
    if (character === "t") return this.readLiteral("true");
    if (character === "f") return this.readLiteral("false");
    if (character === "n") return this.readLiteral("null");
    this.readNumber();
  }

  readIgnoredObject(depth) {
    if (depth > MAX_JSON_DEPTH) refuse("metadata nesting exceeds the limit");
    this.expect("{");
    this.countToken();
    this.skipWhitespace();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return;
    }

    const seenKeys = new Set();
    let fields = 0;
    while (true) {
      const keyToken = this.readString(true);
      if (seenKeys.has(keyToken.value)) refuse("metadata contains duplicate object fields");
      seenKeys.add(keyToken.value);
      fields += 1;
      if (fields > MAX_NESTED_FIELDS) refuse("nested metadata field count exceeds the limit");
      this.expect(":");
      this.readValue(depth);
      this.skipWhitespace();
      if (this.text[this.index] === "}") {
        this.index += 1;
        return;
      }
      this.expect(",");
    }
  }

  readIgnoredArray(depth) {
    if (depth > MAX_JSON_DEPTH) refuse("metadata nesting exceeds the limit");
    this.expect("[");
    this.countToken();
    this.skipWhitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return;
    }

    let items = 0;
    while (true) {
      items += 1;
      if (items > MAX_ARRAY_ITEMS) refuse("nested metadata array exceeds the item limit");
      this.readValue(depth);
      this.skipWhitespace();
      if (this.text[this.index] === "]") {
        this.index += 1;
        return;
      }
      this.expect(",");
    }
  }

  readRecord() {
    this.skipWhitespace();
    const recordStart = this.index;
    this.expect("{");
    this.countToken();
    const seenKeys = new Set();
    let fields = 0;
    let hasMode = false;
    let mode;
    this.skipWhitespace();

    if (this.text[this.index] !== "}") {
      while (true) {
        const keyToken = this.readString(true);
        if (seenKeys.has(keyToken.value)) refuse("metadata record contains duplicate fields");
        seenKeys.add(keyToken.value);
        fields += 1;
        if (fields > MAX_RECORD_FIELDS) refuse("metadata record field count exceeds the limit");
        this.expect(":");

        if (keyToken.value === "encryptionLevel") {
          const modeToken = this.readString(true);
          mode = modeToken.value;
          hasMode = true;
        } else {
          this.readValue(2);
        }

        this.skipWhitespace();
        if (this.text[this.index] === "}") break;
        this.expect(",");
      }
    }

    this.expect("}");
    if (utf8ByteLengthRange(this.text, recordStart, this.index) > MAX_RECORD_BYTES) {
      refuse("metadata record exceeds the size limit");
    }
    if (!hasMode) mode = "server-key";
    if (typeof mode !== "string" || !SUPPORTED_LEGACY_MODES.has(mode)) {
      refuse("metadata contains an unsupported encryption mode");
    }
    return { mode, modeSource: hasMode ? "recorded" : "legacy-default" };
  }

  scan() {
    this.expect("{");
    this.countToken();
    const seenRecordKeys = new Set();
    const records = [];
    this.skipWhitespace();

    if (this.text[this.index] !== "}") {
      while (true) {
        const keyToken = this.readString(false);
        if (keyToken.hasEscape || keyToken.end - keyToken.start <= 2) {
          refuse("metadata record reference is unsupported");
        }
        const keyDigest = crypto.createHash("sha256")
          .update(this.text.slice(keyToken.start, keyToken.end), "utf8")
          .digest("hex");
        if (seenRecordKeys.has(keyDigest)) refuse("metadata contains duplicate record references");
        seenRecordKeys.add(keyDigest);
        this.expect(":");
        records.push(this.readRecord());
        if (records.length > MAX_RECORDS) refuse("metadata record count exceeds the limit");
        this.skipWhitespace();
        if (this.text[this.index] === "}") break;
        this.expect(",");
      }
    }

    this.expect("}");
    this.skipWhitespace();
    if (this.index !== this.text.length) refuse("legacy encryption metadata is malformed");
    return records;
  }
}

function parseMetadata(buffer) {
  return new LegacyMetadataScanner(buffer).scan();
}

function parseArguments(args) {
  if (args.length !== 2 || args[0] !== "--source-dir" || !path.isAbsolute(args[1])) {
    refuse("usage: node scripts/zk-migration-inventory.js --source-dir <absolute-disposable-fixture>");
  }
  return args[1];
}

function buildReport(sourceDirectory, records) {
  const source = assertNoSymlinkComponents(sourceDirectory);
  if (isWithin(repositoryRoot, source)) refuse("fixture must be outside the repository");
  const temporaryRoot = path.resolve(os.tmpdir());
  if (source === temporaryRoot || !isWithin(temporaryRoot, source)) {
    refuse("fixture must be a child of the operating system temporary directory");
  }
  const directoryStat = fs.lstatSync(source);
  if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) refuse("source must be a regular fixture directory");

  const markerPath = assertNoSymlinkComponents(path.join(source, FIXTURE_MARKER));
  const marker = readRegularFile(markerPath, MAX_MARKER_BYTES).toString("utf8").trim();
  if (marker !== FIXTURE_MARKER_VALUE) refuse("fixture marker is missing or invalid");

  const metadataPath = assertNoSymlinkComponents(path.join(source, METADATA_FILE));
  const metadataBuffer = readRegularFile(metadataPath, MAX_METADATA_BYTES);
  const inventoryRecords = parseMetadata(metadataBuffer);
  const runReference = crypto.randomBytes(8).toString("hex");

  return {
    schema: "rootark-migration-inventory-v1",
    runReference: `run-${runReference}`,
    scope: "explicit-disposable-fixture-legacy-metadata-only",
    readOnly: true,
    sourceKind: "legacy-encrypted-files-metadata",
    sourceMetadata: METADATA_FILE,
    fullMigrationCoverage: false,
    recordsExamined: inventoryRecords.length,
    objects: inventoryRecords.map((record, index) => ({
      reference: `object-${runReference}-${String(index + 1).padStart(4, "0")}`,
      currentMode: record.mode,
      modeSource: record.modeSource,
      currentLabel: "legacy-encryption-mode",
      migrationLabel: "not-assessed",
      joinStatus: "unjoined",
      derivedArtifacts: "unknown",
      backups: "unknown",
      externalCloudCopies: "unknown",
      deviceOrKeyAvailability: "unknown",
    })),
    coverage: {
      inspected: [METADATA_FILE],
      notInspected: ["file-content", "user-records", "links", "versions", "derived-data", "backups", "cloud-providers", "devices", "keys", "sync", "webdav", "quarantine", "retention"],
      migrationEligibility: "unavailable-not-evaluated",
      referencesOutsideThisMetadata: "unknown",
    },
    limitations: [
      "This bounded inventory reads only the explicitly supplied disposable fixture marker and legacy encryption metadata.",
      "It does not establish object identity joins, migration readiness, complete coverage, device or key availability, or external-copy state.",
      "No content, filename, path key, username, credential, token, or encryption key is included in the report.",
    ],
  };
}

try {
  const sourceDirectory = parseArguments(process.argv.slice(2));
  const report = buildReport(sourceDirectory);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`Inventory refused: ${error.message}\n`);
  process.exitCode = 2;
}
