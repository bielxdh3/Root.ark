const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

function createCloudTempMutationQueue({ directory, lifecycleLock, localPathFor, upload, remove, isSuppressed = () => false, area = "temp" } = {}) {
  if (!directory || !lifecycleLock?.run || typeof localPathFor !== "function" || typeof upload !== "function" || typeof remove !== "function") {
    throw new TypeError("Cloud mutation queue requires storage, lock, and provider operations");
  }
  if (!["temp", "uploads"].includes(area)) throw new TypeError("Invalid cloud mutation area");
  const queueDirectory = path.resolve(directory);

  function identity(folderId, fileName) {
    const cleanName = path.basename(String(fileName || ""));
    if (!cleanName || cleanName !== fileName) throw new TypeError("Invalid cloud temp filename");
    return { folderId: String(folderId || "root"), fileName: cleanName };
  }

  function recordPath(folderId, fileName) {
    const item = identity(folderId, fileName);
    const digest = crypto.createHash("sha256").update(`${item.folderId}\0${item.fileName}`).digest("hex");
    return path.join(queueDirectory, `${digest}.json`);
  }

  function readRecordSnapshot(filePath) {
    let descriptor;
    try {
      let flags = fs.constants.O_RDONLY;
      if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
      if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
      descriptor = fs.openSync(filePath, flags);
      const opened = fs.fstatSync(descriptor, { bigint: true });
      const current = fs.lstatSync(filePath, { bigint: true });
      if (!opened.isFile() || !current.isFile() || current.isSymbolicLink() || opened.dev !== current.dev || opened.ino !== current.ino) {
        throw new Error("Cloud temp queue record is not a stable regular file");
      }
      return { record: JSON.parse(fs.readFileSync(descriptor, "utf8")), identity: { dev: opened.dev, ino: opened.ino } };
    } finally { if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {} }
  }

  function readRecordFile(filePath) {
    return readRecordSnapshot(filePath).record;
  }

  function read(folderId, fileName) {
    const filePath = recordPath(folderId, fileName);
    try {
      const record = readRecordFile(filePath);
      const item = identity(folderId, fileName);
      if (record?.version !== 1 || record.folderId !== item.folderId || record.fileName !== item.fileName || (record.area || "temp") !== area || !["present", "absent"].includes(record.desired) || typeof record.generation !== "string" || !record.generation) {
        throw new Error("Cloud temp queue record is invalid");
      }
      return record;
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
  }

  function write(record) {
    fs.mkdirSync(queueDirectory, { recursive: true, mode: 0o700 });
    const destination = recordPath(record.folderId, record.fileName);
    const temporary = `${destination}.${crypto.randomUUID()}.tmp`;
    let descriptor;
    try {
      descriptor = fs.openSync(temporary, "wx", 0o600);
      fs.writeFileSync(descriptor, `${JSON.stringify(record)}\n`);
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      fs.renameSync(temporary, destination);
      try {
        const directoryDescriptor = fs.openSync(queueDirectory, "r");
        try { fs.fsyncSync(directoryDescriptor); } finally { fs.closeSync(directoryDescriptor); }
      } catch {}
    } catch (error) {
      if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
      try { fs.rmSync(temporary, { force: true }); } catch {}
      throw error;
    }
  }

  function setDesired(folderId, fileName, desired) {
    if (!["present", "absent"].includes(desired)) throw new TypeError("Invalid cloud temp desired state");
    const item = identity(folderId, fileName);
    const record = { version: 1, ...item, ...(area === "temp" ? {} : { area }), desired, generation: crypto.randomUUID(), updatedAt: new Date().toISOString() };
    write(record);
    return record;
  }

  function getRecord(folderId, fileName) {
    return read(folderId, fileName);
  }

  function restoreRecord(folderId, fileName, record) {
    const item = identity(folderId, fileName);
    if (record === null) {
      fs.rmSync(recordPath(item.folderId, item.fileName), { force: true });
      return;
    }
    if (!record || record.version !== 1 || record.folderId !== item.folderId || record.fileName !== item.fileName
      || (record.area || "temp") !== area || !["present", "absent"].includes(record.desired)
      || typeof record.generation !== "string" || !record.generation) {
      throw new Error("Cloud temp queue snapshot is invalid");
    }
    write(record);
  }

  function hasPending(folderId, fileName) {
    return Boolean(read(folderId, fileName));
  }

  function removeIfCurrent(record) {
    const filePath = recordPath(record.folderId, record.fileName);
    let snapshot;
    try { snapshot = readRecordSnapshot(filePath); }
    catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
    if (snapshot.record?.generation !== record.generation) return false;
    try {
      const current = fs.lstatSync(filePath, { bigint: true });
      if (!current.isFile() || current.isSymbolicLink() || current.dev !== snapshot.identity.dev || current.ino !== snapshot.identity.ino) return false;
    } catch { return false; }
    // Deployment boundary: OS permissions/ACLs must limit write, rename, and delete on runtime-root/data and descendants to the service account. Other writers can alter authoritative state directly; Node has no portable unlink-by-descriptor API.
    fs.rmSync(filePath, { force: false });
    return true;
  }

  async function processLocked(item) {
    for (let pass = 0; pass < 100; pass += 1) {
      const record = read(item.folderId, item.fileName);
      if (!record) return;
      if (record.desired === "absent") {
        await remove(item.folderId, item.fileName, area);
      } else {
        if (area === "temp" && isSuppressed(item.folderId, item.fileName, area)) {
          if (removeIfCurrent(record)) return;
          continue;
        }
        const localPath = localPathFor(item.folderId, item.fileName, area);
        const stat = fs.lstatSync(localPath);
        if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Cloud temp source is not a regular file");
        await upload(localPath, item.folderId, item.fileName, area);
      }
      if (removeIfCurrent(record)) return;
    }
    throw new Error("Cloud temp mutation queue did not converge");
  }

  async function process(folderId, fileName) {
    const item = identity(folderId, fileName);
    return lifecycleLock.run(item.folderId, item.fileName, () => processLocked(item));
  }

  async function enqueue(folderId, fileName, desired) {
    const item = identity(folderId, fileName);
    return lifecycleLock.run(item.folderId, item.fileName, async () => {
      setDesired(item.folderId, item.fileName, desired);
      await processLocked(item);
    });
  }

  async function processAll() {
    if (!fs.existsSync(queueDirectory)) return;
    const records = [];
    for (const entry of fs.readdirSync(queueDirectory, { withFileTypes: true })) {
      if (!entry.isFile() || entry.isSymbolicLink() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) continue;
      let record;
      try { record = readRecordFile(path.join(queueDirectory, entry.name)); }
      catch { throw new Error("Cloud temp queue contains a malformed record"); }
      if (record?.version !== 1 || typeof record.folderId !== "string" || typeof record.fileName !== "string" || (record.area || "temp") !== area || !["present", "absent"].includes(record.desired) || typeof record.generation !== "string") {
        throw new Error("Cloud temp queue contains an invalid record");
      }
      if (recordPath(record.folderId, record.fileName) !== path.join(queueDirectory, entry.name)) throw new Error("Cloud temp queue record identity does not match its filename");
      records.push(record);
    }
    const results = await Promise.allSettled(records.map((record) => process(record.folderId, record.fileName)));
    const failed = results.filter((result) => result.status === "rejected");
    if (failed.length) throw new AggregateError(failed.map((result) => result.reason), "Cloud temp mutations remain pending");
  }

  return { enqueue, getRecord, hasPending, process, processAll, restoreRecord, setDesired };
}

module.exports = { createCloudTempMutationQueue };
