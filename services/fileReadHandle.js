"use strict";

const fs = require("node:fs");

function fileReadError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function invalidInternalFile(message) {
  return fileReadError("INVALID_INTERNAL_FILE", message);
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function openReadHandle(filePath) {
  let descriptor;
  try {
    let flags = fs.constants.O_RDONLY;
    if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
    if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
    descriptor = fs.openSync(filePath, flags);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const currentPath = fs.lstatSync(filePath, { bigint: true });
    const afterPathCheck = fs.fstatSync(descriptor, { bigint: true });
    const stableSnapshot = (stat) => stat.dev === opened.dev && stat.ino === opened.ino
      && stat.mode === opened.mode && stat.size === opened.size
      && stat.mtimeNs === opened.mtimeNs && stat.ctimeNs === opened.ctimeNs;
    if (!opened.isFile() || !currentPath.isFile() || currentPath.isSymbolicLink()
      || !stableSnapshot(currentPath) || !stableSnapshot(afterPathCheck)) {
      throw fileReadError("FILE_HANDLE_CHANGED", "File changed while it was being opened");
    }

    const stats = fs.fstatSync(descriptor);
    const result = { fd: descriptor, stats };
    descriptor = undefined;
    return result;
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    throw error;
  }
}

function readBoundedRegularFile(filePath, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes === Number.MAX_SAFE_INTEGER) {
    throw new TypeError("maxBytes must be a non-negative safe integer below Number.MAX_SAFE_INTEGER");
  }

  let descriptor;
  try {
    let flags = fs.constants.O_RDONLY;
    if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
    if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
    descriptor = fs.openSync(filePath, flags);

    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.isSymbolicLink() || opened.size > BigInt(maxBytes)) {
      throw invalidInternalFile("Internal file must be a bounded regular file");
    }
    const openedPath = fs.lstatSync(filePath, { bigint: true });
    if (!openedPath.isFile() || openedPath.isSymbolicLink() || !sameSnapshot(opened, openedPath)) {
      throw invalidInternalFile("Internal file changed while opening");
    }

    const chunks = [];
    const buffer = Buffer.alloc(Math.min(64 * 1024, maxBytes + 1));
    let total = 0;
    while (total <= maxBytes) {
      const count = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, maxBytes + 1 - total), total);
      if (count === 0) break;
      total += count;
      if (total > maxBytes) throw invalidInternalFile("Internal file exceeds its size limit");
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }

    const stat = fs.fstatSync(descriptor);
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterReadPath = fs.lstatSync(filePath, { bigint: true });
    if (!afterRead.isFile() || afterRead.size > BigInt(maxBytes)
      || !afterReadPath.isFile() || afterReadPath.isSymbolicLink()
      || !sameSnapshot(opened, afterRead) || !sameSnapshot(afterRead, afterReadPath)) {
      throw invalidInternalFile("Internal file changed while reading");
    }

    return { contents: Buffer.concat(chunks, total), stat };
  } catch (error) {
    if (error.code === "ELOOP" || error.code === "EMLINK") {
      throw invalidInternalFile("Internal file cannot be a symbolic link");
    }
    throw error;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

module.exports = { openReadHandle, readBoundedRegularFile };
