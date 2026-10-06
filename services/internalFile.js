const fs = require("node:fs");

function sameFileIdentity(left, right) {
  const exactInteger = (value, allowZero) => {
    if (typeof value === "bigint") return value >= (allowZero ? 0n : 1n) ? value : null;
    if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) return null;
    return BigInt(value);
  };
  const leftDevice = exactInteger(left.dev, true);
  const rightDevice = exactInteger(right.dev, true);
  const leftInode = exactInteger(left.ino, false);
  const rightInode = exactInteger(right.ino, false);
  if (leftDevice === null || rightDevice === null || leftInode === null || rightInode === null) return false;
  return leftDevice === rightDevice && leftInode === rightInode;
}

function assertRegularFile(stat, maxBytes) {
  const tooLarge = typeof stat.size === "bigint" ? stat.size > BigInt(maxBytes) : !Number.isSafeInteger(stat.size) || stat.size > maxBytes;
  if (!stat.isFile() || tooLarge) {
    throw Object.assign(new Error("Internal state file is not a bounded regular file"), { code: "INVALID_INTERNAL_FILE" });
  }
}

function readBoundedRegularFile(filePath, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new TypeError("maxBytes must be a non-negative safe integer");
  // Parent-directory substitution must be prevented by the caller; Node lacks portable dirfd-relative open on Windows.
  const preOpenPathStat = fs.lstatSync(filePath, { bigint: true });
  if (preOpenPathStat.isSymbolicLink()) throw Object.assign(new Error("Internal state file cannot be a symbolic link"), { code: "INVALID_INTERNAL_FILE" });
  assertRegularFile(preOpenPathStat, maxBytes);
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const descriptorStat = fs.fstatSync(descriptor, { bigint: true });
    assertRegularFile(descriptorStat, maxBytes);
    if (!sameFileIdentity(preOpenPathStat, descriptorStat)) {
      throw Object.assign(new Error("Internal state file changed while opening"), { code: "INVALID_INTERNAL_FILE" });
    }
    const pathStat = fs.lstatSync(filePath, { bigint: true });
    if (pathStat.isSymbolicLink() || !sameFileIdentity(pathStat, descriptorStat)) {
      throw Object.assign(new Error("Internal state file changed while opening"), { code: "INVALID_INTERNAL_FILE" });
    }

    const chunks = [];
    const buffer = Buffer.alloc(Math.min(64 * 1024, maxBytes + 1));
    let total = 0;
    while (total <= maxBytes) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, maxBytes + 1 - total), total);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) throw Object.assign(new Error("Internal state file exceeds its size limit"), { code: "INVALID_INTERNAL_FILE" });
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }

    const finalDescriptorStat = fs.fstatSync(descriptor, { bigint: true });
    const finalPathStat = fs.lstatSync(filePath, { bigint: true });
    if (finalPathStat.isSymbolicLink() || !sameFileIdentity(descriptorStat, finalDescriptorStat) || !sameFileIdentity(finalDescriptorStat, finalPathStat)) {
      throw Object.assign(new Error("Internal state file changed while reading"), { code: "INVALID_INTERNAL_FILE" });
    }
    assertRegularFile(finalDescriptorStat, maxBytes);
    return { contents: Buffer.concat(chunks, total), stat: fs.fstatSync(descriptor) };
  } finally {
    fs.closeSync(descriptor);
  }
}

module.exports = { readBoundedRegularFile };
