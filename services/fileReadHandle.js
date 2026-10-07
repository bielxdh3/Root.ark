"use strict";

const fs = require("node:fs");

function fileReadError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function openReadHandle(filePath) {
  let descriptor;
  try {
    const beforeOpen = fs.lstatSync(filePath, { bigint: true });
    if (!beforeOpen.isFile() || beforeOpen.isSymbolicLink()) {
      throw fileReadError("FILE_NOT_REGULAR", "File is not a regular file");
    }

    let flags = fs.constants.O_RDONLY;
    if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
    if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
    descriptor = fs.openSync(filePath, flags);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const sameFile = beforeOpen.dev === opened.dev
      && beforeOpen.ino === opened.ino
      && beforeOpen.mode === opened.mode
      && beforeOpen.size === opened.size
      && beforeOpen.mtimeNs === opened.mtimeNs
      && beforeOpen.ctimeNs === opened.ctimeNs;
    if (!opened.isFile() || !sameFile) {
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

module.exports = { openReadHandle };
