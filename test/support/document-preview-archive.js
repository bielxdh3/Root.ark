"use strict";

// Archiver 7 exposed a callable factory, whereas Archiver 8 (as pinned by
// package-lock.json) exposes ZipArchive as a class. Test fixtures must create
// the same real ZIP in either supported dependency environment.
const archiver = require("archiver");

function createZipArchive(options = { zlib: { level: 9 } }) {
  if (typeof archiver === "function") return archiver("zip", options);
  if (typeof archiver?.ZipArchive === "function") return new archiver.ZipArchive(options);
  throw new TypeError("A supported Archiver ZIP implementation is required");
}

module.exports = { createZipArchive };
