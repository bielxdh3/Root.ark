"use strict";

// The protected WebDAV overwrite MOVE produces two original signed envelopes
// from ONE journal mutation. Valid Ed25519 signatures for unrelated events
// cannot be spliced together, even if metadata.path is identical.
const crypto = require("node:crypto");

function verifyWebdavOverwriteProvenance(deleted, moved) {
  const destination = deleted?.metadata?.path;
  if (typeof destination !== "string" || !destination
    || destination !== moved?.metadata?.path
    || typeof moved?.metadata?.sourcePath !== "string"
    || !moved.metadata.sourcePath
    || deleted.operation !== "delete" || moved.operation !== "move"
    || typeof deleted.operationId !== "string"
    || typeof moved.operationId !== "string") return false;
  const match = /^webdav-([A-Za-z0-9._:-]{1,100})-([0-9a-f]{24})$/
    .exec(deleted.operationId);
  if (!match) return false;
  const eventId = match[1];
  const idFor = (verb) => `webdav-${eventId}-${crypto.createHash("sha256")
    .update(`${verb}:${destination}`, "utf8").digest("hex").slice(0, 24)}`;
  return deleted.operationId === idFor("delete")
    && moved.operationId === idFor("move");
}

module.exports = { verifyWebdavOverwriteProvenance };
