"use strict";

const DOS_RESERVED = /^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const INTERNAL = new Set([
  ".rootark-trash", ".rootark-sync", ".rootark-sync-state.json",
  ".rootark-sync.json", ".rootark-sync-journal.json", ".rootark-sync-index.json",
  ".rootark-sync-evictions",
  ".rootark-sync.lock", ".rootark-webdav-owner.lock",
]);
const INTERNAL_PREFIXES = [".rootark-sync-lock-init-", ".rootark-sync-evictions-archive-"];

function isInternalSegment(segment) {
  const normalized = segment.toLowerCase();
  return INTERNAL.has(normalized) || INTERNAL_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function fail(name) {
  throw Object.assign(new Error(`Invalid ${name}`), { code: "unsafe_path" });
}

function validatePortableRelativePath(value, name = "path") {
  const text = String(value || "");
  if (!text || text.length > 512 || text.includes("%") || text.includes("\\") || text.includes(":") || text.startsWith("/") || /^[A-Za-z]:/.test(text)) fail(name);
  if (/[\u0000-\u001f\u007f]/.test(text)) fail(name);
  const segments = text.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === ".." || isInternalSegment(segment) || DOS_RESERVED.test(segment) || /[. ]$/.test(segment))) fail(name);
  return text;
}

function isInternalRelativePath(value) {
  return String(value || "").split("/").some(isInternalSegment);
}

module.exports = { DOS_RESERVED, INTERNAL, INTERNAL_PREFIXES, isInternalRelativePath, validatePortableRelativePath };
