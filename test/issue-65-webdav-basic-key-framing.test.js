"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createWebDavCredentialCache } = require("../src/services/webdavCredentialCache");

test("WebDAV credential cache keys distinguish username/password boundaries even with embedded NUL", () => {
  const cache = createWebDavCredentialCache();
  const a = cache.keyFor("shared", "suffix\u0000secret");
  const b = cache.keyFor("shared\u0000suffix", "secret");
  assert.notEqual(a, b, "a password must not alias a different username's credential cache entry");
  assert.equal(cache.keyFor("shared", "suffix\u0000secret"), a, "the same credentials retain one cache key");
});
