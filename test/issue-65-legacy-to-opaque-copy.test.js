"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { readLegacyPlaintext } = require("../public/client/rootark-dev-vault-migration");

test("opt-in legacy copy streams original bytes through the existing authenticated file route", async () => {
  const bytes = new Uint8Array([0, 13, 27, 128, 255]);
  const seen = [];
  const result = await readLegacyPlaintext({
    name: "old report.txt", folderId: "abc-123",
    fetchImpl: async (url, options) => {
      seen.push({ url, options });
      return new Response(bytes, { status: 200,
        headers: { "content-type": "text/plain", "content-length": String(bytes.length),
          "content-disposition": "attachment; filename=\"old report.txt\"" } });
    },
  });
  assert.equal(seen[0].url, "/files/old%20report.txt?folderId=abc-123");
  assert.equal(seen[0].options.credentials, "same-origin");
  assert.equal(seen[0].options.redirect, "error");
  assert.equal(seen[0].options.cache, "no-store");
  assert.equal(result.name, "old report.txt");
  assert.equal(result.mediaType, "text/plain");
  assert.deepEqual(result.data, bytes);
});

test("legacy encrypted modes, redirects, unsafe paths and unreadable content fail closed", async () => {
  for (const name of ["../secret", "folder/secret", "folder\\secret", ".",
    "", "bad\u0000name"]) {
    await assert.rejects(readLegacyPlaintext({
      name, fetchImpl: async () => { throw new Error("Must not fetch invalid path"); },
    }));
  }
  await assert.rejects(readLegacyPlaintext({
    name: "file.txt", folderId: "../other", fetchImpl: async () => {
      throw new Error("Must not fetch invalid folder ID");
    },
  }));
  await assert.rejects(readLegacyPlaintext({
    name: "already-encrypted.txt",
    fetchImpl: async () => new Response("Use encrypted download route", { status: 403 }),
  }));
  await assert.rejects(readLegacyPlaintext({
    name: "redirect.txt", fetchImpl: async () => {
      const error = new TypeError("redirect blocked");
      throw error;
    },
  }));
});

test("oversize declared and streamed legacy sources fail closed before new encrypted write", async () => {
  await assert.rejects(readLegacyPlaintext({
    name: "large.txt", maxBytes: 4,
    fetchImpl: async () => new Response("01234567", {
      status: 200, headers: { "content-length": "8",
        "content-disposition": "attachment; filename=\"large.txt\"" },
    }),
  }));
  await assert.rejects(readLegacyPlaintext({
    name: "stream.txt", maxBytes: 4,
    fetchImpl: async () => new Response("01234567", { status: 200,
      headers: { "content-disposition": "attachment; filename=\"stream.txt\"",
        "content-length": "4" } }),
  }));
});

test("200 HTML fallback, absent attachment and truncated source must never be imported", async () => {
  const cases = [
    new Response("<!doctype html>login", { status: 200,
      headers: { "content-type": "text/html", "content-length": "20" } }),
    new Response("source", { status: 200,
      headers: { "content-type": "text/plain", "content-length": "6" } }),
    new Response("source", { status: 200,
      headers: { "content-disposition": "inline; filename=\"source.txt\"",
        "content-length": "6" } }),
    new Response("source", { status: 200,
      headers: { "content-disposition": "attachment; filename=\"source.txt\"" } }),
    new Response("source", { status: 200,
      headers: { "content-disposition": "attachment; filename=\"source.txt\"",
        "content-length": "9" } }),
  ];
  for (const response of cases) {
    await assert.rejects(readLegacyPlaintext({
      name: "source.txt", fetchImpl: async () => response,
    }));
  }
});

test("temporary legacy stream chunks are scrubbed after a safe copy", async () => {
  const chunk = new Uint8Array([27, 28, 29]);
  let consumed = false;
  const original = await readLegacyPlaintext({
    name: "short.txt",
    fetchImpl: async () => ({
      status: 200,
      headers: { get(key) {
        return key === "content-disposition" ? "attachment; filename=\"short.txt\""
          : key === "content-length" ? "3" : "text/plain";
      } },
      body: { getReader() {
        return {
          async read() {
            if (consumed) return { done: true };
            consumed = true;
            return { done: false, value: chunk };
          },
          releaseLock() {},
        };
      } },
    }),
  });
  assert.deepEqual(original.data, new Uint8Array([27, 28, 29]));
  assert.deepEqual(chunk, new Uint8Array([0, 0, 0]),
    "stream buffers should be zeroed once their bytes are in the bounded result");
});
