"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("backup history provides matching column labels for its responsive layout", () => {
  const publicDir = path.join(__dirname, "..", "public");
  const source = fs.readFileSync(path.join(publicDir, "client", "rootark-management.js"), "utf8");
  const css = fs.readFileSync(path.join(publicDir, "styles", "app.css"), "utf8");
  const heading = source.split(/\r?\n/).find((line) => line.includes('id="backups-title"') && line.includes("<thead>"));
  const row = source.split(/\r?\n/).find((line) => line.includes("backup.createdAt") && line.includes("<tr>"));
  assert.ok(heading, "backup history table must have a header");
  assert.ok(row, "backup history must have a row template");
  const columns = Array.from(heading.matchAll(/<th scope="col">([^<]+)<\/th>/g), (match) => match[1]);
  const labels = Array.from(row.matchAll(/<td data-label="([^"]+)">/g), (match) => match[1]);
  assert.equal(columns.length, 5);
  assert.deepEqual(labels, columns);
  assert.match(css, /content:\s*attr\(data-label\)/);
});
