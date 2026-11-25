"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("#66 image-section research probe never resumes untrusted native code", () => {
  const file = path.resolve(__dirname, "support/issue-66-cfapi-image-section-lab.cpp");
  const source = fs.readFileSync(file, "utf8");
  assert.doesNotMatch(source, /\bResumeThread\s*\(/);
  assert.match(source, /\bCREATE_SUSPENDED\b/);
  assert.match(source, /\bTerminateProcess\s*\(/);
  assert.match(source, /\bProcessBasicInformation\b/);
  assert.match(source, /\bReadProcessMemory\s*\(/);
  assert.match(source, /\bexpectedAllowed\b/);
  assert.match(source, /C:\\\\Windows\\\\System32\\\\whoami\.exe/);
  assert.match(source, /C:\\\\Windows\\\\System32\\\\hostname\.exe/);
});
