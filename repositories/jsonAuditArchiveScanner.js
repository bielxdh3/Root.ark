"use strict";

const fs = require("node:fs");

// Read the JSON-mode archive from an already security-checked, pinned fd.
// Size of the complete archive is unrestricted; working space is bounded by
// the read block, the longest examined key/ID, and one candidate audit event.
function findArchivedRestoreAuditMatches(fd, wantedId) {
  const wantedIds = wantedId instanceof Set ? wantedId : new Set([wantedId]);
  const block = Buffer.allocUnsafe(64 * 1024);
  const eventBytes = Buffer.allocUnsafe(64 * 1024);
  const matches = [];
  const matchedIds = new Set();
  let arrayCloseOffset = -1;
  let arrayHasEntries = false;
  let offset = 0;
  let available = 0;
  let bytesRead = 0;
  let recording = false;
  let recorded = 0;
  let oversized = false;

  const invalid = () => { throw new Error("Invalid JSON restore audit history"); };
  function peek() {
    if (offset === available) {
      available = fs.readSync(fd, block, 0, block.length, null);
      offset = 0;
      bytesRead += available;
    }
    return available ? block[offset] : -1;
  }
  function take() {
    const value = peek();
    if (value === -1) invalid();
    offset += 1;
    if (recording) {
      if (recorded < eventBytes.length) eventBytes[recorded++] = value;
      else oversized = true;
    }
    return value;
  }
  function expect(value) { if (take() !== value) invalid(); }
  function whitespace() {
    while (peek() === 9 || peek() === 10 || peek() === 13 || peek() === 32) take();
  }
  function digit(value) { return value >= 48 && value <= 57; }
  function hex(value) {
    return digit(value) || (value >= 65 && value <= 70) || (value >= 97 && value <= 102);
  }
  function string(maxDecodedBytes = 0) {
    // A JSON Unicode escape occupies at most six source bytes for one UTF-8
    // code point's logical bytes. Keep a bounded encoded buffer derived from
    // the decoded-byte budget; comparing source bytes directly misses IDs
    // such as 180 escaped \u0041 sequences whose decoded value is 180 "A"s.
    const encodedBudget = maxDecodedBytes * 6 + 2; // Includes JSON quotes.
    const retained = maxDecodedBytes ? [] : null;
    function accept(value) {
      if (retained && retained.length <= encodedBudget) retained.push(value);
    }
    expect(34);
    accept(34);
    while (true) {
      const value = take();
      accept(value);
      if (value === 34) break;
      if (value < 32) invalid();
      if (value !== 92) continue;
      const escape = take();
      accept(escape);
      if ([34, 47, 92, 98, 102, 110, 114, 116].includes(escape)) continue;
      if (escape !== 117) invalid();
      for (let i = 0; i < 4; i++) {
        const char = take();
        accept(char);
        if (!hex(char)) invalid();
      }
    }
    if (!retained || retained.length > encodedBudget) return undefined;
    // JSON.parse also interprets escaped property names (e.g. "\u0069d").
    const decoded = JSON.parse(Buffer.from(retained).toString("utf8"));
    return Buffer.byteLength(decoded, "utf8") <= maxDecodedBytes ? decoded : undefined;
  }
  function literal(expected) {
    for (const char of expected) expect(char.charCodeAt(0));
  }
  function number() {
    if (peek() === 45) take();
    if (peek() === 48) take();
    else {
      if (peek() < 49 || peek() > 57) invalid();
      do { take(); } while (digit(peek()));
    }
    if (peek() === 46) {
      take();
      if (!digit(peek())) invalid();
      do { take(); } while (digit(peek()));
    }
    if (peek() === 69 || peek() === 101) {
      take();
      if (peek() === 43 || peek() === 45) take();
      if (!digit(peek())) invalid();
      do { take(); } while (digit(peek()));
    }
  }
  function value(depth, wantId = false) {
    if (depth > 256) invalid();
    whitespace();
    switch (peek()) {
      case 34: return string(wantId ? 512 : 0);
      case 123: return object(depth + 1);
      case 91: return array(depth + 1);
      case 116: literal("true"); return;
      case 102: literal("false"); return;
      case 110: literal("null"); return;
      default: number(); return;
    }
  }
  function object(depth, kind = null) {
    if (depth > 256) invalid();
    expect(123);
    whitespace();
    let id;
    let sawLogs = false;
    if (peek() === 125) { take(); return { id, sawLogs }; }
    while (true) {
      if (peek() !== 34) invalid();
      const key = string(512);
      whitespace();
      expect(58);
      whitespace();
      if (kind === "root" && key === "logs") {
        // Duplicate authority arrays would be ambiguous (JSON.parse takes last).
        if (sawLogs || peek() !== 91) invalid();
        sawLogs = true;
        archiveArray(depth + 1);
      } else if (kind === "log" && key === "id") {
        id = value(depth + 1, true);
      } else {
        value(depth + 1);
      }
      whitespace();
      const separator = take();
      if (separator === 125) return { id, sawLogs };
      if (separator !== 44) invalid();
      whitespace();
    }
  }
  function array(depth) {
    if (depth > 256) invalid();
    expect(91);
    whitespace();
    if (peek() === 93) { take(); return; }
    while (true) {
      value(depth + 1);
      whitespace();
      const separator = take();
      if (separator === 93) return;
      if (separator !== 44) invalid();
      whitespace();
    }
  }
  function archiveArray(depth) {
    if (depth > 256) invalid();
    expect(91);
    whitespace();
    if (peek() === 93) {
      arrayCloseOffset = bytesRead - (available - offset);
      take();
      return;
    }
    arrayHasEntries = true;
    while (true) {
      if (peek() === 123) {
        recording = true;
        recorded = 0;
        oversized = false;
        const { id } = object(depth + 1, "log");
        recording = false;
        if (wantedIds.has(id)) {
          if (oversized) throw new Error("Matching JSON restore audit event exceeds safe parse budget");
          if (matchedIds.has(id)) throw new Error("JSON restore audit identity collision");
          matchedIds.add(id);
          matches.push(JSON.parse(eventBytes.subarray(0, recorded).toString("utf8")));
        }
      } else invalid();
      whitespace();
      if (peek() === 93) arrayCloseOffset = bytesRead - (available - offset);
      const separator = take();
      if (separator === 93) return;
      if (separator !== 44) invalid();
      whitespace();
    }
  }

  whitespace();
  if (peek() !== 123) invalid();
  const { sawLogs } = object(0, "root");
  whitespace();
  if (!sawLogs || peek() !== -1) invalid();
  return { matches, bytesRead, arrayCloseOffset, arrayHasEntries };
}

module.exports = { findArchivedRestoreAuditMatches };
