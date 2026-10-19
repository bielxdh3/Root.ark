const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const productDiscovery = fs.readFileSync(
  path.join(__dirname, "..", "docs", "product-discovery.md"),
  "utf8",
);

function d011Record() {
  const start = productDiscovery.indexOf("### D-011:");
  if (start === -1) return "";
  return productDiscovery.slice(start).split(/\n### D-\d{3}:/, 1)[0];
}

test("recordsWebFirstTransferPurposeAndOfflineOwnerRule", () => {
  const record = d011Record();
  assert.notEqual(record, "", "D-011 must be present");
  assert.match(record, /\[DECIDED\]/i);
  assert.match(record, /2026-10-19/);
  assert.match(record, /web-first/i);
  assert.match(record, /temporary encrypted file-transfer service/i);
  assert.match(record, /Android/i);
  assert.match(record, /Windows.{0,40}Linux.{0,40}desktop|Linux.{0,40}Windows.{0,40}desktop/i);
  assert.match(record, /already downloaded|already-exported|already downloaded\/exported/i);
  assert.match(
    record,
    /Every new transfer, download from the service, authorization, device change, and account or content recovery requires an online connection and fresh independent authorization/i,
  );
  assert.match(record, /browser.{0,100}independent.{0,80}verif/i);
});

test("preservesBothRecoveryPathsAndSeparateRetention", () => {
  const record = d011Record();
  assert.notEqual(record, "", "D-011 must be present");
  assert.match(record, /password-protected.{0,80}emergency package/i);
  assert.match(record, /previously trusted devices?/i);
  assert.match(record, /D-008/i);
  assert.match(record, /retention/i);
  assert.match(record, /No transfer TTL is selected/i);
  for (const decision of ["D-006", "D-008", "D-009"]) {
    assert.match(productDiscovery, new RegExp(`^### ${decision}:`, "m"));
  }
  assert.match(record, /supersed.{0,150}new web.{0,80}(flows|Zero-Knowledge)/i);
  assert.match(record, /does not claim legacy synchronization has already changed/i);
});
