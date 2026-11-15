"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fileContent = require("../public/client/rootark-zk1-file-content");
const search = require("../public/client/rootark-zk1-protected-text-batch");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const sha = (bytes) => b64(crypto.createHash("sha256").update(bytes).digest());
const id = () => b64(crypto.randomBytes(16));

async function fixture() {
  const scope = { account_id: id(), compartment_id: id(), keyring_id: id() };
  const digest = b64(crypto.randomBytes(32));
  const grant = { ...scope, device_id: id(), current_epoch: 3,
    manifest_revision: 11, manifest_digest: digest, revoked_at_epoch: null };
  const ownerHead = { epoch: 3, revision: 11, digest };
  const baseline = { head: { sequence: 10, digest: b64(crypto.randomBytes(32)) },
    entries: [] };
  const items = [];
  const checked = new Map();
  for (const [name, content] of [
    ["plan.txt", "No surprises: protected document about orçamento secreto"],
    ["groceries.txt", "arroz, leite, pão e batatas"],
  ]) {
    const selected = { objectId: id(), revision: 1, epoch: 3 };
    const metadata = { ...scope, object_id: selected.objectId, version_id: id(),
      parent_version_id: null, epoch: 3, kind: "file" };
    const rawCek = crypto.randomBytes(32);
    const cek = await fileContent.importFileCek(rawCek);
    const ciphertext = await fileContent.encryptFile({ cek, metadata, name,
      mediaType: "text/plain", data: new TextEncoder().encode(content) });
    const ciphertextDigestBase64 = sha(ciphertext);
    const entry = { ...selected, ciphertextDigestBase64 };
    baseline.entries.push(entry);
    checked.set(selected.objectId + ":" + selected.revision, {
      ...entry, verifiedCiphertext: true, plaintextAvailable: false,
      authorizesMutation: false, ciphertextBase64: b64(ciphertext),
    });
    items.push({ selected: entry, metadata, rawCek,
      cekSha256Pin: sha(rawCek) });
  }
  let active = true;
  const queried = [];
  const input = { query: "ORC\u0327AMENTO", items, grant, ownerHead, baseline,
    assertLive() { if (!active) throw Error("LOGGED_OUT"); },
    async getChecked(objectId, revision) {
      queried.push({ objectId, revision });
      return checked.get(objectId + ":" + revision);
    } };
  return { input, queried, checked, items, logout() { active = false; } };
}

test("bounded signed GET and separately owner-pinned CEKs search several protected texts locally", async () => {
  const f = await fixture();
  const matches = await search.search(f.input);
  assert.equal(matches.totalSearched, 2);
  assert.equal(matches.totalMatches, 1);
  assert.equal(matches.plaintextSentToServer, false);
  assert.equal(matches.matches[0].name, "plan.txt");
  assert.match(matches.matches[0].excerpt, /orçamento secreto/i);
  assert.equal(Object.hasOwn(matches.matches[0], "text"), false);
  assert.deepEqual(f.queried, f.items.map(({ selected }) => ({
    objectId: selected.objectId, revision: selected.revision })));
  assert.equal(JSON.stringify(f.queried).includes("ORC"), false);
});

test("tamper of second signed ciphertext or one CEK denies the entire result, not partial matches", async () => {
  const f = await fixture();
  const second = f.items[1].selected;
  const key = second.objectId + ":" + second.revision;
  f.checked.set(key, { ...f.checked.get(key),
    ciphertextBase64: b64(crypto.randomBytes(48)) });
  await assert.rejects(search.search(f.input), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  f.checked.set(key, { ...f.checked.get(key), ciphertextBase64: "###" });
  await assert.rejects(search.search(f.input), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  const g = await fixture();
  g.items[1].rawCek = crypto.randomBytes(32);
  await assert.rejects(search.search(g.input), /ZK_BATCH_TEXT_SEARCH_DENIED/);
});

test("stale device, wrong scope, session logout and changed signed metadata deny all matches", async () => {
  const f = await fixture();
  f.logout();
  await assert.rejects(search.search(f.input), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  const g = await fixture();
  await assert.rejects(search.search({ ...g.input,
    grant: { ...g.input.grant, revoked_at_epoch: 3 } }),
  /ZK_BATCH_TEXT_SEARCH_DENIED/);
  const h = await fixture();
  await assert.rejects(search.search({ ...h.input,
    ownerHead: { ...h.input.ownerHead, revision: 12 } }),
  /ZK_BATCH_TEXT_SEARCH_DENIED/);
  const i = await fixture();
  i.items[1].metadata = { ...i.items[1].metadata, compartment_id: id() };
  await assert.rejects(search.search(i.input), /ZK_BATCH_TEXT_SEARCH_DENIED/);
});

test("bounded explicit selection and local query reject duplicates, overflow and invalid input", async () => {
  const f = await fixture();
  for (const patch of [
    { query: "" }, { query: " \n" }, { query: "x".repeat(121) },
    { items: [f.items[0], f.items[0]] },
    { items: Array(9).fill(f.items[0]) }, { items: [] },
    { getChecked: null }, { assertLive: null },
  ]) {
    await assert.rejects(search.search({ ...f.input, ...patch }),
      /ZK_BATCH_TEXT_SEARCH_DENIED/);
  }
});
