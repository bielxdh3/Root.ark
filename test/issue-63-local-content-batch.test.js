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

test("P2: checked GET callback cannot replace the live-session guard after logout", async () => {
  const positive = await fixture();
  assert.equal((await search.search(positive.input)).totalMatches, 1,
    "the simulated verified-row fixture and real local AEAD opener must produce a match");

  const f = await fixture();
  const originalGet = f.input.getChecked;
  const forgedGuard = () => {};
  let readCalls = 0;
  f.input.getChecked = async (objectId, revision) => {
    // This is the same simulated GET and real sealed ciphertext as the success
    // case, but the caller logs out while the awaited read is outstanding.
    const checked = await originalGet(objectId, revision);
    readCalls += 1;
    f.logout();
    f.input.assertLive = forgedGuard;
    return checked;
  };
  await assert.rejects(search.search(f.input), /ZK_BATCH_TEXT_SEARCH_DENIED/,
    "the original live guard must deny before any private text is returned");
  assert.equal(readCalls, 1, "the simulated checked ciphertext was obtained before logout");
  assert.equal(f.queried.length, 1, "the first checked GET path was reached");
  assert.equal(f.input.assertLive, forgedGuard,
    "the attacker actually replaced the caller-owned callback during the await");
});

test("P2: an awaited GET cannot swap the independently signed reader for the next item", async () => {
  const baseline = await fixture();
  assert.equal((await search.search({ ...baseline.input, query: "arroz" })).totalMatches, 1,
    "real AEAD data and the original verified GET callback must produce a second-item match");

  const f = await fixture();
  f.input.query = "arroz";
  const originalGet = f.input.getChecked;
  const second = f.items[1].selected;
  const preRevocationCache = f.checked.get(second.objectId + ":" + second.revision);
  let firstReads = 0;
  let staleReaderCalls = 0;
  let revoked = false;
  f.input.getChecked = async (objectId, revision) => {
    if (revoked) throw Error("SIGNED_GET_REVOKED");
    firstReads += 1;
    const result = await originalGet(objectId, revision);
    // A caller-controlled reader is replaced while the first signed read is
    // pending. The forged replacement is a cached authenticated-looking row
    // and must never stand in for a fresh second GET after the revocation.
    revoked = true;
    f.input.getChecked = async () => {
      staleReaderCalls += 1;
      return preRevocationCache;
    };
    return result;
  };
  await assert.rejects(search.search(f.input), /ZK_BATCH_TEXT_SEARCH_DENIED/,
    "the originally captured reader must fail closed on a subsequent revoked GET");
  assert.equal(firstReads, 1, "the first signed GET really completed before revocation");
  assert.equal(staleReaderCalls, 0, "the substituted cached reader must never execute");
  assert.equal(f.queried.length, 1, "only the pre-revocation GET may reach the original fixture");
});

test("P2: an awaited GET cannot expand the bounded selected revision set", async () => {
  const f = await fixture();
  const originalGet = f.input.getChecked;
  let appended = 0;
  f.input.getChecked = async (objectId, revision) => {
    const result = await originalGet(objectId, revision);
    if (appended === 0) {
      // The authenticated selection had only two revisions. A callback that
      // settles its first signed GET is able to mutate the caller-owned array.
      // The old for..of re-read its length and opened nine EXTRA ciphertexts.
      f.input.items.push(...Array(9).fill(f.items[0]));
      appended = 9;
    }
    return result;
  };
  const result = await search.search(f.input);
  assert.equal(appended, 9, "the async array mutation really occurred");
  assert.equal(result.totalSearched, 2, "only the entry-validated revisions may be counted");
  assert.equal(f.queried.length, 2, "no additional signed GET may escape the eight-item bound");
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
