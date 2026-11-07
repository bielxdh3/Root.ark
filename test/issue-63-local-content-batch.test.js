"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const fileContent = require("../public/client/rootark-zk1-file-content");
const search = require("../public/client/rootark-zk1-protected-text-batch");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const sha = (bytes) => b64(crypto.createHash("sha256").update(bytes).digest());
const id = () => b64(crypto.randomBytes(16));

async function fixture(count = 2, replacements = {}) {
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
    ...Array.from({ length: Math.max(0, count - 2) }, (_, index) =>
      ["ledger-" + index + ".txt", "Confidential owner-only content orçamento #" + index]),
  ].slice(0, count).map(([name, content]) =>
    [name, replacements[name] ?? content])) {
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

test("opt-in ALL TERMS matches reordered NFC/case-folded literals; default phrase remains unchanged", async () => {
  const f = await fixture();
  const query = "SeCrEtO   ORC\u0327AMENTO";
  const phrase = await search.search({ ...f.input, query });
  assert.equal(phrase.totalMatches, 0, "default still requires the whole phrase in order");
  const all = await search.search({ ...f.input, query, matchMode: "all-terms" });
  assert.equal(all.totalSearched, 2);
  assert.equal(all.totalMatches, 1);
  assert.equal(all.matches[0].name, "plan.txt");
  assert.match(all.matches[0].excerpt, /orçamento secreto/i);
  assert.equal(all.plaintextSentToServer, false);
  assert.equal(all.authorizesMutation, false);
  assert.equal(f.queried.length, 4, "each mode uses only the existing signed GET per selected revision");
  assert.ok(f.queried.every((entry) => Object.keys(entry).sort().join(",") === "objectId,revision"));
  assert.ok(!JSON.stringify(f.queried).includes("SeCrEtO"));
  const unicodeSpacing = await search.search({ ...f.input,
    query: "SECRETO\u00a0orçamento", matchMode: "all-terms" });
  assert.equal(unicodeSpacing.totalMatches, 1, "Unicode whitespace separates tokens locally");
  const missing = await search.search({ ...f.input,
    query: "secreto inexistente", matchMode: "all-terms" });
  assert.equal(missing.totalMatches, 0, "AND requires every literal term");
});

test("ALL TERMS excerpts map folded offsets back to NFC source for expanding Unicode folds", async () => {
  for (const { source, query, expected } of [
    { source: "İ".repeat(100) + "needle word", query: "needle word",
      expected: "needle word" },
    { source: "İ".repeat(100) + "STRAẞE Cafe\u0301", query: "café straße",
      expected: "STRAẞE Café" },
    { source: "İ".repeat(100) + "EARLY middle LATE", query: "late early",
      expected: "EARLY" },
  ]) {
    const f = await fixture(1, { "plan.txt": source });
    const found = await search.search({ ...f.input, query, matchMode: "all-terms" });
    assert.equal(found.totalMatches, 1, "all required terms match under NFC/lowercase");
    assert.ok(found.matches[0].excerpt.length > 0, "excerpt cannot be empty");
    assert.ok(found.matches[0].excerpt.includes(expected), "excerpt must use original NFC text");
    assert.ok(found.matches[0].excerpt.length <= 160, "excerpt remains bounded");
    assert.equal(found.plaintextSentToServer, false);
    assert.equal(f.queried.length, 1);
    assert.deepEqual(Object.keys(f.queried[0]).sort(), ["objectId", "revision"]);
  }
  const f = await fixture(1, { "plan.txt": "İ".repeat(100) + "needle word" });
  const phrase = await search.search({ ...f.input, query: "needle word" });
  assert.equal(phrase.totalMatches, 1, "phrase search still matches exact literal");
  assert.ok(phrase.matches[0].excerpt.includes("needle word"),
    "phrase mode also gets the safe Unicode offset correction");
  const missing = await search.search({ ...f.input,
    query: "needle absent", matchMode: "all-terms" });
  assert.equal(missing.totalMatches, 0, "missing term prevents a partial AND match");
});

test("invalid Unicode line separators before and after ALL TERMS never start signed GET", async () => {
  const f = await fixture();
  for (const query of ["\u2028alpha beta", "alpha beta\u2029",
    "\u2029alpha beta", "alpha beta\u2028", "alpha\u2028beta", "alpha\u2029beta"]) {
    await assert.rejects(search.search({ ...f.input, matchMode: "all-terms", query }),
      /ZK_BATCH_TEXT_SEARCH_DENIED/);
  }
  assert.equal(f.queried.length, 0, "forbidden separators never reach GET");
});

test("ALL TERMS validates 2-4 distinct bounded tokens before any network or key access", async () => {
  const f = await fixture();
  for (const patch of [
    { matchMode: "all-terms", query: "secreto" },
    { matchMode: "all-terms", query: "um dois tres quatro cinco" },
    { matchMode: "all-terms", query: "x".repeat(41) + " segredo" },
    { matchMode: "all-terms", query: "ORC\u0327AMENTO orçamento" },
    { matchMode: "all-terms", query: "secreto SECRETO" },
    { matchMode: "all-terms", query: "secreto\tsegredo" },
    { matchMode: "all-terms", query: "secreto\u0000segredo" },
    { matchMode: "all-terms", query: "x".repeat(121) },
    { matchMode: "unsupported", query: "secreto orçamento" },
    { matchMode: true, query: "secreto orçamento" },
  ]) {
    await assert.rejects(search.search({ ...f.input, ...patch }),
      /ZK_BATCH_TEXT_SEARCH_DENIED/, JSON.stringify(patch));
  }
  assert.equal(f.queried.length, 0, "bad options never start signed GET");
  const exactlyFour = await search.search({ ...f.input, matchMode: "all-terms",
    query: "No surprises: protected document" });
  assert.equal(exactlyFour.totalMatches, 1);
});

test("64 owner-selected exact revisions run in eight bounded windows with disposable CEKs and progress-only callbacks", async () => {
  const f = await fixture(64);
  const keys = new Map();
  const items = f.items.map(({ rawCek, ...rest }, index) => {
    const cekFile = "offline-" + index + ".bin";
    keys.set(cekFile, rawCek);
    return { ...rest, cekFile };
  });
  let last = null;
  const progress = [];
  const result = await search.search({ ...f.input, items, query: "orçamento",
    async readCek(name) {
      if (last) assert.ok(last.every((byte) => byte === 0),
        "previous CEK must be zeroed before reading the next one");
      last = new Uint8Array(keys.get(name));
      return last;
    },
    onProgress(value) {
      assert.deepEqual(Object.keys(value).sort(), ["completed", "total"],
        "no query, filename, excerpts or CEK may reach progress");
      progress.push({ ...value });
    },
    isCancelled: () => false,
  });
  assert.equal(result.totalSearched, 64);
  assert.equal(result.totalMatches, 63);
  assert.equal(result.matches.length, 63);
  assert.deepEqual(progress, [8, 16, 24, 32, 40, 48, 56, 64].map((completed) =>
    ({ completed, total: 64 })));
  assert.ok(last.every((byte) => byte === 0));
  assert.equal(f.queried.length, 64, "one exact signed GET per selected revision");
  assert.equal(JSON.stringify(f.queried).includes("orçamento"), false);
  assert.ok(result.matches.every((match) => !Object.hasOwn(match, "text")));
});

test("window 2 tamper or cancellation denies ALL earlier-window matches and never reads later keys", async () => {
  for (const mode of ["tamper", "cancel", "all-terms-cancel"]) {
    const f = await fixture(17);
    const keys = new Map();
    const items = f.items.map(({ rawCek, ...rest }, index) => {
      const cekFile = "offline-" + index + ".bin";
      keys.set(cekFile, rawCek);
      return { ...rest, cekFile };
    });
    const next = f.items[8].selected;
    const checkedKey = next.objectId + ":" + next.revision;
    if (mode === "tamper") f.checked.set(checkedKey, { ...f.checked.get(checkedKey),
      ciphertextBase64: b64(crypto.randomBytes(47)) });
    const progress = [];
    let readCount = 0;
    await assert.rejects(search.search({ ...f.input, items,
      query: mode === "all-terms-cancel" ? "owner-only orçamento" : "orçamento",
      ...(mode === "all-terms-cancel" ? { matchMode: "all-terms" } : {}),
      readCek: async (name) => { readCount++; return new Uint8Array(keys.get(name)); },
      onProgress: ({ completed }) => { progress.push(completed); },
      isCancelled: () => mode.includes("cancel") && progress.length >= 1,
    }), /ZK_BATCH_TEXT_SEARCH_DENIED/);
    assert.deepEqual(progress, [8], "no progress or verified result from failed window");
    assert.ok(readCount <= 9, "late windows and keys must never be touched");
  }
});

test("selected set max 64 and cancellation callback bounds reject before any signed GET", async () => {
  const f = await fixture(65);
  await assert.rejects(search.search(f.input), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.queried.length, 0);
  await assert.rejects(search.search({ ...f.input, items: f.items.slice(0, 9) }),
    /ZK_BATCH_TEXT_SEARCH_DENIED/, "multi-window must not borrow all CEKs in memory");
  assert.equal(f.queried.length, 0);
  await assert.rejects(search.search({ ...f.input, items: f.items.slice(0, 9),
    isCancelled: () => true }), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(f.queried.length, 0);
});

test("nine sealed revisions across two windows use signed disposable HTTP; forged last reply reveals no earlier matches", async (t) => {
  const f = await fixture(9, { "ledger-6.txt":
    "İ".repeat(100) + "needle word Confidential owner-only content orçamento #6" });
  const signer = crypto.generateKeyPairSync("ed25519");
  const domain = Buffer.from("Root.ark/zk-1/disposable-window-signed-read/v1\0");
  let tamperLast = false;
  const observed = [];
  const server = http.createServer(async (req, res) => {
    try {
      assert.equal(req.method, "POST");
      assert.equal(req.url, "/signed-content-read");
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const wire = Buffer.concat(chunks).toString("utf8");
      observed.push(wire);
      const { scope, objectId, revision, nonce, signature } = JSON.parse(wire);
      const authorization = JSON.stringify({ scope, objectId, revision, nonce });
      assert.equal(scope, f.input.grant.account_id);
      assert.match(nonce, /^[A-Za-z0-9_-]{22}$/);
      assert.ok(crypto.verify(null, Buffer.concat([domain, Buffer.from(authorization)]),
        signer.publicKey, Buffer.from(signature, "base64url")));
      const exact = f.checked.get(objectId + ":" + revision);
      assert.ok(exact);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(tamperLast && observed.length === 9
        ? { ...exact, ciphertextBase64: b64(crypto.randomBytes(70)) } : exact));
    } catch (_) { res.writeHead(403).end("{}"); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const endpoint = "http://127.0.0.1:" + server.address().port + "/signed-content-read";
  const files = new Map();
  const items = f.items.map(({ rawCek, ...item }, i) => {
    const cekFile = "key-" + i + ".bin";
    files.set(cekFile, rawCek);
    return { ...item, cekFile };
  });
  const run = (options = {}) => search.search({ ...f.input, items, query: "orçamento", ...options,
    readCek: async (name) => new Uint8Array(files.get(name)),
    getChecked: async (objectId, revision) => {
      const auth = { scope: f.input.grant.account_id, objectId, revision,
        nonce: b64(crypto.randomBytes(16)) };
      const signature = b64(crypto.sign(null, Buffer.concat([
        domain, Buffer.from(JSON.stringify(auth))]), signer.privateKey));
      const response = await fetch(endpoint, { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...auth, signature }) });
      assert.equal(response.status, 200);
      return response.json();
    } });
  const matched = await run();
  assert.equal(matched.totalSearched, 9);
  assert.equal(matched.totalMatches, 8);
  assert.equal(observed.length, 9);
  assert.ok(observed.every((wire) => !wire.includes("orçamento")
    && !wire.includes("Confidential") && !wire.includes("cekSha256Pin")
    && !wire.includes("rawCek") && !wire.includes("ciphertextBase64")));
  observed.length = 0;
  const allTerms = await run({ matchMode: "all-terms", query: "OWNER-ONLY   ORÇAMENTO" });
  assert.equal(allTerms.totalSearched, 9);
  assert.equal(allTerms.totalMatches, 7, "only seven ledger versions contain both terms");
  assert.equal(observed.length, 9, "ALL TERMS adds no extra signed GETs");
  assert.ok(observed.every((wire) => !/OWNER-ONLY|ORÇAMENTO/i.test(wire)
    && !wire.includes("cekSha256Pin") && !wire.includes("rawCek")));
  observed.length = 0;
  const unicode = await run({ matchMode: "all-terms", query: "needle word" });
  assert.equal(unicode.totalSearched, 9);
  assert.equal(unicode.totalMatches, 1);
  assert.ok(unicode.matches[0].excerpt.includes("needle word"),
    "signed HTTP + AEAD last-window result must include source literal");
  assert.ok(unicode.matches[0].excerpt.length > 0);
  assert.equal(observed.length, 9, "query adds no extra authenticated GETs");
  assert.ok(observed.every((wire) => !wire.includes("needle")
    && !wire.includes("word") && !wire.includes("rawCek")
    && !wire.includes("cekSha256Pin")));
  observed.length = 0;
  tamperLast = true;
  await assert.rejects(run(), /ZK_BATCH_TEXT_SEARCH_DENIED/);
  assert.equal(observed.length, 9, "later-window corruption must fail after eight authentic reads");
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
