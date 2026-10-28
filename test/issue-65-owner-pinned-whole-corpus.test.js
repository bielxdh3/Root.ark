"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fileContent = require("../public/client/rootark-zk1-file-content");
const corpus = require("../src/crypto/zk1OwnerPinnedCorpusVerifier");

const DOMAIN = Buffer.from("Root.ark/zk-1/externally-pinned-owner-corpus/v1\0");
const b64 = (raw) => Buffer.from(raw).toString("base64url");
const sha = (raw) => crypto.createHash("sha256").update(raw).digest();
const id = () => b64(crypto.randomBytes(16));
const failure = /ZK_OWNER_PINNED_CORPUS_DENIED/;

async function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const pub = await crypto.webcrypto.subtle.importKey("spki",
    owner.publicKey.export({ type: "spki", format: "der" }), "Ed25519", true, ["verify"]);
  const ownerPin = sha(owner.publicKey.export({ type: "spki", format: "der" }));
  const accountId = id(), ownerGenerationId = id();
  const keyrings = [id(), id()].sort();
  const objectA = id(), objectB = id();
  const versions = [
    { keyring: keyrings[0], object: objectA, revision: 1, version: id(), parent: null },
    { keyring: keyrings[0], object: objectA, revision: 2, version: id() },
    { keyring: keyrings[1], object: objectB, revision: 1, version: id(), parent: null },
  ];
  versions[1].parent = versions[0].version;
  const recoveredFiles = [];
  for (const item of versions) {
    const metadata = {
      account_id: accountId, compartment_id: b64(Buffer.from("compartment")),
      keyring_id: item.keyring, object_id: item.object, version_id: item.version,
      parent_version_id: item.parent, epoch: item.revision, kind: "file",
    };
    const cek = crypto.randomBytes(32);
    const key = await fileContent.importFileCek(cek);
    const ciphertext = await fileContent.encryptFile({ cek: key, metadata,
      name: "synthetic.txt", mediaType: "text/plain", data: Buffer.from("synthetic fixture") });
    recoveredFiles.push({ metadata, objectRevision: item.revision, ciphertext, cek });
  }
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  recoveredFiles.sort((a, b) => compare(a.metadata.keyring_id, b.metadata.keyring_id)
    || compare(a.metadata.object_id, b.metadata.object_id)
    || a.objectRevision - b.objectRevision);
  const entries = recoveredFiles.map((row) => ({ metadata: row.metadata,
    objectRevision: row.objectRevision,
    ciphertextSha256: b64(sha(row.ciphertext)), cekSha256: b64(sha(row.cek)) }));
  function signed(sequence, previousCorpusSha256, rows = entries, roster = keyrings) {
    const unsigned = { schema: "rootark-zk1-externally-pinned-owner-corpus/v1",
      accountId, ownerGenerationId, sequence, previousCorpusSha256,
      keyrings: roster, entries: rows };
    const signature = b64(crypto.sign(null,
      Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(unsigned))]), owner.privateKey));
    const manifest = { ...unsigned, signature };
    return { manifest, independentlyPinnedCorpusSha256: sha(Buffer.from(JSON.stringify(manifest))) };
  }
  const first = signed(1, null);
  const input = { ...first, ownerPublicKey: pub, independentOwnerSpkiSha256: ownerPin,
    expectedAccountId: accountId, expectedOwnerGenerationId: ownerGenerationId,
    previousPinnedCorpus: null, recoveredFiles };
  return { input, signed, entries, keyrings, recoveredFiles, accountId };
}

test("owner-signed independently pinned full corpus validates every version and CEK", async () => {
  const f = await fixture();
  const result = await corpus.verifyPinnedOwnerCorpus(f.input);
  assert.equal(result.allExternallyPinnedCorpusEntriesRecovered, true);
  assert.equal(result.accountWideRecoveryAuthorized, false);
  assert.equal(result.globalAccountCompletenessProven, false);
  assert.equal(result.recoveredVersionCount, 3);
  assert.equal(result.verifiedKeyringCount, 2);
});

test("adversarial unknown keyring/object omission is detected against independent full-corpus pin", async () => {
  const f = await fixture();
  // The storage database reports only keyring A. It cannot tell the verifier
  // that independently inventoried B ever existed; the signed external corpus can.
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input,
    recoveredFiles: f.recoveredFiles.filter((v) => v.metadata.keyring_id === f.keyrings[0]) }),
  failure);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input,
    recoveredFiles: f.recoveredFiles.slice(1) }), failure);
  const signedSubset = f.signed(1, null, f.entries.slice(0, 2), [f.keyrings[0]]);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input,
    manifest: signedSubset.manifest, recoveredFiles: f.recoveredFiles.slice(0, 2) }), failure);
});

test("reject counterfeit CEK, mismatched ciphertext, replayed metadata, forged extra version", async () => {
  const f = await fixture();
  const first = f.recoveredFiles[0];
  for (const mutated of [
    { ...first, cek: crypto.randomBytes(32) },
    { ...first, ciphertext: crypto.randomBytes(first.ciphertext.length) },
    { ...first, metadata: { ...first.metadata, version_id: id() } },
  ]) await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input,
    recoveredFiles: [mutated, ...f.recoveredFiles.slice(1)] }), failure);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input,
    recoveredFiles: [...f.recoveredFiles, first] }), failure);
  // An attacker who can produce a valid test owner signature and matching
  // digest for an invalid CEK still cannot open the original authenticated AEAD.
  const wrongCek = crypto.randomBytes(32);
  const changedEntries = f.entries.map((entry) => ({ ...entry }));
  changedEntries[0].cekSha256 = b64(sha(wrongCek));
  const signed = f.signed(1, null, changedEntries);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input, ...signed,
    recoveredFiles: [{ ...first, cek: wrongCek }, ...f.recoveredFiles.slice(1)] }), failure);
});

test("interrupted migration fails closed; restart independently rechecks unchanged external pin", async () => {
  const f = await fixture();
  const partial = { ...f.input, recoveredFiles: f.recoveredFiles.slice(0, 2) };
  await assert.rejects(corpus.verifyPinnedOwnerCorpus(partial), failure);
  const afterRestart = { ...f.input, recoveredFiles: f.recoveredFiles.map((file) => ({
    ...file, ciphertext: Buffer.from(file.ciphertext), cek: Buffer.from(file.cek),
    metadata: { ...file.metadata },
  })) };
  assert.equal((await corpus.verifyPinnedOwnerCorpus(afterRestart)).recoveredVersionCount, 3);
});

test("independently pinned successor enforces exact sequence and predecessor after restart", async () => {
  const f = await fixture();
  const first = f.input.independentlyPinnedCorpusSha256;
  const second = f.signed(2, b64(first));
  const previousPinnedCorpus = { sequence: 1, corpusSha256: first,
    accountId: f.accountId, ownerGenerationId: f.input.expectedOwnerGenerationId,
    ownerSpkiSha256: b64(f.input.independentOwnerSpkiSha256) };
  const successor = { ...f.input, ...second,
    previousPinnedCorpus };
  assert.equal((await corpus.verifyPinnedOwnerCorpus(successor)).corpusSequence, 2);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...successor,
    previousPinnedCorpus: null }), failure);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...successor,
    previousPinnedCorpus: { ...previousPinnedCorpus,
      corpusSha256: crypto.randomBytes(32) } }), failure);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...successor,
    previousPinnedCorpus: { ...previousPinnedCorpus, ownerGenerationId: id() } }), failure);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...successor,
    manifest: f.signed(3, b64(first)).manifest }), failure);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...successor,
    manifest: f.input.manifest }), failure);
});

test("external corpus requires correct owner fingerprint, account and complete ancestry", async () => {
  const f = await fixture();
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input,
    independentOwnerSpkiSha256: crypto.randomBytes(32) }), failure);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input,
    expectedAccountId: id() }), failure);
  const broken = f.entries.map((entry) => ({ ...entry, metadata: { ...entry.metadata } }));
  broken[1].metadata.parent_version_id = id();
  const alt = f.signed(1, null, broken);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input, ...alt }), failure);
  const duplicateObject = f.entries.map((entry) => ({ ...entry, metadata: { ...entry.metadata } }));
  duplicateObject[2].metadata.object_id = duplicateObject[0].metadata.object_id;
  const duplicate = f.signed(1, null, duplicateObject);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input, ...duplicate }), failure);
});

test("owner-signed corpus still rejects CEK reuse across historical versions", async () => {
  const f = await fixture();
  const recycled = f.recoveredFiles[0].cek;
  const imported = await fileContent.importFileCek(recycled);
  const secondCiphertext = await fileContent.encryptFile({ cek: imported,
    metadata: f.recoveredFiles[1].metadata, name: "synthetic.txt",
    mediaType: "text/plain", data: Buffer.from("synthetic fixture") });
  const duplicated = f.entries.map((entry) => ({ ...entry }));
  duplicated[1].cekSha256 = duplicated[0].cekSha256;
  duplicated[1].ciphertextSha256 = b64(sha(secondCiphertext));
  // The independently supplied owner archive cannot override the invariant
  // requiring a fresh CEK for each authenticated content version.
  const signed = f.signed(1, null, duplicated);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input, ...signed,
    recoveredFiles: [f.recoveredFiles[0], { ...f.recoveredFiles[1],
      cek: Buffer.from(recycled), ciphertext: secondCiphertext }, f.recoveredFiles[2]] }), failure);
});

test("owner-signed object cannot silently change immutable compartment ownership across revisions", async () => {
  const f = await fixture();
  const second = f.recoveredFiles[1];
  const movedMetadata = { ...second.metadata,
    compartment_id: b64(Buffer.from("foreign-compartment")) };
  const key = await fileContent.importFileCek(second.cek);
  const movedCiphertext = await fileContent.encryptFile({ cek: key, metadata: movedMetadata,
    name: "synthetic.txt", mediaType: "text/plain", data: Buffer.from("synthetic fixture") });
  const entries = f.entries.map((entry) => ({ ...entry }));
  entries[1].metadata = movedMetadata;
  entries[1].ciphertextSha256 = b64(sha(movedCiphertext));
  const signed = f.signed(1, null, entries);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input, ...signed,
    recoveredFiles: [f.recoveredFiles[0], { ...second, metadata: movedMetadata,
      ciphertext: movedCiphertext }, f.recoveredFiles[2]] }), failure);
});

test("owner-selected signed subset with a NEW pin stays explicitly unproven globally", async () => {
  const f = await fixture();
  const ownSubset = f.signed(1, null, f.entries.slice(0, 2), [f.keyrings[0]]);
  const checked = await corpus.verifyPinnedOwnerCorpus({ ...f.input, ...ownSubset,
    recoveredFiles: f.recoveredFiles.slice(0, 2) });
  assert.equal(checked.allExternallyPinnedCorpusEntriesRecovered, true);
  assert.equal(checked.globalAccountCompletenessProven, false,
    "signature and self-pinned subset cannot prove unknown keyring B exists");
  assert.equal(checked.accountWideRecoveryAuthorized, false);
});

test("noncanonical nested signed manifest metadata is rejected before recovery", async () => {
  const f = await fixture();
  const misordered = f.entries.map((entry) => ({ ...entry,
    metadata: Object.fromEntries(Object.entries(entry.metadata).reverse()) }));
  const signed = f.signed(1, null, misordered);
  await assert.rejects(corpus.verifyPinnedOwnerCorpus({ ...f.input, ...signed }), failure);
});

test("crash/restart recovery in fresh Node process revalidates externally held pin and floor", async () => {
  const f = await fixture();
  const prior = f.input.independentlyPinnedCorpusSha256;
  const next = f.signed(2, b64(prior));
  const wire = {
    ...next, independentlyPinnedCorpusSha256: b64(next.independentlyPinnedCorpusSha256),
    ownerSpki: b64(Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", f.input.ownerPublicKey))),
    ownerPin: b64(f.input.independentOwnerSpkiSha256),
    accountId: f.input.expectedAccountId,
    generation: f.input.expectedOwnerGenerationId,
    floor: { sequence: 1, corpusSha256: b64(prior), accountId: f.accountId,
      ownerGenerationId: f.input.expectedOwnerGenerationId,
      ownerSpkiSha256: b64(f.input.independentOwnerSpkiSha256) },
    files: f.recoveredFiles.map((file) => ({ metadata: file.metadata,
      objectRevision: file.objectRevision, ciphertext: b64(file.ciphertext), cek: b64(file.cek) })),
  };
  const childScript = `const fs=require('node:fs'), c=require('node:crypto');
    const v=require(process.argv[1]);
    const x=JSON.parse(fs.readFileSync(0,'utf8'));
    const d=s=>Buffer.from(s,'base64url');
    (async()=>{const key=await c.webcrypto.subtle.importKey('spki',d(x.ownerSpki),'Ed25519',true,['verify']);
      await v.verifyPinnedOwnerCorpus({manifest:x.manifest,
        independentlyPinnedCorpusSha256:d(x.independentlyPinnedCorpusSha256),
        ownerPublicKey:key,independentOwnerSpkiSha256:d(x.ownerPin),
        expectedAccountId:x.accountId,expectedOwnerGenerationId:x.generation,
        previousPinnedCorpus:x.floor===null?null:{sequence:x.floor.sequence,
          corpusSha256:d(x.floor.corpusSha256),accountId:x.floor.accountId,
          ownerGenerationId:x.floor.ownerGenerationId,ownerSpkiSha256:x.floor.ownerSpkiSha256},
        recoveredFiles:x.files.map(f=>({...f,ciphertext:d(f.ciphertext),cek:d(f.cek)}))});
      process.stdout.write('verified');})().catch(()=>process.exitCode=13);`;
  const invoke = (value) => spawnSync(process.execPath,
    ["-e", childScript, require.resolve("../src/crypto/zk1OwnerPinnedCorpusVerifier")],
    { input: JSON.stringify(value), encoding: "utf8", timeout: 10000 });
  const success = invoke(wire);
  assert.equal(success.status, 0, success.stderr);
  assert.equal(success.stdout, "verified");
  const missingFloor = invoke({ ...wire, floor: null });
  assert.equal(missingFloor.status, 13);
  const interrupted = invoke({ ...wire, files: wire.files.slice(1) });
  assert.equal(interrupted.status, 13);
  const wrongAnchor = invoke({ ...wire, independentlyPinnedCorpusSha256: b64(crypto.randomBytes(32)) });
  assert.equal(wrongAnchor.status, 13);
});
