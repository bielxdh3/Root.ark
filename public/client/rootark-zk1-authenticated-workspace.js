(function () {
  "use strict";

  // Entry lives in the ordinary authenticated files workspace. The server
  // grants capability only in dev/test with an explicitly configured zk-1
  // plane and for its pinned Root.ark account. All keys, grant and owner/head
  // pins are provided offline by the user; none are downloaded from Root.ark.
  const api = window.RootarkApi;
  const dependencyNames = [
    "rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
    "rootark-zk1-ciphertext-download-integrity", "rootark-zk1-owner-signed-checkpoint",
    "rootark-zk1-owner-ciphertext-root-checkpoint",
    "rootark-zk1-protected-http-client", "rootark-zk1-uncertain-put-reconciliation",
    "rootark-zk1-normal-browser-trust-floor", "rootark-zk1-normal-browser-content",
    "rootark-zk1-owner-inventory-trust-head",
    "rootark-zk1-browser-authoritative-backup",
    "rootark-zk1-portable-file-recovery", "rootark-zk1-browser-recovery-http",
    "rootark-zk1-recoverable-pending-journal", "rootark-zk1-recoverable-workspace",
    "rootark-dev-vault-migration", "rootark-zk1-legacy-transition-receipt",
    "rootark-zk1-legacy-migration-workflow",
    "rootark-zk1-legacy-batch-migration",
    "rootark-zk1-v2-device-approval", "rootark-zk1-v2-browser-pop",
    "rootark-zk1-v2-committed-approval",
    "rootark-zk1-keyring-portable-archive",
    "rootark-zk1-browser-versioned-archive",
    "rootark-zk1-account-portable-recovery",
  ];
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const base64 = /^[A-Za-z0-9_-]{43}$/;
  let capability = null;
  let checking = false;
  let loadingScripts = null;
  let busy = false;
  let dialog = null;
  // A logout invalidates the operation even if an awaited crypto/file/network
  // promise later resolves. The CSRF cookie also fences session switches in
  // another tab which do not dispatch this window's logout event.
  let sessionEpoch = 0;
  const activeDownloadUrls = new Set();
  // Session-local branded approval only: logout/close erases it and a new
  // browser profile must import independently anchored evidence again.
  let committedDeviceApproval = null;
  let verifiedCatalog = null;
  // Transient one-step delta anchor. Never persist unverified sync cursors or
  // silently fetch/apply data in the generic workspace.
  let verifiedOpaqueDelta = null;
  let verifiedRevocationHead = null;

  function fail() { throw new Error("ZK_WORKSPACE_INPUT_DENIED"); }
  function supportsOwnerRootedV2(value) {
    return value?.enabled === true && value.securityVersion === 2
      && value.signedHistoryRequired === true;
  }
  function field(name) { return dialog?.querySelector('[data-zk1-field="' + name + '"]'); }
  function status(value) {
    const target = field("status");
    if (target) target.textContent = value;
  }
  function from64(value) {
    if (typeof value !== "string" || !base64.test(value)) fail();
    let decoded;
    try { decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "="); }
    catch (_) { fail(); }
    const bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    if (bytes.length !== 32) fail();
    return bytes;
  }
  function signerIdFrom64(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) fail();
    let text;
    try { text = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=="); }
    catch (_) { fail(); }
    const result = Uint8Array.from(text, (char) => char.charCodeAt(0));
    let check = "";
    for (const byte of result) check += String.fromCharCode(byte);
    if (result.length !== 16
      || btoa(check).replace(/\+/g, "-").replace(/\//g, "_")
        .replace(/=+$/g, "") !== value) fail();
    return result;
  }
  function hex(bytes) {
    return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  }
  function positive(name) {
    const raw = field(name)?.value;
    if (typeof raw !== "string" || !/^[1-9][0-9]*$/.test(raw)) fail();
    const result = Number(raw);
    if (!Number.isSafeInteger(result)) fail();
    return result;
  }
  async function fileBytes(name, minimum, maximum) {
    const files = field(name)?.files;
    if (!files || files.length !== 1) fail();
    const file = files[0];
    if (file.size < minimum || file.size > maximum) fail();
    const result = new Uint8Array(await file.arrayBuffer());
    if (result.byteLength !== file.size) fail();
    return result;
  }
  async function grantAndOwner() {
    if (!window.isSecureContext || !window.crypto?.subtle
      || !window.RootarkZk1NormalBrowserTrustFloor) fail();
    const raw = await fileBytes("owner", 32, 32);
    const ownerPublicKey = await crypto.subtle.importKey("raw", raw, "Ed25519", true, ["verify"]);
    raw.fill(0);
    const signedDeviceGrant = JSON.parse(decoder.decode(await fileBytes("grant", 1, 8192)));
    const histories = field("history")?.files;
    if (!histories || histories.length > 1) fail();
    let ownerHistoryCheckpoint = null;
    let previousOwnerHistoryProof = null;
    if (histories.length) {
      // Imported chain works on a completely new device. Verified predecessor
      // proofs have private WeakMap state, so a deserialized "verified:true"
      // flag is insufficient. Reverify every signature from genesis here.
      const provided = JSON.parse(decoder.decode(await fileBytes("history", 1, 262144)));
      const chain = Array.isArray(provided) ? provided : [provided];
      if (chain.length < 1 || chain.length > 64
        || !window.RootarkZk1OwnerSignedCheckpoint?.verifyOwnerCheckpoint) fail();
      let prior = null;
      for (let index = 0; index < chain.length; index++) {
        const checkpoint = chain[index];
        if (index === chain.length - 1) {
          ownerHistoryCheckpoint = checkpoint;
          previousOwnerHistoryProof = prior;
        }
        prior = await window.RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
          checkpoint,
          scope: { account_id: signedDeviceGrant.account_id,
            compartment_id: signedDeviceGrant.compartment_id,
            keyring_id: signedDeviceGrant.keyring_id },
          signerPublicKey: ownerPublicKey,
          signerKeyId: signerIdFrom64(checkpoint.signer_key_id),
          previous: prior,
        });
      }
    }
    const pinnedCurrentHead = {
      revision: positive("revision"), digest: from64(field("digest").value.trim()),
      epoch: positive("epoch"),
    };
    if (verifiedRevocationHead
      && [signedDeviceGrant.account_id, signedDeviceGrant.compartment_id,
        signedDeviceGrant.keyring_id].join("|") === verifiedRevocationHead.scope) {
      if (signedDeviceGrant.device_id === verifiedRevocationHead.revokedDeviceId
        || pinnedCurrentHead.revision !== verifiedRevocationHead.revision
        || pinnedCurrentHead.epoch !== verifiedRevocationHead.epoch
        || to64(pinnedCurrentHead.digest) !== verifiedRevocationHead.digest) fail();
    }
    return {
      ownerPublicKey,
      pinnedOwnerKeyHash: from64(field("owner-hash").value.trim()),
      independentOwnerSpkiSha256: from64(field("owner-spki").value.trim()),
      pinnedCurrentHead,
      signedDeviceGrant,
      ownerHistoryCheckpoint,
      previousOwnerHistoryProof,
    };
  }
  function randomId() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    let value = "";
    for (const byte of bytes) value += String.fromCharCode(byte);
    return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function to64(data) {
    let text = "";
    for (const item of data) text += String.fromCharCode(item);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function contentFrom64(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(4 * 1024 * 1024 * 4 / 3) + 4) fail();
    const text = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "="));
    const result = Uint8Array.from(text, (c) => c.charCodeAt(0));
    if (result.length < 16 || result.length > 4 * 1024 * 1024
      || to64(result) !== value) fail();
    return result;
  }
  // Download names are intentionally much narrower than valid encrypted file
  // metadata. Never interpret paths from a selected file or an imported archive.
  function localName(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 120
      || value === "." || value === ".." || /[\\/\u0000-\u001f\u007f<>:"|?*]/.test(value)
      || /[. ]$/.test(value)
      || /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(value)) fail();
    return value;
  }
  function downloadLocal(name, content, type = "application/octet-stream", assertLive) {
    assertLive();
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    activeDownloadUrls.add(url);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.append(link);
    try {
      // A download handler may synchronously log the user out. Each artifact
      // in a multi-file export gets its own check immediately before release.
      assertLive();
      link.click();
    } finally {
      link.remove();
      setTimeout(() => {
        activeDownloadUrls.delete(url);
        URL.revokeObjectURL(url);
      }, 60000);
    }
  }
  async function optionalJson(name, maximum = 8192) {
    const files = field(name)?.files;
    if (!files || files.length > 1) fail();
    return files.length ? JSON.parse(decoder.decode(await fileBytes(name, 1, maximum))) : null;
  }
  // The descriptor and each raw CEK are chosen on the local device. A JSON
  // CryptoKey, a server catalog response or a missing source pin is NEVER a
  // substitute for an explicitly imported 32-byte non-extractable CEK.
  async function selectedLegacyBatch(assertLive) {
    const raw = await fileBytes("migration-batch-descriptors", 2, 32 * 1024);
    let manifest;
    try { manifest = JSON.parse(decoder.decode(raw)); }
    finally { raw.fill(0); }
    assertLive();
    if (!manifest || Array.isArray(manifest) || typeof manifest !== "object"
      || Object.keys(manifest).sort().join(",") !== "entries,schema"
      || manifest.schema !== "rootark-zk1-legacy-version-batch/v1"
      || !Array.isArray(manifest.entries)
      || manifest.entries.length < 1 || manifest.entries.length > 12) fail();
    const files = Array.from(field("migration-batch-ceks")?.files || []);
    if (files.length !== manifest.entries.length) fail();
    const byName = new Map();
    for (const file of files) {
      if (!file || file.size !== 32 || !localName(file.name)
        || byName.has(file.name)) fail();
      byName.set(file.name, file);
    }
    const selected = [];
    const used = new Set();
    for (const descriptor of manifest.entries) {
      if (!descriptor || Array.isArray(descriptor) || typeof descriptor !== "object"
        || Object.keys(descriptor).sort().join(",") !== "cekFile,legacy,sourcePin"
        || typeof descriptor.cekFile !== "string"
        || !byName.has(descriptor.cekFile) || used.has(descriptor.cekFile)) fail();
      if (!descriptor.legacy || Array.isArray(descriptor.legacy)
        || Object.keys(descriptor.legacy).sort().join(",") !== "folderId,name"
        || typeof descriptor.legacy.name !== "string"
        || typeof descriptor.legacy.folderId !== "string"
        || !descriptor.sourcePin || Array.isArray(descriptor.sourcePin)
        || Object.keys(descriptor.sourcePin).sort().join(",")
          !== "lastModified,mediaType,sha256,size,storedAs,uploadedAt,version") fail();
      used.add(descriptor.cekFile);
      const rawCek = new Uint8Array(await byName.get(descriptor.cekFile).arrayBuffer());
      try {
        assertLive();
        if (rawCek.byteLength !== 32) fail();
        const cek = await window.RootarkZk1FileContent.importFileCek(rawCek);
        assertLive();
        selected.push({ legacy: descriptor.legacy, sourcePin: descriptor.sourcePin, cek });
      } finally { rawCek.fill(0); }
    }
    if (used.size !== files.length) fail();
    return selected;
  }
  function exactly(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) fail();
  }
  function sameSignedWire(left, right) {
    return left && right && typeof left === "object" && typeof right === "object"
      && !Array.isArray(left) && !Array.isArray(right)
      && Object.keys(left).sort().join(",") === Object.keys(right).sort().join(",")
      && Object.keys(left).every((key) => (typeof left[key] === "string"
        || Number.isSafeInteger(left[key]) || left[key] === null)
        && left[key] === right[key]);
  }
  function checkHistoricalWire(value, scope, signedGrant) {
    exactly(value, ["signedOwnerHistoryChain", "currentSignedDeviceGrant",
      "currentOwnerRootCheckpoints"]);
    if (!sameSignedWire(value.currentSignedDeviceGrant, signedGrant)
      || signedGrant.revoked_at_epoch !== null
      || !["account_id", "compartment_id", "keyring_id"].every((name) =>
        signedGrant[name] === scope[name])
      || !Array.isArray(value.signedOwnerHistoryChain)
      || value.signedOwnerHistoryChain.length < 2
      || value.signedOwnerHistoryChain.length > 64
      || !Array.isArray(value.currentOwnerRootCheckpoints)
      || value.currentOwnerRootCheckpoints.length < 1
      || value.currentOwnerRootCheckpoints.length > 12) fail();
    for (const record of [...value.signedOwnerHistoryChain, ...value.currentOwnerRootCheckpoints]) {
      if (!record || Array.isArray(record) || typeof record !== "object"
        || Object.keys(record).length > 20
        || Object.values(record).some((v) => !(typeof v === "string"
          || Number.isSafeInteger(v) || v === null))) fail();
    }
  }
  async function brandedHistoricalChain(value, trust, scope, signerKeyId, deviceId, assertLive) {
    const chain = value.signedOwnerHistoryChain;
    let previous = null;
    for (let index = 0; index < chain.length; index++) {
      const checkpoint = chain[index];
      if (checkpoint.sequence !== index + 1 || checkpoint.device_id !== deviceId
        || checkpoint.signer_key_id !== to64(signerKeyId)) fail();
      const brand = await window.RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
        checkpoint, scope, signerPublicKey: trust.ownerPublicKey,
        signerKeyId, previous,
      });
      assertLive();
      if (brand.sequence !== index + 1) fail();
      previous = brand;
    }
    const newest = chain.at(-1);
    if (newest.revision !== trust.pinnedCurrentHead.revision
      || newest.manifest_digest !== to64(trust.pinnedCurrentHead.digest)) fail();
    return previous;
  }
  async function selectedHistoricalKeyring(trust, scope, signerKeyId, deviceId, assertLive) {
    const raw = await fileBytes("archive-historical-proof", 2, 512 * 1024);
    let selection;
    try { selection = JSON.parse(decoder.decode(raw)); }
    finally { raw.fill(0); }
    assertLive();
    exactly(selection, ["schema", "scope", "historicalRecovery"]);
    exactly(selection.scope, ["account_id", "compartment_id", "keyring_id"]);
    if (selection.schema !== "rootark-zk1-keyring-history-endorsement/v1"
      || !["account_id", "compartment_id", "keyring_id"].every((name) =>
        selection.scope[name] === scope[name])) fail();
    const historic = selection.historicalRecovery;
    checkHistoricalWire(historic, scope, trust.signedDeviceGrant);
    await brandedHistoricalChain(historic, trust, scope, signerKeyId, deviceId, assertLive);
    // The existing owner-history input is separately imported and verified in
    // grantAndOwner. It must have the EXACT same current signed checkpoint.
    if (!sameSignedWire(historic.signedOwnerHistoryChain.at(-1),
      trust.ownerHistoryCheckpoint)) fail();
    assertLive();
    return historic;
  }
  // One-use device PoP is issued inside the trusted keyring module. Neither
  // challenge nor nonce may be imported from JSON or provided by the server.
  // Only the matching locally imported Ed25519 private key can sign a binding
  // over the exact keyring/account archive hash, current signed grant and head.
  async function signedHistoricalDevicePoP({ scope, pinnedCurrentHead,
    independentOwnerSpkiSha256, currentSignedDeviceGrant, archiveSha256,
    accountArchiveSha256, privateDer, assertLive }) {
    assertLive();
    if (!(privateDer instanceof Uint8Array) || privateDer.length < 1
      || privateDer.length > 8192 || currentSignedDeviceGrant.revoked_at_epoch !== null) fail();
    const keyringApi = window.RootarkZk1KeyringPortableArchive;
    if (!keyringApi?.issueHistoricalRecoveryChallenge
      || !keyringApi?.historicalRecoveryChallengeMessage) fail();
    const devicePrivateKey = await crypto.subtle.importKey("pkcs8", privateDer,
      "Ed25519", false, ["sign"]);
    assertLive();
    const devicePublicKey = await crypto.subtle.importKey("raw",
      from64(currentSignedDeviceGrant.authorization_public_key), "Ed25519", false, ["verify"]);
    const challenge = await keyringApi.issueHistoricalRecoveryChallenge({
      archiveSha256, accountArchiveSha256, scope, pinnedCurrentHead,
      independentOwnerSpkiSha256, currentSignedDeviceGrant,
    });
    assertLive();
    const message = keyringApi.historicalRecoveryChallengeMessage(challenge);
    if (!(message instanceof Uint8Array) || message.length < 1
      || message.length > 4096) fail();
    try {
      const signature = new Uint8Array(await crypto.subtle.sign("Ed25519",
        devicePrivateKey, message));
      assertLive();
      if (signature.length !== 64 || !await crypto.subtle.verify("Ed25519",
        devicePublicKey, signature, message)) fail();
      assertLive();
      return { challenge, signature: to64(signature) };
    } finally { message.fill(0); }
  }
  // Every scope, current head, active signed grant and owner history must be
  // selected outside the archive/server. Rebuild branded history proofs locally.
  async function selectedAccountKeyrings(trust, create, assertLive, accountFiles,
    historicalOptIn = false) {
    if (historicalOptIn && create) fail();
    const raw = await fileBytes("account-descriptors", 2, 512 * 1024);
    let manifest;
    try { manifest = JSON.parse(decoder.decode(raw)); }
    finally { raw.fill(0); }
    assertLive();
    exactly(manifest, ["schema", "accountId", "keyrings"]);
    if (manifest.schema !== "rootark-zk1-account-workspace-selection/v1"
      || !Array.isArray(manifest.keyrings) || manifest.keyrings.length < 1
      || manifest.keyrings.length > 8
      || manifest.accountId !== trust.signedDeviceGrant.account_id) fail();
    const holderFiles = Array.from(field("account-holder-files")?.files || []);
    const localFiles = Array.from(field("account-local-files")?.files || []);
    const privateInputs = Array.from(field("account-historical-device-privates")?.files || []);
    if (holderFiles.length !== manifest.keyrings.length
      || (!create && localFiles.length !== 0)
      || (!historicalOptIn && privateInputs.length)) fail();
    const byName = (files) => {
      const result = new Map();
      for (const item of files) {
        if (!item || !localName(item.name) || result.has(item.name)) fail();
        result.set(item.name, item);
      }
      return result;
    };
    const holders = byName(holderFiles);
    const selections = byName(localFiles);
    const privateByName = byName(privateInputs);
    const usedHolders = new Set(), usedFiles = new Set(), usedRings = new Set();
    const usedPrivates = new Set(), historyPrivateFiles = new Map();
    const keyrings = [];
    let totalBytes = 0;
    for (const selection of manifest.keyrings) {
      const hasRoots = Object.hasOwn(selection || {}, "currentOwnerRootCheckpoints");
      exactly(selection, ["scope", "pinnedCurrentHead", "signedDeviceGrant",
        "ownerHistory", "signerKeyId", "deviceId", "holderSecretFile", "files",
        ...(hasRoots ? ["currentOwnerRootCheckpoints", "devicePrivateFile"] : [])]);
      if (hasRoots && (!historicalOptIn || create)) fail();
      exactly(selection.scope, ["account_id", "compartment_id", "keyring_id"]);
      exactly(selection.pinnedCurrentHead, ["revision", "digest", "epoch"]);
      const scope = { ...selection.scope };
      const ringId = scope.compartment_id + ":" + scope.keyring_id;
      if (scope.account_id !== manifest.accountId || usedRings.has(ringId)
        || selection.signedDeviceGrant?.account_id !== scope.account_id
        || selection.signedDeviceGrant?.compartment_id !== scope.compartment_id
        || selection.signedDeviceGrant?.keyring_id !== scope.keyring_id
        || selection.signedDeviceGrant.revoked_at_epoch !== null
        || typeof selection.deviceId !== "string" || !selection.deviceId
        || selection.deviceId.length > 64
        || selection.signedDeviceGrant.device_id !== selection.deviceId
        || !Array.isArray(selection.ownerHistory) || selection.ownerHistory.length < 1
        || selection.ownerHistory.length > 64
        || !Array.isArray(selection.files)
        || (create && (selection.files.length < 1 || selection.files.length > 12))
        || (!create && selection.files.length !== 0)
        || typeof selection.holderSecretFile !== "string"
        || !holders.has(selection.holderSecretFile)
        || usedHolders.has(selection.holderSecretFile)) fail();
      usedRings.add(ringId);
      usedHolders.add(selection.holderSecretFile);
      const pinnedCurrentHead = { revision: selection.pinnedCurrentHead.revision,
        digest: from64(selection.pinnedCurrentHead.digest),
        epoch: selection.pinnedCurrentHead.epoch };
      if (!Number.isSafeInteger(pinnedCurrentHead.revision)
        || pinnedCurrentHead.revision < 1
        || !Number.isSafeInteger(pinnedCurrentHead.epoch)
        || pinnedCurrentHead.epoch < 1) fail();
      const signerKeyId = signerIdFrom64(selection.signerKeyId);
      let previousOwnerHistoryProof = null;
      let predecessor = null;
      for (const checkpoint of selection.ownerHistory) {
        if (checkpoint?.signer_key_id !== selection.signerKeyId) fail();
        predecessor = previousOwnerHistoryProof;
        previousOwnerHistoryProof = await window.RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
          checkpoint, scope, signerPublicKey: trust.ownerPublicKey,
          signerKeyId, previous: previousOwnerHistoryProof,
        });
        assertLive();
      }
      const ownerHistoryCheckpoint = selection.ownerHistory.at(-1);
      // verifyExternalAnchor consumes the branded predecessor, not the final proof.
      const anchored = { ownerPublicKey: trust.ownerPublicKey,
        independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
        pinnedCurrentHead, signedDeviceGrant: selection.signedDeviceGrant,
        ownerHistoryCheckpoint, previousOwnerHistoryProof: predecessor };
      await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent(anchored);
      assertLive();
      const holderFile = holders.get(selection.holderSecretFile);
      if (holderFile.size !== 32) fail();
      const recoverySecret = new Uint8Array(await holderFile.arrayBuffer());
      if (recoverySecret.length !== 32) { recoverySecret.fill(0); fail(); }
      accountFiles.secrets.push(recoverySecret);
      assertLive();
      const common = { scope, recoverySecret, ownerPublicKey: trust.ownerPublicKey,
        independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
        pinnedCurrentHead, signerKeyId, deviceId: selection.deviceId,
        previousOwnerHistoryProof: predecessor };
      if (create) {
        const selected = [];
        for (const filename of selection.files) {
          if (typeof filename !== "string" || !selections.has(filename)
            || usedFiles.has(filename)) fail();
          usedFiles.add(filename);
          const local = selections.get(filename);
          if (!Number.isSafeInteger(local.size) || local.size < 1
            || local.size > 8 * 1024 * 1024
            || (totalBytes += local.size) > 8 * 1024 * 1024) fail();
          const data = new Uint8Array(await local.arrayBuffer());
          accountFiles.plaintext.push(data);
          assertLive();
          if (data.length !== local.size) fail();
          selected.push({ metadata: { ...scope, object_id: randomId(),
            version_id: randomId(), parent_version_id: null,
            epoch: pinnedCurrentHead.epoch, kind: "file" },
          objectRevision: 1, name: localName(filename),
          mediaType: local.type || "application/octet-stream", data });
        }
        keyrings.push({ ...common, files: selected,
          signedDeviceGrant: selection.signedDeviceGrant,
          ownerHistoryCheckpoint });
      } else if (hasRoots) {
        if (typeof selection.devicePrivateFile !== "string"
          || !privateByName.has(selection.devicePrivateFile)
          || usedPrivates.has(selection.devicePrivateFile)) fail();
        const privateFile = privateByName.get(selection.devicePrivateFile);
        if (!Number.isSafeInteger(privateFile.size) || privateFile.size < 1
          || privateFile.size > 8192) fail();
        const devicePrivateDer = new Uint8Array(await privateFile.arrayBuffer());
        accountFiles.privates.push(devicePrivateDer);
        assertLive();
        if (devicePrivateDer.length !== privateFile.size) fail();
        usedPrivates.add(selection.devicePrivateFile);
        historyPrivateFiles.set(ringId, devicePrivateDer);
        const historicalRecovery = { signedOwnerHistoryChain: selection.ownerHistory,
          currentSignedDeviceGrant: selection.signedDeviceGrant,
          currentOwnerRootCheckpoints: selection.currentOwnerRootCheckpoints };
        checkHistoricalWire(historicalRecovery, scope, selection.signedDeviceGrant);
        await brandedHistoricalChain(historicalRecovery,
          { ...trust, pinnedCurrentHead }, scope, signerKeyId, selection.deviceId, assertLive);
        assertLive();
        keyrings.push({ ...common, previousOwnerHistoryProof: null, historicalRecovery });
      } else keyrings.push(common);
    }
    if (usedHolders.size !== holders.size
      || (create && usedFiles.size !== selections.size)
      || usedPrivates.size !== privateByName.size) fail();
    keyrings.sort((a, b) => {
      const left = a.scope.compartment_id + ":" + a.scope.keyring_id;
      const right = b.scope.compartment_id + ":" + b.scope.keyring_id;
      return left < right ? -1 : left > right ? 1 : 0;
    });
    return { accountId: manifest.accountId, keyrings,
      ...(historicalOptIn ? { historyPrivateFiles } : {}) };
  }
  function sessionFetch(url, options) {
    // Existing protected HTTP signing uses fetch directly; the real Root.ark
    // session requires the same CSRF double-submit header as RootarkApi.
    const cookie = document.cookie.split(";").map((value) => value.trim())
      .find((value) => value.startsWith("rootark_csrf="));
    if (!cookie) fail();
    const csrf = decodeURIComponent(cookie.slice("rootark_csrf=".length));
    if (!csrf) fail();
    const headers = new Headers(options.headers);
    headers.set("X-CSRF-Token", csrf);
    return fetch(url, { ...options, headers, credentials: "same-origin" });
  }
  function currentCsrf() {
    const cookie = document.cookie.split(";").map((value) => value.trim())
      .find((value) => value.startsWith("rootark_csrf="));
    if (!cookie) fail();
    const value = decodeURIComponent(cookie.slice("rootark_csrf=".length));
    if (!value) fail();
    return value;
  }
  // The catalog writer's CAS and recovery witness are independently operated
  // signed authorities. Browsers cannot inspect a TLS peer's SPKI: pin the
  // Ed25519 signing SPKI explicitly, and never obtain these pins from Root.ark.
  async function importPinnedCatalogAuthority(raw, expectedSpkiSha256) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32) fail();
    const spki = new Uint8Array(44);
    spki.set(Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b,
      0x65, 0x70, 0x03, 0x21, 0x00]));
    spki.set(raw, 12);
    const actual = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= actual[i] ^ expectedSpkiSha256[i];
    if (diff !== 0) fail();
    return crypto.subtle.importKey("raw", raw, "Ed25519", false, ["verify"]);
  }
  function independentCatalogEndpoint(value, rootOrigin) {
    if (typeof value !== "string" || value.length > 2048 || !value) fail();
    let url;
    try { url = new URL(value); } catch (_) { fail(); }
    if (url.href !== value || url.origin === rootOrigin || url.username || url.password
      || url.hash || url.search || url.pathname === "/"
      || !(url.protocol === "https:"
        || (url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)))) fail();
    return url;
  }
  function independentCatalogProbe(url, assertLive) {
    return async ({ scope, nonce }) => {
      assertLive();
      if (typeof AbortController !== "function") fail();
      const controller = new AbortController();
      let timer, reader, complete = false;
      try {
        // The limit covers DNS/headers and every chunk of the body, even when
        // the server omits or lies about Content-Length or stops sending bytes.
        const work = (async () => {
          const response = await fetch(url.href, {
            method: "POST", mode: "cors", credentials: "omit", redirect: "error",
            referrerPolicy: "no-referrer", cache: "no-store", signal: controller.signal,
            headers: { "content-type": "application/json", accept: "application/cbor" },
            body: JSON.stringify({ scope, nonceBase64: to64(nonce) }),
          });
          assertLive();
          if (response.status !== 200
            || response.headers?.get("content-type")?.split(";")[0].trim() !== "application/cbor"
            || Number(response.headers.get("content-length") || 0) > 8192
            || !response.body || typeof response.body.getReader !== "function") fail();
          reader = response.body.getReader();
          const raw = new Uint8Array(8192);
          let total = 0, chunks = 0;
          while (true) {
            const next = await reader.read();
            assertLive();
            if (controller.signal.aborted) fail();
            if (next.done) { complete = true; break; }
            if (!(next.value instanceof Uint8Array) || next.value.byteLength < 1
              || ++chunks > 8192 || next.value.byteLength > raw.length - total) fail();
            raw.set(next.value, total);
            total += next.value.byteLength;
          }
          if (total < 1) fail();
          return raw.slice(0, total);
        })();
        const result = await Promise.race([work, new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new Error("ZK_WORKSPACE_INPUT_DENIED"));
          }, 10000);
        })]);
        assertLive();
        return result;
      } finally {
        clearTimeout(timer);
        controller.abort();
        if (reader) {
          if (!complete) try { Promise.resolve(reader.cancel()).catch(() => {}); }
            catch (_) { /* stream is already closed */ }
          try { reader.releaseLock(); } catch (_) { /* stream is aborted */ }
        }
      }
    };
  }
  function loadScript(name) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "/client/" + name + ".js";
      script.onload = resolve;
      script.onerror = reject;
      document.head.append(script);
    });
  }
  async function ensureScripts() {
    if (!loadingScripts) loadingScripts = (async () => {
      for (const name of dependencyNames) await loadScript(name);
      if (!window.RootarkZk1NormalBrowserContent?.uploadAndVerify
        || !window.RootarkZk1NormalBrowserTrustFloor?.provisionOffline
        || !window.RootarkZk1RecoverableWorkspace?.restoreOnNewDevice
        || !window.RootarkZk1LegacyMigrationWorkflow?.openMigrationJournal
        || !window.RootarkZk1LegacyBatchMigration?.runLegacyMigrationBatch
        || !window.RootarkZk1V2DeviceApproval?.verifyImportedApproval
        || !window.RootarkZk1V2BrowserPop?.respond
        || !window.RootarkZk1V2CommittedApproval?.verifyCommittedApproval
        || !window.RootarkZk1KeyringPortableArchive?.createArchive
        || !window.RootarkZk1KeyringPortableArchive?.recoverArchive
        || !window.RootarkZk1KeyringPortableArchive?.issueHistoricalRecoveryChallenge
        || !window.RootarkZk1KeyringPortableArchive?.historicalRecoveryChallengeMessage) fail();
      if (!window.RootarkZk1AccountPortableRecovery?.createArchive
        || !window.RootarkZk1AccountPortableRecovery?.recoverArchive) fail();
      if (!window.RootarkZk1BrowserAuthoritativeBackup?.verifyBackupSnapshot
        || !window.RootarkZk1KeyringPortableArchive?.verifyVersionedAuthority
        || !window.RootarkZk1BrowserVersionedArchive?.createArchive
        || !window.RootarkZk1BrowserVersionedArchive?.recoverArchive) fail();
    })();
    return loadingScripts;
  }
  function createDialog() {
    if (dialog) return dialog;
    dialog = document.createElement("dialog");
    dialog.className = "zk1-workspace-dialog";
    dialog.setAttribute("aria-label", "Arquivo zk-1 de desenvolvimento");
    // None of the inputs may be prefilled with server-supplied keys or pins.
    dialog.innerHTML = '<div class="panel-heading"><div><p class="eyebrow">ROOT.ARK · DESENVOLVIMENTO</p>'
      + '<h2>Arquivo zk-1 protegido</h2></div><button type="button" class="button button-quiet" data-zk1-action="close">Fechar</button></div>'
      + '<p class="muted">Somente arquivos descartáveis. Importe proprietário, revisão e grant por canal independente do servidor. '
      + 'A verificação local bloqueia rollback do perfil atual, mas não prova durabilidade externa.</p>'
      + '<form class="zk1-workspace-form" autocomplete="off">'
      + '<label>Chave pública do proprietário (Ed25519 raw, 32 bytes)<input type="file" data-zk1-field="owner" required></label>'
      + '<label>Hash SHA-256 da chave raw do proprietário (pin externo)<input type="text" data-zk1-field="owner-hash" maxlength="43" required spellcheck="false"></label>'
      + '<label>Hash SHA-256 do SPKI do proprietário (pin externo)<input type="text" data-zk1-field="owner-spki" maxlength="43" required spellcheck="false"></label>'
      + '<label>Revisão atual confirmada fora do servidor<input type="number" min="1" step="1" data-zk1-field="revision" required></label>'
      + '<label>Digest da revisão (pin externo)<input type="text" data-zk1-field="digest" maxlength="43" required spellcheck="false"></label>'
      + '<label>Época atual confirmada fora do servidor<input type="number" min="1" step="1" data-zk1-field="epoch" required></label>'
      + '<label>Grant do dispositivo assinado (.json)<input type="file" data-zk1-field="grant" accept=".json,application/json" required></label>'
      + '<label>Histórico do proprietário assinado: checkpoint ou cadeia ordenada desde gênese (.json, até 64)<input type="file" data-zk1-field="history" accept=".json,application/json"></label>'
      + '<label>Inventário owner-signed portátil (.json, offline)<input type="file" data-zk1-field="inventory-portable" accept=".json,application/json"></label>'
      + '<label>Hash SHA-256 do checkpoint do inventário fixado fora do servidor (hex)<input type="text" data-zk1-field="inventory-pin" maxlength="64" spellcheck="false"></label>'
      + '<label>Hash SHA-256 SPKI do signer do inventário (hex, externo)<input type="text" data-zk1-field="inventory-signer-spki" maxlength="64" spellcheck="false"></label>'
      + '<label>Chave pública do dispositivo (Ed25519 raw)<input type="file" data-zk1-field="device" required></label>'
      + '<label>Chave privada do dispositivo (PKCS#8, local)<input type="file" data-zk1-field="private" required></label>'
      + '<label>Pedido original emitido no dispositivo novo (.json)<input type="file" data-zk1-field="new-request" accept=".json,application/json"></label>'
      + '<label>Desafio HPKE emitido pelo proprietário (.json; para provar posse)<input type="file" data-zk1-field="pop-challenge" accept=".json,application/json"></label>'
      + '<label>Chave privada X25519 do dispositivo novo (PKCS#8, local)<input type="file" data-zk1-field="hpke-private"></label>'
      + '<label>Pacote assinado pelo proprietário APÓS confirmação do witness (JSON: request,approval,grant,recibos)<input type="file" data-zk1-field="new-approval" accept=".json,application/json"></label>'
      + '<label>Chave pública Ed25519 do witness independente (raw, 32 bytes)<input type="file" data-zk1-field="witness-key"></label>'
      + '<label>SHA-256 SPKI do witness fixado por canal externo<input data-zk1-field="witness-spki" maxlength="43" spellcheck="false"></label>'
      + '<label>SHA-256 do recibo ANTERIOR do witness fixado fora do pacote<input data-zk1-field="witness-prior" maxlength="43" spellcheck="false"></label>'
      + '<label>Arquivo descartável (até 2 MiB)<input type="file" data-zk1-field="file" required></label>'
      + '<label>Segredo de recuperação separado (arquivo binário de 32 bytes)<input type="file" data-zk1-field="secret"></label>'
      + '<label>Pacote cifrado exportado (.json, sem segredo)<input type="file" data-zk1-field="bundle" accept=".json,application/json"></label>'
      + '<label>Objeto com GET pendente (ID opaco base64url, consultar lista local)<input type="text" data-zk1-field="pending-object" maxlength="22" autocomplete="off" spellcheck="false"></label>'
      + '<label>Raiz histórica SHA-256 confirmada independentemente pelo proprietário<input type="text" data-zk1-field="root" maxlength="43" spellcheck="false"></label>'
      + '<label>Checkpoint de root Ed25519 assinado pelo proprietário (.json)<input type="file" data-zk1-field="owner-root" accept=".json,application/json"></label>'
      + '<label>Identidade do proprietário no checkpoint (device_id)<input type="text" data-zk1-field="owner-device" maxlength="64" spellcheck="false"></label>'
      + '<label>signer_key_id do proprietário (base64url, 16 bytes)<input type="text" data-zk1-field="owner-signer" maxlength="22" spellcheck="false"></label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="provision">Provisionar piso offline</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="verify-inventory">Verificar checkpoint owner-signed</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="new-secret">Gerar segredo de 256 bits</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="new-device">Solicitar novo dispositivo ao proprietário</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="answer-pop">Responder desafio HPKE com as duas chaves locais</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="import-approval">Verificar compromisso witness + aprovação V2</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="upload">Cifrar, enviar e conferir GET</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="upload-recoverable">Enviar e exportar pacote recuperável</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="pending-list">Listar IDs locais pendentes</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="pending-resume">Retomar GET sem PUT</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="restore">Recuperar arquivo do novo dispositivo</button></div>'
      + '<fieldset><legend>Catálogo opaco entre dispositivos (DEV)</legend>'
      + '<p class="muted">Importe o grant do dispositivo que assinou o catálogo e a chave pública do CAS independente, ambos recebidos fora do servidor. '
      + 'Informe o head do catálogo fixado externamente. Os nomes ficam cifrados; só o navegador com a chave de metadados consegue abri-los. '
      + 'Nunca usa o sync-v2 genérico. O segundo dispositivo precisa do próprio grant ativo e da chave privada local.</p>'
      + '<label>Grant owner-signed do dispositivo assinante do catálogo (.json)<input type="file" data-zk1-field="catalog-signer-grant" accept=".json,application/json"></label>'
      + '<label>Chave pública Ed25519 do CAS do catálogo (raw, 32 bytes)<input type="file" data-zk1-field="catalog-cas-key"></label>'
      + '<label>SHA-256 do SPKI do CAS, pin offline (base64url)<input data-zk1-field="catalog-cas-spki" maxlength="43" spellcheck="false" autocomplete="off"></label>'
      + '<label>Sequência exata do catálogo confirmada fora do servidor<input type="number" min="1" max="128" step="1" data-zk1-field="catalog-sequence"></label>'
      + '<label>Digest do catálogo confirmado fora do servidor (base64url)<input data-zk1-field="catalog-digest" maxlength="43" spellcheck="false" autocomplete="off"></label>'
      + '<label>Chave AES de metadados de 32 bytes (local, opcional)<input type="file" data-zk1-field="catalog-metadata-key"></label>'
      + '<label>Página local (0–127)<input type="number" min="0" max="127" step="1" value="0" data-zk1-field="catalog-page"></label>'
      + '<label>Índice na página (0–31) para GET do ciphertext<input type="number" min="0" max="31" step="1" value="0" data-zk1-field="catalog-entry"></label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-primary" data-zk1-action="catalog-discover">Descobrir e conferir catálogo</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="catalog-page">Exibir página verificada</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="catalog-get">GET ciphertext conferido</button></div>'
      + '<div data-zk1-field="catalog-list" role="region" aria-label="IDs de versões opacas validadas"></div>'
      + '<fieldset><legend>Conferir tombstone e restauração entre dispositivos (DEV)</legend>'
      + '<p class="muted">O outro dispositivo exige seu próprio grant, chave privada e o head CAS exato fixado fora do servidor acima. '
      + 'Importe todas as revisões do objeto, com metadados AEAD, e uma CEK de 32 bytes por revisão, na mesma ordem. '
      + 'Use somente um cofre/arquivo de CEKs previamente verificado fora do servidor. A conferência faz GET assinado, '
      + 'descriptografa e apaga os dados temporários localmente. Nunca sincroniza plaintext, apaga versões nem autoriza restore de produção.</p>'
      + '<label>Object ID a conferir (base64url de 16 bytes)<input data-zk1-field="catalog-lifecycle-id" maxlength="22" autocomplete="off" spellcheck="false"></label>'
      + '<label>Metadados históricos locais (.json com schema rootark-zk1-lifecycle-selection/v1, objectId, versions)<input type="file" data-zk1-field="catalog-lifecycle-history" accept=".json,application/json"></label>'
      + '<label>CEKs locais por revisão (arquivos binários de 32 bytes, em ordem)<input type="file" multiple data-zk1-field="catalog-lifecycle-ceks"></label>'
      + '<label><input type="checkbox" data-zk1-field="catalog-lifecycle-opt-in"> Confirmo o head CAS e a origem externa do histórico e das CEKs.</label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button-quiet button" data-zk1-action="catalog-lifecycle">Conferir estado atual assinado</button></div>'
      + '</fieldset>'
      + '<fieldset><legend>Checkpoint global V2 #129 (GET cifrado, opt-in DEV)</legend>'
      + '<p class="muted">Importe o intent CBOR assinado pelo dispositivo autorizado e as três chaves públicas fixadas offline. '
      + 'O relay autenticado consulta o CAS e floor V2 independentes por mTLS. Somente duas confirmações Ed25519 FINALIZED, '
      + 'o checkpoint Merkle completo, a aprovação e o grant owner-signed atual permitem listar IDs opacos. '
      + 'Permite GET de ciphertext de uma versão selecionada após nova confirmação, prova de posse da chave do dispositivo e SHA-256 do catálogo assinado. '
      + 'Não descriptografa nem publica. Os dados V1 permanecem na sequência 128.</p>'
      + '<label>Intents V2 assinados em ordem (129 até o atual, até 10 MiB cada)<input type="file" multiple data-zk1-field="catalog-v2-intent" accept=".cbor,application/cbor,application/octet-stream"></label>'
      + '<label>Endossos históricos independentes assinados pelo proprietário (.json, um por intent em ordem; obrigatório quando o signer mudou)<input type="file" data-zk1-field="catalog-v2-historical-endorsements" accept=".json,application/json"></label>'
      + '<label>Digest gênese owner V2 fixado fora do servidor (base64url)<input data-zk1-field="catalog-v2-genesis-pin" maxlength="43" spellcheck="false"></label>'
      + '<label>PIN SHA-256 SPKI witness owner V2 fixado fora do servidor (base64url)<input data-zk1-field="catalog-v2-owner-witness-pin" maxlength="43" spellcheck="false"></label>'
      + '<label>Chave CAS V2 Ed25519 raw (32 bytes)<input type="file" data-zk1-field="catalog-v2-cas-key"></label>'
      + '<label>PIN SHA-256 SPKI CAS V2 (base64url)<input data-zk1-field="catalog-v2-cas-pin" maxlength="43" spellcheck="false"></label>'
      + '<label>Chave floor V2 Ed25519 raw (32 bytes)<input type="file" data-zk1-field="catalog-v2-floor-key"></label>'
      + '<label>PIN SHA-256 SPKI floor V2 (base64url)<input data-zk1-field="catalog-v2-floor-pin" maxlength="43" spellcheck="false"></label>'
      + '<label>Chave checkpoint V2 Ed25519 raw (32 bytes)<input type="file" data-zk1-field="catalog-v2-checkpoint-key"></label>'
      + '<label>PIN SHA-256 SPKI checkpoint V2 (base64url)<input data-zk1-field="catalog-v2-checkpoint-pin" maxlength="43" spellcheck="false"></label>'
      + '<label>Digest checkpoint V1 #128 fixado fora do servidor (base64url)<input data-zk1-field="catalog-v2-predecessor-checkpoint" maxlength="43" spellcheck="false"></label>'
      + '<label><input type="checkbox" data-zk1-field="catalog-v2-opt-in"> Autorizar somente consulta V2 autenticada do catálogo opaco.</label>'
      + '<label>Índice global da versão V2 (0–4095)<input type="number" min="0" max="4095" step="1" value="0" data-zk1-field="catalog-v2-index"></label>'
      + '<label><input type="checkbox" data-zk1-field="catalog-v2-get-opt-in"> Autorizo GET cifrado somente da versão V2 escolhida, com revalidação do CAS e floor.</label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="catalog-v2-read">Conferir CAS + floor V2 #129</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="catalog-v2-get">Conferir V2 e baixar ciphertext exato</button></div>'
      + '<div data-zk1-field="catalog-v2-list" role="region" aria-label="Inventário V2 opaco autenticado"></div>'
      + '</fieldset>'
      + '<fieldset><legend>Publicar versão cifrada no catálogo completo (DEV, opt-in)</legend>'
      + '<p class="muted">Selecione somente ciphertext já cifrado (16 bytes a 4 MiB). O nome é cifrado localmente com AES-GCM; '
      + 'a chave de metadados e o nome nunca são enviados ao servidor. O journal assinado é gravado localmente ANTES do PUT. '
      + 'O catálogo completo anterior é lido e autenticado, preservando todas as versões e aceitando apenas inclusão. '
      + 'Após PUT, GET exato assinado e CAS, anote sequência e digest retornados em canal externo para os dois dispositivos. '
      + 'As URLs independentes respondem a POST JSON {scope,nonceBase64} com CBOR Ed25519 application/cbor; '
      + 'elas não podem ser o servidor Root.ark nem compartilhar origem entre si. '
      + 'Opcionalmente, o relay autenticado Root.ark transporta provas assinadas dos serviços mTLS configurados. '
      + 'Pins de assinatura continuam vindo de fora do servidor. Prova de nuvem/host físico não é inferida.</p>'
      + '<label>Versão ciphertext local (.bin)<input type="file" data-zk1-field="catalog-write-ciphertext" accept=".bin,.ciphertext,application/octet-stream"></label>'
      + '<label>Nome privado (cifrado no cliente, 1–220 bytes UTF-8)<input data-zk1-field="catalog-write-name" maxlength="220" autocomplete="off" spellcheck="false"></label>'
      + '<label>Object ID opaco (base64url 16 bytes, vazio gera ID novo)<input data-zk1-field="catalog-write-id" maxlength="22" autocomplete="off" spellcheck="false"></label>'
      + '<label>Chave AES-GCM de metadados (32 bytes, local)<input type="file" data-zk1-field="catalog-write-key"></label>'
      + '<label>Chave pública Ed25519 do witness (raw 32 bytes, offline)<input type="file" data-zk1-field="catalog-witness-key"></label>'
      + '<label>ID do witness (base64url 16 bytes, offline)<input data-zk1-field="catalog-witness-id" maxlength="22" spellcheck="false"></label>'
      + '<label>SHA-256 SPKI do witness (base64url, pin offline)<input data-zk1-field="catalog-witness-spki" maxlength="43" spellcheck="false"></label>'
      + '<label>URL de consulta direta ao witness independente (HTTPS POST)<input type="url" data-zk1-field="catalog-witness-url" spellcheck="false"></label>'
      + '<label>URL de consulta direta ao CAS independente (HTTPS POST)<input type="url" data-zk1-field="catalog-cas-url" spellcheck="false"></label>'
      + '<label><input type="checkbox" data-zk1-field="catalog-relay-opt-in"> Usar relay autenticado Root.ark para obter provas assinadas do witness e CAS independentes via mTLS (dispensa URLs diretas).</label>'
      + '<label>Sequência mínima do CAS fixada offline (0 para novo catálogo)<input type="number" min="0" max="128" step="1" data-zk1-field="catalog-write-sequence"></label>'
      + '<label>Digest mínimo do CAS fixado offline (base64url; 32 bytes, zero no início)<input data-zk1-field="catalog-write-digest" maxlength="43" spellcheck="false"></label>'
      + '<label><input type="checkbox" data-zk1-field="catalog-write-opt-in"> Confirmo ciphertext local, grants V2 ativos e autoridade CAS/witness independente; autorizo somente PUT e commit aditivo.</label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-primary" data-zk1-action="catalog-publish">Journal → PUT → GET assinado → commit</button></div>'
      + '<p class="muted">Journal local desta tentativa (não é pin nem confirmação): <output data-zk1-field="catalog-write-journal"></output></p>'
      + '<fieldset><legend>Sincronização ZK opaca incremental entre dispositivos (DEV, manual)</legend>'
      + '<p class="muted">Abra esta tela em cada dispositivo autorizado, com seu próprio grant, chave privada e pins externos. '
      + 'Ancore o CAS exato ANTES da mutação do outro dispositivo. Importe um delta .json recebido por canal externo somente para conferir '
      + 'contra um novo CAS/witness assinado e GET protegido feito neste dispositivo. Não usa sync-v2 genérico, não aplica '
      + 'arquivos ao sistema e não transmite nomes, caminhos ou CEKs em texto claro. Sem sincronização automática.</p>'
      + '<label><input type="checkbox" data-zk1-field="catalog-delta-opt-in"> Autorizo esta ação manual com meu grant ativo, CAS/witness independentes e journal local para escrita.</label>'
      + '<label>Delta opaco exportado por outro dispositivo (.json, somente ciphertext e metadados cifrados)<input type="file" data-zk1-field="catalog-delta-package" accept=".json,application/json"></label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="catalog-delta-anchor">Ancorar CAS assinado atual</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="catalog-delta-pull">Conferir e exportar delta cifrado</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="catalog-delta-list">Listar nomes localmente (AES-GCM)</button>'
      + '<button type="button" class="button button-quiet" data-zk1-action="catalog-delta-trash-inspect">Conferir tombstone assinado</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="catalog-delta-import">Importar e comparar delta com GET assinado</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="catalog-delta-publish">Publicar nova versão cifrada via journal → PUT → CAS</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="catalog-delta-trash">Trash lógico (nova revisão assinada, sem deletar histórico)</button></div>'
      + '<div data-zk1-field="catalog-delta-private-list" role="region" aria-label="Nomes locais abertos após CAS e witness assinados"></div>'
      + '<output data-zk1-field="catalog-delta-summary" role="status" aria-live="polite"></output>'
      + '</fieldset>'
      + '</fieldset>'
      + '</fieldset>'
      + '<fieldset><legend>Revogação de dispositivo e rotação V2 (recibo offline, DEV)</legend>'
      + '<p class="muted">Importe o recibo assinado do proprietário e, por canal separado, as chaves públicas SPKI e pins atuais de proprietário, witness e CAS. '
      + 'O JSON de pins independente contém ownerSpkiSha256, witnessSpkiSha256, casSpkiSha256, priorReceiptSha256, casSequence, revision, digest, epoch, previousRevision e previousDigest. '
      + 'A transferência validada NÃO libera grants, GET, restore nem autoriza ProtectedObjectStore sem verificar todo o histórico V2 atual e o compromisso remoto.</p>'
      + '<label>Recibo assinado do proprietário (.json)<input type="file" data-zk1-field="revoke-delivery" accept=".json,application/json"></label>'
      + '<label>Pins externos independentes (.json)<input type="file" data-zk1-field="revoke-pins" accept=".json,application/json"></label>'
      + '<label>SPKI DER do proprietário (.der)<input type="file" data-zk1-field="revoke-owner-spki"></label>'
      + '<label>SPKI DER do witness (.der)<input type="file" data-zk1-field="revoke-witness-spki"></label>'
      + '<label>SPKI DER do CAS (.der)<input type="file" data-zk1-field="revoke-cas-spki"></label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="verify-revocation">Conferir revogação assinada e epoch</button></div>'
      + '</fieldset>'
      + '<fieldset><legend>Migração opt-in de arquivo legado (apenas laboratório)</legend>'
      + '<p class="muted">O caminho legado /files já entrega plaintext pelo servidor antigo. Na cópia ZK, apenas ciphertext é enviado. '
      + 'O original permanece intacto. Guarde a CEK e os IDs fora do servidor para retomada; '
      + 'a cópia não autoriza exclusão nem prova durabilidade externa.</p>'
      + '<label>Nome exato do arquivo legado<input data-zk1-field="legacy-name" maxlength="255" autocomplete="off"></label>'
      + '<label>ID da pasta antiga (opcional)<input data-zk1-field="legacy-folder" maxlength="128" autocomplete="off"></label>'
      + '<label>ID do objeto ZK (22 caracteres; gerado na primeira tentativa)<input data-zk1-field="migration-object" maxlength="22" autocomplete="off"></label>'
      + '<label>ID da versão ZK (22 caracteres; gerado na primeira tentativa)<input data-zk1-field="migration-version" maxlength="22" autocomplete="off"></label>'
      + '<label>CEK externa de 32 bytes (reimportar a mesma para retomar)<input type="file" data-zk1-field="migration-cek"></label>'
      + '<label>Checkpoint de raiz do proprietário assinado fora do servidor (.json; para confirmar)<input type="file" data-zk1-field="migration-proof" accept=".json,application/json"></label>'
      + '<label><input type="checkbox" data-zk1-field="migration-opt-in"> Solicito expressamente uma cópia não destrutiva do arquivo legado.</label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="migrate">Copiar / retomar GET</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="migration-finalize">Verificar checkpoint assinado</button></div>'
      + '</fieldset>'
      + '<fieldset><legend>Migração histórica em lote: 1–12 versões (DEV)</legend>'
      + '<p class="muted">Importe um JSON local com schema rootark-zk1-legacy-version-batch/v1 e entries: '
      + '[{legacy:{name,folderId},sourcePin:{version,storedAs,uploadedAt,size,lastModified,sha256,mediaType},cekFile}]. '
      + 'Cada cekFile aponta para um arquivo binário distinto de 32 bytes selecionado abaixo. '
      + 'O segredo de migração é um arquivo separado de 32 bytes; reimporte exatamente os mesmos '
      + 'descritores, CEKs e segredo para retomar uma operação incerta. '
      + 'Cópias parciais exigem revisão e checkpoint assinado externo. '
      + 'Nenhum resultado autoriza excluir originais, restaurar, ou fazer cutover.</p>'
      + '<label>Descritores históricos e pins de versões (.json, offline)<input type="file" data-zk1-field="migration-batch-descriptors" accept=".json,application/json"></label>'
      + '<label>CEKs binárias locais: 1–12 arquivos distintos de 32 bytes<input type="file" multiple data-zk1-field="migration-batch-ceks"></label>'
      + '<label>migrationSecret separado (binário, exatamente 32 bytes)<input type="file" data-zk1-field="migration-batch-secret"></label>'
      + '<label><input type="checkbox" data-zk1-field="migration-batch-opt-in"> Autorizo cópias históricas somente de leitura da origem. Entendo que não há exclusão nem migração definitiva.</label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-primary" data-zk1-action="migration-batch">Copiar / retomar versões e baixar relatório local</button></div>'
      + '</fieldset>'
      + '<fieldset><legend>Pacote local de arquivos selecionados de um keyring: 1–12 (DEV)</legend>'
      + '<p class="muted">Selecione arquivos descartáveis (até 8 MiB somados). O pacote representa apenas a seleção manual; '
      + 'não comprova inventário completo do keyring ou histórico de versões. '
      + 'Criação exige chave Ed25519 privada do PROPRIETÁRIO e histórico assinado atual; '
      + 'a recuperação exige a âncora SHA-256 do arquivo recebida por canal separado. '
      + 'Sem upload, CEK ou plaintext no servidor. O segredo e o hash devem ficar separados do pacote.</p>'
      + '<label>Arquivos locais (1–12, máx. 8 MiB somados)<input type="file" multiple data-zk1-field="archive-files"></label>'
      + '<label>Chave PKCS#8 do proprietário para assinar offline (somente criação)<input type="file" data-zk1-field="archive-owner-private"></label>'
      + '<label>Arquivo cifrado e assinado (.json, somente recuperação)<input type="file" data-zk1-field="archive-json" accept=".json,application/json"></label>'
      + '<label>SHA-256 externo do arquivo assinado (base64url, 32 bytes)<input data-zk1-field="archive-sha" maxlength="43" spellcheck="false" autocomplete="off"></label>'
      + '<label><input type="checkbox" data-zk1-field="archive-opt-in"> Autorizo a operação local sem persistir arquivos recuperados no servidor.</label>'
      + '<label><input type="checkbox" data-zk1-field="archive-historical-opt-in"> Recuperar pacote de head antigo: exigir histórico completo genesis→atual, grant ATIVO atual e reendosso assinado de cada raiz (sem substituição automática).</label>'
      + '<label>Endossos históricos atuais escolhidos offline (.json, schema rootark-zk1-keyring-history-endorsement/v1, {schema,scope,historicalRecovery:{signedOwnerHistoryChain,currentSignedDeviceGrant,currentOwnerRootCheckpoints}})<input type="file" data-zk1-field="archive-historical-proof" accept=".json,application/json"></label>'
      + '<p class="muted">Para recuperar head antigo, importe também no campo "Chave privada do dispositivo (PKCS#8, local)" a chave Ed25519 ATUAL vinculada ao grant. O desafio PoP é criado neste navegador, é de uso único e nunca vem do JSON ou do servidor.</p>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="archive-create">Assinar e baixar arquivo cifrado + hash separado</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="archive-recover">Verificar e baixar 1–12 arquivos locais</button></div>'
      + '</fieldset>'
      + '<fieldset><legend>Arquivo histórico de versões ZK1, com inventário assinado (DEV)</legend>'
      + '<p class="muted">Importe o snapshot autoritativo assinado com todas as 1–12 revisões, roster assinado de UM keyring, '
      + 'checkpoint owner-signed e assinatura CBOR do inventário. O snapshot e a lista escolhida devem conter as mesmas versões, sem omissão. '
      + 'Hashes do snapshot, roster, signer e checkpoint devem ter origem independente. '
      + 'A operação é local; ciphertext e CEK nunca são enviados ao servidor.</p>'
      + '<label>Snapshot autoritativo owner-signed (.json)<input type="file" data-zk1-field="v2-snapshot" accept=".json,application/json"></label>'
      + '<label>SHA-256 externo desse snapshot (base64url)<input data-zk1-field="v2-snapshot-pin" maxlength="43" autocomplete="off"></label>'
      + '<label>Roster owner-signed completo desse keyring (.json)<input type="file" data-zk1-field="v2-roster" accept=".json,application/json"></label>'
      + '<label>SHA-256 externo do roster (base64url)<input data-zk1-field="v2-roster-pin" maxlength="43" autocomplete="off"></label>'
      + '<label>Chave pública Ed25519 SPKI DER do inventário (.der)<input type="file" data-zk1-field="v2-inventory-signer"></label>'
      + '<label>ID da chave pública do inventário (base64url, 16 bytes)<input data-zk1-field="v2-inventory-signer-id" maxlength="22" autocomplete="off"></label>'
      + '<label>Versões locais selecionadas (.json): {schema:"rootark-zk1-version-selection/v1",versions:[{metadata,objectRevision,ciphertextBase64,cekBase64}]}</label>'
      + '<input type="file" data-zk1-field="v2-versions" accept=".json,application/json">'
      + '<label><input type="checkbox" data-zk1-field="v2-opt-in"> Autorizo exportação/importação criptográfica local de todas as revisões fixadas no inventário.</label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="versioned-create">Exportar v2 cifrado + hash externo</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="versioned-recover">Verificar v2 e baixar ciphertext + CEKs</button></div>'
      + '</fieldset>'
      + '<fieldset><legend>Pacote de arquivos locais selecionados de 1–8 keyrings (somente offline, DEV)</legend>'
      + '<p class="muted">Importe seleção JSON offline schema rootark-zk1-account-workspace-selection/v1: '
      + '{accountId,keyrings:[{scope,pinnedCurrentHead:{revision,digest,epoch},signedDeviceGrant,ownerHistory:[checkpoints assinados],signerKeyId,deviceId,holderSecretFile,files:[nomes locais]}]}. '
      + 'Para recuperar, use files:[] em cada keyring. Selecione todos os segredos de 32 bytes separadamente, '
      + 'um por keyring, com nomes iguais a holderSecretFile. Na criação, selecione os arquivos citados em files. '
      + 'Cada keyring exige grant e histórico atuais assinados e piso provisionado. '
      + 'A recuperação exige o SHA-256 da conta guardado externamente. Nunca envia plaintext/CEK ao servidor; '
      + 'não comprova inventário completo da conta, versões históricas ou permissões e não restaura em produção.</p>'
      + '<label>Seleção offline da conta e pins por keyring (.json)<input type="file" data-zk1-field="account-descriptors" accept=".json,application/json"></label>'
      + '<label>Segredos holder: 1–8 arquivos binários distintos, 32 bytes<input type="file" multiple data-zk1-field="account-holder-files"></label>'
      + '<label>Arquivos locais citados na seleção (somente criação, até 8 MiB somados)<input type="file" multiple data-zk1-field="account-local-files"></label>'
      + '<label>PKCS#8 privado do proprietário (somente criação)<input type="file" data-zk1-field="account-owner-private"></label>'
      + '<label>Arquivo cifrado e assinado da conta (somente recuperação)<input type="file" data-zk1-field="account-archive" accept=".json,application/json"></label>'
      + '<label>SHA-256 do arquivo da conta fixado externamente (base64url, 32 bytes)<input data-zk1-field="account-sha" maxlength="43" autocomplete="off" spellcheck="false"></label>'
      + '<label><input type="checkbox" data-zk1-field="account-opt-in"> Confirmo cópia/recuperação local sem upload, exclusão ou cutover. Pins/segredos foram escolhidos por canal independente.</label>'
      + '<label><input type="checkbox" data-zk1-field="account-historical-opt-in"> Recuperar pacote com heads antigos: adicionar currentOwnerRootCheckpoints de cada keyring antigo à seleção offline; nunca recuperar com grant revogado ou sem todos os reendossos.</label>'
      + '<label>Chaves privadas Ed25519 PKCS#8 dos grants atuais dos keyrings históricos (1 arquivo por keyring antigo; nomes em devicePrivateFile no JSON da seleção)<input type="file" multiple data-zk1-field="account-historical-device-privates"></label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="account-create">Assinar e baixar pacote da conta + hash</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="account-recover">Conferir e baixar arquivos de todos os keyrings</button></div>'
      + '</fieldset>'
      + '</form><p class="muted" data-zk1-field="status" role="status" aria-live="polite">Nenhuma autoridade foi importada.</p>';
    document.body.append(dialog);
    dialog.addEventListener("cancel", (event) => { if (busy) event.preventDefault(); });
    dialog.addEventListener("click", (event) => {
      const button = event.target.closest("[data-zk1-action]");
      if (button) void perform(button.dataset.zk1Action);
    });
    return dialog;
  }
  async function perform(action) {
    if (busy) return;
    if (action === "close") {
      committedDeviceApproval = null;
      verifiedCatalog = null;
      verifiedOpaqueDelta = null;
      const deltaSummary = field("catalog-delta-summary");
      if (deltaSummary) deltaSummary.textContent = "";
      const privateList = field("catalog-delta-private-list");
      if (privateList) privateList.replaceChildren();
      verifiedRevocationHead = null;
      const journal = field("catalog-write-journal");
      if (journal) journal.textContent = "";
      window.RootarkZk1V2OwnerRevocationBrowser?.clear();
      dialog.close();
      dialog.querySelector("form").reset();
      status("Nenhuma autoridade foi importada.");
      return;
    }
    if (!["provision", "verify-inventory", "upload", "upload-recoverable",
      "pending-list", "pending-resume",
      "restore", "new-secret", "new-device", "answer-pop", "import-approval", "verify-revocation",
      "migrate", "migration-finalize", "migration-batch", "archive-create", "archive-recover",
      "account-create", "account-recover", "versioned-create", "versioned-recover",
      "catalog-discover", "catalog-page", "catalog-get", "catalog-publish",
      "catalog-lifecycle", "catalog-v2-read", "catalog-v2-get",
      "catalog-delta-anchor", "catalog-delta-list", "catalog-delta-pull", "catalog-delta-import",
      "catalog-delta-publish", "catalog-delta-trash", "catalog-delta-trash-inspect"].includes(action)) return;
    busy = true;
    dialog.querySelectorAll("button").forEach((button) => { button.disabled = true; });
    status("Validando pins externos, assinatura do proprietário e dispositivo…");
    let privateDer;
    let data;
    let secret;
    let ownerSigningDer;
    let archiveFiles;
    const accountFiles = { plaintext: [], secrets: [], privates: [] };
    let accountRecovered;
    try {
      const operationEpoch = sessionEpoch;
      const initialCsrf = currentCsrf();
      const assertLive = () => {
        if (sessionEpoch !== operationEpoch || dialog?.open !== true
          || currentCsrf() !== initialCsrf) fail();
      };
      const guardedFetch = async (url, options) => {
        assertLive();
        const response = await sessionFetch(url, options);
        assertLive();
        return response;
      };
      await ensureScripts();
      assertLive();
      // Capability is checked again before every user-initiated operation.
      const available = await api.get("/zk-1/v1/workspace-capability");
      assertLive();
      if (!supportsOwnerRootedV2(available)) fail();
      if (action === "verify-revocation") {
        // The optional offline revocation inspector is loaded only for this
        // ceremony. Neither ordinary protected I/O nor pre-existing archive
        // and recovery flows depend on its scripts being available.
        if (!window.RootarkZk1V2OwnerRevocationImport?.verifyRevocationDelivery)
          await loadScript("rootark-zk1-v2-owner-revocation-import");
        assertLive();
        if (!window.RootarkZk1V2OwnerRevocationBrowser?.verifyOfflineTransfer)
          await loadScript("rootark-zk1-v2-owner-revocation-browser");
        assertLive();
        if (!window.RootarkZk1V2OwnerRevocationBrowser?.verifyOfflineTransfer) fail();
        // A previous approved grant cannot survive a newly presented owner
        // revocation receipt; neither a failed nor successful import releases it.
        committedDeviceApproval = null;
        const delivery = JSON.parse(decoder.decode(await fileBytes("revoke-delivery", 1, 400000)));
        const independentPins = JSON.parse(decoder.decode(await fileBytes("revoke-pins", 1, 8192)));
        const ownerSpki = await fileBytes("revoke-owner-spki", 40, 512);
        const witnessSpki = await fileBytes("revoke-witness-spki", 40, 512);
        const casSpki = await fileBytes("revoke-cas-spki", 40, 512);
        assertLive();
        const verified = await window.RootarkZk1V2OwnerRevocationBrowser.verifyOfflineTransfer({
          delivery, ownerSpki, witnessSpki, casSpki, independentPins,
          nowSeconds: Math.floor(Date.now() / 1000), assertLive,
        });
        assertLive();
        if (verified.verified !== true || verified.grantsReleased !== false
          || verified.authorizesProtectedIo !== false) fail();
        verifiedRevocationHead = { scope: [delivery.scope.account_id,
          delivery.scope.compartment_id, delivery.scope.keyring_id].join("|"),
          revision: verified.revision, digest: independentPins.digest,
          epoch: verified.epoch, revokedDeviceId: verified.revokedDeviceId };
        status("Revogação V2 assinada confirmada: dispositivo "
          + verified.revokedDeviceId + ", revisão " + verified.revision
          + ", época " + verified.epoch + ". " + verified.signedSurvivorCount
          + " grants conferidos, zero liberados. Exija histórico V2 integral antes de qualquer acesso protegido.");
        return;
      }
      if (action === "verify-inventory") {
        const raw = decoder.decode(await fileBytes("inventory-portable", 1, 400000));
        const grant = JSON.parse(decoder.decode(await fileBytes("grant", 1, 8192)));
        const report = await window.RootarkZk1OwnerInventoryTrustHead.importPortableEnrollment({
          serialized: raw,
          independentOwnerSpkiSha256: hex(from64(field("owner-spki").value.trim())),
          independentCheckpointDigest: field("inventory-pin").value.trim(),
          expectedInventorySpkiSha256: field("inventory-signer-spki").value.trim(),
          expectedScope: [grant.account_id, grant.compartment_id, grant.keyring_id],
          nowSeconds: Math.floor(Date.now() / 1000),
        });
        if (report.ownerSignatureVerified !== true
          || report.independentlyPinnedDigestMatched !== true
          || report.authorizesProtectedIo !== false) fail();
        status("Checkpoint offline #" + report.ownerCheckpointCounter
          + " e assinatura Ed25519 validados; raiz " + report.inventoryRoot
          + ". A assinatura CBOR e a durabilidade externa exigem validação independente.");
        return;
      }
      if (action === "new-secret") {
        secret = window.RootarkZk1PortableFileRecovery.generateRecoverySecret();
        downloadLocal("rootark-holder-secret-256bit.bin", secret, undefined, assertLive);
        status("Segredo de 32 bytes exportado SOMENTE neste dispositivo. Guarde fora do servidor e separado do pacote cifrado.");
        return;
      }
      if (action === "new-device") {
        const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
        const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
        privateDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
        // The recovery V2 device enrollment also requires a distinct HPKE
        // X25519 identity and offline target proof-of-possession. A plain
        // Ed25519 public key is not enough to enroll a real device.
        const hpke = await crypto.subtle.generateKey("X25519", true, ["deriveBits"]);
        const hpkeRaw = new Uint8Array(await crypto.subtle.exportKey("raw", hpke.publicKey));
        const hpkePrivate = new Uint8Array(await crypto.subtle.exportKey("pkcs8", hpke.privateKey));
        const request = { schema: "rootark-zk1-device-enrollment-request/v1",
          device_id: randomId(), authorization_key_id: randomId(), hpke_key_id: randomId(),
          authorization_public_key: to64(raw), challenge: to64(crypto.getRandomValues(new Uint8Array(32))),
          hpke_public_key: to64(hpkeRaw),
          approval: "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT" };
        try {
          downloadLocal("rootark-new-device-auth-private.pk8", privateDer, undefined, assertLive);
          downloadLocal("rootark-new-device-hpke-private.pk8", hpkePrivate, undefined, assertLive);
        } finally { hpkePrivate.fill(0); hpkeRaw.fill(0); }
        downloadLocal("rootark-owner-enrollment-request.json", JSON.stringify(request), "application/json", assertLive);
        raw.fill(0);
        status("Chaves Ed25519 e X25519 exportadas localmente. Solicitação NÃO é um grant: proprietário deve confirmar identidade, completar PoP V2, assinar a transição e conceder grant atual fora do servidor.");
        return;
      }
      if (action === "answer-pop") {
        const request = JSON.parse(decoder.decode(await fileBytes("new-request", 1, 8192)));
        const challenge = JSON.parse(decoder.decode(await fileBytes("pop-challenge", 1, 8192)));
        privateDer = await fileBytes("private", 1, 8192);
        const hpkeDer = await fileBytes("hpke-private", 1, 8192);
        try {
          const response = await window.RootarkZk1V2BrowserPop.respond({
            request, challenge, deviceHpkePrivateDer: hpkeDer,
            deviceAuthorizationPrivateDer: privateDer,
            nowSeconds: Math.floor(Date.now() / 1000),
          });
          assertLive();
          downloadLocal("rootark-v2-device-pop-response.json",
            JSON.stringify(response), "application/json", assertLive);
          status("PoP X25519 + Ed25519 assinado localmente. O proprietário ainda DEVE verificar o desafio original, obter V2 assinado e recibo independente do witness; resposta NÃO é aprovação.");
        } finally { hpkeDer.fill(0); }
        return;
      }
      const trust = await grantAndOwner();
      assertLive();
      if (["catalog-delta-list", "catalog-delta-pull", "catalog-delta-import",
        "catalog-delta-publish", "catalog-delta-trash", "catalog-delta-trash-inspect"].includes(action)) {
        if (available.opaqueCatalogV1 !== true
          || field("catalog-delta-opt-in")?.checked !== true
          || trust.signedDeviceGrant.revoked_at_epoch !== null
          || !trust.ownerHistoryCheckpoint || !verifiedOpaqueDelta) fail();
        const held = verifiedOpaqueDelta;
        if (held.epoch !== sessionEpoch || held.csrf !== initialCsrf
          || held.origin !== location.origin || held.grant !== JSON.stringify(trust.signedDeviceGrant)
          || held.ownerDigest !== to64(trust.pinnedCurrentHead.digest)
          || held.ownerRevision !== trust.pinnedCurrentHead.revision
          || held.ownerEpoch !== trust.pinnedCurrentHead.epoch
          || held.minimumSequence !== field("catalog-write-sequence")?.value.trim()
          || held.minimumDigest !== field("catalog-write-digest")?.value.trim()
          || held.casPin !== field("catalog-cas-spki")?.value.trim()
          || held.witnessPin !== field("catalog-witness-spki")?.value.trim()) fail();
        await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        assertLive();
        if (action !== "catalog-delta-list")
          field("catalog-delta-private-list")?.replaceChildren();
        if (action === "catalog-delta-trash" || action === "catalog-delta-trash-inspect") {
          const objectId = field("catalog-write-id")?.value.trim();
          if (!/^[A-Za-z0-9_-]{22}$/.test(objectId)) fail();
          const raw = await fileBytes("catalog-write-key", 32, 32);
          let metadataKey;
          try { metadataKey = await crypto.subtle.importKey("raw", raw,
            { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]); }
          finally { raw.fill(0); }
          if (action === "catalog-delta-trash-inspect") {
            const result = await held.client.readTrash({
              previous: held.baseline, objectId, metadataKey });
            assertLive();
            if (result.state !== "trashed" || result.signedByAuthorizedDevice !== true
              || result.originalHistoryPreserved !== true
              || result.serverPlaintextExposed !== false) fail();
            field("catalog-delta-summary").textContent = "Tombstone autenticado · revisão "
              + result.revision + " · " + result.retainedHistoricalVersions
              + " versões históricas preservadas";
            status("Tombstone cifrado e assinado conferido contra GET exato, witness e CAS. "
              + "Nenhuma restauração ou deleção física.");
            return;
          }
          const source = held.baseline.entries.filter((row) => row.objectId === objectId);
          if (!source.length) fail();
          const expectedRevision = Math.max(...source.map((item) => item.revision));
          // No second mutation may reuse this owner's signed CAS anchor.
          verifiedOpaqueDelta = null;
          let result;
          try { result = await held.client.trashVersion({
            previous: held.baseline, objectId, expectedRevision, metadataKey }); }
          catch (error) {
            if (typeof error?.outcome?.journalId === "string"
              && /^[A-Za-z0-9_-]{43}$/.test(error.outcome.journalId))
              field("catalog-write-journal").textContent = error.outcome.journalId;
            throw error;
          }
          assertLive();
          if (result.state !== "trashed" || result.tombstoneSignedAndSealed !== true
            || result.originalHistoryPreserved !== true
            || result.serverPlaintextExposed !== false
            || result.journalClearedAfterSignedProof !== true) fail();
          field("catalog-delta-summary").textContent = "Trash lógico · CAS #"
            + result.sequence + " · revisão " + result.revision;
          status("Tombstone AES-GCM/Ed25519 publicado em nova revisão: PUT uma vez, "
            + "GET exato e CAS assinado. Histórico imutável permanece; nenhum delete físico.");
          return;
        }
        if (action === "catalog-delta-list") {
          // The metadata key is imported for DECRYPT only and never exported
          // or sent to the server. Render via textContent, never HTML.
          const raw = await fileBytes("catalog-write-key", 32, 32);
          let metadataKey;
          try { metadataKey = await crypto.subtle.importKey("raw", raw,
            { name: "AES-GCM", length: 256 }, false, ["decrypt"]); }
          finally { raw.fill(0); }
          const list = field("catalog-delta-private-list");
          list.replaceChildren();
          const opened = await held.client.readPrivateListing(held.baseline, metadataKey);
          assertLive();
          if (opened.independentlySignedCatalog !== true
            || opened.plaintextSentToServer !== false
            || opened.authorizesMutation !== false
            || opened.head.sequence !== held.baseline.head.sequence
            || opened.head.digest !== held.baseline.head.digest
            || !Array.isArray(opened.entries)) fail();
          const content = document.createDocumentFragment();
          for (const entry of opened.entries) {
            if ((typeof entry.name !== "string" || !entry.name)
              && !(entry.name === null && entry.logicalTrashCandidate === true)) fail();
            const item = document.createElement("div");
            item.textContent = (entry.logicalTrashCandidate === true
              ? "Lixeira lógica (verifique o tombstone assinado)" : entry.name)
              + " · revisão " + entry.revision;
            content.appendChild(item);
          }
          assertLive();
          list.replaceChildren(content);
          field("catalog-delta-summary").textContent = "Listagem local de "
            + opened.entries.length + " versão(ões) · CAS #" + opened.head.sequence;
          status("Metadados autenticados via CAS/witness e abertos só neste navegador. "
            + "Nenhum nome ou chave enviado ao servidor.");
          return;
        }
        if (action === "catalog-delta-publish") {
          // A dedicated manual action; the existing writer guarantees one
          // signed PUT/CAS, fresh exact GET and a durable intent journal even
          // if either network ACK disappears. Never loop or retry here.
          const name = field("catalog-write-name")?.value;
          if (typeof name !== "string" || /[\u0000-\u001f\u007f]/.test(name)
            || new TextEncoder().encode(name).length < 1
            || new TextEncoder().encode(name).length > 220) fail();
          const objectId = field("catalog-write-id")?.value.trim();
          if (!/^[A-Za-z0-9_-]{22}$/.test(objectId)) fail();
          const source = held.baseline.entries.filter((row) => row.objectId === objectId);
          const expectedRevision = source.length
            ? Math.max(...source.map((item) => item.revision)) : null;
          const raw = await fileBytes("catalog-write-key", 32, 32);
          let metadataKey;
          try { metadataKey = await crypto.subtle.importKey("raw", raw,
            { name: "AES-GCM", length: 256 }, false, ["encrypt"]); }
          finally { raw.fill(0); }
          data = await fileBytes("catalog-write-ciphertext", 16, 4 * 1024 * 1024);
          assertLive();
          // Once a mutation starts, this anchor cannot authorize any second
          // mutation, including after lost ACK or a transient catch.
          verifiedOpaqueDelta = null;
          let result;
          try {
            result = await held.client.commitVersion({ previous: held.baseline,
              objectId, expectedRevision, revision: expectedRevision === null ? 1
                : expectedRevision + 1, epoch: trust.pinnedCurrentHead.epoch,
              ciphertext: data, name, metadataKey });
          } catch (error) {
            if (typeof error?.outcome?.journalId === "string"
              && /^[A-Za-z0-9_-]{43}$/.test(error.outcome.journalId))
              field("catalog-write-journal").textContent = error.outcome.journalId;
            // No retry button is enabled from this anchor after uncertainty.
            throw error;
          }
          assertLive();
          if (result.journalClearedAfterSignedProof !== true
            || result.plaintextMetadataExposed !== false
            || result.productionDurabilityProven !== false) fail();
          field("catalog-delta-summary").textContent = "CAS assinado #" + result.sequence;
          status("Versão cifrada enviada uma única vez, GET exato e catálogo CAS assinados. "
            + "Fixe o novo head externamente e ancore novamente em ambos os dispositivos. "
            + "Nenhuma sincronização automática ou durabilidade de nuvem comprovada.");
          return;
        }
        // Import never trusts the uploaded JSON. Fresh independent witness/CAS
        // and this device's signed exact protected GET reconstruct *every*
        // byte before accepting the portable ciphertext-only delta package.
        let imported = null;
        if (action === "catalog-delta-import") {
          const raw = await fileBytes("catalog-delta-package", 2, 12 * 1024 * 1024);
          try { imported = JSON.parse(decoder.decode(raw)); } finally { raw.fill(0); }
          exactly(imported, ["format", "fromSequence", "toSequence", "catalogDigest", "additions"]);
          if (imported.format !== "rootark-zk1-opaque-device-delta/v1"
            || !Array.isArray(imported.additions) || imported.additions.length < 1
            || imported.additions.length > 4096) fail();
        }
        // Prevent any second import attempt against a consumed/stale anchor.
        verifiedOpaqueDelta = null;
        const delta = await held.client.pullDelta(held.baseline);
        assertLive();
        if (delta.fromSequence !== held.baseline.head.sequence
          || delta.toSequence !== delta.fromSequence + 1
          || delta.plaintextMetadataExposed !== false
          || delta.productionDurabilityProven !== false
          || !Array.isArray(delta.additions) || !delta.additions.length) fail();
        const portable = {
          format: "rootark-zk1-opaque-device-delta/v1",
          fromSequence: delta.fromSequence, toSequence: delta.toSequence,
          catalogDigest: delta.catalogDigest,
          additions: delta.additions.map((entry) => ({
            objectId: entry.objectId, revision: entry.revision, epoch: entry.epoch,
            ciphertextDigestBase64: entry.ciphertextDigestBase64,
            metadataCiphertextBase64: entry.metadataCiphertextBase64,
            ciphertextBase64: entry.ciphertextBase64,
          })),
        };
        if (imported) {
          // The exact canonical representation is intentionally narrow: extra
          // fields, plaintext paths, reordering, omissions or altered bytes
          // fail before any local export/application.
          if (JSON.stringify(imported) !== JSON.stringify(portable)) fail();
          field("catalog-delta-summary").textContent = "Importado e conferido: "
            + portable.additions.length + " versão(ões) cifradas · CAS #" + portable.toSequence;
          status("Delta importado conferido com CAS/witness independentes e GET assinado local. "
            + "Nenhuma escrita, aplicação de arquivo ou plaintext no servidor.");
        } else {
          downloadLocal("rootark-zk1-opaque-delta.json", JSON.stringify(portable),
            "application/json", assertLive);
          field("catalog-delta-summary").textContent = "Exportado: "
            + portable.additions.length + " versão(ões) cifradas · CAS #" + portable.toSequence;
          status("Delta opaco conferido e exportado manualmente; só contém ciphertext "
            + "e metadados AES-GCM. O outro dispositivo deve revalidar CAS e GET.");
        }
        return;
      }
      if (action === "catalog-v2-read" || action === "catalog-v2-get") {
        if (field("catalog-v2-opt-in")?.checked !== true
          || available.opaqueCheckpointV2Read !== true
          || !trust.ownerHistoryCheckpoint
          || trust.signedDeviceGrant.revoked_at_epoch !== null
          || positive("catalog-sequence") !== 128) fail();
        if (action === "catalog-v2-get"
          && field("catalog-v2-get-opt-in")?.checked !== true) fail();
        await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        assertLive();
        if (!window.RootarkZk1BrowserAuthorityHeadRelay?.readFinalizedV2)
          await loadScript("rootark-zk1-browser-authority-head-relay");
        const v2 = window.RootarkZk1BrowserAuthorityHeadRelay;
        if (!v2?.readFinalizedV2) fail();
        const names = ["catalog-v2-cas-key", "catalog-v2-floor-key",
          "catalog-v2-checkpoint-key"];
        const keys = await Promise.all(names.map((name) => fileBytes(name, 32, 32)));
        const deviceRaw = from64(trust.signedDeviceGrant.authorization_public_key);
        const deviceKey = await crypto.subtle.importKey("raw", deviceRaw,
          "Ed25519", true, ["verify"]);
        const deviceSpki = new Uint8Array(await crypto.subtle.exportKey("spki", deviceKey));
        const devicePin = new Uint8Array(await crypto.subtle.digest("SHA-256", deviceSpki));
        const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
          .map((name) => [name, trust.signedDeviceGrant[name]]));
        try {
          const chosenIntents = field("catalog-v2-intent")?.files;
          if (!chosenIntents?.length || chosenIntents.length > 128) fail();
          const signedIntents = [];
          for (const file of chosenIntents) {
            if (file.size < 1 || file.size > 10 * 1024 * 1024) fail();
            const raw = new Uint8Array(await file.arrayBuffer());
            assertLive();
            if (raw.byteLength !== file.size) fail();
            signedIntents.push(raw);
          }
          const ownerKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw",
            trust.ownerPublicKey));
          const historicalFile = field("catalog-v2-historical-endorsements")?.files;
          let historical = null;
          if (historicalFile?.length) {
            const raw = await fileBytes("catalog-v2-historical-endorsements", 2, 128 * 8192);
            historical = JSON.parse(decoder.decode(raw));
            if (!Array.isArray(historical) || historical.length !== signedIntents.length) fail();
          }
          const result = await v2.readFinalizedV2({
            origin: location.origin + "/", fetchImpl: guardedFetch, assertLive,
            csrfToken: () => { assertLive(); return initialCsrf; },
            scope, previousDigest: from64(field("catalog-digest").value.trim()),
            previousCheckpointDigest: from64(field("catalog-v2-predecessor-checkpoint").value.trim()),
            ownerRevision: trust.pinnedCurrentHead.revision,
            ownerDigest: trust.pinnedCurrentHead.digest,
            ownerEpoch: trust.pinnedCurrentHead.epoch,
            ownerDeviceId: trust.signedDeviceGrant.device_id,
            signedIntent: signedIntents.at(-1), signedIntents,
            signedDeviceGrant: trust.signedDeviceGrant,
            ownerKeyRaw, ownerSpkiPin: trust.independentOwnerSpkiSha256,
            ...(historical ? { historicalSignerEndorsements: historical,
              independentGenesisDigest: from64(field("catalog-v2-genesis-pin").value.trim()),
              independentWitnessSpkiSha256:
                from64(field("catalog-v2-owner-witness-pin").value.trim()) } : {}),
            casKeyRaw: keys[0], casSpkiPin: from64(field("catalog-v2-cas-pin").value.trim()),
            floorKeyRaw: keys[1], floorSpkiPin: from64(field("catalog-v2-floor-pin").value.trim()),
            checkpointKeyRaw: keys[2],
            checkpointSpkiPin: from64(field("catalog-v2-checkpoint-pin").value.trim()),
            deviceKeyRaw: deviceRaw, deviceSpkiPin: devicePin,
          });
          assertLive();
          if (result.sequence !== 128 + signedIntents.length
            || result.independentlyFinalized !== true
            || result.productionDurabilityProven !== false) fail();
          const list = field("catalog-v2-list");
          list.replaceChildren();
          for (const [index, row] of result.rows.entries()) {
            const p = document.createElement("p");
            p.textContent = String(index) + " · "
              + row.objectId + " · v" + row.revision;
            list.append(p);
          }
          if (action === "catalog-v2-get") {
            const selected = Number(field("catalog-v2-index")?.value);
            if (!Number.isSafeInteger(selected) || selected < 0
              || selected >= result.rows.length) fail();
            privateDer = await fileBytes("private", 1, 8192);
            const devicePrivate = await crypto.subtle.importKey("pkcs8", privateDer,
              "Ed25519", false, ["sign"]);
            const checked = await v2.getFinalizedV2Ciphertext(result, selected, devicePrivate);
            assertLive();
            if (checked.productionDurabilityProven !== false
              || checked.objectId !== result.rows[selected].objectId
              || checked.revision !== result.rows[selected].revision) fail();
            downloadLocal("zk1-v2-" + checked.objectId + "-v" + checked.revision
              + ".ciphertext", contentFrom64(checked.ciphertextBase64),
            "application/octet-stream", assertLive);
            status("Checkpoint V2 #" + result.sequence + " e GET exato autenticados: " + checked.objectId
              + " · v" + checked.revision + ". Ciphertext salvo localmente, sem prova de nuvem.");
          } else {
            status("Checkpoint V2 #" + result.sequence + " autenticado por CAS e floor independentes. "
              + result.totalCount + " versão(ões) opacas; digest " + result.digest
              + ". Sem escrita ou prova de nuvem.");
          }
        } finally { for (const key of keys) key.fill(0); deviceRaw.fill(0); }
        return;
      }
      if (action === "catalog-publish" || action === "catalog-delta-anchor") {
        const anchoringDelta = action === "catalog-delta-anchor";
        if (anchoringDelta) verifiedOpaqueDelta = null;
        if ((anchoringDelta ? field("catalog-delta-opt-in")?.checked !== true
          : field("catalog-write-opt-in")?.checked !== true)
          || available.opaqueCatalogV1 !== true
          || trust.signedDeviceGrant.revoked_at_epoch !== null
          || !trust.ownerHistoryCheckpoint) fail();
        await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        assertLive();
        if (!window.RootarkZk1BrowserOpaqueCatalogCommit)
          await loadScript("rootark-zk1-browser-opaque-catalog-commit");
        assertLive();
        if (anchoringDelta && !window.RootarkZk1OpaqueDeviceDeltaSync?.createClient)
          await loadScript("rootark-zk1-opaque-device-delta-sync");
        assertLive();
        if (anchoringDelta && !window.RootarkZk1OpaqueDeviceDeltaSync?.createClient) fail();
        if (!window.RootarkZk1BrowserOpaqueCatalogCommit?.createClient
          || !window.RootarkZk1ProtectedHttpClient?.signProtectedContentOperation
          || !window.RootarkZk1ProtectedHttpClient?.postProtectedCiphertextPut) fail();
        const rootOrigin = location.origin;
        const relayOptIn = field("catalog-relay-opt-in")?.checked === true;
        let witnessUrl, casUrl;
        if (!relayOptIn) {
          witnessUrl = independentCatalogEndpoint(field("catalog-witness-url").value.trim(), rootOrigin);
          casUrl = independentCatalogEndpoint(field("catalog-cas-url").value.trim(), rootOrigin);
          if (witnessUrl.origin === casUrl.origin) fail();
        }
        const signerGrant = JSON.parse(decoder.decode(await fileBytes("catalog-signer-grant", 1, 8192)));
        const witnessRaw = await fileBytes("catalog-witness-key", 32, 32);
        const casRaw = await fileBytes("catalog-cas-key", 32, 32);
        const writerKeyRaw = anchoringDelta ? null : await fileBytes("catalog-write-key", 32, 32);
        let witnessKey, casKey, metadataKey, relayProbes;
        try {
          const witnessPin = from64(field("catalog-witness-spki").value.trim());
          const casPin = from64(field("catalog-cas-spki").value.trim());
          witnessKey = await importPinnedCatalogAuthority(witnessRaw, witnessPin);
          casKey = await importPinnedCatalogAuthority(casRaw, casPin);
          if (!anchoringDelta) metadataKey = await crypto.subtle.importKey("raw", writerKeyRaw,
            { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
          if (relayOptIn) {
            if (!window.RootarkZk1BrowserAuthorityHeadRelay)
              await loadScript("rootark-zk1-browser-authority-head-relay");
            assertLive();
            if (!window.RootarkZk1BrowserAuthorityHeadRelay?.createProbes) fail();
            relayProbes = await window.RootarkZk1BrowserAuthorityHeadRelay.createProbes({
              origin: rootOrigin + "/", fetchImpl: guardedFetch, assertLive,
              csrfToken: () => { assertLive(); return initialCsrf; },
              ownerWitnessKeyRaw: witnessRaw, ownerWitnessSpkiSha256: witnessPin,
              ownerWitnessKeyId: signerIdFrom64(field("catalog-witness-id").value.trim()),
              catalogAuthorityKeyRaw: casRaw, catalogAuthoritySpkiSha256: casPin,
            });
            assertLive();
          }
        } finally { witnessRaw.fill(0); casRaw.fill(0); writerKeyRaw?.fill(0); }
        assertLive();
        const privateRaw = await fileBytes("private", 1, 8192);
        let devicePrivateKey;
        try { devicePrivateKey = await crypto.subtle.importKey("pkcs8", privateRaw,
          "Ed25519", false, ["sign"]); } finally { privateRaw.fill(0); }
        const deviceRaw = await fileBytes("device", 32, 32);
        let devicePublicKey;
        // The opaque catalog UMD exports only this public key's raw bytes to
        // compare them with the owner-signed grant; private keys stay sealed.
        try { devicePublicKey = await crypto.subtle.importKey("raw", deviceRaw,
          "Ed25519", true, ["verify"]); } finally { deviceRaw.fill(0); }
        let name, objectId;
        if (!anchoringDelta) {
          name = field("catalog-write-name").value;
          if (typeof name !== "string" || /[\u0000-\u001f\u007f]/.test(name)
            || new TextEncoder().encode(name).length < 1
            || new TextEncoder().encode(name).length > 220) fail();
          const enteredId = field("catalog-write-id").value.trim();
          if (enteredId && !/^[A-Za-z0-9_-]{22}$/.test(enteredId)) fail();
          objectId = enteredId || randomId();
          field("catalog-write-id").value = objectId;
        }
        const rawSequence = field("catalog-write-sequence").value.trim();
        if (!/^(0|[1-9][0-9]*)$/.test(rawSequence)) fail();
        const sequence = Number(rawSequence);
        if (!Number.isSafeInteger(sequence) || sequence > 127) fail();
        const catalogFloor = from64(field("catalog-write-digest").value.trim());
        if (sequence === 0 && catalogFloor.some((byte) => byte !== 0)) fail();
        if (!anchoringDelta) data = await fileBytes("catalog-write-ciphertext", 16, 4 * 1024 * 1024);
        assertLive();
        const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
          .map((key) => [key, trust.signedDeviceGrant[key]]));
        const signerGrants = [trust.signedDeviceGrant];
        if (signerGrant.device_id !== trust.signedDeviceGrant.device_id) signerGrants.push(signerGrant);
        else if (JSON.stringify(signerGrant) !== JSON.stringify(trust.signedDeviceGrant)) fail();
        const authority = {
          origin: rootOrigin + "/", fetchImpl: guardedFetch,
          ownerPublicKey: trust.ownerPublicKey,
          pinnedOwnerKeyHash: trust.pinnedOwnerKeyHash,
          pinnedOwnerHead: { revision: trust.pinnedCurrentHead.revision,
            digest: trust.pinnedCurrentHead.digest, epoch: trust.pinnedCurrentHead.epoch },
          signedDeviceGrant: trust.signedDeviceGrant, devicePublicKey, devicePrivateKey,
          signerGrants, ownerWitnessPublicKey: witnessKey,
          ownerWitnessKeyId: signerIdFrom64(field("catalog-witness-id").value.trim()),
          ownerWitnessProbe: relayOptIn ? relayProbes.ownerWitnessProbe
            : independentCatalogProbe(witnessUrl, assertLive),
          catalogAuthorityPublicKey: casKey,
          catalogProbe: relayOptIn ? relayProbes.catalogProbe
            : independentCatalogProbe(casUrl, assertLive),
          minimumCatalogHead: { sequence, digest: catalogFloor },
          csrfToken: () => { assertLive(); return initialCsrf; },
          isSessionCurrent: () => {
            try { assertLive(); return true; } catch (_) { return false; }
          },
          assertCurrent: async () => {
            assertLive();
            await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
              ownerPublicKey: trust.ownerPublicKey,
              independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
              pinnedCurrentHead: trust.pinnedCurrentHead,
              signedDeviceGrant: trust.signedDeviceGrant,
              ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
              previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
            });
            assertLive();
          },
          nowSeconds: () => Math.floor(Date.now() / 1000),
        };
        if (anchoringDelta) {
          const privateList = field("catalog-delta-private-list");
          if (privateList) privateList.replaceChildren();
          const client = window.RootarkZk1OpaqueDeviceDeltaSync.createClient({ authority, assertLive });
          const baseline = await client.readCurrent();
          assertLive();
          // Never bootstrap an independent floor from what the server just
          // returned. Its exact sequence/digest MUST have been pinned offline.
          if (baseline.head.sequence !== sequence
            || baseline.head.digest !== to64(catalogFloor)
            || baseline.plaintextMetadataExposed !== false
            || baseline.independentCloudDurabilityProven !== false) fail();
          verifiedOpaqueDelta = {
            client, baseline, csrf: initialCsrf, epoch: sessionEpoch,
            origin: location.origin, grant: JSON.stringify(trust.signedDeviceGrant),
            ownerDigest: to64(trust.pinnedCurrentHead.digest),
            ownerRevision: trust.pinnedCurrentHead.revision,
            ownerEpoch: trust.pinnedCurrentHead.epoch,
            minimumSequence: field("catalog-write-sequence").value.trim(),
            minimumDigest: field("catalog-write-digest").value.trim(),
            casPin: field("catalog-cas-spki").value.trim(),
            witnessPin: field("catalog-witness-spki").value.trim(),
          };
          field("catalog-delta-summary").textContent = "Piso CAS #" + baseline.head.sequence
            + " · " + baseline.entries.length + " versão(ões) opacas";
          status("Piso independente CAS #" + baseline.head.sequence
            + " autenticado. Agora outra sessão/dispositivo pode publicar UMA nova revisão; "
            + "volte para importar ou exportar o delta cifrado manualmente.");
          return;
        }
        const client = window.RootarkZk1BrowserOpaqueCatalogCommit.createClient(authority);
        const addition = { objectId, revision: 1, epoch: trust.pinnedCurrentHead.epoch,
          ciphertext: data, name, metadataKey };
        const journalId = await client.prepareIntent([{ objectId, revision: 1,
          epoch: addition.epoch, ciphertext: data }]);
        assertLive();
        field("catalog-write-journal").textContent = journalId;
        status("Intenção assinada persistida no IndexedDB. Enviando ciphertext opaco por PUT autenticado…");
        const signedPut = await window.RootarkZk1ProtectedHttpClient.signProtectedContentOperation({
          signerKey: devicePrivateKey, scope, deviceId: trust.signedDeviceGrant.device_id,
          operation: "put", objectId, expectedObjectRevision: null,
          manifestRevision: trust.pinnedCurrentHead.revision,
          manifestDigest: trust.pinnedCurrentHead.digest, epoch: addition.epoch,
          nowSeconds: Math.floor(Date.now() / 1000), ciphertext: data,
        });
        assertLive();
        let uncertainPut = false;
        try {
          const ack = await window.RootarkZk1ProtectedHttpClient.postProtectedCiphertextPut({
            origin: rootOrigin + "/", request: signedPut, fetchImpl: guardedFetch,
          });
          if (ack.id !== objectId || ack.revision !== 1) fail();
        } catch (_) {
          // Never repeat an uncertain PUT. The catalog client's fresh signed
          // exact-version GET and byte comparison resolve its actual outcome.
          uncertainPut = true;
        }
        assertLive();
        const result = await client.commit([addition], journalId);
        assertLive();
        verifiedCatalog = null;
        if (result.verifiedSignedReadback !== true || result.productionDurabilityProven !== false) fail();
        status("Catálogo completo #" + result.sequence + " confirmado por GET assinado + CAS: "
          + result.digest + ". " + result.totalCount + " versão(ões). Object ID: " + objectId
          + (uncertainPut ? ". ACK do PUT incerto, GET conferido." : ".")
          + " Fixe sequência/digest por canal externo antes do segundo dispositivo. Sem prova de durabilidade em nuvem.");
        return;
      }
      if (["catalog-discover", "catalog-page", "catalog-get", "catalog-lifecycle"].includes(action)) {
        if (!window.RootarkZk1BrowserCatalog) await loadScript("rootark-zk1-browser-catalog");
        assertLive();
        if (!window.RootarkZk1BrowserCatalog?.openCatalog
          || !window.RootarkZk1BrowserCatalog?.getCatalogCiphertext) fail();
        if (available.opaqueCatalogV1 !== true
          || trust.signedDeviceGrant.revoked_at_epoch !== null
          || !trust.ownerHistoryCheckpoint) fail();
        const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
          .map((name) => [name, trust.signedDeviceGrant[name]]));
        await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        assertLive();
        if (action === "catalog-discover" || action === "catalog-lifecycle") {
          if (action === "catalog-discover") verifiedCatalog = null;
          const signerGrant = JSON.parse(decoder.decode(
            await fileBytes("catalog-signer-grant", 1, 8192)));
          const casRaw = await fileBytes("catalog-cas-key", 32, 32);
          let casKey;
          try { casKey = await crypto.subtle.importKey("raw", casRaw,
            "Ed25519", true, ["verify"]); }
          finally { casRaw.fill(0); }
          privateDer = await fileBytes("private", 1, 8192);
          const devicePrivateKey = await crypto.subtle.importKey("pkcs8", privateDer,
            "Ed25519", false, ["sign"]);
          const catalogRead = {
            trust, signerGrant, devicePrivateKey, catalogAuthorityKey: casKey,
            independentAuthoritySpkiHash: from64(field("catalog-cas-spki").value.trim()),
            pinnedCatalogHead: {
              sequence: positive("catalog-sequence"),
              digest: field("catalog-digest").value.trim(),
            },
            origin: location.origin + "/", fetchImpl: guardedFetch,
            assertLive, indexedDBImpl: indexedDB,
            nowSeconds: () => Math.floor(Date.now() / 1000),
          };
          if (action === "catalog-lifecycle") {
            if (field("catalog-lifecycle-opt-in")?.checked !== true) fail();
            if (!window.RootarkZk1CrossDeviceTrashObserver)
              await loadScript("rootark-zk1-cross-device-trash-observer");
            assertLive();
            if (!window.RootarkZk1CrossDeviceTrashObserver?.inspect
              || !window.RootarkZk1FileContent?.importFileCek) fail();
            const packed = await fileBytes("catalog-lifecycle-history", 2, 65536);
            let selected;
            try { selected = JSON.parse(decoder.decode(packed)); }
            finally { packed.fill(0); }
            exactly(selected, ["schema", "objectId", "versions"]);
            if (selected.schema !== "rootark-zk1-lifecycle-selection/v1"
              || selected.objectId !== field("catalog-lifecycle-id")?.value.trim()
              || !/^[A-Za-z0-9_-]{22}$/.test(selected.objectId)
              || !Array.isArray(selected.versions) || selected.versions.length < 1
              || selected.versions.length > 12) fail();
            const keys = Array.from(field("catalog-lifecycle-ceks")?.files || []);
            if (keys.length !== selected.versions.length
              || keys.some((key) => key.size !== 32)) fail();
            const reviewed = await window.RootarkZk1CrossDeviceTrashObserver.inspect({
              catalogRead, objectId: selected.objectId,
              versionMetadata: selected.versions, assertLive,
              readArchivedCek: async (requested) => {
                assertLive();
                if (!["account_id", "compartment_id", "keyring_id"]
                  .every((name) => requested[name] === scope[name])) fail();
                const index = requested.revision - 1;
                if (!Number.isSafeInteger(index) || index < 0 || index >= keys.length
                  || selected.versions[index]?.version_id !== requested.versionId) fail();
                const raw = new Uint8Array(await keys[index].arrayBuffer());
                try {
                  assertLive();
                  if (raw.length !== 32) fail();
                  return await window.RootarkZk1FileContent.importFileCek(raw);
                } finally { raw.fill(0); }
              },
            });
            assertLive();
            if (reviewed.exactSignedGetAndAeadVerified !== true
              || reviewed.monotonicPinnedFloorVerified !== true
              || reviewed.authorizesProductionRestore !== false
              || reviewed.physicalErasureProven !== false) fail();
            status("Objeto " + reviewed.objectId + ": "
              + (reviewed.state === "trashed" ? "tombstone conferido" : reviewed.restoredAfterTombstone
                ? "restauração conferida" : "arquivo conferido")
              + " na revisão " + reviewed.revision + ". CAS assinado #"
              + reviewed.catalogSequence + ". Sem exclusão física ou restore de produção.");
            return;
          }
          const result = await window.RootarkZk1BrowserCatalog.openCatalog(catalogRead);
          assertLive();
          verifiedCatalog = { result, scope, epoch: sessionEpoch, csrf: initialCsrf };
          status("Catálogo #" + result.sequence + " · " + result.totalCount
            + " versão(ões) criptografadas conferidas. Páginas modificadas: "
            + (result.changedPageIndices.join(", ") || "nenhuma")
            + ". Head: " + result.catalogDigest + ". GET sempre assinado e verificado."
            + (result.sequence === 128 ? " LIMITE ATINGIDO: novas publicações bloqueadas até um rollover assinado e auditado." : ""));
        } else if (!verifiedCatalog || verifiedCatalog.epoch !== sessionEpoch
          || verifiedCatalog.csrf !== initialCsrf
          || !Object.keys(scope).every((key) => scope[key] === verifiedCatalog.scope[key])) fail();
        const current = verifiedCatalog.result;
        const page = Number(field("catalog-page").value);
        if (!Number.isSafeInteger(page) || page < 0 || page > 127
          || page >= Math.max(1, Math.ceil(current.totalCount / 32))) fail();
        const offset = page * 32;
        const visible = current.entries.slice(offset, offset + 32);
        if (action === "catalog-discover" || action === "catalog-page") {
          const container = field("catalog-list");
          container.replaceChildren();
          let metadataKey = null;
          const files = field("catalog-metadata-key")?.files;
          if (files?.length) metadataKey = await fileBytes("catalog-metadata-key", 32, 32);
          try {
            for (let i = 0; i < visible.length; i++) {
              assertLive();
              const entry = visible[i];
              const line = document.createElement("p");
              let localLabel = "(nome cifrado)";
              if (metadataKey) localLabel = await window.RootarkZk1BrowserCatalog.openCatalogName(
                current, offset + i, metadataKey);
              assertLive();
              line.textContent = String(i) + " · " + entry.objectId + " · v"
                + entry.revision + " · " + localLabel;
              container.append(line);
            }
          } finally { metadataKey?.fill(0); }
        } else {
          const selected = Number(field("catalog-entry").value);
          if (!Number.isSafeInteger(selected) || selected < 0
            || selected >= visible.length) fail();
          const checked = await window.RootarkZk1BrowserCatalog.getCatalogCiphertext(
            current, offset + selected);
          assertLive();
          downloadLocal("zk1-" + checked.objectId + "-v" + checked.revision + ".ciphertext",
            contentFrom64(checked.ciphertextBase64),
            "application/octet-stream", assertLive);
          status("GET autenticado e digest SHA-256 conferido: " + checked.objectId
            + " · versão " + checked.revision + ". Ciphertext entregue localmente.");
        }
        return;
      }
      if (action === "account-create" || action === "account-recover") {
        if (field("account-opt-in")?.checked !== true || !trust.ownerHistoryCheckpoint
          || trust.signedDeviceGrant.revoked_at_epoch !== null) fail();
        await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        assertLive();
        const create = action === "account-create";
        const accountHistory = field("account-historical-opt-in")?.checked === true;
        const selected = await selectedAccountKeyrings(trust, create, assertLive, accountFiles,
          accountHistory);
        if (create) {
          ownerSigningDer = await fileBytes("account-owner-private", 1, 8192);
          assertLive();
          const ownerSigningKey = await crypto.subtle.importKey("pkcs8", ownerSigningDer,
            "Ed25519", false, ["sign"]);
          const probe = crypto.getRandomValues(new Uint8Array(32));
          try {
            const sig = await crypto.subtle.sign("Ed25519", ownerSigningKey, probe);
            assertLive();
            if (!await crypto.subtle.verify("Ed25519", trust.ownerPublicKey, sig, probe)) fail();
          } finally { probe.fill(0); }
          const sealed = await window.RootarkZk1AccountPortableRecovery.createArchive({
            ...selected, ownerPublicKey: trust.ownerPublicKey,
            independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
            ownerSigningKey,
            keyrings: selected.keyrings.map((ring) => ({ ...ring, ownerSigningKey,
              issuedAt: Math.floor(Date.now() / 1000) })),
          });
          assertLive();
          if (sealed.authorizesProductionRestore !== false
            || sealed.archive?.keyrings?.length !== selected.keyrings.length
            || sealed.archive?.accountId !== selected.accountId
            || sealed.archiveSha256?.byteLength !== 32) fail();
          downloadLocal("rootark-account-archive.json", JSON.stringify(sealed.archive),
            "application/json", assertLive);
          downloadLocal("rootark-account-archive.sha256.txt", to64(sealed.archiveSha256),
            "text/plain", assertLive);
          status("Pacote cifrado e assinado de " + selected.keyrings.length
            + " keyring(s) baixado. Preserve hash, pins atuais e segredos separadamente. Sem restauração de produção.");
        } else {
          const rawArchive = await fileBytes("account-archive", 1, 16 * 1024 * 1024);
          let accountArchive;
          try { accountArchive = JSON.parse(decoder.decode(rawArchive)); }
          finally { rawArchive.fill(0); }
          assertLive();
          if (!Array.isArray(accountArchive?.keyrings)
            || accountArchive.keyrings.length !== selected.keyrings.length) fail();
          const independentAccountHash = from64(field("account-sha").value.trim());
          let historicCount = 0;
          for (let index = 0; index < selected.keyrings.length; index++) {
            const expected = selected.keyrings[index];
            const entry = accountArchive.keyrings[index];
            if (!entry || !["account_id", "compartment_id", "keyring_id"].every((name) =>
              expected.scope[name] === entry.scope?.[name])) fail();
            const old = entry.ownerRevision !== expected.pinnedCurrentHead.revision
              || entry.ownerDigest !== to64(expected.pinnedCurrentHead.digest)
              || entry.ownerEpoch !== expected.pinnedCurrentHead.epoch;
            const historical = Object.hasOwn(expected, "historicalRecovery");
            if (old !== historical || (old && !accountHistory)) fail();
            if (old) {
              const ringId = expected.scope.compartment_id + ":" + expected.scope.keyring_id;
              const devicePrivateDer = selected.historyPrivateFiles?.get(ringId);
              if (!devicePrivateDer) fail();
              const devicePoP = await signedHistoricalDevicePoP({
                scope: expected.scope,
                pinnedCurrentHead: expected.pinnedCurrentHead,
                independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
                currentSignedDeviceGrant: expected.historicalRecovery.currentSignedDeviceGrant,
                archiveSha256: from64(entry.archiveSha256),
                accountArchiveSha256: independentAccountHash,
                privateDer: devicePrivateDer, assertLive,
              });
              assertLive();
              expected.historicalRecovery = { ...expected.historicalRecovery, devicePoP };
              historicCount++;
            }
          }
          if (accountHistory && historicCount === 0) fail();
          accountRecovered = await window.RootarkZk1AccountPortableRecovery.recoverArchive({
            accountArchive, accountId: selected.accountId,
            independentlyPinnedAccountSha256: independentAccountHash,
            ownerPublicKey: trust.ownerPublicKey,
            independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
            keyrings: selected.keyrings,
          });
          assertLive();
          if (accountRecovered.allKeyringsVerified !== true
            || accountRecovered.aggregateSignatureVerified !== true
            || accountRecovered.aggregateIndependentPinMatched !== true
            || accountRecovered.authorizesProductionRestore !== false
            || accountRecovered.keyrings?.length !== selected.keyrings.length) fail();
          // Check EVERY name, scope, byte buffer and collision before the first
          // release. Recovery module itself wipes previous rings on a late MAC failure.
          const releases = [];
          const names = new Set();
          for (let index = 0; index < accountRecovered.keyrings.length; index++) {
            const ring = accountRecovered.keyrings[index];
            if (!ring || !Array.isArray(ring.files) || ring.files.length < 1
              || ring.files.length > 12 || ring.scope?.keyring_id !== selected.keyrings[index].scope.keyring_id
              || ring.scope?.compartment_id !== selected.keyrings[index].scope.compartment_id
              || ring.scope?.account_id !== selected.accountId) fail();
            for (const file of ring.files) {
              if (!(file.data instanceof Uint8Array) || !file.data.length
                || file.data.length > 8 * 1024 * 1024) fail();
              const name = localName("keyring-" + ring.scope.keyring_id + "-" + localName(file.name));
              if (names.has(name.toLowerCase())) fail();
              names.add(name.toLowerCase());
              releases.push({ name, data: file.data, mediaType: file.mediaType });
            }
          }
          assertLive();
          for (const file of releases) {
            downloadLocal(file.name, file.data, file.mediaType || "application/octet-stream", assertLive);
          }
          status("Assinatura e hash independentes da conta + todos os "
            + selected.keyrings.length + " keyring(s) verificados; " + releases.length
            + " arquivos baixados localmente. "
            + (historicCount ? "Heads antigos exigiram concessão atual ATIVA, cadeia assinada e raízes reendossadas. " : "")
            + "Sem autorização de restore em produção.");
        }
        return;
      }
      if (action === "archive-create" || action === "archive-recover") {
        if (field("archive-opt-in")?.checked !== true || !trust.ownerHistoryCheckpoint) fail();
        if (trust.signedDeviceGrant.revoked_at_epoch !== null) fail();
        // The runtime's signed grant/history proof is not sufficient to pick a
        // trust root: independently entered SPKI/head + browser floor are
        // checked AGAIN on every invocation, without trusting JSON flags.
        await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
          .map((name) => [name, trust.signedDeviceGrant[name]]));
        const archiveCommon = {
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead, scope,
          signerKeyId: signerIdFrom64(field("owner-signer").value.trim()),
          deviceId: field("owner-device").value.trim(),
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        };
        secret = await fileBytes("secret", 32, 32);
        if (action === "archive-create") {
          const selections = Array.from(field("archive-files")?.files || []);
          if (selections.length < 1 || selections.length > 12
            || selections.some((file) => !file || file.size < 1 || file.size > 8 * 1024 * 1024)
            || selections.reduce((sum, file) => sum + file.size, 0) > 8 * 1024 * 1024) fail();
          const checkedNames = selections.map((file) => localName(file.name));
          if (new Set(checkedNames.map((name) => name.toLowerCase())).size !== selections.length) fail();
          ownerSigningDer = await fileBytes("archive-owner-private", 1, 8192);
          const ownerSigningKey = await crypto.subtle.importKey("pkcs8", ownerSigningDer,
            "Ed25519", false, ["sign"]);
          // Private key must really match the pinned owner's public key.
          const probe = crypto.getRandomValues(new Uint8Array(32));
          const probeSignature = await crypto.subtle.sign("Ed25519", ownerSigningKey, probe);
          if (!await crypto.subtle.verify("Ed25519", trust.ownerPublicKey, probeSignature, probe)) fail();
          archiveFiles = [];
          for (let index = 0; index < selections.length; index++) {
            const selected = selections[index];
            const bytes = new Uint8Array(await selected.arrayBuffer());
            if (bytes.length !== selected.size) fail();
            archiveFiles.push({ metadata: { ...scope,
              object_id: randomId(), version_id: randomId(), parent_version_id: null,
              epoch: trust.pinnedCurrentHead.epoch, kind: "file" },
              objectRevision: 1, name: checkedNames[index],
              mediaType: selected.type || "application/octet-stream", data: bytes });
          }
          const sealed = await window.RootarkZk1KeyringPortableArchive.createArchive({
            ...archiveCommon, recoverySecret: secret, ownerSigningKey,
            files: archiveFiles, signedDeviceGrant: trust.signedDeviceGrant,
            ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
            issuedAt: Math.floor(Date.now() / 1000),
          });
          downloadLocal("rootark-keyring-archive.json", JSON.stringify(sealed.archive), "application/json", assertLive);
          downloadLocal("rootark-keyring-archive.sha256.txt", to64(sealed.archiveSha256), "text/plain", assertLive);
          status("Arquivo de " + selections.length + " objeto(s) cifrado e assinado localmente. Guarde SHA-256 externamente, separado do arquivo e do segredo. Não é backup de produção.");
        } else {
          const archiveFile = await fileBytes("archive-json", 1, 17 * 1024 * 1024);
          let archive;
          try { archive = JSON.parse(decoder.decode(archiveFile)); }
          finally { archiveFile.fill(0); }
          const historicOptIn = field("archive-historical-opt-in")?.checked === true;
          if (historicOptIn && (archive?.ownerRevision === trust.pinnedCurrentHead.revision
            && archive?.ownerDigest === to64(trust.pinnedCurrentHead.digest)
            && archive?.ownerEpoch === trust.pinnedCurrentHead.epoch)) fail();
          if (!historicOptIn && (archive?.ownerRevision !== trust.pinnedCurrentHead.revision
            || archive?.ownerDigest !== to64(trust.pinnedCurrentHead.digest)
            || archive?.ownerEpoch !== trust.pinnedCurrentHead.epoch)) fail();
          const historicalRecovery = historicOptIn
            ? await selectedHistoricalKeyring(trust, scope, archiveCommon.signerKeyId,
              archiveCommon.deviceId, assertLive) : null;
          assertLive();
          if (historicOptIn) {
            privateDer = await fileBytes("private", 1, 8192);
            assertLive();
            historicalRecovery.devicePoP = await signedHistoricalDevicePoP({
              scope, pinnedCurrentHead: trust.pinnedCurrentHead,
              independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
              currentSignedDeviceGrant: historicalRecovery.currentSignedDeviceGrant,
              archiveSha256: from64(field("archive-sha").value.trim()),
              accountArchiveSha256: null, privateDer, assertLive,
            });
            assertLive();
          }
          const recovered = await window.RootarkZk1KeyringPortableArchive.recoverArchive({
            ...archiveCommon, previousOwnerHistoryProof: historicOptIn
              ? null : archiveCommon.previousOwnerHistoryProof,
            ...(historicOptIn ? { historicalRecovery } : {}),
            recoverySecret: secret, archive,
            independentlyPinnedArchiveSha256: from64(field("archive-sha").value.trim()),
          });
          try {
            if (recovered.files.length < 1 || recovered.files.length > 12
              || recovered.signedManifestVerified !== true
              || recovered.independentArchiveHashMatched !== true
              || recovered.allOwnerSignedRootsVerified !== true
              || recovered.activeSignedGrantAtPinnedHeadVerified !== true
              || (historicOptIn && (recovered.historicalOwnerContinuityVerified !== true
                || recovered.currentSignedGrantAtPinnedHeadVerified !== true))) fail();
            const names = recovered.files.map((file) => localName(file.name));
            if (new Set(names.map((name) => name.toLowerCase())).size !== names.length) fail();
            // Validate all output paths BEFORE creating the first download.
            for (let index = 0; index < recovered.files.length; index++) {
              const file = recovered.files[index];
              downloadLocal(names[index], file.data, file.mediaType || "application/octet-stream", assertLive);
            }
            status("Assinatura, escopo, grant, histórico, todas as raízes e hash externo conferidos. "
              + (historicOptIn ? "Grant atual e reendosso de cada raiz confirmados. " : "")
              + recovered.files.length + " arquivo(s) baixados localmente. Revogação online/durabilidade externa não comprovadas.");
          } finally { for (const file of recovered.files) file.data.fill(0); }
        }
        return;
      }
      if (action === "versioned-create" || action === "versioned-recover") {
        if (field("v2-opt-in")?.checked !== true || !trust.ownerHistoryCheckpoint
          || trust.signedDeviceGrant.revoked_at_epoch !== null) fail();
        const historicOptIn = action === "versioned-recover"
          && field("archive-historical-opt-in")?.checked === true;
        if (action === "versioned-create"
          && field("archive-historical-opt-in")?.checked === true) fail();
        const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
          .map((name) => [name, trust.signedDeviceGrant[name]]));
        const signerKeyId = signerIdFrom64(field("owner-signer").value.trim());
        const deviceId = field("owner-device").value.trim();
        if (deviceId !== trust.signedDeviceGrant.device_id) fail();
        const historical = historicOptIn
          ? await selectedHistoricalKeyring(trust, scope, signerKeyId, deviceId, assertLive)
          : null;
        const backupJson = JSON.parse(decoder.decode(await fileBytes("v2-snapshot", 1,
          13 * 1024 * 1024)));
        const roster = JSON.parse(decoder.decode(await fileBytes("v2-roster", 1, 20000)));
        const ownerInventoryPortable = decoder.decode(await fileBytes("inventory-portable", 1, 400000));
        const inventorySignerSpki = await fileBytes("v2-inventory-signer", 44, 256);
        const inventorySignerPublicKey = await crypto.subtle.importKey("spki",
          inventorySignerSpki, "Ed25519", true, ["verify"]);
        inventorySignerSpki.fill(0);
        const independentRosterSha256 = from64(field("v2-roster-pin").value.trim());
        const backupVerification = {
          snapshot: backupJson, roster, independentRosterSha256,
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead, scope, ownerInventoryPortable,
          independentlyPinnedInventoryCheckpointDigest: field("inventory-pin").value.trim(),
          independentlyPinnedInventorySignerSpkiSha256: field("inventory-signer-spki").value.trim(),
          inventorySignerPublicKey, inventorySignerKeyId:
            signerIdFrom64(field("v2-inventory-signer-id").value.trim()),
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
          signerKeyId, deviceId,
          independentlyPinnedBackupSha256: from64(field("v2-snapshot-pin").value.trim()),
          nowSeconds: Math.floor(Date.now() / 1000),
          ...(historical ? { archivalHistoryChain: historical.signedOwnerHistoryChain } : {}),
        };
        const versionedAuthority = await window.RootarkZk1KeyringPortableArchive.verifyVersionedAuthority({
          backupVerification,
          rosterVerification: { roster,
            independentlyPinnedRosterSha256: independentRosterSha256,
            ownerPublicKey: trust.ownerPublicKey,
            independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
            accountId: scope.account_id },
          otherVerifiedKeyringProofs: [],
        });
        assertLive();
        if (versionedAuthority.completeRelativeToOwnerCheckpoint !== true
          || versionedAuthority.authorizesProductionRestore !== false) fail();
        const archiveCommon = { ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead, scope,
          signerKeyId, deviceId, previousOwnerHistoryProof: trust.previousOwnerHistoryProof };
        secret = await fileBytes("secret", 32, 32);
        if (action === "versioned-create") {
          const raw = await fileBytes("v2-versions", 2, 12 * 1024 * 1024);
          let chosen;
          try { chosen = JSON.parse(decoder.decode(raw)); }
          finally { raw.fill(0); }
          exactly(chosen, ["schema", "versions"]);
          if (chosen.schema !== "rootark-zk1-version-selection/v1"
            || !Array.isArray(chosen.versions) || chosen.versions.length < 1
            || chosen.versions.length > 12) fail();
          ownerSigningDer = await fileBytes("archive-owner-private", 1, 8192);
          const ownerSigningKey = await crypto.subtle.importKey("pkcs8", ownerSigningDer,
            "Ed25519", false, ["sign"]);
          const probe = crypto.getRandomValues(new Uint8Array(32));
          if (!await crypto.subtle.verify("Ed25519", trust.ownerPublicKey,
            await crypto.subtle.sign("Ed25519", ownerSigningKey, probe), probe)) fail();
          assertLive();
          const sealed = await window.RootarkZk1BrowserVersionedArchive.createArchive({
            archiveInput: { ...archiveCommon, recoverySecret: secret, ownerSigningKey,
              signedDeviceGrant: trust.signedDeviceGrant,
              ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
              issuedAt: Math.floor(Date.now() / 1000) },
            versions: chosen.versions, verifiedAuthority: versionedAuthority, assertLive });
          assertLive();
          downloadLocal("rootark-keyring-versions-v2.json", JSON.stringify(sealed.archive),
            "application/json", assertLive);
          downloadLocal("rootark-keyring-versions-v2.sha256.txt",
            to64(sealed.archiveSha256), "text/plain", assertLive);
          status("V2: todas as versões verificadas contra snapshot CBOR, roster assinado, roots e AEAD da CEK. Guarde o hash externo e o segredo separados.");
        } else {
          const archivedBytes = await fileBytes("archive-json", 1, 17 * 1024 * 1024);
          let archived;
          try { archived = JSON.parse(decoder.decode(archivedBytes)); }
          finally { archivedBytes.fill(0); }
          if (archived?.format !== "rootark-zk1-keyring-portable-archive/v2") fail();
          if (historicOptIn === (archived.ownerRevision === trust.pinnedCurrentHead.revision
            && archived.ownerDigest === to64(trust.pinnedCurrentHead.digest)
            && archived.ownerEpoch === trust.pinnedCurrentHead.epoch)) fail();
          if (historicOptIn) {
            privateDer = await fileBytes("private", 1, 8192);
            historical.devicePoP = await signedHistoricalDevicePoP({
              scope, pinnedCurrentHead: trust.pinnedCurrentHead,
              independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
              currentSignedDeviceGrant: historical.currentSignedDeviceGrant,
              archiveSha256: from64(field("archive-sha").value.trim()),
              accountArchiveSha256: null, privateDer, assertLive,
            });
          }
          const opened = await window.RootarkZk1BrowserVersionedArchive.recoverArchive({
            recoveryInput: { ...archiveCommon,
              previousOwnerHistoryProof: historicOptIn ? null
                : archiveCommon.previousOwnerHistoryProof,
              ...(historicOptIn ? { historicalRecovery: historical } : {}),
              recoverySecret: secret, archive: archived,
              independentlyPinnedArchiveSha256: from64(field("archive-sha").value.trim()) },
            verifiedAuthority: versionedAuthority, assertLive });
          try {
            const output = [];
            const seen = new Set();
            for (const file of opened.files) {
              if (!(file.ciphertext instanceof Uint8Array)
                || !(file.cek instanceof Uint8Array) || file.cek.length !== 32
                || !/^[A-Za-z0-9_-]{22}$/.test(file.objectId)
                || !Number.isSafeInteger(file.objectRevision)
                || file.objectRevision < 1) fail();
              const prefix = "zk1-" + file.objectId + "-r" + file.objectRevision;
              if (seen.has(prefix)) fail();
              seen.add(prefix);
              output.push({ name: localName(prefix + ".ciphertext"), data: file.ciphertext });
              output.push({ name: localName(prefix + ".cek"), data: file.cek });
            }
            assertLive();
            for (const item of output) downloadLocal(item.name, item.data,
              "application/octet-stream", assertLive);
            status("V2: " + opened.files.length + " versões autenticadas, ciphertext e CEK baixados separadamente. Nenhuma restauração no servidor.");
          } finally {
            for (const file of opened.files) {
              file.ciphertext.fill(0); file.cek.fill(0);
            }
          }
        }
        return;
      }
      if (action === "import-approval") {
        committedDeviceApproval = null;
        // Never infer owner approval from an unsigned request or server data:
        // current head, owner SPKI/raw pins and grant all arrive independently.
        const delivery = JSON.parse(decoder.decode(await fileBytes("new-approval", 1, 400000)));
        if (!delivery || delivery.schema !== "rootark-zk1-v2-owner-browser-delivery/v1"
          || Object.keys(delivery).sort().join(",")
            !== "approval,committedReceipt,previousReceipt,request,schema,signedDeviceGrant,signedV2Manifest"
          || JSON.stringify(delivery.signedDeviceGrant) !== JSON.stringify(trust.signedDeviceGrant)) fail();
        const publicRaw = await fileBytes("device", 32, 32);
        const devicePublicKey = await crypto.subtle.importKey("raw", publicRaw,
          "Ed25519", true, ["verify"]);
        publicRaw.fill(0);
        privateDer = await fileBytes("private", 1, 8192);
        const devicePrivateKey = await crypto.subtle.importKey("pkcs8", privateDer,
          "Ed25519", false, ["sign"]);
        const witnessRaw = await fileBytes("witness-key", 32, 32);
        const witnessPublicKey = await crypto.subtle.importKey("raw", witnessRaw,
          "Ed25519", true, ["verify"]);
        witnessRaw.fill(0);
        const original = {
          request: delivery.request, approval: delivery.approval,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedOwnerKeyHash: trust.pinnedOwnerKeyHash,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          devicePublicKey, devicePrivateKey, nowSeconds: Math.floor(Date.now() / 1000),
          committedReceipt: delivery.committedReceipt, previousReceipt: delivery.previousReceipt,
          witnessPublicKey,
          independentWitnessSpkiSha256: from64(field("witness-spki").value.trim()),
          independentlyPinnedPreviousReceiptSha256: from64(field("witness-prior").value.trim()),
          signedV2Manifest: delivery.signedV2Manifest,
        };
        const result = await window.RootarkZk1V2CommittedApproval.verifyCommittedApproval(original);
        assertLive();
        if (result.committedOwnerApprovalVerified !== true
          || result.signedWitnessReceiptVerified !== true
          || result.previousReceiptHashPinned !== true
          || result.committedV2ManifestDigestMatched !== true
          || result.authorizesProductionIo !== false) fail();
        committedDeviceApproval = { proof: result, original, sessionEpoch };
        status("Prova V2/witness e grant vinculados ao pedido, chave nova e head atual. Provisione o piso offline antes do GET. Histórico completo V2 continua exigido pelo servidor.");
        return;
      }
      if (action === "pending-list") {
        if (!window.RootarkZk1RecoverablePendingJournal?.openStore) fail();
        const ids = await window.RootarkZk1RecoverablePendingJournal.openStore(indexedDB)
          .listPendingIds();
        assertLive();
        status(ids.length ? "IDs opacos preservados localmente (pendentes até GET): "
          + ids.join(", ") : "Sem pendências locais neste perfil. Não há consulta de nomes ao servidor.");
      } else if (action === "provision") {
        const result = await window.RootarkZk1NormalBrowserTrustFloor.provisionOffline({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        assertLive();
        status(result.initialProvision ? "Âncora offline provisionada neste navegador."
          : "Piso local verificado/avançado. Confira os pins atuais fora do servidor.");
      } else {
        const deviceRaw = await fileBytes("device", 32, 32);
        const devicePublicKey = await crypto.subtle.importKey("raw", deviceRaw, "Ed25519", true, ["verify"]);
        deviceRaw.fill(0);
        privateDer = await fileBytes("private", 1, 8192);
        const devicePrivateKey = await crypto.subtle.importKey("pkcs8", privateDer, "Ed25519", false, ["sign"]);
        const common = { ...trust, devicePublicKey, devicePrivateKey,
          origin: location.origin + "/", fetchImpl: guardedFetch,
          nowSeconds: Math.floor(Date.now() / 1000) };
        if (action === "migration-batch") {
          if (field("migration-batch-opt-in")?.checked !== true
            || !trust.ownerHistoryCheckpoint || trust.signedDeviceGrant.revoked_at_epoch !== null) fail();
          await window.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
            ownerPublicKey: trust.ownerPublicKey,
            independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
            pinnedCurrentHead: trust.pinnedCurrentHead,
            signedDeviceGrant: trust.signedDeviceGrant,
            ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
            previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
          });
          assertLive();
          const entries = await selectedLegacyBatch(assertLive);
          secret = await fileBytes("migration-batch-secret", 32, 32);
          assertLive();
          const journal = await window.RootarkZk1LegacyMigrationWorkflow.openMigrationJournal();
          try {
            assertLive();
            const result = await window.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch({
              optIn: true, entries, migrationSecret: secret,
              trust: { ...trust, devicePublicKey, devicePrivateKey },
              origin: location.origin + "/", fetchImpl: guardedFetch,
              journal, nowSeconds: Math.floor(Date.now() / 1000),
            });
            assertLive();
            if (result.canDeleteLegacy !== false || result.authorizesCutover !== false
              || result.total !== entries.length || result.results.length !== entries.length
              || result.results.some((entry) => entry.canDeleteLegacy !== false
                || entry.authorizesCutover !== false)) fail();
            const report = { schema: "rootark-zk1-legacy-version-batch-report/v1",
              ...result, requiresIndependentOwnerCheckpoint: true,
              productionAuthorized: false };
            downloadLocal("rootark-legacy-version-batch-report.json",
              JSON.stringify(report), "application/json", assertLive);
            status("Versões conferidas localmente: " + result.verified + "/" + result.total
              + ". Relatório baixado; cada falha exige revisão manual. Originais mantidos, sem exclusão/cutover e sem prova de durabilidade externa.");
          } finally { journal.close(); }
        } else if (action === "pending-resume") {
          if (!window.RootarkZk1RecoverablePendingJournal?.openStore) fail();
          const objectId = field("pending-object")?.value.trim();
          if (!/^[A-Za-z0-9_-]{22}$/.test(objectId)) fail();
          secret = await fileBytes("secret", 32, 32);
          const resumed = await window.RootarkZk1RecoverableWorkspace.resumePendingProtectedFile({
            ...common, recoverySecret: secret, objectId,
            journal: window.RootarkZk1RecoverablePendingJournal.openStore(indexedDB),
          });
          assertLive();
          if (!resumed.resumedSignedGetOnly || !resumed.clientReadbackVerified) fail();
          downloadLocal("rootark-recovery-" + objectId + ".json",
            JSON.stringify(resumed.bundle), "application/json", assertLive);
          status("GET histórico autenticado sem repetir PUT. Pacote recuperável exportado; "
            + "aguarde checkpoint histórico independente assinado pelo proprietário. "
            + "O diário cifrado local permanece como cópia pendente.");
        } else if (action === "restore") {
          if (!committedDeviceApproval || committedDeviceApproval.sessionEpoch !== sessionEpoch) fail();
          await window.RootarkZk1V2CommittedApproval.assertForRestore({
            proof: committedDeviceApproval.proof,
            original: committedDeviceApproval.original,
            trust, devicePublicKey,
          });
          assertLive();
          secret = await fileBytes("secret", 32, 32);
          const bundle = JSON.parse(decoder.decode(await fileBytes("bundle", 1, 6 * 1024 * 1024)));
          const checkpoint = await optionalJson("owner-root");
          if (!checkpoint || !trust.ownerHistoryCheckpoint) fail();
          const restored = await window.RootarkZk1RecoverableWorkspace.restoreOnNewDevice({
            ...common, recoverySecret: secret, bundle,
            expectedMetadata: bundle.metadata,
            independentlyPinnedCiphertextRoot: from64(field("root").value.trim()),
            ownerSignerKeyId: field("owner-signer").value.trim(),
            ownerDeviceId: field("owner-device").value.trim(),
            ownerRootCheckpoint: checkpoint,
            previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
          });
          try {
            downloadLocal(restored.name, restored.data, restored.mediaType || "application/octet-stream", assertLive);
            status("Arquivo histórico recuperado após novo grant + prova Ed25519 do proprietário + GET protegido. Nenhuma CEK/plaintext enviada ao servidor.");
          } finally { restored.data.fill(0); }
        } else if (action === "upload" || action === "upload-recoverable") {
          const selected = field("file").files[0];
          if (!selected || selected.size < 1 || selected.size > 2 * 1024 * 1024
            || selected.name.length > 255) fail();
          data = await fileBytes("file", 1, 2 * 1024 * 1024);
          const scope = trust.signedDeviceGrant;
          const metadata = { account_id: scope.account_id, compartment_id: scope.compartment_id,
            keyring_id: scope.keyring_id, object_id: randomId(), version_id: randomId(),
            parent_version_id: null, epoch: trust.pinnedCurrentHead.epoch, kind: "file" };
          if (action === "upload-recoverable") {
            secret = await fileBytes("secret", 32, 32);
            const result = await window.RootarkZk1RecoverableWorkspace.createRecoverableProtectedFile({
              ...common, recoverySecret: secret, metadata,
              name: selected.name, mediaType: selected.type || "", data,
              journal: window.RootarkZk1RecoverablePendingJournal.openStore(indexedDB),
            });
            downloadLocal("rootark-recovery-" + result.objectId + ".json",
              JSON.stringify(result.bundle), "application/json", assertLive);
            status("Pacote recuperável exportado após PUT/GET. "
              + (result.lostPutAckReconciled ? "ACK do PUT perdido, resolvido por GET assinado. " : "")
              + "Guarde-o fora do servidor e solicite ao proprietário checkpoint histórico assinado para o root "
              + result.ciphertextRoot + ". O segredo de 32 bytes deve permanecer separado.");
          } else {
            const result = await window.RootarkZk1NormalBrowserContent.uploadAndVerify({
              ...common, metadata, fileName: selected.name, mediaType: selected.type || "", data,
            });
            assertLive();
            status("PUT/GET protegidos verificados: " + result.objectId
              + " · root " + result.ciphertextRoot
              + (result.lostPutAckReconciled ? " · ACK perdido reconciliado" : "")
              + ". CEK efêmera: este arquivo não é recuperável após fechar a sessão.");
          }
        } else if (action === "migrate" || action === "migration-finalize") {
          if (field("migration-opt-in")?.checked !== true) fail();
          const rawCek = await fileBytes("migration-cek", 32, 32);
          let cek;
          try { cek = await window.RootarkZk1FileContent.importFileCek(rawCek); }
          finally { rawCek.fill(0); }
          const objectInput = field("migration-object");
          const versionInput = field("migration-version");
          // Set opaque IDs BEFORE network I/O so ambiguous outcomes can be
          // resumed with the same ciphertext journal and externally held CEK.
          if (action === "migrate" && !objectInput.value) objectInput.value = randomId();
          if (action === "migrate" && !versionInput.value) versionInput.value = randomId();
          if (!/^[A-Za-z0-9_-]{22}$/.test(objectInput.value)
            || !/^[A-Za-z0-9_-]{22}$/.test(versionInput.value)) fail();
          const scope = trust.signedDeviceGrant;
          const migrationOptions = {
            optIn: true,
            legacy: { name: field("legacy-name").value, folderId: field("legacy-folder").value },
            metadata: {
              account_id: scope.account_id, compartment_id: scope.compartment_id,
              keyring_id: scope.keyring_id, object_id: objectInput.value,
              version_id: versionInput.value, parent_version_id: null,
              epoch: trust.pinnedCurrentHead.epoch, kind: "file",
            },
            trust: { ...trust, devicePublicKey, devicePrivateKey },
            cek, origin: location.origin + "/", fetchImpl: guardedFetch,
            nowSeconds: Math.floor(Date.now() / 1000),
          };
          const journal = await window.RootarkZk1LegacyMigrationWorkflow.openMigrationJournal();
          try {
            const workflow = window.RootarkZk1LegacyMigrationWorkflow;
            const result = action === "migrate"
              ? await workflow.beginLegacyMigration({ ...migrationOptions, journal })
              : await workflow.finalizeLegacyMigration({ ...migrationOptions, journal,
                signedRootCheckpoint: JSON.parse(decoder.decode(
                  await fileBytes("migration-proof", 1, 8192))) });
            assertLive();
            status("Objeto " + result.objectId + " · versão " + versionInput.value
              + " · root " + result.root + ". "
              + (action === "migrate" ? "GET conferido; importe checkpoint externo assinado."
                : "Checkpoint assinado e GET conferidos localmente.")
              + " Original preservado, corte e exclusão proibidos.");
          } finally { journal.close(); }
        }
      }
    } catch (_) {
      status("Operação recusada: autoridade, permissão, sessão ou ciphertext não verificado.");
    } finally {
      privateDer?.fill(0);
      data?.fill(0);
      secret?.fill(0);
      ownerSigningDer?.fill(0);
      for (const item of archiveFiles || []) item.data.fill(0);
      for (const item of accountFiles.plaintext) item.fill(0);
      for (const item of accountFiles.secrets) item.fill(0);
      for (const item of accountFiles.privates) item.fill(0);
      if (Array.isArray(accountRecovered?.keyrings)) {
        for (const ring of accountRecovered.keyrings) {
          if (Array.isArray(ring?.files)) for (const file of ring.files) {
            if (file?.data instanceof Uint8Array) file.data.fill(0);
          }
        }
      }
      // The original File/Blob remains held by the input until explicitly reset.
      for (const name of ["private", "hpke-private", "pop-challenge", "new-approval", "file", "secret", "bundle", "migration-cek", "migration-proof",
        "catalog-cas-key", "catalog-signer-grant", "catalog-metadata-key",
        "catalog-lifecycle-history", "catalog-lifecycle-ceks",
        "catalog-write-ciphertext", "catalog-write-key", "catalog-witness-key",
        "catalog-delta-package",
        "migration-batch-descriptors", "migration-batch-ceks", "migration-batch-secret",
        "archive-files", "archive-owner-private", "archive-json", "archive-historical-proof",
        "account-descriptors", "account-holder-files", "account-local-files",
        "account-historical-device-privates",
        "account-owner-private", "account-archive",
        "v2-snapshot", "v2-roster", "v2-inventory-signer", "v2-versions",
        "revoke-delivery", "revoke-pins", "revoke-owner-spki", "revoke-witness-spki", "revoke-cas-spki"]) {
        const control = field(name);
        if (control) control.value = "";
      }
      busy = false;
      dialog.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    }
  }
  function showEntry() {
    const target = document.getElementById("protectedClientStatus");
    if (!target || !capability || document.getElementById("zk1-workspace-open")) return;
    const panel = target.closest(".protected-client-panel");
    if (!panel) return;
    const button = document.createElement("button");
    button.type = "button";
    button.id = "zk1-workspace-open";
    button.className = "button button-quiet";
    button.textContent = "Arquivo zk-1 (desenvolvimento)";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        if (!supportsOwnerRootedV2(await api.get("/zk-1/v1/workspace-capability"))) fail();
        createDialog().showModal();
      } catch (_) { capability = false; button.remove(); }
      finally { button.disabled = false; }
    });
    panel.append(button);
  }
  window.addEventListener("rootark:workspace-rendered", () => {
    if (capability === true) return showEntry();
    if (capability === false || checking || !document.getElementById("protectedClientStatus")) return;
    checking = true;
    api.get("/zk-1/v1/workspace-capability").then((result) => {
      capability = supportsOwnerRootedV2(result);
      showEntry();
    }).catch(() => { capability = false; }).finally(() => { checking = false; });
  });
  window.addEventListener("rootark:logout", () => {
    sessionEpoch++;
    verifiedCatalog = null;
    verifiedOpaqueDelta = null;
    const deltaSummary = field("catalog-delta-summary");
    if (deltaSummary) deltaSummary.textContent = "";
    const privateList = field("catalog-delta-private-list");
    if (privateList) privateList.replaceChildren();
    const journal = field("catalog-write-journal");
    if (journal) journal.textContent = "";
    for (const url of activeDownloadUrls) URL.revokeObjectURL(url);
    activeDownloadUrls.clear();
    committedDeviceApproval = null;
    verifiedRevocationHead = null;
    window.RootarkZk1V2OwnerRevocationBrowser?.clear();
    capability = false;
    if (dialog?.open) dialog.close();
    dialog?.querySelector("form")?.reset();
  });
}());
