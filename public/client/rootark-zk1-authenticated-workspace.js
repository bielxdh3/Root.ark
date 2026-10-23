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
    "rootark-zk1-portable-file-recovery", "rootark-zk1-browser-recovery-http",
    "rootark-zk1-recoverable-workspace",
    "rootark-dev-vault-migration", "rootark-zk1-legacy-transition-receipt",
    "rootark-zk1-legacy-migration-workflow",
    "rootark-zk1-legacy-batch-migration",
    "rootark-zk1-v2-device-approval", "rootark-zk1-v2-browser-pop",
    "rootark-zk1-v2-committed-approval",
    "rootark-zk1-keyring-portable-archive",
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
    return {
      ownerPublicKey,
      pinnedOwnerKeyHash: from64(field("owner-hash").value.trim()),
      independentOwnerSpkiSha256: from64(field("owner-spki").value.trim()),
      pinnedCurrentHead: {
        revision: positive("revision"),
        digest: from64(field("digest").value.trim()),
        epoch: positive("epoch"),
      },
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
      + '<button type="button" class="button button-primary" data-zk1-action="restore">Recuperar arquivo do novo dispositivo</button></div>'
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
      dialog.close();
      dialog.querySelector("form").reset();
      status("Nenhuma autoridade foi importada.");
      return;
    }
    if (!["provision", "verify-inventory", "upload", "upload-recoverable",
      "restore", "new-secret", "new-device", "answer-pop", "import-approval",
      "migrate", "migration-finalize", "migration-batch", "archive-create", "archive-recover",
      "account-create", "account-recover"].includes(action)) return;
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
      if (action === "provision") {
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
            });
            downloadLocal("rootark-recovery-" + result.objectId + ".json",
              JSON.stringify(result.bundle), "application/json", assertLive);
            status("Pacote recuperável exportado após PUT/GET. Guarde-o fora do servidor e solicite ao proprietário checkpoint histórico assinado para o root "
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
        "migration-batch-descriptors", "migration-batch-ceks", "migration-batch-secret",
        "archive-files", "archive-owner-private", "archive-json", "archive-historical-proof",
        "account-descriptors", "account-holder-files", "account-local-files",
        "account-historical-device-privates",
        "account-owner-private", "account-archive"]) {
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
    for (const url of activeDownloadUrls) URL.revokeObjectURL(url);
    activeDownloadUrls.clear();
    committedDeviceApproval = null;
    capability = false;
    if (dialog?.open) dialog.close();
    dialog?.querySelector("form")?.reset();
  });
}());
