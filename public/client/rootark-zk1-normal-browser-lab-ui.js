(function (root) {
  "use strict";
  const byId = (id) => document.getElementById(id);
  const button = byId("upload");
  const provision = byId("provision-owner");
  const status = byId("status");
  const base64 = /^[A-Za-z0-9_-]{43}$/;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  function fail() { throw new Error("Entrada local ou autoridade indisponível"); }
  function bytesFrom64(value) {
    if (typeof value !== "string" || !base64.test(value)) fail();
    let raw;
    try {
      raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=");
    } catch (_) { fail(); }
    const result = Uint8Array.from(raw, (char) => char.charCodeAt(0));
    if (result.length !== 32) fail();
    return result;
  }
  function number(id) {
    const raw = byId(id).value;
    if (!/^[1-9][0-9]*$/.test(raw)) fail();
    const n = Number(raw);
    if (!Number.isSafeInteger(n)) fail();
    return n;
  }
  async function fileBytes(id, limit) {
    const field = byId(id);
    if (!field?.files || field.files.length !== 1) fail();
    const source = field.files[0];
    if (source.size < 1 || source.size > limit) fail();
    const bytes = new Uint8Array(await source.arrayBuffer());
    if (bytes.length !== source.size) fail();
    return bytes;
  }
  function randomId() {
    let binary = "";
    for (const v of root.crypto.getRandomValues(new Uint8Array(16))) {
      binary += String.fromCharCode(v);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  async function trustInputs() {
    if (!root.isSecureContext || !root.crypto?.subtle
      || !root.RootarkZk1NormalBrowserTrustFloor) fail();
    const ownerRaw = await fileBytes("owner-key", 32);
    const ownerPublicKey = await root.crypto.subtle.importKey("raw", ownerRaw,
      "Ed25519", true, ["verify"]);
    const signedDeviceGrant = JSON.parse(decoder.decode(await fileBytes("device-grant", 8192)));
    const checkpointFiles = byId("owner-history").files;
    if (checkpointFiles.length > 1) fail();
    const ownerHistoryCheckpoint = checkpointFiles.length === 1
      ? JSON.parse(decoder.decode(await fileBytes("owner-history", 8192))) : null;
    return { ownerPublicKey,
      independentOwnerSpkiSha256: bytesFrom64(byId("owner-spki-hash").value.trim()),
      pinnedCurrentHead: { revision: number("head-revision"),
        digest: bytesFrom64(byId("head-digest").value.trim()),
        epoch: number("head-epoch") }, signedDeviceGrant, ownerHistoryCheckpoint };
  }
  provision.addEventListener("click", async () => {
    provision.disabled = true;
    button.disabled = true;
    status.textContent = "Verificando a âncora externa e a assinatura do proprietário…";
    try {
      const trust = await trustInputs();
      const result = await root.RootarkZk1NormalBrowserTrustFloor.provisionOffline(trust);
      status.textContent = (result.initialProvision ? "Âncora local criada" : "Piso local conferido ou avançado")
        + ". Assinatura do proprietário e SPKI conferidos. Preserve o pin e o head atual fora do servidor.";
    } catch (_) {
      status.textContent = "Provisionamento recusado: assinatura, fingerprint, revisão, época ou armazenamento inválido.";
    } finally { provision.disabled = false; button.disabled = false; }
  });
  button.addEventListener("click", async () => {
    button.disabled = true;
    status.textContent = "Verificando assinatura, pins e chave local…";
    let privateDer;
    let data;
    try {
      if (!root.RootarkZk1NormalBrowserContent) fail();
      const trust = await trustInputs();
      const deviceRaw = await fileBytes("device-public", 32);
      privateDer = await fileBytes("device-private", 8192);
      const devicePublicKey = await root.crypto.subtle.importKey("raw", deviceRaw,
        "Ed25519", true, ["verify"]);
      const devicePrivateKey = await root.crypto.subtle.importKey("pkcs8", privateDer,
        "Ed25519", false, ["sign"]);
      const grant = trust.signedDeviceGrant;
      const selected = byId("file").files?.[0];
      if (!selected || selected.size > 2 * 1024 * 1024
        || selected.name.length > 255) fail();
      data = new Uint8Array(await selected.arrayBuffer());
      const objectId = randomId();
      const result = await root.RootarkZk1NormalBrowserContent.uploadAndVerify({
        ...trust,
        pinnedOwnerKeyHash: bytesFrom64(byId("owner-hash").value.trim()),
        devicePublicKey, devicePrivateKey,
        metadata: {
          account_id: grant.account_id, compartment_id: grant.compartment_id,
          keyring_id: grant.keyring_id, object_id: objectId,
          version_id: randomId(), parent_version_id: null,
          epoch: number("head-epoch"), kind: "file",
        },
        fileName: selected.name, mediaType: selected.type || "",
        data, origin: root.location.origin + "/",
        fetchImpl: root.fetch.bind(root),
        nowSeconds: Math.floor(Date.now() / 1000),
      });
      status.textContent = "Ciphertext conferido: ID " + result.objectId
        + " · root " + result.ciphertextRoot
        + (result.lostPutAckReconciled ? " · ACK perdido, GET verificado" : "")
        + " · sem chave persistente ou garantia de durabilidade externa";
    } catch (_) {
      status.textContent = "Operação recusada: pin, assinatura, permissão, servidor ou GET inválido.";
    } finally {
      privateDer?.fill(0);
      data?.fill(0);
      // A File input retains the original PKCS#8/plaintext Blob even after
      // our array copies are zeroed. Release those selections on every path.
      byId("device-private").value = "";
      byId("file").value = "";
      button.disabled = false;
    }
  });
}(typeof globalThis === "object" ? globalThis : this));
