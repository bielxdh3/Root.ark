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
    "rootark-zk1-protected-http-client", "rootark-zk1-uncertain-put-reconciliation",
    "rootark-zk1-normal-browser-trust-floor", "rootark-zk1-normal-browser-content",
  ];
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const base64 = /^[A-Za-z0-9_-]{43}$/;
  let capability = null;
  let checking = false;
  let loadingScripts = null;
  let busy = false;
  let dialog = null;

  function fail() { throw new Error("ZK_WORKSPACE_INPUT_DENIED"); }
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
        || !window.RootarkZk1NormalBrowserTrustFloor?.provisionOffline) fail();
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
      + '<label>Chave pública do dispositivo (Ed25519 raw)<input type="file" data-zk1-field="device" required></label>'
      + '<label>Chave privada do dispositivo (PKCS#8, local)<input type="file" data-zk1-field="private" required></label>'
      + '<label>Arquivo descartável (até 2 MiB)<input type="file" data-zk1-field="file" required></label>'
      + '<div class="zk1-workspace-actions"><button type="button" class="button button-quiet" data-zk1-action="provision">Provisionar piso offline</button>'
      + '<button type="button" class="button button-primary" data-zk1-action="upload">Cifrar, enviar e conferir GET</button></div>'
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
      dialog.close();
      dialog.querySelector("form").reset();
      status("Nenhuma autoridade foi importada.");
      return;
    }
    if (action !== "provision" && action !== "upload") return;
    busy = true;
    dialog.querySelectorAll("button").forEach((button) => { button.disabled = true; });
    status("Validando pins externos, assinatura do proprietário e dispositivo…");
    let privateDer;
    let data;
    try {
      await ensureScripts();
      // Capability is checked again before every user-initiated operation.
      const available = await api.get("/zk-1/v1/workspace-capability");
      if (available?.enabled !== true) fail();
      const trust = await grantAndOwner();
      if (action === "provision") {
        const result = await window.RootarkZk1NormalBrowserTrustFloor.provisionOffline({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        status(result.initialProvision ? "Âncora offline provisionada neste navegador."
          : "Piso local verificado/avançado. Confira os pins atuais fora do servidor.");
      } else {
        const deviceRaw = await fileBytes("device", 32, 32);
        const devicePublicKey = await crypto.subtle.importKey("raw", deviceRaw, "Ed25519", true, ["verify"]);
        deviceRaw.fill(0);
        privateDer = await fileBytes("private", 1, 8192);
        const devicePrivateKey = await crypto.subtle.importKey("pkcs8", privateDer, "Ed25519", false, ["sign"]);
        const selected = field("file").files[0];
        if (!selected || selected.size < 1 || selected.size > 2 * 1024 * 1024
          || selected.name.length > 255) fail();
        data = await fileBytes("file", 1, 2 * 1024 * 1024);
        const scope = trust.signedDeviceGrant;
        const result = await window.RootarkZk1NormalBrowserContent.uploadAndVerify({
          ...trust, devicePublicKey, devicePrivateKey,
          metadata: {
            account_id: scope.account_id, compartment_id: scope.compartment_id,
            keyring_id: scope.keyring_id, object_id: randomId(),
            version_id: randomId(), parent_version_id: null,
            epoch: trust.pinnedCurrentHead.epoch, kind: "file",
          },
          fileName: selected.name, mediaType: selected.type || "", data,
          origin: location.origin + "/", fetchImpl: sessionFetch,
          nowSeconds: Math.floor(Date.now() / 1000),
        });
        status("PUT/GET protegidos verificados: " + result.objectId
          + " · root " + result.ciphertextRoot
          + (result.lostPutAckReconciled ? " · ACK perdido reconciliado" : "")
          + ". CEK efêmera: este arquivo não é recuperável após fechar a sessão.");
      }
    } catch (_) {
      status("Operação recusada: autoridade, permissão, sessão ou ciphertext não verificado.");
    } finally {
      privateDer?.fill(0);
      data?.fill(0);
      // The original File/Blob remains held by the input until explicitly reset.
      for (const name of ["private", "file"]) {
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
        if ((await api.get("/zk-1/v1/workspace-capability"))?.enabled !== true) fail();
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
      capability = result?.enabled === true;
      showEntry();
    }).catch(() => { capability = false; }).finally(() => { checking = false; });
  });
  window.addEventListener("rootark:logout", () => {
    capability = false;
    if (dialog?.open) dialog.close();
    dialog?.querySelector("form")?.reset();
  });
}());
