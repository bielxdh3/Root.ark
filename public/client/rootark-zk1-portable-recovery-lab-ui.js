(function (root) {
  "use strict";
  // Development-only, explicitly opt-in file recovery laboratory. An
  // independently held 32-byte random secret is NOT a password or account key.
  const find = (id) => document.getElementById(id);
  const status = find("status");
  const generate = find("portable-generate-secret");
  const publish = find("portable-publish");
  const restore = find("portable-restore");
  const re64 = /^[A-Za-z0-9_-]{43}$/;
  const text = new TextDecoder("utf-8", { fatal: true });
  const maxFile = 2 * 1024 * 1024;
  let pageEpoch = 0;
  root.addEventListener("pagehide", () => { pageEpoch++; });
  function deny() { throw new Error("PORTABLE_RECOVERY_INPUT_INVALID"); }
  function decode64(value) {
    if (typeof value !== "string" || !re64.test(value)) deny();
    let content;
    try { content = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "="); }
    catch (_) { deny(); }
    const bytes = Uint8Array.from(content, (part) => part.charCodeAt(0));
    if (bytes.length !== 32) deny();
    return bytes;
  }
  function decodeSignerKeyId(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) deny();
    let content;
    try { content = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=="); }
    catch (_) { deny(); }
    const bytes = Uint8Array.from(content, (part) => part.charCodeAt(0));
    let roundtrip = "";
    for (const byte of bytes) roundtrip += String.fromCharCode(byte);
    if (bytes.length !== 16 || btoa(roundtrip).replace(/\+/g, "-")
      .replace(/\//g, "_").replace(/=+$/g, "") !== value) deny();
    return bytes;
  }
  function randomId() {
    const source = root.crypto.getRandomValues(new Uint8Array(16));
    let raw = "";
    for (const value of source) raw += String.fromCharCode(value);
    source.fill(0);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function count(id) {
    const value = find(id).value;
    if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) deny();
    return Number(value);
  }
  async function fileBytes(id, minimum, maximum) {
    const selection = find(id)?.files;
    if (!selection || selection.length !== 1
      || selection[0].size < minimum || selection[0].size > maximum) deny();
    return new Uint8Array(await selection[0].arrayBuffer());
  }
  function download(name, data, type) {
    const blob = new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    try {
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.rel = "noopener";
      link.click();
    } finally {
      // The URL must persist until the browser has begun processing the click.
      // RequestAnimationFrame is used rather than retaining file bytes in DOM.
      requestAnimationFrame(() => URL.revokeObjectURL(url));
    }
  }
  async function context() {
    if (!root.isSecureContext || !root.crypto?.subtle
      || !root.RootarkZk1PortableFileRecovery
      || !root.RootarkZk1BrowserRecoveryHttp
      || !root.RootarkZk1NormalBrowserContent
      || !root.RootarkZk1NormalBrowserTrustFloor
      || !root.RootarkZk1ProtectedHttpClient) deny();
    const ownerRaw = await fileBytes("owner-key", 32, 32);
    const deviceRaw = await fileBytes("device-public", 32, 32);
    const privateDer = await fileBytes("device-private", 32, 8192);
    try {
      const ownerPublicKey = await root.crypto.subtle.importKey(
        "raw", ownerRaw, "Ed25519", true, ["verify"]);
      const devicePublicKey = await root.crypto.subtle.importKey(
        "raw", deviceRaw, "Ed25519", true, ["verify"]);
      const devicePrivateKey = await root.crypto.subtle.importKey(
        "pkcs8", privateDer, "Ed25519", false, ["sign"]);
      const grant = JSON.parse(text.decode(await fileBytes("device-grant", 1, 8192)));
      let ownerHistoryCheckpoint = null;
      let previousOwnerHistoryProof = null;
      if (find("owner-history").files.length === 1) {
        const imported = JSON.parse(text.decode(await fileBytes("owner-history", 1, 262144)));
        // A portable JSON chain can be imported on a genuinely NEW device:
        // private WeakMap proofs cannot be serialized, so verify genesis ->
        // current in this browser session before using the final signed head.
        const chain = Array.isArray(imported) ? imported : [imported];
        if (chain.length < 1 || chain.length > 64
          || !root.RootarkZk1OwnerSignedCheckpoint?.verifyOwnerCheckpoint) deny();
        let prior = null;
        for (let index = 0; index < chain.length; index++) {
          const current = chain[index];
          if (index === chain.length - 1) {
            ownerHistoryCheckpoint = current;
            previousOwnerHistoryProof = prior;
          }
          prior = await root.RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
            checkpoint: current,
            scope: { account_id: grant.account_id, compartment_id: grant.compartment_id,
              keyring_id: grant.keyring_id },
            signerPublicKey: ownerPublicKey,
            signerKeyId: decodeSignerKeyId(current.signer_key_id), previous: prior,
          });
        }
      }
      return {
        ownerPublicKey,
        pinnedOwnerKeyHash: decode64(find("owner-hash").value.trim()),
        independentOwnerSpkiSha256: decode64(find("owner-spki-hash").value.trim()),
        pinnedCurrentHead: { revision: count("head-revision"),
          digest: decode64(find("head-digest").value.trim()), epoch: count("head-epoch") },
        signedDeviceGrant: grant, ownerHistoryCheckpoint,
        previousOwnerHistoryProof,
        devicePublicKey, devicePrivateKey,
        origin: root.location.origin + "/", fetchImpl: root.fetch.bind(root),
        nowSeconds: Math.floor(Date.now() / 1000),
      };
    } finally { privateDer.fill(0); ownerRaw.fill(0); deviceRaw.fill(0); }
  }
  async function beforeNetwork(ctx, metadata) {
    if (metadata.epoch !== ctx.pinnedCurrentHead.epoch
      || ["account_id", "compartment_id", "keyring_id"]
        .some((name) => metadata[name] !== ctx.signedDeviceGrant[name])) deny();
    await root.RootarkZk1NormalBrowserContent.verifyOwnerGrant({
      ownerPublicKey: ctx.ownerPublicKey,
      pinnedOwnerKeyHash: ctx.pinnedOwnerKeyHash,
      pinnedCurrentHead: ctx.pinnedCurrentHead,
      signedDeviceGrant: ctx.signedDeviceGrant,
      devicePublicKey: ctx.devicePublicKey,
      devicePrivateKey: ctx.devicePrivateKey,
    });
    await root.RootarkZk1NormalBrowserTrustFloor.assertCurrent({
      ownerPublicKey: ctx.ownerPublicKey,
      independentOwnerSpkiSha256: ctx.independentOwnerSpkiSha256,
      pinnedCurrentHead: ctx.pinnedCurrentHead,
      signedDeviceGrant: ctx.signedDeviceGrant,
      ownerHistoryCheckpoint: ctx.ownerHistoryCheckpoint,
      previousOwnerHistoryProof: ctx.previousOwnerHistoryProof,
    });
  }
  function signer(ctx) {
    return { signerKey: ctx.devicePrivateKey,
      scope: Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
        .map((key) => [key, ctx.signedDeviceGrant[key]])),
      deviceId: ctx.signedDeviceGrant.device_id,
      manifestRevision: ctx.pinnedCurrentHead.revision,
      manifestDigest: ctx.pinnedCurrentHead.digest,
      epoch: ctx.pinnedCurrentHead.epoch, nowSeconds: ctx.nowSeconds };
  }
  function cleanupInputs() {
    for (const id of ["portable-secret", "device-private", "file", "portable-bundle",
      "portable-owner-root", "portable-chunk-inventory", "portable-chunks"])
      find(id).value = "";
  }
  async function withBusy(action) {
    for (const item of [generate, publish, restore]) item.disabled = true;
    try { await action(); }
    catch (error) {
      status.textContent = error?.message === "ZK_BROWSER_RECOVERY_EXTERNAL_TRUST_REQUIRED"
        ? "Recuperação local recusada: faltam pins externos independentes, histórico assinado ou inventário/chunks locais. Não confie em pins do servidor."
        : "Operação portátil recusada: autoridade, arquivo, rede ou chave inválida.";
    }
    finally {
      cleanupInputs();
      for (const item of [generate, publish, restore]) item.disabled = false;
    }
  }
  generate.addEventListener("click", () => withBusy(async () => {
    const secret = root.RootarkZk1PortableFileRecovery.generateRecoverySecret();
    try {
      download("rootark-zk1-secret-32bytes.bin", secret, "application/octet-stream");
      status.textContent = "Segredo aleatório gerado. Salve em local independente do pacote e do servidor.";
    } finally { secret.fill(0); }
  }));
  publish.addEventListener("click", () => withBusy(async () => {
    let secret, plain, opened;
    try {
      const ctx = await context();
      secret = await fileBytes("portable-secret", 32, 32);
      const selection = find("file").files?.[0];
      if (!selection || selection.size > maxFile || !selection.name
        || selection.name.length > 255) deny();
      plain = new Uint8Array(await selection.arrayBuffer());
      const metadata = {
        account_id: ctx.signedDeviceGrant.account_id,
        compartment_id: ctx.signedDeviceGrant.compartment_id,
        keyring_id: ctx.signedDeviceGrant.keyring_id,
        object_id: randomId(), version_id: randomId(), parent_version_id: null,
        epoch: ctx.pinnedCurrentHead.epoch, kind: "file",
      };
      await beforeNetwork(ctx, metadata);
      const bundle = await root.RootarkZk1PortableFileRecovery.sealForUserHeldSecret({
        recoverySecret: secret, metadata,
        name: selection.name, mediaType: selection.type || "", data: plain,
      });
      const binary = atob(bundle.ciphertextBase64.replace(/-/g, "+")
        .replace(/_/g, "/").padEnd(Math.ceil(bundle.ciphertextBase64.length / 4) * 4, "="));
      const ciphertext = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      const http = root.RootarkZk1ProtectedHttpClient;
      const signed = await http.signProtectedContentOperation({
        ...signer(ctx), operation: "put", objectId: metadata.object_id,
        expectedObjectRevision: null, ciphertext,
      });
      try {
        await http.postProtectedCiphertextPut({
          origin: ctx.origin, request: signed, fetchImpl: ctx.fetchImpl,
        });
      } catch (_) {
        // A lost ACK may follow a durable commit; verify exact historical
        // readback instead of retrying a create-only PUT.
      }
      opened = await root.RootarkZk1BrowserRecoveryHttp.recoverFromProtectedGet({
        ...ctx, recoverySecret: secret, bundle, expectedMetadata: metadata,
        independentlyPinnedCiphertextRoot: decode64(bundle.ciphertextRoot),
      });
      if (opened.data.length !== plain.length
        || opened.data.some((byte, index) => byte !== plain[index])) deny();
      download("rootark-zk1-" + metadata.object_id + ".json",
        JSON.stringify(bundle), "application/json");
      find("portable-root").value = bundle.ciphertextRoot;
      status.textContent = "Ciphertext enviado e GET autenticado. Pacote cifrado salvo; root "
        + bundle.ciphertextRoot
        + ". Conserve a raiz de forma independente e valide com a assinatura do proprietário.";
    } finally { secret?.fill(0); plain?.fill(0); opened?.data?.fill(0); }
  }));
  restore.addEventListener("click", () => withBusy(async () => {
    let secret, opened;
    try {
      const offline = find("portable-offline-opt-in")?.checked === true;
      if (offline && (!find("owner-key")?.files?.length
        || !find("owner-spki-hash")?.value.trim()
        || !find("owner-hash")?.value.trim()
        || !find("head-digest")?.value.trim()
        || !find("head-revision")?.value.trim()
        || !find("head-epoch")?.value.trim()
        || !find("portable-root")?.value.trim()
        || !find("portable-source-chunk-root")?.value.trim()
        || !find("owner-history")?.files?.length
        || !find("portable-owner-root")?.files?.length
        || !find("portable-chunk-inventory")?.files?.length
        || !find("portable-chunks")?.files?.length)) {
        throw new Error("ZK_BROWSER_RECOVERY_EXTERNAL_TRUST_REQUIRED");
      }
      const ctx = await context();
      secret = await fileBytes("portable-secret", 32, 32);
      const bundle = JSON.parse(text.decode(
        await fileBytes("portable-bundle", 1, 6 * 1024 * 1024)));
      const ownerRootCheckpoint = JSON.parse(text.decode(
        await fileBytes("portable-owner-root", 1, 8192)));
      if (!ctx.ownerHistoryCheckpoint) deny();
      // The root is supplied separately. Do not fill it from bundle contents.
      const independentlyPinnedCiphertextRoot =
        decode64(find("portable-root").value.trim());
      if (offline) {
        // Source chunks need their own externally retained native root.
        // Never derive this trust pin from the inventory, bundle, or server.
        const independentlyPinnedSourceChunkRoot =
          decode64(find("portable-source-chunk-root").value.trim());
        if (independentlyPinnedSourceChunkRoot.length !== 32) deny();
        const inventory = JSON.parse(text.decode(
          await fileBytes("portable-chunk-inventory", 2, 16384)));
        const chunks = Array.from(find("portable-chunks").files || []);
        if (!root.RootarkZk1PersistedPortableChunkRecovery
          || !Array.isArray(inventory.chunkLengths)
          || inventory.chunkLengths.length < 1 || inventory.chunkLengths.length > 16
          || chunks.length !== inventory.chunkLengths.length) deny();
        const started = pageEpoch;
        const assertLive = () => {
          if (started !== pageEpoch || !root.isSecureContext) deny();
        };
        await beforeNetwork(ctx, bundle.metadata);
        opened = await root.RootarkZk1BrowserRecoveryHttp.recoverFromOwnerSignedPersistedChunks({
          ownerPublicKey: ctx.ownerPublicKey,
          pinnedOwnerKeyHash: ctx.pinnedOwnerKeyHash,
          independentOwnerSpkiSha256: ctx.independentOwnerSpkiSha256,
          pinnedCurrentHead: ctx.pinnedCurrentHead,
          signedDeviceGrant: ctx.signedDeviceGrant,
          devicePublicKey: ctx.devicePublicKey,
          devicePrivateKey: ctx.devicePrivateKey,
          ownerHistoryCheckpoint: ctx.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: ctx.previousOwnerHistoryProof,
          recoverySecret: secret, bundle,
          expectedMetadata: bundle.metadata, independentlyPinnedCiphertextRoot,
          independentlyPinnedSourceChunkRoot,
          ownerRootCheckpoint,
          ownerSignerKeyId: ownerRootCheckpoint.signer_key_id,
          ownerDeviceId: ownerRootCheckpoint.device_id,
          signedInventory: inventory,
          readChunk: async ({ index }) => {
            assertLive();
            if (!Number.isSafeInteger(index) || index < 0 || index >= chunks.length
              || chunks[index].size !== inventory.chunkLengths[index]
              || chunks[index].size > 1024 * 1024) deny();
            return new Uint8Array(await chunks[index].arrayBuffer());
          },
          assertLive,
        });
      } else {
        // Existing authenticated GET path is unchanged when opt-in is OFF.
        opened = await root.RootarkZk1BrowserRecoveryHttp.recoverFromOwnerSignedProtectedGet({
          ...ctx, recoverySecret: secret, bundle,
          expectedMetadata: bundle.metadata, independentlyPinnedCiphertextRoot,
          ownerRootCheckpoint,
          ownerSignerKeyId: ownerRootCheckpoint.signer_key_id,
          ownerDeviceId: ownerRootCheckpoint.device_id,
          previousOwnerHistoryProof: ctx.previousOwnerHistoryProof,
        });
      }
      download(opened.name, opened.data, opened.mediaType || "application/octet-stream");
      status.textContent = offline
        ? "Recuperação local concluída: assinatura do proprietário e todos os chunks verificados; nenhuma requisição GET ao servidor. Sem prova de witness remoto/durabilidade."
        : "GET protegido, assinatura da raiz do proprietário e abertura local concluídos. Nenhuma CEK foi enviada ao servidor.";
    } finally { secret?.fill(0); opened?.data?.fill(0); }
  }));
}(typeof globalThis === "object" ? globalThis : this));
