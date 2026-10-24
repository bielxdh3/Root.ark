(function () {
  "use strict";
  // Experimental web-first encrypted transfer. No plaintext is submitted by
  // this page. Device-local CryptoKeys are non-extractable WebCrypto handles.
  const api = window.RootarkApi;
  const cryptoFile = window.RootarkDevVaultCrypto;
  const migration = window.RootarkDevVaultMigration;
  const emergency = window.RootarkDevVaultEmergency;
  const trustedDevice = window.RootarkDevVaultTrustedDevice;
  const $ = (id) => document.getElementById(id);
  const state = { username: null, key: null, keyId: null, busy: false, lockGeneration: 0 };
  const path = "/zk-dev/v1";
  const status = (message) => { $("status").textContent = message; };
  function clearEmergencySecrets() {
    $("emergency-password").value = "";
    $("emergency-recovery-key").value = "";
    $("emergency-file").value = "";
    $("device-request-file").value = "";
    $("device-response-file").value = "";
    $("device-confirm-code").value = "";
  }
  function invalidateLocalKey() {
    state.lockGeneration += 1;
    state.key = null;
    state.keyId = null;
    clearEmergencySecrets();
  }
  function assertNotRelocked(generation) {
    if (generation !== state.lockGeneration || !state.username) {
      const error = new Error("Local vault lock cancelled pending operation");
      error.code = "DEV_VAULT_CANCELLED";
      throw error;
    }
  }
  function lockForAccountChange() {
    invalidateLocalKey();
    state.username = null;
    $("recovery").value = "";
    $("recovery").type = "password";
    $("file").value = "";
    $("objects").replaceChildren();
    $("device-request-code").textContent = "Nenhuma solicitação pendente";
    $("account").textContent = "A conta ativa mudou. Recarregue esta página.";
  }
  const report = (error) => {
    if (error?.code === "DEV_VAULT_CANCELLED") return;
    if (error?.code === "VAULT_READBACK_MISMATCH") {
      status("A cópia cifrada foi enviada, mas NÃO passou na verificação de recuperação. O arquivo original foi preservado. Não apague o original.");
      return;
    }
    if (error?.payload?.error === "VAULT_ACCOUNT_CHANGED") {
      lockForAccountChange();
      status("A conta mudou durante a operação. Nenhum arquivo foi enviado; recarregue a página.");
      return;
    }
    if (error?.payload?.error === "VAULT_LIMIT") {
      status("Limite deste cofre de desenvolvimento atingido. Não foi possível armazenar mais arquivos.");
      return;
    }
    if (error?.payload?.error === "VAULT_KEY_MISMATCH") {
      status("Esta chave não corresponde à chave usada pelos arquivos atuais. Nenhuma alteração foi aplicada.");
      return;
    }
    status("Não foi possível concluir: "
    + (error?.status === 401 ? "faça login no Root.ark."
      : error?.status === 403 ? "permissão insuficiente."
        : error?.status === 404 ? "item indisponível."
          : error?.status === 409 ? "conflito de revisão. Atualize a lista."
            : "verifique sua chave, seus dados e a conexão."));
  };
  async function requireCurrentAccount() {
    if (!state.username) throw new Error("Protected vault session unavailable");
    const current = await api.get(path + "/session");
    if (current.username !== state.username) {
      const error = new Error("Vault account changed");
      error.status = 409;
      error.payload = { error: "VAULT_ACCOUNT_CHANGED" };
      throw error;
    }
    return current.username;
  }
  async function requireMatchingVaultKey(keyId) {
    if (typeof keyId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(keyId)) {
      throw new Error("Uninitialized local vault key commitment");
    }
    const account = await requireCurrentAccount();
    const current = await api.get(path + "/session");
    if (current.username !== account) {
      lockForAccountChange();
      const error = new Error("Vault account changed");
      error.status = 409;
      error.payload = { error: "VAULT_ACCOUNT_CHANGED" };
      throw error;
    }
    if (current.activeKeyId !== null && current.activeKeyId !== keyId) {
      const error = new Error("Vault key differs");
      error.status = 409;
      error.payload = { error: "VAULT_KEY_MISMATCH" };
      throw error;
    }
    return account;
  }
  function requireKey() {
    if (!state.key) throw new Error("Local vault key is locked");
    return state.key;
  }
  async function run(operation) {
    if (state.busy) return;
    state.busy = true;
    try { await operation(); } catch (error) { report(error); }
    finally { state.busy = false; }
  }
  function objectId() {
    const random = crypto.getRandomValues(new Uint8Array(16));
    let binary = "";
    for (const byte of random) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  async function openLocalDatabase() {
    if (!window.indexedDB) throw new Error("Local device storage unavailable");
    return new Promise((resolve, reject) => {
      const pending = indexedDB.open("rootark-opaque-dev-vault-key-v1", 2);
      pending.onupgradeneeded = () => {
        if (!pending.result.objectStoreNames.contains("keys"))
          pending.result.createObjectStore("keys");
        if (!pending.result.objectStoreNames.contains("trusted"))
          pending.result.createObjectStore("trusted");
        if (!pending.result.objectStoreNames.contains("pending"))
          pending.result.createObjectStore("pending");
      };
      pending.onsuccess = () => resolve(pending.result);
      pending.onerror = () => reject(pending.error);
    });
  }
  async function localKey(action, key, generation = state.lockGeneration) {
    const username = state.username;
    const db = await openLocalDatabase();
    try {
      assertNotRelocked(generation);
      return await new Promise((resolve, reject) => {
        const tx = db.transaction("keys", action === "load" ? "readonly" : "readwrite");
        const store = tx.objectStore("keys");
        let result = null;
        let policyError = null;
        if (action === "save") {
          // The get/conditional put occur inside one IndexedDB readwrite
          // transaction. No other tab can insert a different key between
          // the check and the write for this object store.
          const check = store.get(username);
          check.onsuccess = () => {
            if (generation !== state.lockGeneration || username !== state.username) {
              policyError = new Error("Local vault lock cancelled pending operation");
              policyError.code = "DEV_VAULT_CANCELLED";
              tx.abort();
              return;
            }
            if (!cryptoFile.canSaveDeviceKey(check.result, key?.keyId)) {
              policyError = new Error("Cannot silently replace device key");
              policyError.status = 409;
              policyError.payload = { error: "VAULT_KEY_MISMATCH" };
              tx.abort();
              return;
            }
            store.put(key, username);
          };
        } else {
          const req = action === "load" ? store.get(username) : store.delete(username);
          req.onsuccess = () => { result = req.result; };
        }
        tx.oncomplete = () => resolve(result);
        tx.onerror = () => reject(policyError || tx.error || new Error("Local key store unavailable"));
        tx.onabort = () => reject(policyError || tx.error || new Error("Local key store aborted"));
      });
    } finally { db.close(); }
  }
  async function localDeviceRecord(kind, action, value, generation = state.lockGeneration) {
    if (kind !== "trusted" && kind !== "pending") throw new Error("Invalid local record");
    const username = state.username;
    const db = await openLocalDatabase();
    try {
      assertNotRelocked(generation);
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(kind, action === "load" ? "readonly" : "readwrite");
        const store = tx.objectStore(kind);
        let result = null;
        let cancelled = null;
        if (action === "save" || action === "delete-if-current") {
          const check = store.get(username);
          check.onsuccess = () => {
            if (generation !== state.lockGeneration || username !== state.username) {
              cancelled = new Error("Local operation cancelled");
              cancelled.code = "DEV_VAULT_CANCELLED";
              tx.abort();
            } else if (action === "delete-if-current") {
              // Another tab may have replaced the pending ECDH request since
              // it was read. Never delete a newer request in that case.
              const saved = check.result?.request;
              const expected = value?.request;
              if (!saved || !expected || saved.format !== expected.format
                || saved.username !== expected.username
                || saved.requestId !== expected.requestId
                || saved.publicKey !== expected.publicKey
                || !Object.is(saved.createdAt, expected.createdAt)
                || !Object.is(saved.expiresAt, expected.expiresAt)) {
                cancelled = new Error("Local recovery request changed");
                cancelled.code = "DEV_VAULT_CANCELLED";
                tx.abort();
              } else {
                store.delete(username);
              }
            } else if (check.result) {
              cancelled = new Error("Local trusted device record already exists");
              tx.abort();
            } else {
              store.put(value, username);
            }
          };
        } else {
          const request = action === "load" ? store.get(username)
            : store.delete(username);
          request.onsuccess = () => { result = request.result; };
        }
        tx.oncomplete = () => resolve(result);
        tx.onerror = () => reject(cancelled || tx.error || new Error("IndexedDB unavailable"));
        tx.onabort = () => reject(cancelled || tx.error || new Error("IndexedDB operation aborted"));
      });
    } finally { db.close(); }
  }
  function downloadJson(filename, payload) {
    const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.hidden = true;
      document.body.append(a);
      a.click();
      a.remove();
    } finally { setTimeout(() => URL.revokeObjectURL(url), 5_000); }
  }
  async function readSmallJson(input) {
    const file = input.files?.[0];
    if (!file || file.size > 5000 || file.size < 2) throw new Error("Invalid recovery JSON");
    return JSON.parse(await file.text());
  }
  function expiredRecoveryRequest(pending) {
    const request = pending?.request;
    return request?.username === state.username
      && Number.isSafeInteger(request.createdAt)
      && Number.isSafeInteger(request.expiresAt)
      && request.expiresAt === request.createdAt + 15 * 60 * 1000
      && request.expiresAt <= Date.now();
  }
  async function refresh() {
    await requireCurrentAccount();
    const listed = await api.get(path + "/objects");
    await requireCurrentAccount();
    const area = $("objects");
    area.replaceChildren();
    if (!listed.objects.length) {
      const li = document.createElement("li");
      li.textContent = "Nenhum arquivo protegido neste cofre.";
      area.append(li);
    }
    for (const item of listed.objects) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = "Arquivo " + item.id.slice(0, 10) + "… · revisão " + item.revision;
      const actions = document.createElement("div");
      actions.className = "actions";
      const open = document.createElement("button");
      open.type = "button";
      open.textContent = "Descriptografar e baixar";
      open.addEventListener("click", () => run(async () => {
        const generation = state.lockGeneration;
        const account = await requireCurrentAccount();
        const key = requireKey();
        const record = await api.get(path + "/objects/" + encodeURIComponent(item.id));
        await requireCurrentAccount();
        if (record.keyId !== state.keyId) {
          const error = new Error("Key differs from stored document");
          error.status = 409;
          error.payload = { error: "VAULT_KEY_MISMATCH" };
          throw error;
        }
        const opened = await cryptoFile.decryptFile({
          key, id: record.id, username: account, envelope: record.envelope,
        });
        // A user may explicitly lock the vault while decrypt is pending.
        // Never complete that download with a previously captured key.
        assertNotRelocked(generation);
        const blob = new Blob([opened.data], {
          type: opened.mediaType || "application/octet-stream",
        });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = opened.name;
        anchor.hidden = true;
        document.body.append(anchor);
        anchor.click();
        anchor.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5_000);
        status("Arquivo descriptografado localmente. Nenhum conteúdo claro foi enviado ao servidor.");
      }));
      const erase = document.createElement("button");
      erase.type = "button";
      erase.textContent = "Excluir";
      erase.className = "quiet";
      erase.addEventListener("click", () => run(async () => {
        if (!confirm("Excluir este arquivo cifrado? A remoção não poderá ser desfeita.")) return;
        const account = await requireCurrentAccount();
        await api.delete(path + "/objects/" + encodeURIComponent(item.id), {
          json: { account, expectedRevision: item.revision },
        });
        await refresh();
        status("Arquivo removido do cofre.");
      }));
      actions.append(open, erase);
      li.append(label, actions);
      area.append(li);
    }
  }
  async function boot() {
    if (!api || !cryptoFile || !window.crypto?.subtle) {
      status("Este navegador não possui os recursos necessários.");
      return;
    }
    try {
      const session = await api.get(path + "/session");
      state.username = session.username;
      $("account").textContent = "Conta autenticada: " + state.username;
      await refresh();
      if (trustedDevice) {
        try {
          const pending = await localDeviceRecord("pending", "load");
          if (pending?.request) {
            $("device-request-code").textContent = expiredRecoveryRequest(pending)
              ? "Solicitação expirada. Crie outra sem apagar as chaves locais."
              : await trustedDevice.requestFingerprint({
                username: state.username, request: pending.request,
              });
          }
        } catch (_) {
          $("device-request-code").textContent = "Solicitação local indisponível";
        }
      }
      status("Cofre acessível. Importe sua chave, gere uma nova ou use a salva neste navegador.");
    } catch (error) {
      $("account").textContent = "Acesso indisponível.";
      report(error);
    }
  }
  $("generate").addEventListener("click", () => run(async () => {
    const generation = state.lockGeneration;
    const account = await requireCurrentAccount();
    const objects = (await api.get(path + "/objects")).objects;
    // This development vault has no versioned multi-key manifest yet.
    // Never silently mix different content keys in a nonempty collection.
    if (objects.length) {
      status("O cofre já contém arquivos. Importe sua chave original ou exclua todos os arquivos antes de gerar outra.");
      return;
    }
    await requireCurrentAccount();
    const created = await cryptoFile.generateRecoveryKey();
    const keyId = await cryptoFile.keyCommitment(created.recoveryKey, account);
    await requireMatchingVaultKey(keyId);
    assertNotRelocked(generation);
    state.key = created.key;
    state.keyId = keyId;
    $("recovery").value = created.recoveryKey;
    $("recovery").type = "text";
    status("Nova chave gerada apenas neste navegador. Guarde-a antes de enviar arquivos.");
  }));
  $("import").addEventListener("click", () => run(async () => {
    const generation = state.lockGeneration;
    const account = await requireCurrentAccount();
    const raw = $("recovery").value.trim();
    $("recovery").value = "";
    $("recovery").type = "password";
    const keyId = await cryptoFile.keyCommitment(raw, account);
    await requireMatchingVaultKey(keyId);
    const importedKey = await cryptoFile.importRecoveryKey(raw);
    await requireMatchingVaultKey(keyId);
    assertNotRelocked(generation);
    state.key = importedKey;
    state.keyId = keyId;
    $("recovery").value = "";
    $("recovery").type = "password";
    status("Chave importada na memória; tente abrir seus arquivos.");
  }));
  $("reveal").addEventListener("click", () => {
    $("recovery").type = $("recovery").type === "password" ? "text" : "password";
  });
  $("save-device").addEventListener("click", () => run(async () => {
    const generation = state.lockGeneration;
    const key = requireKey();
    const keyId = state.keyId;
    await requireMatchingVaultKey(keyId);
    assertNotRelocked(generation);
    // Do not silently replace a stored key, even if the remote list was empty
    // at the last check; another device can add a file between two requests.
    const previous = await localKey("load");
    await requireMatchingVaultKey(keyId);
    assertNotRelocked(generation);
    if (!cryptoFile.canSaveDeviceKey(previous, keyId)) {
      const error = new Error("Saved key is different");
      error.status = 409;
      error.payload = { error: "VAULT_KEY_MISMATCH" };
      throw error;
    }
    await localKey("save", { key, keyId }, generation);
    assertNotRelocked(generation);
    status("Chave não exportável salva no IndexedDB deste navegador. Preserve também sua recuperação independente.");
  }));
  $("restore-browser").addEventListener("click", () => run(async () => {
    const generation = state.lockGeneration;
    await requireCurrentAccount();
    const saved = await localKey("load");
    if (!saved || !saved.key || saved.key.type !== "secret"
      || saved.key.extractable !== false || saved.key.algorithm?.name !== "AES-GCM"
      || !/^[A-Za-z0-9_-]{43}$/.test(saved.keyId || "")) {
      throw new Error("Saved local key unavailable");
    }
    await requireMatchingVaultKey(saved.keyId);
    assertNotRelocked(generation);
    state.key = saved.key;
    state.keyId = saved.keyId;
    status("Chave local reaberta. Tente descriptografar um arquivo.");
  }));
  $("forget-device").addEventListener("click", () => run(async () => {
    await requireCurrentAccount();
    if (!confirm("Remover TODAS as chaves, aprovações e solicitações de recuperação salvas neste navegador? Garanta sua recuperação independente.")) return;
    invalidateLocalKey();
    await localKey("delete");
    await localDeviceRecord("trusted", "delete");
    await localDeviceRecord("pending", "delete");
    $("device-request-code").textContent = "Nenhuma solicitação pendente";
    $("recovery").value = "";
    status("A chave deste navegador foi removida. Arquivos remotos não foram excluídos.");
  }));
  $("lock").addEventListener("click", () => {
    invalidateLocalKey();
    $("recovery").value = "";
    $("recovery").type = "password";
    $("file").value = "";
    status("Chave apagada da sessão em memória. Salvos locais só são removidos com 'Esquecer'.");
  });
  async function persistVerifiedCopy({ name, mediaType, original }) {
    try {
      const generation = state.lockGeneration;
      const account = await requireMatchingVaultKey(state.keyId);
      const keyId = state.keyId;
      const key = requireKey();
      const id = objectId();
      const envelope = await cryptoFile.encryptFile({
        key, id, username: account, name, mediaType, data: original,
      });
      await requireMatchingVaultKey(keyId);
      assertNotRelocked(generation);
      await api.post(path + "/objects", { account, id, envelope, keyId });
      let valid = false;
      try {
        await requireMatchingVaultKey(keyId);
        const stored = await api.get(path + "/objects/" + encodeURIComponent(id));
        await cryptoFile.verifyStoredCopy({
          key, username: account, id, keyId, expectedEnvelope: envelope,
          original, name, mediaType, record: stored,
        });
        assertNotRelocked(generation);
        valid = true;
      } catch (error) {
        if (error?.code === "DEV_VAULT_CANCELLED") throw error;
        const mismatch = new Error("Opaque copy read-back failed");
        mismatch.code = "VAULT_READBACK_MISMATCH";
        throw mismatch;
      }
      if (!valid) throw new Error("Unverified encrypted copy");
      await refresh();
      return true;
    } finally {
      original.fill(0);
    }
  }
  $("upload").addEventListener("click", () => run(async () => {
    const file = $("file").files?.[0];
    if (!file) throw new Error("File required");
    if (file.size > cryptoFile.MAX_PLAINTEXT_BYTES) {
      status("Arquivo acima do limite de 4 MiB.");
      return;
    }
    await persistVerifiedCopy({
      name: file.name, mediaType: file.type || "application/octet-stream",
      original: new Uint8Array(await file.arrayBuffer()),
    });
    $("file").value = "";
    status("Cópia cifrada confirmada: o arquivo persistido foi recuperado e os bytes, nome e tipo originais conferem.");
  }));
  $("legacy-copy").addEventListener("click", () => run(async () => {
    if (!migration) throw new Error("Legacy copy support unavailable");
    const generation = state.lockGeneration;
    await requireCurrentAccount();
    if (!confirm("Copiar este arquivo legado sem removê-lo nem alterar a proteção original?")) return;
    const selectedName = $("legacy-name").value;
    const selectedFolder = $("legacy-folder").value.trim();
    const source = await migration.readLegacyPlaintext({
      name: selectedName, folderId: selectedFolder,
    });
    try {
      assertNotRelocked(generation);
      await persistVerifiedCopy({
        name: source.name, mediaType: source.mediaType, original: source.data,
      });
      assertNotRelocked(generation);
      status("Cópia legada cifrada e verificada. O arquivo ORIGINAL continua intacto. Não o exclua até concluir uma migração zk-1 aprovada.");
    } finally { source.data.fill(0); }
  }));
  $("refresh").addEventListener("click", () => run(refresh));
  $("emergency-export").addEventListener("click", () => run(async () => {
    const generation = state.lockGeneration;
    if (!emergency) throw new Error("Emergency recovery unavailable");
    const passwordInput = $("emergency-password");
    const keyInput = $("emergency-recovery-key");
    try {
      const account = await requireCurrentAccount();
      const recoveryKey = keyInput.value.trim();
      const keyId = await cryptoFile.keyCommitment(recoveryKey, account);
      if (state.keyId && state.keyId !== keyId) {
        const error = new Error("Incorrect recovery key");
        error.status = 409;
        error.payload = { error: "VAULT_KEY_MISMATCH" };
        throw error;
      }
      await requireMatchingVaultKey(keyId);
      const pkg = await emergency.createEmergencyPackage({
        username: account, recoveryKey, password: passwordInput.value,
      });
      await requireMatchingVaultKey(keyId);
      assertNotRelocked(generation);
      const blob = new Blob([JSON.stringify(pkg)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      try {
        const a = document.createElement("a");
        a.href = url;
        a.download = "rootark-emergency-dev-v1.json";
        a.hidden = true;
        document.body.append(a);
        a.click();
        a.remove();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 5_000);
      }
      status("Pacote protegido por senha criado localmente. Guarde o arquivo e a senha separadamente.");
    } finally {
      keyInput.value = "";
      passwordInput.value = "";
    }
  }));
  $("emergency-import").addEventListener("click", () => run(async () => {
    const generation = state.lockGeneration;
    if (!emergency) throw new Error("Emergency recovery unavailable");
    const input = $("emergency-file");
    const passwordInput = $("emergency-password");
    try {
      const file = input.files?.[0];
      if (!file || file.size > 4096) throw new Error("Invalid package file");
      const account = await requireCurrentAccount();
      const packageBytes = JSON.parse(await file.text());
      const raw = await emergency.openEmergencyPackage({
        username: account, packageBytes, password: passwordInput.value,
      });
      const keyId = await cryptoFile.keyCommitment(raw, account);
      await requireMatchingVaultKey(keyId);
      const restoredKey = await cryptoFile.importRecoveryKey(raw);
      await requireMatchingVaultKey(keyId);
      assertNotRelocked(generation);
      state.key = restoredKey;
      state.keyId = keyId;
      status("Chave restaurada localmente pelo pacote protegido por senha.");
    } finally {
      input.value = "";
      passwordInput.value = "";
    }
  }));
  $("device-enroll").addEventListener("click", () => run(async () => {
    if (!trustedDevice) throw new Error("Trusted device recovery unavailable");
    const generation = state.lockGeneration;
    const field = $("emergency-recovery-key");
    try {
      const username = await requireCurrentAccount();
      const raw = field.value.trim();
      const keyId = await cryptoFile.keyCommitment(raw, username);
      await requireMatchingVaultKey(keyId);
      const previous = await localDeviceRecord("trusted", "load", undefined, generation);
      if (previous) {
        status("Este navegador já tem autorização local. Para removê-la, use Esquecer chave deste navegador.");
        return;
      }
      if (!confirm("Confiar neste navegador para aprovar recuperação de outros navegadores? Use somente um dispositivo pessoal protegido.")) return;
      const record = await trustedDevice.enrollTrustedDevice({
        username, recoveryKey: raw, keyId,
      });
      await requireMatchingVaultKey(keyId);
      assertNotRelocked(generation);
      await localDeviceRecord("trusted", "save", record, generation);
      status("Navegador confiável autorizado localmente. Proteja o perfil do navegador e mantenha sua chave de emergência.");
    } finally { field.value = ""; }
  }));
  $("device-request").addEventListener("click", () => run(async () => {
    if (!trustedDevice) throw new Error("Trusted device recovery unavailable");
    const generation = state.lockGeneration;
    const username = await requireCurrentAccount();
    const previous = await localDeviceRecord("pending", "load", undefined, generation);
    if (previous) {
      if (!expiredRecoveryRequest(previous)) {
        status("Existe uma solicitação pendente. Conclua-a ou use Cancelar solicitação para criar outra.");
        return;
      }
      await requireCurrentAccount();
      await localDeviceRecord("pending", "delete-if-current", previous, generation);
    }
    const pending = await trustedDevice.createRecoveryRequest({ username });
    await requireCurrentAccount();
    assertNotRelocked(generation);
    await localDeviceRecord("pending", "save", pending, generation);
    assertNotRelocked(generation);
    $("device-request-code").textContent = await trustedDevice.requestFingerprint({
      username, request: pending.request,
    });
    assertNotRelocked(generation);
    downloadJson("rootark-device-request-dev-v1.json", pending.request);
    status("Solicitação gerada. Anote o código criptográfico exibido acima no navegador solicitante. Envie o JSON ao dispositivo confiável.");
  }));
  $("device-cancel").addEventListener("click", () => run(async () => {
    const generation = state.lockGeneration;
    await requireCurrentAccount();
    const pending = await localDeviceRecord("pending", "load", undefined, generation);
    if (!pending) {
      $("device-request-code").textContent = "Nenhuma solicitação pendente";
      status("Não há solicitação para cancelar.");
      return;
    }
    if (!confirm("Cancelar esta solicitação? Uma resposta já recebida não poderá mais ser usada neste navegador.")) return;
    await requireCurrentAccount();
    await localDeviceRecord("pending", "delete-if-current", pending, generation);
    assertNotRelocked(generation);
    $("device-request-code").textContent = "Nenhuma solicitação pendente";
    $("device-response-file").value = "";
    status("Solicitação cancelada neste navegador. Chaves e autorizações locais preservadas.");
  }));
  $("device-approve").addEventListener("click", () => run(async () => {
    if (!trustedDevice) throw new Error("Trusted device recovery unavailable");
    const generation = state.lockGeneration;
    const username = await requireCurrentAccount();
    const record = await localDeviceRecord("trusted", "load", undefined, generation);
    if (!record) {
      status("Este navegador não foi autorizado previamente como dispositivo confiável.");
      return;
    }
    await requireMatchingVaultKey(record.keyId);
    const input = $("device-request-file");
    try {
      const request = await readSmallJson(input);
      if (request?.username !== username || typeof request.requestId !== "string"
        || !/^[A-Za-z0-9_-]{22}$/.test(request.requestId)) {
        throw new Error("Invalid recovery request");
      }
      const requiredCode = await trustedDevice.requestFingerprint({ username, request });
      const typedCode = $("device-confirm-code").value.trim();
      if (!trustedDevice.confirmRequestFingerprint(typedCode, requiredCode)) {
        status("CÓDIGO NÃO CONFERE: solicitação adulterada ou código incorreto. A recuperação foi bloqueada.");
        return;
      }
      if (!confirm("Você comparou pessoalmente o código completo no navegador solicitante e aprovou conscientemente esse dispositivo?")) return;
      const response = await trustedDevice.approveRecoveryRequest({
        username, record, request,
      });
      await requireMatchingVaultKey(record.keyId);
      assertNotRelocked(generation);
      downloadJson("rootark-device-answer-dev-v1.json", response);
      status("Resposta protegida criada. Entregue-a somente ao navegador que gerou a solicitação.");
    } finally {
      input.value = "";
      $("device-confirm-code").value = "";
    }
  }));
  $("device-complete").addEventListener("click", () => run(async () => {
    if (!trustedDevice) throw new Error("Trusted device recovery unavailable");
    const generation = state.lockGeneration;
    const username = await requireCurrentAccount();
    const pending = await localDeviceRecord("pending", "load", undefined, generation);
    if (!pending) {
      status("Nenhuma solicitação local pendente. Gere uma solicitação neste navegador primeiro.");
      return;
    }
    const input = $("device-response-file");
    try {
      const answer = await readSmallJson(input);
      const result = await trustedDevice.completeRecoveryRequest({
        username, request: pending.request, privateKey: pending.privateKey, answer,
      });
      const computed = await cryptoFile.keyCommitment(result.recoveryKey, username);
      if (computed !== result.keyId) throw new Error("Device response key mismatch");
      await requireMatchingVaultKey(computed);
      const recoveredKey = await cryptoFile.importRecoveryKey(result.recoveryKey);
      await requireMatchingVaultKey(computed);
      assertNotRelocked(generation);
      await localDeviceRecord("pending", "delete-if-current", pending, generation);
      assertNotRelocked(generation);
      $("device-request-code").textContent = "Nenhuma solicitação pendente";
      state.key = recoveredKey;
      state.keyId = computed;
      status("Chave restaurada a partir do navegador confiável. Use Salvar chave neste navegador se desejar.");
    } finally { input.value = ""; }
  }));
  boot();
}());
