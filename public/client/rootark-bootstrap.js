(function () {
  "use strict";

  const index = window.RootarkProtectedIndex;
  const protectedStore = window.RootarkProtectedStore?.createProtectedStore?.();
  const session = window.RootarkProtectedSession;
  session?.attachStore?.(protectedStore);

  function setStatus(message) {
    const status = document.getElementById("protectedClientStatus");
    if (status) status.textContent = message;
  }

  function updateStatus() {
    if (!("serviceWorker" in navigator)) return setStatus("Offline indisponivel nesta sessao.");
    setStatus(navigator.onLine
      ? "Online: o conteúdo protegido não é armazenado no cache público."
      : "Offline: o conteúdo protegido exige um índice e uma chave já desbloqueados neste dispositivo.");
  }

  document.addEventListener("click", async (event) => {
    const searchButton = event.target.closest?.("#protectedSearchButton");
    if (!searchButton) return;
    const result = document.getElementById("protectedSearchResult");
    const input = document.getElementById("protectedSearchInput");
    if (!index || !protectedStore || typeof session?.getKey !== "function") {
      if (result) result.textContent = "Nenhum indice protegido local foi desbloqueado.";
      return;
    }
    try {
      await protectedStore.open();
      const key = await session.getKey();
      const entries = await protectedStore.listIndex(key);
      const matches = await index.search(entries, input?.value || "", key);
      if (result) result.textContent = `${matches.length} resultado(s) local(is).`;
    } catch {
      if (result) result.textContent = "Indice protegido indisponivel ou chave incorreta.";
    }
  });

  window.addEventListener("online", async () => {
    updateStatus();
    try { await session?.syncOnce?.(); } catch { setStatus("Online: sincronização protegida aguardando autorização."); }
  });
  window.addEventListener("offline", updateStatus);
  window.addEventListener("rootark:workspace-rendered", updateStatus);
  window.addEventListener("rootark:logout", () => session?.logout?.() || protectedStore?.logout?.());
  window.addEventListener("rootark:device-revoked", () => session?.revoke?.() || protectedStore?.revoke?.());
  updateStatus();
}());
