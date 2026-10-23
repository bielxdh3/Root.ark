(function (root) {
  "use strict";
  // Runs unchanged against Node VM (Node 22/24) and actual Microsoft Edge.
  // The signed-authority HTTP path is separately exercised by the full
  // two-device Express/CAS/witness integration test.
  const b64 = (value) => {
    let binary = "";
    for (const n of value) binary += String.fromCharCode(n);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
  const enc = new TextEncoder();
  const digest = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const deny = async (callback) => {
    try { await callback(); } catch (error) {
      if (error.message === "ZK_LOGICAL_TRASH_DENIED") return;
      throw error;
    }
    throw Error("MISSING_FAIL_CLOSED_REJECTION");
  };
  root.runRestoreReconnectionScenario = async function () {
    const file = root.RootarkZk1FileContent;
    const lifecycle = root.RootarkZk1ClientLogicalTrash;
    const scope = { account_id: b64(rnd(16)), compartment_id: b64(enc.encode("private")),
      keyring_id: b64(rnd(16)) };
    const objectId = b64(rnd(16));
    const original = { ...scope, object_id: objectId, version_id: b64(rnd(16)),
      parent_version_id: null, epoch: 1, kind: "file" };
    const tombstone = { ...original, version_id: b64(rnd(16)),
      parent_version_id: original.version_id };
    const restored = { ...tombstone, version_id: b64(rnd(16)),
      parent_version_id: tombstone.version_id };
    const keys = await Promise.all(Array.from({ length: 3 }, () => file.generateFileCek()));
    const payload = enc.encode("secret payload shared only between client devices");
    const originalBytes = await file.encryptFileWithParent({ cek: keys[0], metadata: original,
      name: "private.bin", mediaType: "application/octet-stream",
      parentFolderId: null, data: payload });
    const reference = { revision: 1, ciphertextDigest: b64(await digest(originalBytes)),
      versionId: original.version_id };
    const iv = rnd(12);
    const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128,
      additionalData: enc.encode("Root.ark/zk-1/logical-trash-aead/v1\0"
        + JSON.stringify(tombstone) + "\0" + JSON.stringify(reference)),
    }, keys[1], enc.encode('{"state":"trashed","retention":"unknown"}'));
    const tombstoneBytes = enc.encode(JSON.stringify({
      format: "rootark-zk1-logical-trash/v1", metadata: tombstone,
      predecessor: reference, nonce: b64(iv), ciphertext: b64(new Uint8Array(sealed)),
    }));
    const restoredBytes = await file.encryptFileWithParent({ cek: keys[2], metadata: restored,
      name: "private.bin", mediaType: "application/octet-stream",
      parentFolderId: null, data: payload });
    const all = [originalBytes, tombstoneBytes, restoredBytes];
    const headDigest = rnd(32), journalId = b64(rnd(32));
    const snapshot = { head: { sequence: 3, digest: headDigest }, rows: await Promise.all(
      all.map(async (wire, i) => ({ object_id: objectId,
        revision: i + 1, epoch: 1, ciphertext_digest: await digest(wire) }))) };
    let live = true, clears = 0, gets = 0, putCount = 0;
    const writer = {
      async readAll() { return snapshot; },
      async readVerifiedCiphertext(received, id, revision) {
        gets++;
        if (received !== snapshot || id !== objectId) throw Error("INVALID_SNAPSHOT");
        return { objectId, revision, epoch: 1, ciphertextBase64: b64(all[revision - 1]) };
      },
      async confirmPendingIntent(id) {
        if (id !== journalId) throw Error("WRONG_JOURNAL");
        clears++;
        return true;
      },
      async commit() { putCount++; throw Error("NO_RETRY_COMMIT"); },
    };
    const escrow = async ({ objectId: id, revision, versionId, nonce }) => {
      if (id !== objectId || nonce !== journalId
        || versionId !== [original, tombstone, restored][revision - 1]?.version_id)
        throw Error("WRONG_ESCROW_NONCE");
      return keys[revision - 1];
    };
    const params = () => ({ catalogWriter: writer, journalId,
      pinnedCatalogHead: { sequence: 3, digest: b64(headDigest) },
      originalMetadata: original, sourceMetadata: tombstone, destinationMetadata: restored,
      originalRevision: 1, sourceRevision: 2, destinationRevision: 3,
      readArchivedCek: escrow,
      assertLive() { if (!live) throw Error("LOGOUT"); },
    });
    await deny(() => lifecycle.reconcileCommittedRestore({ ...params(),
      pinnedCatalogHead: { sequence: 2, digest: b64(rnd(32)) } }));
    await deny(() => lifecycle.reconcileCommittedRestore({ ...params(),
      destinationMetadata: { ...restored, parent_version_id: original.version_id } }));
    await deny(() => lifecycle.reconcileCommittedRestore({ ...params(),
      readArchivedCek: async ({ revision, ...selection }) => revision === 3
        ? file.generateFileCek() : escrow({ revision, ...selection }) }));
    // A correctly authenticated but semantically wrong restore must not be
    // treated as restoring the old file (even when the signed CAS accepts it).
    const fraudulent = await file.encryptFileWithParent({ cek: keys[2], metadata: restored,
      name: "private.bin", mediaType: "application/octet-stream",
      parentFolderId: null, data: enc.encode("another file") });
    const previous = all[2], originalDigest = snapshot.rows[2].ciphertext_digest;
    all[2] = fraudulent; snapshot.rows[2].ciphertext_digest = await digest(fraudulent);
    await deny(() => lifecycle.reconcileCommittedRestore(params()));
    all[2] = previous; snapshot.rows[2].ciphertext_digest = originalDigest;
    live = false;
    await deny(() => lifecycle.reconcileCommittedRestore(params()));
    live = true;
    await deny(() => lifecycle.reconcileCommittedRestore({ ...params(),
      catalogWriter: { ...writer,
        async readVerifiedCiphertext(...args) {
          const answer = await writer.readVerifiedCiphertext(...args);
          if (args[2] === 3) live = false;
          return answer;
        },
      },
    }));
    live = true;
    if (clears !== 0) throw Error("INVALID_EARLY_JOURNAL_CLEAR");
    const result = await lifecycle.reconcileCommittedRestore(params());
    if (result.state !== "file" || result.restoredAfterTombstone !== true
      || result.productionDurabilityProven !== false || clears !== 1
      || gets < 3 || putCount !== 0) throw Error("RESTORE_RECONNECT_NOT_VERIFIED");
    payload.fill(0);
    return { result: "PASS", rejected: 6, signedGets: gets, puts: putCount };
  };
  if (typeof document === "object") {
    root.addEventListener("load", () => {
      root.runRestoreReconnectionScenario().then(() => {
        document.querySelector("#result").textContent = "EDGE_RESTORE_RECONNECT_PASS";
      }, (error) => {
        document.querySelector("#result").textContent = "EDGE_RESTORE_RECONNECT_FAIL:" + error.message;
      });
    });
  }
}(typeof window === "object" ? window : globalThis));
