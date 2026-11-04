(function (root) {
  "use strict";
  const te = new TextEncoder();
  const b64 = (raw) => {
    let value = "";
    for (const byte of raw) value += String.fromCharCode(byte);
    return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const raw64 = (value) => Uint8Array.from(atob(value.replace(/-/g, "+")
    .replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")),
  (char) => char.charCodeAt(0));
  const sha = async (value) => new Uint8Array(await root.crypto.subtle.digest("SHA-256", value));
  const strict = (condition, reason) => { if (!condition) throw Error(reason); };
  root.runOpaqueRestoreProbe = async function (fixture) {
    const rekey = fixture.caseName.startsWith("rekey");
    const activeEpoch = (fixture.caseName === "epochRollover" || rekey) ? 2 : 1;
    const scope = { ...fixture.scope };
    const original = { ...fixture.sourceMetadata };
    const metadataKey = await root.crypto.subtle.importKey("raw",
      raw64(fixture.metadataKeyBase64), "AES-GCM", false,
      rekey ? ["decrypt"] : ["encrypt", "decrypt"]);
    const tombstoneMetadataKey = await root.crypto.subtle.importKey("raw",
      raw64(fixture.tombstoneMetadataKeyBase64), "AES-GCM", false,
      ["encrypt", "decrypt"]);
    const rawCek = raw64(fixture.cekBase64);
    const cek = await root.RootarkZk1FileContent.importFileCek(rawCek);
    rawCek.fill(0);
    const sourceCiphertext = await root.RootarkZk1FileContent.encryptFileWithParent({
      cek, metadata: original, name: "restored-private-name.txt", mediaType: "text/plain",
      parentFolderId: null, data: te.encode("private-file-content") });
    const sourceDigest = await sha(sourceCiphertext);
    const sourceMetadata = raw64(fixture.sourceMetadataCiphertextBase64);
    const parentDigest = await sha(sourceMetadata);
    const signer = await root.crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
    const signerPublic = new Uint8Array(await root.crypto.subtle.exportKey("raw", signer.publicKey));
    const substitute = fixture.caseName === "rekeySignerSubstitute"
      ? await root.crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]) : signer;
    const substitutePublic = new Uint8Array(await root.crypto.subtle.exportKey(
      "raw", substitute.publicKey));
    const ownerDigest = new Uint8Array(32).fill(8);
    const previousDigest = new Uint8Array(32).fill(1);
    const statement = { format: "rootark-zk1-opaque-logical-trash/v1", ...scope,
      deviceId: "restoring-device", objectId: fixture.objectId,
      parentRevision: 1, parentEpoch: 1, parentDigest: b64(sourceDigest),
      parentMetadataDigest: b64(parentDigest),
      revision: 2, epoch: activeEpoch, previousSequence: 1,
      previousDigest: b64(previousDigest),
      ownerRevision: 1, ownerDigest: b64(ownerDigest),
      nonce: b64(root.crypto.getRandomValues(new Uint8Array(32))),
      issuedAt: 1700000000 };
    const domain = te.encode("Root.ark/zk-1/opaque-logical-trash/v1\0");
    let signature = new Uint8Array(await root.crypto.subtle.sign("Ed25519",
      substitute.privateKey, new Uint8Array([...domain, ...te.encode(JSON.stringify(statement))])));
    if (fixture.caseName === "forgedSignature") signature[0] ^= 1;
    const clear = te.encode(JSON.stringify({ statement, signature: b64(signature) }));
    const aad = te.encode("Root.ark/zk-1/opaque-logical-trash-aead/v1\0"
      + JSON.stringify({ ...scope, objectId: fixture.objectId,
        revision: 2, epoch: activeEpoch }));
    const nonce = root.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await root.crypto.subtle.encrypt({
      name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128,
    }, tombstoneMetadataKey, clear));
    clear.fill(0); signature.fill(0);
    const envelope = new Uint8Array(12 + ciphertext.length);
    envelope.set(nonce); envelope.set(ciphertext, 12);
    const rows = [
      { object_id: fixture.objectId, revision: 1, epoch: 1,
        ciphertext_digest: sourceDigest, metadata_ciphertext: sourceMetadata },
      { object_id: fixture.objectId, revision: 2, epoch: activeEpoch,
        ciphertext_digest: await sha(envelope),
        metadata_ciphertext: raw64(fixture.tombstoneMetadataCiphertextBase64) },
    ];
    const head = { sequence: 2, digest: new Uint8Array(32).fill(2) };
    const snapshot = { head, rows };
    let puts = 0, gets = 0, pending = null, confirmed = false, changed = false;
    let nowSeconds = 1700000000;
    let live = true, restoreMetadata = null, committedCiphertext = null;
    const network = async (route, body) => {
      const response = await root.fetch(fixture.origin + route, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(body) });
      strict(response.ok, "HTTP_" + route + "_" + response.status);
      return response.json();
    };
    await network("/fixture", { objectId: fixture.objectId, revision: 1,
      ciphertextBase64: b64(sourceCiphertext) });
    await network("/fixture", { objectId: fixture.objectId, revision: 2,
      ciphertextBase64: b64(envelope) });
    const verifiedOpenMetadata = root.RootarkZk1BrowserOpaqueCatalogCommit.openMetadata;
    root.RootarkZk1BrowserOpaqueCatalogCommit = {
      openMetadata: verifiedOpenMetadata,
      createClient() {
        return {
          async readAll() {
            if (["rollback", "rekeyRollback"].includes(fixture.caseName) && changed) {
              return { head: { sequence: 1, digest: previousDigest }, rows: [rows[0]] };
            }
            changed = true;
            return snapshot;
          },
          async readVerifiedPredecessorDigest() { return previousDigest; },
          async readSignedHistoricalHead(authoritySnapshot, sequence, expectedRow) {
            strict(authoritySnapshot === snapshot && sequence === statement.previousSequence + 1
              && expectedRow.objectId === fixture.objectId && expectedRow.revision === 2
              && expectedRow.epoch === activeEpoch
              && b64(expectedRow.ciphertextDigest) === b64(rows[1].ciphertext_digest)
              && b64(expectedRow.metadataCiphertext) === b64(rows[1].metadata_ciphertext),
            "HISTORICAL_CATALOG_RECEIPT_MISMATCH");
            // The isolated probe supplies the authenticated historical-head
            // contract; production verification lives in the independent
            // owner/CAS/witness client and is not replaced by this stub.
            return { exactHistoricalAuthorityVerified: true, epoch: activeEpoch,
              manifestRevision: statement.ownerRevision,
              manifestDigest: statement.ownerDigest,
              previousDigest: statement.previousDigest, issuedAt: statement.issuedAt };
          },
          async verifyAuthorizedSigner(deviceId, epoch) {
            strict(deviceId === statement.deviceId && epoch === activeEpoch
              && trust.signedDeviceGrant.current_epoch === epoch
              && trust.signedDeviceGrant.revoked_at_epoch === null
              && trust.signerGrants.length === 1
              && trust.signerGrants[0].revoked_at_epoch === null,
            "CURRENT_OWNER_SIGNER_NOT_VERIFIED");
            return signer.publicKey;
          },
          async readVerifiedCiphertext(_snapshot, objectId, revision) {
            gets++;
            const row = rows.find((item) => item.object_id === objectId
              && item.revision === revision);
            strict(Boolean(row), "SIGNED_ROW_UNKNOWN");
            const response = await network("/protected-get", { objectId, revision });
            let bytes = raw64(response.ciphertextBase64);
            if (fixture.caseName === "tamperedSource" && revision === 1)
              bytes[bytes.length - 1] ^= 1;
            // This mock enforces the protected GET's pinned digest on the
            // loopback wire; the production writer verifies independent CAS,
            // owner witness, signed pages and real device request signatures.
            strict(b64(await sha(bytes)) === b64(row.ciphertext_digest), "GET_DIGEST_MISMATCH");
            if (fixture.caseName === "rekeyExpiredDuringRead" && revision === 1)
              nowSeconds = 1700000600;
            return { objectId, revision, epoch: row.epoch,
              ciphertextDigestBase64: b64(row.ciphertext_digest),
              ciphertextBase64: b64(bytes) };
          },
          async prepareIntent(additions) {
            strict(additions.length === 1 && pending === null && puts === 0,
              "JOURNAL_BEFORE_PUT");
            pending = b64(root.crypto.getRandomValues(new Uint8Array(32)));
            return pending;
          },
          async commit(additions, journalId, options = {}) {
            // A delayed CAS admission must re-check expiry AFTER the
            // writer's own async work, not only at its call boundary.
            if (fixture.caseName === "rekeyExpiredInCommit")
              nowSeconds = 1700000600;
            if (options.beforeCasAdmission) {
              strict(typeof options.beforeCasAdmission === "function",
                "MISSING_CAS_ADMISSION_FENCE");
              options.beforeCasAdmission();
            }
            strict(journalId === pending && puts === 1
              && additions.length === 1 && additions[0].revision === 3, "COMMIT_GUARD");
            committedCiphertext = new Uint8Array(additions[0].ciphertext);
            const parsed = JSON.parse(new TextDecoder().decode(committedCiphertext));
            restoreMetadata = parsed.metadata;
            strict(additions[0].name === "restored-private-name.txt", "NAME_CHANGED");
            return { verifiedSignedReadback: true, sequence: 3,
              digest: b64(new Uint8Array(32).fill(3)) };
          },
          async confirmPendingIntent(journalId, receipt) {
            strict(journalId === pending && receipt.verifiedSignedReadback,
              "SIGNED_JOURNAL_RECONCILIATION");
            confirmed = true; pending = null; return true;
          },
        };
      },
    };
    root.RootarkZk1ProtectedHttpClient = {
      async signProtectedContentOperation(input) {
        const challenge = te.encode(input.operation + ":" + input.objectId);
        await root.crypto.subtle.sign("Ed25519", input.signerKey, challenge);
        return { operation: input.operation, objectId: input.objectId,
          revision: input.operation === "put" ? input.expectedObjectRevision + 1
            : input.expectedObjectRevision,
          ciphertextBase64: input.operation === "put" ? b64(input.ciphertext) : null };
      },
      async postProtectedCiphertextPut({ request }) {
        puts++;
        await network("/protected-put", request);
      },
      async postProtectedCiphertextBackupRead({ request, expectedRoot }) {
        const response = await network("/protected-get", {
          objectId: request.objectId, revision: request.revision });
        if (["lostReadback", "rekeyLostReadback"].includes(fixture.caseName))
          throw Error("LOST_SIGNED_GET");
        const check = raw64(response.ciphertextBase64);
        const actualRoot = await root.RootarkZk1CiphertextRoot.computeCiphertextRoot([check]);
        strict(b64(actualRoot) === b64(expectedRoot), "READBACK_ROOT");
        return { ciphertextBase64: response.ciphertextBase64,
          integrityMatchesPinnedRoot: true };
      },
    };
    // The real implementation is re-evaluated against the loopback adapters.
    await root.installOpaqueRestoreClient();
    const trust = { signedDeviceGrant: { ...scope, device_id: "restoring-device" },
      signerGrants: [{ device_id: "restoring-device",
        authorization_public_key: b64(substitutePublic),
        revoked_at_epoch: fixture.caseName === "revoked" ? 1 : null,
        current_epoch: activeEpoch }],
      pinnedOwnerHead: { revision: fixture.caseName === "staleOwner" ? 2 : 1,
        digest: ownerDigest, epoch: activeEpoch },
      devicePrivateKey: signer.privateKey, origin: fixture.origin + "/",
      fetchImpl: root.fetch, csrfToken: () => "csrf",
      isSessionCurrent: () => live, nowSeconds: () => nowSeconds };
    trust.signedDeviceGrant.authorization_public_key = b64(signerPublic);
    trust.signedDeviceGrant.current_epoch = activeEpoch;
    trust.signedDeviceGrant.revoked_at_epoch =
      fixture.caseName === "rekeyRevokedGrant" ? activeEpoch : null;
    const owner = await root.crypto.subtle.generateKey("Ed25519", false,
      ["sign", "verify"]);
    trust.ownerPublicKey = owner.publicKey;
    trust.pinnedOwnerKeyHash = await sha(new Uint8Array(
      await root.crypto.subtle.exportKey("raw", owner.publicKey)));
    const nextCekRaw = fixture.caseName === "rekeySameCek"
      ? raw64(fixture.cekBase64) : root.crypto.getRandomValues(new Uint8Array(32));
    const nextMetadataRaw = fixture.caseName === "rekeySameMetadataKey"
      ? raw64(fixture.metadataKeyBase64)
      : root.crypto.getRandomValues(new Uint8Array(32));
    const grantPayload = {
      format: "rootark-zk1-opaque-owner-epoch-restore-grant/v1",
      ...scope, deviceId: trust.signedDeviceGrant.device_id, objectId: fixture.objectId,
      sourceRevision: 1, sourceEpoch: 1, sourceDigest: b64(sourceDigest),
      tombstoneRevision: 2, tombstoneEpoch: activeEpoch,
      tombstoneDigest: b64(rows[1].ciphertext_digest),
      catalogSequence: 2, catalogDigest: b64(head.digest),
      ownerRevision: trust.pinnedOwnerHead.revision,
      ownerDigest: b64(ownerDigest), currentEpoch: activeEpoch,
      destinationRevision: 3, currentCekSha256: b64(await sha(nextCekRaw)),
      currentMetadataKeySha256: b64(await sha(nextMetadataRaw)),
      nonce: b64(root.crypto.getRandomValues(new Uint8Array(32))),
      issuedAt: 1699999990, expiresAt: 1700000280,
    };
    const rekeyDomain = te.encode("Root.ark/zk-1/opaque-owner-epoch-restore-grant/v1\0");
    const rekeySig = new Uint8Array(await root.crypto.subtle.sign("Ed25519",
      owner.privateKey, new Uint8Array([...rekeyDomain,
        ...te.encode(JSON.stringify(grantPayload))])));
    const ownerRekeyGrant = { ...grantPayload, signature: b64(rekeySig) };
    if (fixture.caseName === "rekeyForgedGrant") ownerRekeyGrant.signature =
      b64(new Uint8Array(64).fill(18));
    if (fixture.caseName === "rekeyWrongOwner") trust.pinnedOwnerKeyHash =
      new Uint8Array(32).fill(31);
    if (fixture.caseName === "rekeyStaleDeviceGrant")
      trust.signedDeviceGrant.current_epoch = 1;
    if (fixture.caseName === "rekeyStaleGrant") ownerRekeyGrant.catalogDigest =
      b64(new Uint8Array(32).fill(14));
    if (fixture.caseName === "rekeyWrongEpoch") ownerRekeyGrant.currentEpoch = 1;
    if (fixture.caseName === "rekeyWrongMetadataKey")
      ownerRekeyGrant.currentMetadataKeySha256 = b64(new Uint8Array(32).fill(99));
    if (fixture.caseName === "rekeyExpiredGrant") ownerRekeyGrant.expiresAt = 1699999999;
    // Re-sign adversarial semantic mutations with the actual owner, rather
    // than accidentally testing only malformed Ed25519 signatures.
    if (["rekeyStaleGrant", "rekeyWrongEpoch", "rekeyWrongMetadataKey",
      "rekeyExpiredGrant"].includes(fixture.caseName)) {
      const changed = Object.fromEntries(Object.keys(grantPayload)
        .map((key) => [key, ownerRekeyGrant[key]]));
      ownerRekeyGrant.signature = b64(new Uint8Array(await root.crypto.subtle.sign(
        "Ed25519", owner.privateKey, new Uint8Array([...rekeyDomain,
          ...te.encode(JSON.stringify(changed))]))));
    }
    const client = root.RootarkZk1OpaqueDeviceDeltaSync.createClient({
      authority: trust, assertLive() { return live; } });
    const baseline = await client.readCurrent();
    if (["valid", "rekeyValid"].includes(fixture.caseName)) {
      let genericResurrectionRejected = false;
      try {
        await client.commitVersion({ previous: baseline, objectId: fixture.objectId,
          expectedRevision: 2, revision: 3, epoch: activeEpoch,
          ciphertext: new Uint8Array(32).fill(88), name: "forged-generic-resurrection.txt",
          metadataKey });
      } catch (error) {
        genericResurrectionRejected =
          error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED";
      }
      strict(genericResurrectionRejected && pending === null && puts === 0,
        "UNAUTHORIZED_GENERIC_RESURRECTION");
    }
    if (fixture.caseName === "logout") live = false;
    const selectedMetadata = { ...original,
      version_id: fixture.caseName === "wrongAncestry"
        ? b64(new Uint8Array(16).fill(17)) : original.version_id };
    const key = fixture.caseName === "wrongCek"
      ? await root.RootarkZk1FileContent.importFileCek(new Uint8Array(32).fill(7)) : cek;
    try {
      const rekeyOptions = rekey && fixture.caseName !== "rekeyNoGrant"
        ? { ownerRekeyGrant, currentEpochCekRaw: nextCekRaw,
          currentEpochMetadataKeyRaw: nextMetadataRaw,
          tombstoneMetadataKey } : {};
      const result = await client.restoreVersion({ previous: baseline,
        objectId: fixture.objectId, metadataKey, sourceMetadata: selectedMetadata,
        sourceCek: key, ...rekeyOptions });
      strict(["valid", "rekeyValid"].includes(fixture.caseName), "UNSAFE_RESTORE_ACCEPTED");
      strict(result.state === "restored" && result.revision === 3
        && result.tombstoneSignedAndVerified && result.originalHistoryPreserved
        && result.journalClearedAfterSignedProof && !result.serverPlaintextExposed
        && !result.physicalDeletionAuthorized && confirmed
        && pending === null && puts === 1
        && gets === (rekey ? 3 : 2), "SUCCESS_INVARIANT");
      strict(result.independentlyOwnerSignedEpochRekey === rekey
        && result.originalCekReused === !rekey, "REKEY_PROOF_FLAG");
      const opened = await root.RootarkZk1FileContent.decryptFile({
        cek: rekey ? await root.RootarkZk1FileContent.importFileCek(nextCekRaw) : cek,
        metadata: restoreMetadata, envelopeBytes: committedCiphertext });
      strict(opened.name === "restored-private-name.txt"
        && new TextDecoder().decode(opened.data) === "private-file-content"
        && restoreMetadata.parent_version_id === original.version_id
        && restoreMetadata.version_id !== original.version_id,
      "RE_ENCRYPTED_RESTORED_CONTENT");
      opened.data.fill(0);
      let replayDenied = false;
      try { await client.restoreVersion({ previous: baseline,
        objectId: fixture.objectId, metadataKey, sourceMetadata: original, sourceCek: cek }); }
      catch (error) { replayDenied = error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED"; }
      strict(replayDenied && puts === 1, "CAS_REPLAY_ACCEPTED");
      return { caseName: fixture.caseName, result: "PASS", puts, gets };
    } catch (error) {
      if (["valid", "rekeyValid"].includes(fixture.caseName)) throw error;
      if (fixture.caseName === "rekeyExpiredInCommit") {
        strict(error.code === "ZK_OPAQUE_DELTA_COMMIT_UNCERTAIN"
          && error.outcome?.retrySafe === false && pending !== null
          && puts === 1 && !confirmed,
        "EXPIRED_CAS_JOURNAL_MUST_REMAIN_UNCERTAIN");
      } else if (["lostReadback", "rekeyLostReadback"].includes(fixture.caseName)) {
        strict(error.code === "ZK_OPAQUE_DELTA_PUT_UNCERTAIN"
          && error.outcome?.retrySafe === false && pending !== null
          && puts === 1 && !confirmed, "UNCERTAIN_JOURNAL_NOT_PRESERVED");
      } else {
        strict(error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED"
          && puts === 0 && !confirmed, "PREPUT_FAILURE_NOT_CLOSED:" + fixture.caseName + ":" + error.message);
      }
      return { caseName: fixture.caseName, result: "PASS", puts, gets };
    }
  };
}(typeof window === "object" ? window : globalThis));
