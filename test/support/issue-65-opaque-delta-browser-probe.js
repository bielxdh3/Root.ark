(function (root) {
  "use strict";
  // Portable browser contract probe. Cryptographic owner/CAS/GET acceptance is
  // separately checked against the REAL signed Express/SQLite fixture.
  const b64 = (raw) => {
    let text = "";
    for (const n of raw) text += String.fromCharCode(n);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const raw64 = (encoded) => Uint8Array.from(atob(encoded.replace(/-/g, "+")
    .replace(/_/g, "/").padEnd(Math.ceil(encoded.length / 4) * 4, "=")),
  (x) => x.charCodeAt(0));
  function make(version) {
    const rows = Array.from({ length: version }, (_, n) => ({
      object_id: b64(new Uint8Array(16).fill(17)), revision: n + 1,
      epoch: 1, ciphertext_digest: new Uint8Array(32).fill(n + 1),
      metadata_ciphertext: new Uint8Array(284).fill(77),
    }));
    return { head: { sequence: version, digest: new Uint8Array(32).fill(version) }, rows };
  }
  root.runOpaqueDeltaBrowserProbe = async function () {
    const first = make(1), successor = make(2);
    const fixture = root.__deltaCryptoFixture;
    if (fixture) {
      first.rows[0].object_id = fixture.objectId;
      first.rows[0].metadata_ciphertext = raw64(fixture.ciphertextBase64);
    }
    const wireId = first.rows[0].object_id;
    let live = true, gets = 0, changed = false;
    root.RootarkZk1BrowserOpaqueCatalogCommit.createClient = function () {
        return {
          async readAll() { return changed ? successor : first; },
          async readSignedSuccessor(previous) {
            if (previous !== first) throw Error("NOT_VERIFIED");
            changed = true;
            return { snapshot: successor, additions: [{ objectId: wireId,
              revision: 2, epoch: 1, ciphertextDigestBase64: b64(new Uint8Array(32).fill(2)),
              metadataCiphertextBase64: b64(new Uint8Array(284).fill(77)) }] };
          },
          async readVerifiedCiphertext() {
            gets++;
            return { objectId: wireId, revision: 2, epoch: 1,
              ciphertextDigestBase64: b64(new Uint8Array(32).fill(2)),
              ciphertextBase64: b64(new Uint8Array(32).fill(88)) };
          },
        };
      };
    const sync = root.RootarkZk1OpaqueDeviceDeltaSync.createClient({
      authority: { signedDeviceGrant: fixture?.scope || {}, pinnedOwnerHead: { epoch: 1,
        digest: new Uint8Array(32) }, signerGrants: [],
      csrfToken: () => "csrf-a", isSessionCurrent: () => live },
      assertLive() { if (!live) throw Error("LOGOUT"); },
    });
    const before = await sync.readCurrent();
    const metadataKey = await root.crypto.subtle.importKey("raw",
      new Uint8Array(32).fill(12), "AES-GCM", false, ["decrypt"]);
    let listingRejected = false;
    try { await sync.readPrivateListing(before, metadataKey); } catch (error) {
      listingRejected = error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED";
    }
    if (!listingRejected) throw Error("UNVERIFIED_PRIVATE_LISTING");
    if (fixture) {
      const rightKey = await root.crypto.subtle.importKey("raw",
        raw64(fixture.metadataKeyBase64), "AES-GCM", false, ["decrypt"]);
      const opened = await sync.readPrivateListing(before, rightKey);
      if (opened.entries.length !== 1 || opened.entries[0].name !== fixture.name
        || !opened.independentlySignedCatalog || opened.plaintextSentToServer)
        throw Error("PRIVATE_LISTING_NOT_OPENED_LOCALLY");
      const wrongScope = { ...fixture.scope, keyring_id: b64(new Uint8Array(16).fill(99)) };
      let aadRejected = false;
      try { await root.RootarkZk1BrowserOpaqueCatalogCommit.openMetadata({
        scope: wrongScope, objectId: fixture.objectId, revision: 1, epoch: 1,
        metadataKey: rightKey, ciphertext: raw64(fixture.ciphertextBase64),
      }); } catch (error) { aadRejected = error.message === "ZK_BROWSER_CATALOG_UNVERIFIED"; }
      if (!aadRejected) throw Error("CROSS_ACCOUNT_AAD_REPLAY");
      // Real Edge WebCrypto: independent Ed25519 signed tombstone, AES-GCM
      // ciphertext with scope+revision AAD and authentic catalog metadata.
      const signing = await root.crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
      const trashKey = await root.crypto.subtle.importKey("raw",
        raw64(fixture.metadataKeyBase64), "AES-GCM", false, ["encrypt", "decrypt"]);
      const signerPublic = new Uint8Array(await root.crypto.subtle.exportKey("raw", signing.publicKey));
      const prevDigest = new Uint8Array(32).fill(11);
      const previousMetadata = raw64(fixture.ciphertextBase64);
      const digest = async (raw) => new Uint8Array(await root.crypto.subtle.digest("SHA-256", raw));
      const parentCipherDigest = new Uint8Array(32).fill(18);
      const statement = {
        format: "rootark-zk1-opaque-logical-trash/v1", ...fixture.scope,
        deviceId: "edge-issuer", objectId: fixture.objectId,
        parentRevision: 1, parentEpoch: 1, parentDigest: b64(parentCipherDigest),
        parentMetadataDigest: b64(await digest(previousMetadata)),
        revision: 2, epoch: 1, previousSequence: 1, previousDigest: b64(prevDigest),
        ownerRevision: 1, ownerDigest: b64(new Uint8Array(32).fill(8)),
        nonce: b64(root.crypto.getRandomValues(new Uint8Array(32))),
        issuedAt: 1700000000,
      };
      const domain = new TextEncoder().encode("Root.ark/zk-1/opaque-logical-trash/v1\0");
      const message = new TextEncoder().encode(JSON.stringify(statement));
      const signed = new Uint8Array(await root.crypto.subtle.sign("Ed25519",
        signing.privateKey, new Uint8Array([...domain, ...message])));
      const plaintext = new TextEncoder().encode(JSON.stringify({
        statement, signature: b64(signed) }));
      const aad = new TextEncoder().encode("Root.ark/zk-1/opaque-logical-trash-aead/v1\0"
        + JSON.stringify({ ...fixture.scope, objectId: fixture.objectId, revision: 2, epoch: 1 }));
      const iv = root.crypto.getRandomValues(new Uint8Array(12));
      const encrypted = new Uint8Array(await root.crypto.subtle.encrypt({
        name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, trashKey, plaintext));
      plaintext.fill(0);
      const envelope = new Uint8Array(12 + encrypted.length);
      envelope.set(iv); envelope.set(encrypted, 12);
      const candidate = {
        head: { sequence: 2, digest: new Uint8Array(32).fill(12) },
        rows: [
          { object_id: fixture.objectId, revision: 1, epoch: 1,
            ciphertext_digest: parentCipherDigest, metadata_ciphertext: previousMetadata },
          { object_id: fixture.objectId, revision: 2, epoch: 1,
            ciphertext_digest: await digest(envelope),
            metadata_ciphertext: raw64(fixture.trashMetadataBase64) },
        ],
      };
      let badGet = false;
      // The Edge probe isolates the AES-GCM/Ed25519 browser primitive. The
      // full owner grant, CAS and historical header verification is exercised
      // against the signed HTTP/SQLite fixture, not these local stubs.
      const verifiedLocalAuthority = {
        async readSignedHistoricalHead(snapshot, sequence, expectedRow) {
          if (snapshot !== candidate || sequence !== 2
            || expectedRow.objectId !== fixture.objectId || expectedRow.revision !== 2)
            throw Error("UNVERIFIED_HISTORY");
          return { exactHistoricalAuthorityVerified: true, previousDigest: b64(prevDigest),
            epoch: 1, manifestRevision: 1, manifestDigest: statement.ownerDigest,
            issuedAt: 1700000000 };
        },
        async verifyAuthorizedSigner(deviceId, epoch) {
          if (deviceId !== "edge-issuer" || epoch !== 1) throw Error("UNVERIFIED_SIGNER");
          return signing.publicKey;
        },
        async verifyHistoricalSigner(deviceId, epoch, revision, digest) {
          if (deviceId !== "edge-issuer" || epoch !== 1 || revision !== 1
            || b64(digest) !== statement.ownerDigest) throw Error("UNVERIFIED_HISTORICAL_OWNER_GRANT");
          return signing.publicKey;
        },
      };
      root.RootarkZk1BrowserOpaqueCatalogCommit.createClient = () => ({
        ...verifiedLocalAuthority,
        async readAll() { return candidate; },
        async readVerifiedPredecessorDigest() { return prevDigest; },
        async readVerifiedCiphertext() {
          const raw = envelope.slice();
          if (badGet) raw[raw.length - 1] ^= 1;
          return { ciphertextBase64: b64(raw) };
        },
      });
      const trust = { signedDeviceGrant: { ...fixture.scope, device_id: "edge-reader" },
        pinnedOwnerHead: { revision: 1, epoch: 1, digest: new Uint8Array(32).fill(8) },
        signerGrants: [{ device_id: "edge-issuer", authorization_public_key: b64(signerPublic),
          revoked_at_epoch: null, current_epoch: 1 }],
        csrfToken: () => "edge-csrf", isSessionCurrent: () => true, nowSeconds: () => 1700000000 };
      const newReader = () => root.RootarkZk1OpaqueDeviceDeltaSync.createClient({
        authority: trust, assertLive() { return true; } });
      const reader = newReader(), pinned = await reader.readCurrent();
      const tombstone = await reader.readTrash({
        previous: pinned, objectId: fixture.objectId, metadataKey: trashKey });
      if (!tombstone.signedByAuthorizedDevice || tombstone.retainedHistoricalVersions !== 1
        || tombstone.state !== "trashed") throw Error("EDGE_TRASH_SIGNATURE_NOT_VERIFIED");
      // A party with only the AES metadata key may replace encrypted bytes,
      // but cannot manufacture the missing Ed25519 device signature.
      const alteredSignature = signed.slice();
      alteredSignature[0] ^= 1;
      const reencrypted = new TextEncoder().encode(JSON.stringify({
        statement, signature: b64(alteredSignature) }));
      const anotherIv = root.crypto.getRandomValues(new Uint8Array(12));
      const anotherEncrypted = new Uint8Array(await root.crypto.subtle.encrypt({
        name: "AES-GCM", iv: anotherIv, additionalData: aad, tagLength: 128 },
      trashKey, reencrypted));
      reencrypted.fill(0);
      const originalEnvelope = envelope.slice();
      const forgedEnvelope = new Uint8Array(anotherIv.length + anotherEncrypted.length);
      forgedEnvelope.set(anotherIv); forgedEnvelope.set(anotherEncrypted, anotherIv.length);
      root.RootarkZk1BrowserOpaqueCatalogCommit.createClient = () => ({
        ...verifiedLocalAuthority,
        async readAll() { return candidate; },
        async readVerifiedPredecessorDigest() { return prevDigest; },
        async readVerifiedCiphertext() { return { ciphertextBase64: b64(forgedEnvelope) }; },
      });
      const alteredReader = newReader(), alteredBase = await alteredReader.readCurrent();
      let signatureRejected = false;
      try { await alteredReader.readTrash({ previous: alteredBase,
        objectId: fixture.objectId, metadataKey: trashKey }); }
      catch (error) { signatureRejected = error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED"; }
      if (!signatureRejected) throw Error("EDGE_INVALID_SIGNER_ACCEPTED");
      root.RootarkZk1BrowserOpaqueCatalogCommit.createClient = () => ({
        ...verifiedLocalAuthority,
        async readAll() { return candidate; },
        async readVerifiedPredecessorDigest() { return prevDigest; },
        async readVerifiedCiphertext() {
          const raw = originalEnvelope.slice();
          if (badGet) raw[raw.length - 1] ^= 1;
          return { ciphertextBase64: b64(raw) };
        },
      });
      badGet = true;
      const forgedReader = newReader(), forgedBase = await forgedReader.readCurrent();
      let forgedRejected = false;
      try { await forgedReader.readTrash({ previous: forgedBase,
        objectId: fixture.objectId, metadataKey: trashKey }); }
      catch (error) { forgedRejected = error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED"; }
      if (!forgedRejected) throw Error("EDGE_TRASH_FORGED_CIPHERTEXT_ACCEPTED");
      badGet = false;
      // After owner rotation, only a correctly epoch-indexed AES key may
      // inspect the old encrypted tombstone. This path is strictly read-only.
      trust.pinnedOwnerHead = { revision: 2, epoch: 2,
        digest: new Uint8Array(32).fill(9) };
      const oldReadOnlyKey = await root.crypto.subtle.importKey("raw",
        raw64(fixture.metadataKeyBase64), "AES-GCM", false, ["decrypt"]);
      const historicalReader = newReader(), historicalBaseline = await historicalReader.readCurrent();
      const old = await historicalReader.readTrash({ previous: historicalBaseline,
        objectId: fixture.objectId, historicalMetadataKeys: [{ epoch: 1, key: oldReadOnlyKey }] });
      if (!old.historicEpochVerifiedReadOnly || old.mutationAuthorized !== false
        || old.ownerApprovedRekeyRequired !== true) throw Error("EDGE_HISTORIC_TRASH_NOT_READ_ONLY");
      const wrongEpochReader = newReader(), wrongEpochBase = await wrongEpochReader.readCurrent();
      let wrongEpochDenied = false;
      try { await wrongEpochReader.readTrash({ previous: wrongEpochBase,
        objectId: fixture.objectId, historicalMetadataKeys: [{ epoch: 2, key: oldReadOnlyKey }] }); }
      catch (error) { wrongEpochDenied = error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED"; }
      if (!wrongEpochDenied) throw Error("EDGE_HISTORIC_KEY_EPOCH_DOWNGRADE");
    }
    if (before.head.sequence !== 1 || before.entries.length !== 1
      || Object.hasOwn(before.entries[0], "name")) throw Error("PLAIN_METADATA");
    const delta = await sync.pullDelta(before);
    if (delta.additions.length !== 1 || delta.toSequence !== 2 || gets !== 1
      || delta.additions[0].metadataCiphertextBase64 !== b64(new Uint8Array(284).fill(77))
      || JSON.stringify(delta).includes("secret-owner-filename")) throw Error("WRONG_DELTA");
    let rejected = false;
    try { await sync.pullDelta(before); } catch (error) {
      rejected = error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED";
    }
    if (!rejected) throw Error("REPLAY_NOT_REJECTED");
    live = false;
    rejected = false;
    try { await sync.readCurrent(); } catch (error) {
      rejected = error.message === "ZK_OPAQUE_DELTA_SYNC_DENIED";
    }
    if (!rejected) throw Error("SESSION_NOT_REJECTED");
    return "PASS";
  };
  if (typeof document === "object") root.addEventListener("load", () => {
    root.runOpaqueDeltaBrowserProbe().then(() => {
      document.getElementById("probe-result").textContent = "EDGE_OPAQUE_DELTA_PASS";
    }, (error) => {
      document.getElementById("probe-result").textContent = "EDGE_OPAQUE_DELTA_FAIL:" + error.message;
    });
  });
}(typeof window === "object" ? window : globalThis));
