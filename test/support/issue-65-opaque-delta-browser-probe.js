(function (root) {
  "use strict";
  // Portable browser contract probe. Cryptographic owner/CAS/GET acceptance is
  // separately checked against the REAL signed Express/SQLite fixture.
  const b64 = (raw) => {
    let text = "";
    for (const n of raw) text += String.fromCharCode(n);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
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
      authority: { signedDeviceGrant: {}, pinnedOwnerHead: { epoch: 1,
        digest: new Uint8Array(32) }, signerGrants: [],
      csrfToken: () => "csrf-a", isSessionCurrent: () => live },
      assertLive() { if (!live) throw Error("LOGOUT"); },
    });
    const before = await sync.readCurrent();
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
