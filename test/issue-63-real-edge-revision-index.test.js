"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { spawn, execFileSync } = require("node:child_process");

test("real Edge IndexedDB protects 128 historical revisions across signed CAS, pages and session expiry", {
  timeout: 85_000,
}, async (t) => {
  const edgeFile = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edgeFile)) {
    t.skip("Real Windows Edge unavailable");
    return;
  }
  let stage = "fixture";
  t.after(() => { if (stage !== "complete") t.diagnostic("EDGE_REVISION_INDEX_STAGE " + stage); });
  // The probe synthesizes all plaintext, offline keys and a real Ed25519
  // signed baseline inside Edge. No query, plaintext, key or CEK is served.
  const probe = `window.addEventListener("load", async () => {
    const output=document.getElementById("result");
    const encoder=new TextEncoder();
    const b64=bytes=>btoa(String.fromCharCode(...bytes)).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"");
    const random=n=>crypto.getRandomValues(new Uint8Array(n));
    const id=()=>b64(random(16));
    const deny=async fn=>{try{await fn();return false;}catch(e){return e?.message==="ZK_REVISION_INDEX_DENIED";}};
    let phase="initialize";
    try {
      const index=window.RootarkZk1ProtectedRevisionIndex;
      if(!index?.append||!index?.search)throw Error("MODULE_NOT_LOADED");
      const scope={account_id:id(),compartment_id:id(),keyring_id:id()};
      const ownerDigest=b64(random(32));
      let grant={...scope,device_id:id(),manifest_revision:8,
        manifest_digest:ownerDigest,current_epoch:2,revoked_at_epoch:null};
      let ownerHead={revision:8,epoch:2,digest:ownerDigest};
      const oid=id();
      const rows=Array.from({length:128},(_,i)=>({objectId:oid,revision:i+1,
        epoch:2,ciphertextDigestBase64:b64(random(32)),
        name:"browser-test-"+(i+1)+".txt",mediaType:"text/plain",
        text:"owner-private browser fixture revision "+(i+1)+" needle"}));
      const baseline={head:{sequence:17,digest:b64(random(32))},
        entries:rows.map(({objectId,revision,epoch,ciphertextDigestBase64})=>
          ({objectId,revision,epoch,ciphertextDigestBase64}))};
      const signing=await crypto.subtle.generateKey("Ed25519",false,["sign","verify"]);
      const signed=async()=>new Uint8Array(await crypto.subtle.sign("Ed25519",
        signing.privateKey,encoder.encode(JSON.stringify(baseline))));
      let signature=await signed(),live=true, checks=0;
      const ownerWire=()=>encoder.encode(JSON.stringify({grant,ownerHead}));
      const signedOwner=async()=>new Uint8Array(await crypto.subtle.sign("Ed25519",
        signing.privateKey,ownerWire()));
      let signedGrant=await signedOwner();
      const metadataRaw=random(32);
      const client={async verifyPrivateListingHead() {
        checks++;
        if(!live||!await crypto.subtle.verify("Ed25519",signing.publicKey,
          signature,encoder.encode(JSON.stringify(baseline))))throw Error("HEAD_NOT_AUTHORIZED");
        return {scope,head:baseline.head};
      }};
      const input=()=>({grant,ownerHead,baseline,metadataRaw,client,
        indexedDBImpl:indexedDB,assertLive:()=>live,
        async verifyOwnerGrant(){
          if(!await crypto.subtle.verify("Ed25519",signing.publicKey,
            signedGrant,ownerWire()))throw Error("OWNER_GRANT_REVOKED");
          return {verifiedCurrent:true,grant,ownerHead};
        }});
      phase="real-idb-single-owner-selected-128-batch";
      const oneShot=await index.append({...input(),entries:rows});
      if(oneShot.indexedCount!==128||!oneShot.persistedIndex
        ||oneShot.coverage!=="owner-selected-revisions-only")
        throw Error("SINGLE_VERIFIED_128_NOT_COMMITTED");
      await index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live});
      phase="real-idb-insert";
      const one=await index.append({...input(),entries:rows.slice(0,64)});
      const two=await index.append({...input(),entries:rows.slice(64)});
      if(one.indexedCount!==64||two.indexedCount!==128||two.discardedCount!==0)
        throw Error("WRONG_INDEX_COUNT");
      phase="real-idb-at-rest";
      const readStored=()=>new Promise((resolve,reject)=>{
        const request=indexedDB.open("rootark-zk1-protected-revision-index-v1",1);
        request.onerror=()=>reject(Error("DB_OPEN"));
        request.onsuccess=()=>{
          const db=request.result;
          const transaction=db.transaction("revisions","readonly");
          const item=transaction.objectStore("revisions").get(JSON.stringify([
            scope.account_id,scope.compartment_id,scope.keyring_id]));
          item.onerror=()=>reject(Error("DB_READ"));
          item.onsuccess=()=>resolve(item.result);
          transaction.oncomplete=()=>db.close();
        };
      });
      const stored=await readStored();
      if(!stored?.ciphertext||JSON.stringify(stored).includes("owner-private")
        ||JSON.stringify(stored).includes("browser-test-"))throw Error("PLAINTEXT_AT_REST");
      phase="real-idb-paging";
      const first=await index.search({...input(),query:"needle"});
      const priorChecks=checks;
      const second=await first.readPage(50),third=await first.readPage(100);
      if(first.offset!==0||second.offset!==50||third.offset!==100
        ||first.entries.length!==50||second.entries.length!==50||third.entries.length!==28
        ||first.entries[0].revision!==1||second.entries[0].revision!==51
        ||third.entries[0].revision!==101||third.entries.at(-1).revision!==128
        ||third.hasNext||!third.hasPrevious||checks<priorChecks+2)
        throw Error("INACCESSIBLE_RESULTS");
      phase="real-signed-cas-migration";
      baseline.head={sequence:18,digest:b64(random(32))};
      signature=await signed();
      if(!await deny(()=>first.readPage(50)))throw Error("STALE_PAGE_RELEASED");
      const migrated=await index.append({...input(),entries:rows.slice(127)});
      if(migrated.indexedCount!==128||migrated.discardedCount!==0
        ||migrated.replacedIncompatibleIndex)throw Error("VALID_CAS_LOST_PREVIOUS");
      const current=await index.search({...input(),query:"needle"});
      if((await current.readPage(100)).entries.at(-1)?.revision!==128)
        throw Error("CAS_PAGINATION_FAILED");
      phase="real-idb-logout-cas";
      const originalGet=IDBObjectStore.prototype.get;
      let expiredInside=false;
      IDBObjectStore.prototype.get=function(key){
        const req=originalGet.call(this,key);
        if(!expiredInside&&this.transaction.mode==="readwrite"){
          expiredInside=true;
          queueMicrotask(()=>{live=false;});
        }
        return req;
      };
      let rejected=false;
      try { rejected=await deny(()=>index.append({...input(),entries:rows.slice(127)})); }
      finally { IDBObjectStore.prototype.get=originalGet; live=true; }
      if(!expiredInside||!rejected)throw Error("LOGOUT_DID_NOT_ABORT_IDB_WRITE");
      const unaffected=await index.search({...input(),query:"needle"});
      if(unaffected.indexedCount!==128)throw Error("LOGOUT_CORRUPTED_DB");
      phase="real-idb-post-put-logout";
      const beforePostPut=await readStored();
      const originalPut=IDBObjectStore.prototype.put;
      let postPutQueued=false;
      IDBObjectStore.prototype.put=function(value,key){
        const req=originalPut.call(this,value,key);
        if(!postPutQueued&&this.transaction.mode==="readwrite"){
          postPutQueued=true;
          queueMicrotask(()=>{live=false;});
        }
        return req;
      };
      let postPutDenied=false;
      try { postPutDenied=await deny(()=>index.append({...input(),entries:rows.slice(127)})); }
      finally { IDBObjectStore.prototype.put=originalPut; live=true; }
      if(!postPutQueued||!postPutDenied)throw Error("POST_PUT_LOGOUT_NOT_DENIED");
      const afterPostPut=await readStored();
      if(afterPostPut?.nonce!==beforePostPut.nonce)
        throw Error("POST_PUT_LOGOUT_PERSISTED_LOCAL_INDEX");
      phase="real-idb-post-put-success-event-logout";
      const beforeSuccessEvent=await readStored();
      const originalSuccessPut=IDBObjectStore.prototype.put;
      let successEventScheduled=false;
      IDBObjectStore.prototype.put=function(value,key){
        const req=originalSuccessPut.call(this,value,key);
        if(!successEventScheduled&&this.transaction.mode==="readwrite"){
          successEventScheduled=true;
          // This microtask runs AFTER put.onsuccess dispatched, but before
          // IndexedDB can autonomously commit the transaction.
          req.addEventListener("success",()=>queueMicrotask(()=>{live=false;}),
            {once:true});
        }
        return req;
      };
      let successEventDenied=false;
      try { successEventDenied=await deny(()=>index.append({...input(),entries:rows.slice(127)})); }
      finally { IDBObjectStore.prototype.put=originalSuccessPut; live=true; }
      if(!successEventScheduled||!successEventDenied)
        throw Error("POST_PUT_SUCCESS_EVENT_NOT_DENIED");
      const afterSuccessEvent=await readStored();
      if(afterSuccessEvent?.nonce!==beforeSuccessEvent.nonce)
        throw Error("POST_PUT_SUCCESS_EVENT_PERSISTED_LOCAL_INDEX");
      phase="real-idb-revoke";
      live=false;
      if(!await deny(()=>unaffected.readPage(100)))throw Error("REVOKED_PAGE_RELEASED");
      live=true;
      phase="real-idb-clear";
      const staleAfterClear=await index.search({...input(),query:"needle"});
      await index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live});
      if(!await deny(()=>index.search({...input(),query:"needle"})))
        throw Error("CLEAR_STILL_EXPOSED_CACHE");
      if(!await deny(()=>staleAfterClear.readPage(50)))
        throw Error("STALE_PAGE_AFTER_SCOPED_CLEAR");
      phase="real-idb-clear-inflight-append";
      const originalVerifyHead=client.verifyPrivateListingHead;
      let verificationCalls=0, unblockVerification, reachedVerification;
      const verificationGate=new Promise(resolve=>{unblockVerification=resolve;});
      const verificationPaused=new Promise(resolve=>{reachedVerification=resolve;});
      client.verifyPrivateListingHead=async (...args)=>{
        if(++verificationCalls===2){reachedVerification();await verificationGate;}
        return originalVerifyHead(...args);
      };
      const pendingAppend=index.append({...input(),entries:rows.slice(0,1)});
      await Promise.race([verificationPaused,new Promise((_resolve,reject)=>
        setTimeout(()=>reject(Error("PENDING_APPEND_NOT_REACHED")),8000))]);
      try {
        await index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live});
      }finally{unblockVerification();client.verifyPrivateListingHead=originalVerifyHead;}
      const rejectedAfterClear=await deny(()=>pendingAppend);
      if(!rejectedAfterClear)throw Error("POST_CLEAR_APPEND_REPERSISTED");
      const afterRacingClear=await readStored();
      if(afterRacingClear?.format!=="rootark-zk1-protected-revision-index-clear/v1"
        ||typeof afterRacingClear.nonce!=="string"
        ||Object.keys(afterRacingClear).sort().join(",")!=="format,nonce")
        throw Error("SCOPED_CLEAR_TOMBSTONE_MISSING");
      phase="real-idb-append-after-clear";
      const freshAppend=await index.append({...input(),entries:rows.slice(0,1)});
      if(freshAppend.indexedCount!==1)throw Error("FRESH_APPEND_AFTER_CLEAR_FAILED");
      const afterFresh=await readStored();
      if(!afterFresh?.ciphertext||afterFresh.nonce===afterRacingClear.nonce
        ||JSON.stringify(afterFresh).includes("owner-private"))
        throw Error("POST_CLEAR_FRESH_APPEND_NOT_SEALED");
      if(!await deny(()=>staleAfterClear.readPage(50)))
        throw Error("STALE_PAGE_REOPENED_AFTER_FRESH_APPEND");
      await index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live});
      const repeatedClear=await readStored();
      if(repeatedClear?.format!=="rootark-zk1-protected-revision-index-clear/v1"
        ||repeatedClear.nonce===afterRacingClear.nonce
        ||JSON.stringify(repeatedClear).includes("owner-private"))
        throw Error("REPEATED_CLEAR_TOMBSTONE_INVALID");
      phase="real-idb-pre-context-clear-race";
      const originalDigest=crypto.subtle.digest;
      let digestPaused=false,digestReleased,digestReached;
      const digestGate=new Promise(resolve=>{digestReleased=resolve;});
      const digestWaiting=new Promise(resolve=>{digestReached=resolve;});
      crypto.subtle.digest=function(...args){
        if(!digestPaused&&args[0]==="SHA-256"){
          digestPaused=true;digestReached();
          return digestGate.then(()=>originalDigest.apply(this,args));
        }
        return originalDigest.apply(this,args);
      };
      const earlyAppend=index.append({...input(),entries:rows.slice(0,1)});
      try {
        await Promise.race([digestWaiting,new Promise((_resolve,reject)=>
          setTimeout(()=>reject(Error("EARLY_CONTEXT_DIGEST_NOT_PAUSED")),8000))]);
        await index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live});
      }finally{crypto.subtle.digest=originalDigest;digestReleased();}
      if(!await deny(()=>earlyAppend))throw Error("PRE_CONTEXT_CLEAR_APPEND_REPERSISTED");
      const afterEarlyClear=await readStored();
      if(afterEarlyClear?.format!=="rootark-zk1-protected-revision-index-clear/v1")
        throw Error("PRE_CONTEXT_CLEAR_TOMBSTONE_LOST");
      phase="real-idb-inflight-first-page-after-clear";
      await index.append({...input(),entries:rows.slice(0,1)});
      const beforeFirstPage=client.verifyPrivateListingHead;
      let headCalls=0,firstPageUnblock,firstPageReached;
      const firstPageGate=new Promise(resolve=>{firstPageUnblock=resolve;});
      const firstPageWaiting=new Promise(resolve=>{firstPageReached=resolve;});
      client.verifyPrivateListingHead=async (...args)=>{
        if(++headCalls===2){firstPageReached();await firstPageGate;}
        return beforeFirstPage(...args);
      };
      const inFlightFirstPage=index.search({...input(),query:"needle"});
      try {
        await Promise.race([firstPageWaiting,new Promise((_resolve,reject)=>
          setTimeout(()=>reject(Error("FIRST_PAGE_VERIFY_NOT_PAUSED")),8000))]);
        await index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live});
      }finally{client.verifyPrivateListingHead=beforeFirstPage;firstPageUnblock();}
      if(!await deny(()=>inFlightFirstPage))
        throw Error("PRIVATE_FIRST_PAGE_RELEASED_AFTER_CLEAR");
      phase="real-idb-cross-realm-web-lock";
      if(typeof navigator.locks?.request!=="function")
        throw Error("BROWSER_WEB_LOCKS_UNAVAILABLE");
      const frame=document.createElement("iframe");
      frame.src="/frame.html";
      document.body.append(frame);
      await Promise.race([new Promise((resolve,reject)=>{
        frame.addEventListener("load",resolve,{once:true});
        frame.addEventListener("error",()=>reject(Error("FRAME_LOAD_FAILED")),{once:true});
      }),new Promise((_resolve,reject)=>
        setTimeout(()=>reject(Error("FRAME_LOAD_TIMEOUT")),8000))]);
      const other=frame.contentWindow;
      const otherIndex=other?.RootarkZk1ProtectedRevisionIndex;
      if(!otherIndex?.append||!other?.indexedDB)
        throw Error("CROSS_REALM_INDEX_NOT_LOADED");
      const lockName="rootark-zk1-protected-revision-index-v1/"+
        JSON.stringify([scope.account_id,scope.compartment_id,scope.keyring_id]);
      let unblockHeldLock,heldLockReached;
      const heldLockGate=new Promise(resolve=>{unblockHeldLock=resolve;});
      const heldLockReady=new Promise(resolve=>{heldLockReached=resolve;});
      const holdLock=navigator.locks.request(lockName,{mode:"exclusive"},async()=>{
        heldLockReached();await heldLockGate;
      });
      await heldLockReady;
      let otherHeadCalls=0,unblockOtherHead,otherHeadReached;
      const otherHeadGate=new Promise(resolve=>{unblockOtherHead=resolve;});
      const otherClient={...client,async verifyPrivateListingHead(...args){
        if(++otherHeadCalls===1)await otherHeadGate;
        return client.verifyPrivateListingHead(...args);
      }};
      const otherInput={...input(),client:otherClient,
        indexedDBImpl:other.indexedDB,
        metadataRaw:new other.Uint8Array(metadataRaw)};
      const otherPending=otherIndex.append({...otherInput,entries:rows.slice(0,1)});
      // Clear is invoked AFTER the other tab queued its initial scoped lock,
      // while both are blocked by an unrelated same-origin lock holder.
      const clearPending=index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live});
      try {
        unblockHeldLock();await holdLock;
        await clearPending;
      }finally{unblockHeldLock();unblockOtherHead();}
      const crossRealmMarker=await readStored();
      let crossRealmOutcome="RESOLVED";
      try{await otherPending;}catch(error){crossRealmOutcome=error?.message||"UNKNOWN_ERROR";}
      const parentAfterOther=await readStored();
      const otherAfterOther=await new Promise((resolve,reject)=>{
        const op=other.indexedDB.open("rootark-zk1-protected-revision-index-v1",1);
        op.onerror=()=>reject(Error("FRAME_DB_OPEN"));
        op.onsuccess=()=>{
          const db=op.result;
          const tx=db.transaction("revisions","readonly");
          const get=tx.objectStore("revisions").get(JSON.stringify([
            scope.account_id,scope.compartment_id,scope.keyring_id]));
          get.onerror=()=>reject(Error("FRAME_DB_GET"));
          get.onsuccess=()=>resolve(get.result);
          tx.oncomplete=()=>db.close();
        };
      });
      if(crossRealmOutcome!=="ZK_REVISION_INDEX_DENIED")
        throw Error("CROSS_REALM_PRE_CLEAR_APPEND_REPERSISTED:"+crossRealmOutcome+
          ":"+crossRealmMarker?.format+":"+parentAfterOther?.format+
          ":"+otherAfterOther?.format+":"+location.origin+
          ":"+other.location.origin);
      if(crossRealmMarker?.format!=="rootark-zk1-protected-revision-index-clear/v1")
        throw Error("CROSS_REALM_TOMBSTONE_LOST");
      if(parentAfterOther?.format!==crossRealmMarker.format
        ||otherAfterOther?.format!==crossRealmMarker.format)
        throw Error("CROSS_REALM_OLD_APPEND_PERSISTED_AFTER_CLEAR");
      const scopedStorageKey="rootark-zk1-protected-revision-index-v1/clear/"+
        JSON.stringify([scope.account_id,scope.compartment_id,scope.keyring_id]);
      const crossRealmStamp=localStorage.getItem(scopedStorageKey);
      if(crossRealmStamp!==parentAfterOther.nonce
        ||other.localStorage.getItem(scopedStorageKey)!==crossRealmStamp
        ||!/^[-A-Za-z0-9_]{22}$/.test(crossRealmStamp)
        ||crossRealmStamp.includes("owner-private"))
        throw Error("CROSS_REALM_SHARED_GENERATION_NOT_OPAQUE");
      const freshOther=await otherIndex.append({...otherInput,client,
        entries:rows.slice(0,1)});
      const freshCrossRealmRow=await readStored();
      if(freshOther.indexedCount!==1
        ||freshCrossRealmRow?.format!=="rootark-zk1-protected-revision-index/v1"
        ||freshCrossRealmRow.clearNonce!==crossRealmStamp
        ||JSON.stringify(freshCrossRealmRow).includes("owner-private"))
        throw Error("FRESH_CROSS_REALM_APPEND_AFTER_CLEAR_FAILED");
      phase="real-idb-cross-realm-first-page-clear";
      let pageVerifications=0,unblockFramePage,framePageReached;
      const framePageGate=new Promise(resolve=>{unblockFramePage=resolve;});
      const framePageReady=new Promise(resolve=>{framePageReached=resolve;});
      const frameSearchClient={...client,async verifyPrivateListingHead(...args){
        if(++pageVerifications===2){framePageReached();await framePageGate;}
        return client.verifyPrivateListingHead(...args);
      }};
      const frameSearch=otherIndex.search({...otherInput,client:frameSearchClient,
        query:"needle"});
      await Promise.race([framePageReady,new Promise((_resolve,reject)=>
        setTimeout(()=>reject(Error("CROSS_REALM_FIRST_PAGE_NOT_PAUSED")),8000))]);
      try { await index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live}); }
      finally { unblockFramePage(); }
      if(!await deny(()=>frameSearch))
        throw Error("CROSS_REALM_PRIVATE_FIRST_PAGE_AFTER_CLEAR");
      phase="real-idb-concurrent-cross-realm-clears";
      await Promise.all([
        index.clear({grant,indexedDBImpl:indexedDB,assertLive:()=>live}),
        otherIndex.clear({grant,indexedDBImpl:other.indexedDB,assertLive:()=>live}),
      ]);
      const afterConcurrentClears=await readStored();
      if(afterConcurrentClears?.format!=="rootark-zk1-protected-revision-index-clear/v1"
        ||afterConcurrentClears.nonce!==localStorage.getItem(scopedStorageKey)
        ||afterConcurrentClears.nonce!==other.localStorage.getItem(scopedStorageKey))
        throw Error("CONCURRENT_CLEARS_LEFT_INCONSISTENT_GENERATION");
      const opaqueStamp=afterConcurrentClears.nonce;
      localStorage.setItem(scopedStorageKey,"malformed");
      const malformedDenied=await deny(()=>index.append({...input(),entries:rows.slice(0,1)}));
      localStorage.setItem(scopedStorageKey,opaqueStamp);
      if(!malformedDenied)throw Error("MALFORMED_SHARED_GENERATION_AUTHORIZED_APPEND");
      frame.remove();
      metadataRaw.fill(0);
      output.textContent="EDGE_REVISION_INDEX_PASS";
    }catch(error){output.textContent="EDGE_REVISION_INDEX_FAIL:"+phase+":"+error.message;}
  });`;
  const server = http.createServer((request, response) => {
    if (request.url === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'none'; script-src 'self'; connect-src 'self'; frame-src 'self'" });
      response.end("<!doctype html><meta charset='utf-8'><output id='result'>PENDING</output>"
        + "<script defer src='/client/rootark-zk1-protected-revision-index.js'></script>"
        + "<script defer src='/probe.js'></script>");
    } else if (request.url === "/frame.html") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'none'; script-src 'self'" });
      response.end("<!doctype html><meta charset='utf-8'>"
        + "<script defer src='/client/rootark-zk1-protected-revision-index.js'></script>");
    } else if (request.url === "/client/rootark-zk1-protected-revision-index.js") {
      response.writeHead(200, { "content-type": "text/javascript" });
      response.end(fs.readFileSync(path.join(__dirname,
        "../public/client/rootark-zk1-protected-revision-index.js")));
    } else if (request.url === "/probe.js") {
      response.writeHead(200, { "content-type": "text/javascript" });
      response.end(probe);
    } else { response.writeHead(404); response.end(); }
  });
  stage = "listen";
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue63-edge-index-"));
  const profile = path.join(directory, "edge-profile");
  let edge, socket;
  let complete = false;
  try {
    stage = "launch";
    edge = spawn(edgeFile, ["--headless=new", "--disable-gpu", "--no-first-run",
      "--disable-extensions", "--remote-debugging-port=0",
      "--user-data-dir=" + profile, "about:blank"], { stdio: "ignore", windowsHide: true });
    const waitFor = async (fn, ms = 26000) => {
      const deadline = Date.now() + ms;
      while (Date.now() < deadline) {
        const found = await fn();
        if (found) return found;
        await new Promise((resolve) => setTimeout(resolve, 80));
      }
      throw Error("EDGE_REVISION_TIMEOUT");
    };
    stage = "port";
    const port = await waitFor(() => {
      const file = path.join(profile, "DevToolsActivePort");
      if (!fs.existsSync(file)) return null;
      const value = Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]);
      return Number.isSafeInteger(value) && value > 0 ? value : null;
    });
    stage = "target";
    const tabs = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const tab = tabs.find((item) => item.type === "page");
    assert.ok(tab?.webSocketDebuggerUrl);
    stage = "websocket";
    socket = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    const pending = new Map();
    let sequence = 0;
    socket.addEventListener("message", ({ data }) => {
      const message = JSON.parse(data);
      const item = pending.get(message.id);
      if (!item) return;
      pending.delete(message.id);
      if (message.error) item.reject(Error(message.error.message));
      else item.resolve(message.result);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++sequence;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
    stage = "navigate";
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/` });
    stage = "outcome";
    const result = await waitFor(async () => {
      const outcome = await send("Runtime.evaluate", {
        expression: "document.getElementById('result')?.textContent || null",
        returnByValue: true,
      });
      const value = outcome.result?.value;
      return typeof value === "string" && /^EDGE_REVISION_INDEX_(PASS|FAIL)/.test(value)
        ? value : null;
    }, 32000);
    assert.equal(result, "EDGE_REVISION_INDEX_PASS");
    complete = true;
  } finally {
    if (complete) stage = "cleanup";
    socket?.close();
    if (edge?.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10000 }); }
      catch (_) { edge.kill(); }
    }
    server.closeAllConnections();
    server.close();
    server.unref();
    let removed = false;
    for (let i = 0; i < 15; i++) {
      try { fs.rmSync(directory, { recursive: true, force: true }); removed = true; break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 180));
      }
    }
    if (!removed) process.stderr.write("EDGE_REVISION_INDEX_CLEANUP_PENDING\n");
  }
  stage = "complete";
});
