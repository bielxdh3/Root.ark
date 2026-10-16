const assert = require("node:assert/strict");
const test = require("node:test");
const UploadChunkSlidingWindowStore = require("../src/middlewares/uploadChunkSlidingWindowStore");

test("chunk upload rate limits expire each request on a sliding window without counting rejected attempts", (t) => {
  const originalNow = Date.now;
  let now = 1000;
  Date.now = () => now;
  const store = new UploadChunkSlidingWindowStore(2000, 2);
  t.after(() => {
    Date.now = originalNow;
    store.shutdown();
  });

  assert.deepEqual(store.increment("uploader"), { totalHits: 1, resetTime: new Date(3000) });
  now = 2300;
  assert.deepEqual(store.increment("uploader"), { totalHits: 2, resetTime: new Date(3000) });

  now = 3100;
  assert.deepEqual(store.increment("uploader"), { totalHits: 2, resetTime: new Date(4300) });
  assert.deepEqual(store.increment("uploader"), { totalHits: 3, resetTime: new Date(4300) });
  assert.deepEqual(store.get("uploader"), { totalHits: 2, resetTime: new Date(4300) });
});
