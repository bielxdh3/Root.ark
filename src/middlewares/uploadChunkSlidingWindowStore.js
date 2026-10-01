class UploadChunkSlidingWindowStore {
  constructor(windowMs, limit) {
    this.windowMs = windowMs;
    this.limit = limit;
    this.requestsByAccount = new Map();
    this.localKeys = true;
    this.prefix = "upload-chunk";
    this.cleanupTimer = setInterval(() => this.sweep(Date.now()), Math.min(windowMs, 60 * 1000));
    this.cleanupTimer.unref?.();
  }

  getRequests(account, now = Date.now()) {
    const requests = this.requestsByAccount.get(account) || [];
    const oldestAllowed = now - this.windowMs;
    while (requests.length && requests[0] <= oldestAllowed) requests.shift();
    if (requests.length) this.requestsByAccount.set(account, requests);
    else this.requestsByAccount.delete(account);
    return requests;
  }

  increment(account) {
    const now = Date.now();
    const requests = this.getRequests(account, now);
    if (requests.length >= this.limit) {
      return { totalHits: this.limit + 1, resetTime: new Date(requests[0] + this.windowMs) };
    }

    requests.push(now);
    this.requestsByAccount.set(account, requests);
    return { totalHits: requests.length, resetTime: new Date(requests[0] + this.windowMs) };
  }

  decrement(account) {
    const requests = this.getRequests(account);
    requests.pop();
    if (requests.length) this.requestsByAccount.set(account, requests);
    else this.requestsByAccount.delete(account);
  }

  get(account) {
    const requests = this.getRequests(account);
    return requests.length
      ? { totalHits: requests.length, resetTime: new Date(requests[0] + this.windowMs) }
      : undefined;
  }

  resetKey(account) {
    this.requestsByAccount.delete(account);
  }

  resetAll() {
    this.requestsByAccount.clear();
  }

  sweep(now) {
    for (const account of this.requestsByAccount.keys()) this.getRequests(account, now);
  }

  shutdown() {
    clearInterval(this.cleanupTimer);
  }
}

module.exports = UploadChunkSlidingWindowStore;
