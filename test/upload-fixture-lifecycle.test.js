const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const http = require("node:http");
const test = require("node:test");
const { fixtureRequest } = require("./support/upload-fixture-lifecycle");

test("upload fixture diagnostics distinguish a closed listener from a delayed child exit without retry", { timeout: 10_000 }, async (t) => {
  const child = spawn(process.execPath, ["-e", `
    require(${JSON.stringify(require.resolve("./support/upload-fixture-lifecycle"))}).installFixtureListenerProbe();
    const server = require("node:http").createServer((_req, res) => res.end("fixture"));
    server.listen(0, "127.0.0.1", () => process.send(server.address().port));
    process.on("message", (message) => {
      if (message === "close") {
        process.stderr.write("Erro no upload em blocos: EIO\\nfixture-private-sentinel\\n");
        server.close(() => process.send("closed"));
      }
      if (message === "exit") process.exit(7);
    });
  `], { stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true });
  const stdout = [], stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk.toString()));
  child.stderr.on("data", (chunk) => stderr.push(chunk.toString()));
  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const closed = once(child, "close");
    child.kill();
    await closed;
  });
  const [port] = await once(child, "message");
  await new Promise((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port, agent: false }, (response) => {
      assert.equal(response.statusCode, 200);
      response.resume();
      response.once("end", resolve);
    });
    request.once("error", reject);
  });
  const closed = once(child, "message");
  child.send("close");
  assert.equal((await closed)[0], "closed");
  const harness = { child, port, stdout, stderr };
  // Model a refused connect after the observed close without racing another
  // test for the now-free ephemeral port. This tests diagnostics, not a fix
  // for the hosted connection refusal.
  const refusal = Object.assign(new Error("synthetic refused connection"), {
    code: "ECONNREFUSED", syscall: "connect", address: "127.0.0.1", port,
  });
  let calls = 0;
  await assert.rejects(() => fixtureRequest(harness, "retry-request", async () => {
    calls++;
    throw refusal;
  }), (error) => {
    assert.equal(error.cause, refusal);
    assert.match(error.message, /code=ECONNREFUSED syscall=connect address=loopback4 port=match/);
    assert.match(error.message, /childAtError=pending childAfter=pending/);
    assert.match(error.message, /listener=IPv4\/loopback4\/match accepts=1 closed=true/);
    assert.match(error.message, /closing=true/);
    assert.match(error.message, /expectedEio=true/);
    assert.doesNotMatch(error.message, /fixture-private-sentinel/);
    return true;
  });
  await assert.rejects(() => fixtureRequest(harness, "retry-request", async () => {
    calls++;
    child.send("exit");
    throw refusal;
  }), (error) => {
    assert.equal(error.cause, refusal);
    assert.match(error.message, /childAtError=pending childAfter=exit:7/);
    assert.match(error.message, /processExit=7/);
    return true;
  });
  assert.equal(calls, 2, "each failure is observed once, never retried");
});
