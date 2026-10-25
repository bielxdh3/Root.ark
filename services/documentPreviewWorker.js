const mammoth = require("mammoth");
const WordExtractor = require("word-extractor");

async function main() {
  const request = JSON.parse(process.argv[2] || "{}");
  if (Object.keys(request).length !== 1 || ![".doc", ".docx"].includes(request.extension)) {
    throw new Error("unsupported parser request");
  }
  const chunks = [];
  let total = 0;
  for await (const part of process.stdin) {
    total += part.length;
    if (total > 16 * 1024 * 1024) throw new Error("parser input too large");
    chunks.push(part);
  }
  if (!total) throw new Error("empty parser input");
  const snapshot = Buffer.concat(chunks, total);
  const value = request.extension === ".docx"
    ? (await mammoth.extractRawText({ buffer: snapshot })).value
    : (await new WordExtractor().extract(snapshot)).getBody();
  process.stdout.write(JSON.stringify({ ok: true, content: String(value || "") }));
}

main().catch((error) => {
  process.stderr.write(String(error?.message || "parser failure").slice(0, 512));
  process.exitCode = 1;
});
