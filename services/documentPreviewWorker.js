const mammoth = require("mammoth");
const WordExtractor = require("word-extractor");

async function main() {
  const request = JSON.parse(process.argv[2] || "{}");
  if (![".doc", ".docx"].includes(request.extension) ||
      !Number.isSafeInteger(request.maxInputBytes) || request.maxInputBytes < 0 ||
      request.maxInputBytes > 50 * 1024 * 1024) throw new Error("unsupported parser request");
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > request.maxInputBytes) throw new Error("parser input too large");
    chunks.push(chunk);
  }
  const input = Buffer.concat(chunks, length);
  const value = request.extension === ".docx"
    ? (await mammoth.extractRawText({ buffer: input })).value
    : (await new WordExtractor().extract(input)).getBody();
  process.stdout.write(JSON.stringify({ ok: true, content: String(value || "") }));
}

main().catch((error) => {
  process.stderr.write(String(error?.message || "parser failure").slice(0, 512));
  process.exitCode = 1;
});
