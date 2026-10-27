// Read from stdin in a fresh isolated container by smoke.sh.
import assert from "node:assert/strict";
import { execFile, execFileSync, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { accessSync, constants, mkdtempSync, readFileSync,
  realpathSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { once } from "node:events";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const run = (cmd, args, opts = {}) => execFileSync(cmd, args, {
  encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 180_000,
  maxBuffer: 16 * 1024 * 1024, ...opts
}).trim();
const read = (file) => JSON.parse(readFileSync(file, "utf8"));
const cli = (...args) => JSON.parse(run("/usr/local/bin/codex-security-entrypoint", [...args, "--json"]));

assert.equal(process.getuid(), 10001);
assert.equal(process.getgid(), 10001);
assert.equal(process.cwd(), "/state");
assert.equal(process.env.HOME, "/state");
assert.equal(process.env.CODEX_HOME, "/state");
assert.equal(process.env.CODEX_SECURITY_STATE_DIR, "/output/.codex-security-state");
assert.equal(process.env.GIT_TERMINAL_PROMPT, "0");
assert.equal(process.env.PYTHON, "/usr/bin/python3");
accessSync("/input", constants.R_OK | constants.X_OK);
for (const p of ["/state", "/output"]) accessSync(p, constants.W_OK | constants.X_OK);
run(process.env.PYTHON, ["-c",
  "import ssl, sqlite3; assert ssl.create_default_context().get_ca_certs(); assert sqlite3.connect(':memory:').execute('select 1').fetchone() == (1,)"]);
console.log("PASS non-root account, state directories, Python SQLite and CA trust");

const info = cli("info");
assert.equal(info.cliVersion, "0.7.0");
assert.equal(info.codexVersion, "0.164.0");
const launcher = realpathSync(run("/bin/sh", ["-c", "command -v codex-security"]));
const pkg = dirname(dirname(launcher));
assert.equal(read(join(pkg, "package.json")).name, "@openai/codex-security");
const { resolveCodexCommand } = await import(pathToFileURL(join(pkg, "dist/index.js")));
const { command: codex } = resolveCodexCommand({});
assert.equal(run(codex, ["--version"]), `codex-cli ${info.codexVersion}`);
const plugin = join(pkg, "_bundled_plugin");
const libc = process.report.getReport().header.glibcVersionRuntime ? "gnu" : "musl";
const addon = join(plugin, "mcp/native", `linux-${process.arch}-${libc}`, "unix.node");
assert.equal(createRequire(import.meta.url)(addon).unixEnvironment(Buffer.from("HOME")).toString(), "/state");
const mcp = read(join(plugin, ".mcp.json")).mcpServers["codex-security"];
const initialized = JSON.parse(run(join(plugin, mcp.command), mcp.args, { cwd: plugin,
  input: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
    protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "offline-image-test", version: "1" }
  } }) + "\n" }));
assert.equal(initialized.result.serverInfo.name, "codex-security");
console.log(`PASS native Codex ${info.codexVersion}, plugin addon and MCP startup on linux/${process.arch}; Node ${process.version}`);

const helper = "/usr/local/bin/codex-security-git-credential";
const helperResult = (host) => run(helper, ["get"], { env: { ...process.env, GH_TOKEN: "fixture-only" },
  input: `protocol=https\nhost=${host}\n\n` });
assert.equal(helperResult("github.com"), "username=x-access-token\npassword=fixture-only");
assert.equal(helperResult("not-github.example"), "");
console.log("PASS Git credential helper is limited to its configured host");

process.umask(0o077);
const repo = mkdtempSync("/input/codex-smoke-");
const scanDir = join(mkdtempSync("/output/codex-smoke-"), "scan");
const source = join(repo, "hello.py");
const original = 'print("offline fixture")\n';
writeFileSync(source, original);
const git = (...args) => run("git", ["-C", repo, ...args]);
git("init", "-q"); git("add", "hello.py");
git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture");
// /input is a writable, disposable tmpfs in this test. Use the exact same
// child in both cases to distinguish Codex confinement from a Docker mount.
const probe = [process.env.PYTHON, "-c", `from pathlib import Path
import errno,sys
p=Path(sys.argv[1])
if p.read_text() != sys.argv[2]: sys.exit(41)
try: p.write_text("changed")
except OSError as e: sys.exit({errno.EROFS:45, errno.EACCES:46, errno.EPERM:47}.get(e.errno, 48))
sys.exit(42)`, source, original];
const launch = (args) => spawnSync(args[0], args.slice(1), {cwd: repo, encoding: "utf8", timeout: 30_000});
const control = launch(probe);
assert.equal(control.status, 42, control.error?.message || control.stderr);
assert.equal(readFileSync(source, "utf8"), "changed");
writeFileSync(source, original);
const sandbox = launch([codex, "sandbox", "--permission-profile", ":read-only", "--", ...probe]);
const why = {45: "EROFS", 46: "EACCES", 47: "EPERM"}[sandbox.status];
assert(why, `sandbox code=${sandbox.status} signal=${sandbox.signal}; ${sandbox.error?.message || sandbox.stderr}`);
assert.equal(readFileSync(source, "utf8"), original);
assert.equal(git("status", "--porcelain"), "");
console.log(`PASS read-only sandbox: the child read hello.py and its write failed with ${why}; the same child wrote it outside, and the checkout is clean`);

// This turn goes through the installed native model client and its shell tool.
// The only server is this loopback Responses fixture.
const nonce = randomUUID();
const draft = `python3 - <<'PY'
import json,os
from pathlib import Path
assert (Path(os.environ["CODEX_SECURITY_REPOSITORY"])/"hello.py").read_text() == ${JSON.stringify(original)}
out = Path(os.environ["CODEX_SECURITY_SCAN_DIR"])
docs = {"scan-manifest.json":{"scan":{"target":{"kind":os.environ["CODEX_SECURITY_TARGET_KIND"]},
        "scope":{"summary":"Synthetic offline smoke test: ${nonce}"}}}, "findings.json":{"findings":[]},
        "coverage.json":{"inventoryStrategy":"repository","surfaces":[],"explicitExclusions":[],"deferred":[]}}
for name,data in docs.items():
    with (out/name).open("x") as f: json.dump(data,f)
print("fixture-draft-written")
PY`;
let requests = 0;
let fixtureError;
const server = createServer(async (req, res) => {
  try {
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/openai/v1/responses");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const request = JSON.parse(Buffer.concat(chunks));
    requests++;
    let item;
    if (requests === 1) {
      assert(request.tools.some(t => t.name === "exec_command"));
      item = {type: "function_call", call_id: "draft", name: "exec_command",
        arguments: JSON.stringify({cmd: draft})};
    } else {
      assert.equal(requests, 2);
      assert(request.input.some(i => i.type === "function_call_output" && i.call_id === "draft" &&
        JSON.stringify(i.output).includes("fixture-draft-written")));
      item = {type: "message", role: "assistant", id: "reply", content: [{type: "output_text", text: nonce}]};
    }
    const response = {id: `r${requests}`, usage: {input_tokens: 1, output_tokens: 1, total_tokens: 2}};
    const events = [{type:"response.created",response}, {type:"response.output_item.done",item},
      {type:"response.completed",response}];
    res.writeHead(200, {"Content-Type": "text/event-stream"});
    res.end(events.map(e => `data: ${JSON.stringify(e)}\n\n`).join(""));
  } catch (error) {
    fixtureError = error;
    res.writeHead(400).end("invalid fixture request");
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
try {
  const base = `http://127.0.0.1:${server.address().port}/openai/v1`;
  await promisify(execFile)("/usr/local/bin/codex-security-entrypoint",
    ["scan", repo, "--mode", "standard", "--headless", "--output-dir", scanDir, "--provider", "amazon-bedrock", "--model", "openai.gpt-5.6-luna",
     "--codex", `model_providers.amazon-bedrock.base_url="${base}"`, "--codex", 'model_providers.amazon-bedrock.aws.region="us-west-2"'],
    {env:{...process.env, AWS_ACCESS_KEY_ID:"offline-test", AWS_SECRET_ACCESS_KEY:"offline-test-only",
      AWS_REGION:"us-west-2", AWS_EC2_METADATA_DISABLED:"true", NO_PROXY:"127.0.0.1,localhost"},timeout:75_000});
  assert.ifError(fixtureError);
  assert.equal(requests, 2);
  const scan = read(join(scanDir, "scan-manifest.json")).scan;
  assert(scan.status === "completed" && scan.sealedAt && scan.scope.summary.includes(nonce));
  assert(scan.artifacts.length > 0);
  for (const artifact of scan.artifacts) {
    const sha256 = createHash("sha256").update(readFileSync(join(scanDir, artifact.path))).digest("hex");
    assert.equal(sha256, artifact.sha256, artifact.path);
  }
  assert.deepEqual(read(join(scanDir, "findings.json")).findings, []);
  assert.equal(read(join(scanDir, "exports/results.sarif")).version, "2.1.0");
  assert(statSync(join(process.env.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3")).size > 0);
  assert(cli("scans", "list", repo).scans.some(s => s.scanId === scan.id));
  assert.equal(git("status", "--porcelain"), "");
  console.log("PASS loopback scan: native shell tool, sealed marker and artifact hashes, SARIF, SQLite history, unchanged source");
} finally {
  server.closeAllConnections();
  server.close();
}
