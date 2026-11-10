import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { startRpc } from "./package-rpc.mjs";

const plugin = join(await realpath(process.argv[2]), "_bundled_plugin");
const node = process.env.CODEX_MCP_NODE_PATH;
assert.ok(node, "Set CODEX_MCP_NODE_PATH to the Node executable under test.");
const root = await realpath(await mkdtemp(join(tmpdir(), "package-review-")));
try {
  const cwd = join(root, "repository");
  await mkdir(cwd);
  // Observe the actual MCP server process so a launcher fallback cannot pass.
  const recordHost = join(root, "record-host.mjs");
  await writeFile(
    recordHost,
    'import { writeFileSync } from "node:fs";\n' +
      'writeFileSync(new URL("./host-path", import.meta.url), process.execPath);\n',
  );
  const env = {
    PATH: process.env.PATH,
    HOME: root,
    CODEX_HOME: join(root, ".codex"),
    CODEX_MCP_NODE_PATH: node,
    NODE_OPTIONS: `--import=${pathToFileURL(recordHost).href}`,
    CODEX_SECURITY_PLUGIN_ROOT: plugin,
    CODEX_SECURITY_SCAN_ROOT: join(root, "scans"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const git = (...args) =>
    execFileSync("git", args, { cwd, env, encoding: "utf8" }).trim();
  git("init", "-q");
  git("config", "user.email", "fixture@example.invalid");
  git("config", "user.name", "Fixture");
  await writeFile(join(cwd, "unchanged.py"), "value = 1\n");
  git("add", ".");
  git("commit", "-qm", "base");
  const baseRevision = git("rev-parse", "HEAD");
  await writeFile(join(cwd, "handler.py"), "value = 2\n");
  git("add", ".");
  git("commit", "-qm", "head");
  const headRevision = git("rev-parse", "HEAD");

  const rpc = await startRpc(
    join(plugin, "scripts", "launch_codex_security_mcp"),
    ["--stdio"],
    { cwd, env },
  );
  try {
    assert.equal(
      await realpath(await readFile(join(root, "host-path"), "utf8")),
      await realpath(node),
      "The packaged launcher must use the selected Node.",
    );
    const call = (name, args) =>
      rpc.call(name, args, { "openai/threadId": "package-review-owner" });
    const { scan } = await call("start_codex_security_prompt_only_scan", {
      targetPath: cwd,
      scope: ".",
      mode: "diff",
      diffTarget: { kind: "range", baseRevision, headRevision },
    });
    const bound = { scanId: scan.scanId };
    const prepared = await call("prepare_codex_security_review_items", bound);
    assert.equal(prepared.reviewItemsTotal, 1);
    const inventory = await call("list_codex_security_review_items", bound);
    assert.deepEqual(inventory.items, [{ path: "handler.py" }]);
  } finally {
    await rpc.close();
  }
} finally {
  await rm(root, { recursive: true, force: true });
}
