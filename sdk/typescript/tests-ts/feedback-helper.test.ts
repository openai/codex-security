import { spawn } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { resolvePluginPython } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("feedback manifest launches the helper after existing MCP arguments with stdin still open", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-feedback-helper-")),
  );
  try {
    const plugin = join(root, "plugin with spaces");
    const scripts = join(plugin, "scripts");
    const cwd = join(root, "caller with spaces");
    await Promise.all([
      mkdir(scripts, { recursive: true }),
      mkdir(cwd),
      cp(join(PLUGIN_ROOT, "mcp"), join(plugin, "mcp"), { recursive: true }),
    ]);
    const windows = process.platform === "win32";
    const name = `launch_codex_security_mcp${windows ? ".cmd" : ""}`;
    const launcher = join(scripts, name);
    await cp(join(PLUGIN_ROOT, "scripts", name), launcher);
    await writeFile(
      join(scripts, "collect_feedback.py"),
      `import json, os, sys
request = json.loads(sys.stdin.readline())
json.dump({"request": request, "cwd": os.getcwd(), "utf8": sys.flags.utf8_mode}, sys.stdout)
`,
    );
    const manifest = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"), "utf8"),
    );
    expect(manifest.feedbackCollector.mcpServer).toBe("codex-security");
    const args = ["--stdio", ...manifest.feedbackCollector.args] as string[];
    const node = Bun.which("node");
    expect(node).not.toBeNull();
    const child = spawn(
      windows ? process.env["ComSpec"] ?? "cmd.exe" : launcher,
      windows
        ? [
            "/d",
            "/s",
            "/c",
            `""${launcher}" ${args.map((arg) => `"${arg}"`).join(" ")}"`,
          ]
        : args,
      {
        cwd,
        env: {
          ...process.env,
          CODEX_MCP_NODE_PATH: node!,
          PYTHON: await resolvePluginPython(),
        },
        windowsHide: true,
        windowsVerbatimArguments: windows,
      },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    const closed = new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    child.stdin.write(`${JSON.stringify({ threadIds: ["owner-1"] })}\n`);
    expect(await closed, stderr).toBe(0);
    expect(JSON.parse(stdout)).toEqual({
      request: { threadIds: ["owner-1"] },
      cwd,
      utf8: 1,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("bundled server dispatches feedback before starting the MCP server", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-security-feedback-main-"));
  try {
    const node = Bun.which("node");
    expect(node).not.toBeNull();
    const child = spawn(
      node!,
      [
        join(PLUGIN_ROOT, "mcp", "server.mjs"),
        "--stdio",
        "--helper",
        "collect-feedback",
      ],
      {
        env: {
          ...process.env,
          CODEX_HOME: join(root, "home"),
          CODEX_SECURITY_STATE_DIR: join(root, "no-state"),
          PYTHON: await resolvePluginPython(),
        },
        windowsHide: true,
      },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    const closed = new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    child.stdin.write(`${JSON.stringify({ threadIds: ["missing-owner"] })}\n`);
    expect(await closed, stderr).toBe(0);
    expect(stdout).toBe("");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
