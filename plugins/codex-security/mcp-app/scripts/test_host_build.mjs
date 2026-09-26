import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import test from "node:test";

const plugin = resolve(import.meta.dirname, "../..");

function runNode(args, options = {}) {
  return execFileSync(process.execPath, args, {
    cwd: plugin,
    stdio: "inherit",
    ...options,
  });
}

test("builds and loads the host runtime from standalone plugin source", async (t) => {
  const output = await mkdtemp(join(tmpdir(), "codex-security-host-build-"));
  const mcp = join(output, "mcp");
  t.after(() => rm(output, { recursive: true, force: true }));

  runNode(["mcp-app/scripts/build_native.mjs"]);
  runNode([
    "mcp-app/scripts/build_mcp_app.mjs",
    "--output",
    mcp,
    "--native",
    "host",
  ]);

  const { nativeTarget } = await import("../../native/platform.mjs");
  const contract = JSON.parse(
    await readFile(join(plugin, "plugin-files.json"), "utf8"),
  );
  const actual = (await readdir(mcp, { recursive: true, withFileTypes: true }))
    .filter((entry) => entry.isFile())
    .map((entry) =>
      relative(output, join(entry.parentPath, entry.name)).split(sep).join("/"),
    );
  const expected = contract.shippedExact.filter(
    (path) =>
      path.startsWith("mcp/") &&
      (!path.endsWith(".node") ||
        path.startsWith(`mcp/native/${nativeTarget}/`)),
  );
  assert.deepEqual(actual.sort(), expected.sort());

  const emptyPathEnvironment = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(
        ([key]) => key.toLowerCase() !== "path",
      ),
    ),
    PATH: "",
  };
  const nativeFile = expected.find((path) => path.endsWith(".node"));
  runNode(
    [
      "-e",
      `const assert = require("node:assert/strict");
      const os = require("node:os");
      const native = require(process.argv[1]);
      if (process.platform === "win32") {
        assert.ok(native.windowsArguments().length);
      } else {
        const { username, homedir } = os.userInfo();
        assert.equal(native.userHome(Buffer.from(username)).value.toString(), homedir);
      }`,
      join(output, nativeFile),
    ],
    { env: emptyPathEnvironment },
  );

  const proof =
    process.platform === "win32" ? "proof-windows.mjs" : "proof.mjs";
  runNode(["--expose-gc", join("native", proof)], {
    env: emptyPathEnvironment,
  });

  const windows = process.platform === "win32";
  const launcher = `launch_codex_security_mcp${windows ? ".cmd" : ""}`;
  await mkdir(join(output, "scripts"));
  await copyFile(
    join(plugin, "scripts", launcher),
    join(output, "scripts", launcher),
  );
  const helperArgs = [
    "--helper",
    "resolve-security-md",
    "--repo",
    ".",
    "--list",
  ];
  const launcherOutput = execFileSync(
    windows ? (process.env.ComSpec ?? "cmd.exe") : "sh",
    windows
      ? ["/d", "/s", "/c", `scripts\\${launcher} ${helperArgs.join(" ")}`]
      : [`scripts/${launcher}`, ...helperArgs],
    {
      cwd: output,
      encoding: "utf8",
      env: { ...process.env, CODEX_MCP_NODE_PATH: process.execPath },
    },
  );
  assert.equal(launcherOutput, "[]\n");
});

test("rejects an unsupported native host before replacing existing output", async (t) => {
  const output = await mkdtemp(join(tmpdir(), "codex-security-unsupported-"));
  t.after(() => rm(output, { recursive: true, force: true }));
  const marker = join(output, "keep");
  await writeFile(marker, "previous output");

  const loader = `export function resolve(specifier, context, nextResolve) {
    if (specifier === "../../native/platform.mjs") {
      return {
        url: "data:text/javascript," + encodeURIComponent('export const nativeTarget = "unsupported-platform";'),
        shortCircuit: true,
      };
    }
    return nextResolve(specifier, context);
  }`;
  const register = `import { register } from "node:module";
    register(new URL(${JSON.stringify(`data:text/javascript,${encodeURIComponent(loader)}`)}));`;
  assert.throws(
    () =>
      runNode(
        [
          "--import",
          `data:text/javascript,${encodeURIComponent(register)}`,
          "mcp-app/scripts/build_mcp_app.mjs",
          "--output",
          output,
          "--native",
          "host",
        ],
        { stdio: "pipe", encoding: "utf8" },
      ),
    (error) => {
      assert.equal(error.status, 1);
      assert.equal(
        error.stderr.trim(),
        "Unsupported native target: unsupported-platform.",
      );
      return true;
    },
  );
  assert.equal(await readFile(marker, "utf8"), "previous output");
});
