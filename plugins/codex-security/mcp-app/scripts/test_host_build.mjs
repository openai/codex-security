import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
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

  const proof =
    process.platform === "win32" ? "proof-windows.mjs" : "proof.mjs";
  runNode(["--expose-gc", join("native", proof)], {
    env: {
      ...Object.fromEntries(
        Object.entries(process.env).filter(
          ([key]) => key.toLowerCase() !== "path",
        ),
      ),
      PATH: "",
    },
  });

  assert.equal(
    runNode(
      [
        join(mcp, "helpers.mjs"),
        "resolve-security-md",
        "--repo",
        output,
        "--list",
      ],
      { stdio: "pipe", encoding: "utf8" },
    ),
    "[]\n",
  );
});
