import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const plugin = resolve(import.meta.dirname, "../..");

test("builds and loads the host runtime from standalone plugin source", async (t) => {
  const output = await mkdtemp(join(tmpdir(), "codex-security-host-build-"));
  t.after(() => rm(output, { recursive: true, force: true }));

  execFileSync(
    process.execPath,
    [join(plugin, "mcp-app/scripts/build_native.mjs")],
    {
      stdio: "inherit",
    },
  );
  execFileSync(
    process.execPath,
    [
      join(plugin, "mcp-app/scripts/build_mcp_app.mjs"),
      "--output",
      join(output, "mcp"),
      "--native",
      "host",
    ],
    { stdio: "inherit" },
  );

  const { nativeTarget } = await import("../../native/platform.mjs");
  const contract = JSON.parse(
    await readFile(join(plugin, "plugin-files.json"), "utf8"),
  );
  assert.deepEqual(
    await files(join(output, "mcp")),
    contract.shippedExact
      .filter((path) => path.startsWith("mcp/"))
      .filter(
        (path) =>
          !path.endsWith(".node") ||
          path.startsWith(`mcp/native/${nativeTarget}/`),
      )
      .map((path) => path.slice("mcp/".length))
      .sort(),
  );

  const proof =
    process.platform === "win32" ? "proof-windows.mjs" : "proof.mjs";
  execFileSync(
    process.execPath,
    ["--expose-gc", join(plugin, "native", proof)],
    {
      env: {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([key]) => key.toLowerCase() !== "path",
          ),
        ),
        PATH: "",
      },
      stdio: "inherit",
    },
  );

  assert.equal(
    execFileSync(
      process.execPath,
      [
        join(output, "mcp/helpers.mjs"),
        "resolve-security-md",
        "--repo",
        output,
        "--list",
      ],
      { encoding: "utf8" },
    ),
    "[]\n",
  );
});

async function files(root, prefix = "") {
  const paths = await Promise.all(
    (await readdir(join(root, prefix), { withFileTypes: true })).map(
      (entry) => {
        const path = prefix ? `${prefix}/${entry.name}` : entry.name;
        return entry.isDirectory() ? files(root, path) : [path];
      },
    ),
  );
  return paths.flat().sort();
}
