import { execFile } from "node:child_process";
import {
  chmod,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, test } from "bun:test";
import { transform } from "esbuild";
import { buildBundledPlugin } from "../scripts/build-plugin.mjs";
import { assertGeneratedPluginUntracked } from "../scripts/check-plugin-source.mjs";

const temporaryDirectories: string[] = [];
const execFileAsync = promisify(execFile);

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codex-security-plugin-"));
  temporaryDirectories.push(directory);
  return directory;
}

async function writeFixture(
  root: string,
  path: string,
  contents: string,
): Promise<void> {
  const destination = join(root, ...path.split("/"));
  await mkdir(join(destination, ".."), { recursive: true });
  await writeFile(destination, contents);
}

async function files(root: string, prefix = ""): Promise<string[]> {
  const entries = await readdir(join(root, prefix), { withFileTypes: true });
  const paths = await Promise.all(
    entries.map(async (entry) => {
      const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      return entry.isDirectory() ? files(root, path) : [path];
    }),
  );
  return paths.flat().sort();
}

async function snapshot(root: string) {
  return Promise.all(
    (await files(root)).map(async (path) => {
      const file = join(root, ...path.split("/"));
      return {
        contents: await readFile(file),
        mode: (await stat(file)).mode & 0o777,
        path,
      };
    }),
  );
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("bundled plugin build", () => {
  test("bundles the native policy proof with only SDK dependencies", async () => {
    const root = await temporaryDirectory();
    const plugin = join(root, "plugins", "codex-security");
    const native = join(plugin, "native");
    const sdk = join(root, "sdk", "typescript");
    const source = new URL("../../../plugins/codex-security/", import.meta.url);
    await mkdir(native, { recursive: true });
    await mkdir(sdk, { recursive: true });
    await symlink(
      fileURLToPath(new URL("../node_modules", import.meta.url)),
      join(sdk, "node_modules"),
      process.platform === "win32" ? "junction" : "dir",
    );
    for (const name of ["schemas", "mcp-app/src"]) {
      await cp(new URL(name, source), join(plugin, name), { recursive: true });
    }
    await copyFile(
      new URL("mcp-app/helpers-main.ts", source),
      join(plugin, "mcp-app", "helpers-main.ts"),
    );
    for (const name of [
      "binding",
      "platform",
      "windows-binding",
      "windows-flags",
      "windows-files",
      "proof-policy-windows",
    ]) {
      const compiled = await transform(
        await readFile(new URL(`native/${name}.mts`, source), "utf8"),
        { loader: "ts", format: "esm", target: "node20" },
      );
      await writeFile(join(native, `${name}.mjs`), compiled.code);
    }
    const { nativeTarget } = await import(
      pathToFileURL(join(native, "platform.mjs")).href
    );
    const binary = process.platform === "win32" ? "windows.node" : "unix.node";
    // The build copies this artifact; this portable test does not load native code.
    await writeFixture(
      native,
      `dist/${nativeTarget}/${binary}`,
      "native fixture",
    );
    await expect(
      stat(join(plugin, "mcp-app", "node_modules")),
    ).rejects.toMatchObject({
      code: "ENOENT",
    });
    await execFileAsync(
      "node",
      [join(native, "proof-policy-windows.mjs"), "build"],
      {
        cwd: native,
        env: { ...process.env, NODE_PATH: "" },
      },
    );
    const proof = join(native, "dist", nativeTarget, "policy-proof");
    expect(
      await readFile(
        join(proof, "native", nativeTarget, "windows.node"),
        "utf8",
      ),
    ).toBe("native fixture");
    const helper = join(root, "helpers.cjs");
    await copyFile(join(proof, "helpers.cjs"), helper);
    await execFileAsync("node", [
      "--eval",
      "require('node:fs').unlinkSync(process.argv[1])",
      join(sdk, "node_modules"),
    ]);
    await expect(stat(join(sdk, "node_modules"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    const result = await execFileAsync(
      "node",
      [
        "--eval",
        `
      const assert = require("node:assert/strict");
      const helper = require(process.argv.pop());
      const input = {
        scanId: "synthetic-scan",
        manifest: { scan: {} },
        findings: { findings: [] },
        coverage: {
          completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [],
        },
      };
      assert.equal(helper.parseCanonicalScanDraft(input).scanId, input.scanId);
      assert.throws(() => helper.parseCanonicalScanDraft({
        ...input, coverage: { ...input.coverage, completeness: "invalid" },
      }));
      console.log("Bundled parser accepted valid input and rejected invalid coverage.");
    `,
        helper,
      ],
      { cwd: root, env: { ...process.env, NODE_PATH: "" } },
    );
    expect(result.stdout).toBe(
      "Bundled parser accepted valid input and rejected invalid coverage.\n",
    );
    expect(result.stderr).toBe("");
  });

  test("builds the MCP runtime without invoking an npm launcher", async () => {
    const root = await temporaryDirectory();
    const bin = join(root, "bin");
    const launcher = process.platform === "win32" ? "npm.cmd" : "npm";
    await writeFixture(
      bin,
      launcher,
      process.platform === "win32" ? "@exit /b 91\r\n" : "#!/bin/sh\nexit 91\n",
    );
    if (process.platform !== "win32") await chmod(join(bin, launcher), 0o755);

    const destination = join(root, "mcp");
    await execFileAsync(
      "node",
      [
        fileURLToPath(
          new URL(
            "../../../plugins/codex-security/mcp-app/scripts/build_mcp_app.mjs",
            import.meta.url,
          ),
        ),
        "--output",
        destination,
      ],
      {
        env: {
          ...process.env,
          PATH: [bin, process.env["PATH"]].filter(Boolean).join(delimiter),
        },
      },
    );

    const contract = JSON.parse(
      await readFile(
        new URL(
          "../../../plugins/codex-security/plugin-files.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as { shippedExact: string[] };
    expect(await files(destination)).toEqual(
      contract.shippedExact
        .filter((path) => path.startsWith("mcp/"))
        .map((path) => path.slice(4))
        .sort(),
    );
    const helper = await execFileAsync("node", [
      join(destination, "helpers.mjs"),
      "resolve-security-md",
      "--repo",
      root,
      "--list",
    ]);
    expect(helper.stdout).toBe("[]\n");
    expect(helper.stderr).toBe("");
  });

  test("builds from a source snapshot without Git metadata", async () => {
    const root = await temporaryDirectory();
    const packageRoot = join(root, "sdk", "typescript");
    const source = join(root, "plugins", "codex-security");

    await writeFixture(
      packageRoot,
      "package.json",
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );
    await writeFixture(
      packageRoot,
      "scripts/build-plugin.mjs",
      await readFile(
        new URL("../scripts/build-plugin.mjs", import.meta.url),
        "utf8",
      ),
    );
    await writeFixture(
      packageRoot,
      "scripts/check-plugin-source.mjs",
      await readFile(
        new URL("../scripts/check-plugin-source.mjs", import.meta.url),
        "utf8",
      ),
    );
    await writeFixture(
      source,
      "plugin-files.json",
      `${JSON.stringify({
        externalOwnedExact: [".codex-plugin/plugin.json"],
        shippedExact: ["scripts/launch"],
      })}\n`,
    );
    await writeFixture(source, ".codex-plugin/plugin.json", "{}\n");
    await writeFixture(source, "scripts/launch", "#!/bin/sh\nexit 0\n");

    await execFileAsync(process.execPath, ["--run", "build:plugin"], {
      cwd: packageRoot,
    });

    expect(
      await readFile(
        join(packageRoot, "_bundled_plugin", "scripts", "launch"),
        "utf8",
      ),
    ).toBe("#!/bin/sh\nexit 0\n");
  });

  test("stages only declared runtime files from the canonical plugin source", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "plugins", "codex-security");
    const destination = join(root, "sdk", "typescript", "_bundled_plugin");
    const contractPath = join(source, "plugin-files.json");

    await writeFixture(
      source,
      ".codex-plugin/plugin.json",
      '{"name":"fixture"}\n',
    );
    await writeFixture(source, "scripts/launch", "#!/bin/sh\nexit 0\n");
    await chmod(join(source, "scripts", "launch"), 0o755);
    await writeFixture(source, "schemas/scan.json", "{}\n");
    await writeFixture(
      source,
      "mcp-app/package.json",
      `${JSON.stringify({
        scripts: { build: "node scripts/build_mcp_app.mjs" },
      })}\n`,
    );
    await writeFixture(
      source,
      "mcp-app/scripts/build_mcp_app.mjs",
      `import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const outputFlag = process.argv.indexOf("--output");
if (outputFlag === -1 || process.argv[outputFlag + 1] === undefined) {
  throw new Error("Missing --output.");
}
const output = process.argv[outputFlag + 1];
await mkdir(output, { recursive: true });
await writeFile(join(output, "server.mjs"), "generated mcp runtime\\n");
`,
    );
    await writeFixture(source, "tests/plugin.test.py", "assert True\n");
    await writeFixture(source, "sdk/typescript/owned-by-sdk.txt", "sdk\n");
    await writeFixture(destination, "stale.txt", "stale\n");
    await writeFixture(
      source,
      "plugin-files.json",
      `${JSON.stringify(
        {
          externalOwnedExact: [".codex-plugin/plugin.json"],
          shippedExact: [
            "mcp/server.mjs",
            "schemas/scan.json",
            "scripts/launch",
            "sdk/typescript/owned-by-sdk.txt",
          ],
        },
        null,
        2,
      )}\n`,
    );

    await buildBundledPlugin({ contractPath, destination, source });

    expect(await files(destination)).toEqual([
      ".codex-plugin/plugin.json",
      "mcp/server.mjs",
      "schemas/scan.json",
      "scripts/launch",
    ]);
    expect(
      await readFile(join(destination, "schemas", "scan.json"), "utf8"),
    ).toBe("{}\n");
    expect(await readFile(join(destination, "mcp", "server.mjs"), "utf8")).toBe(
      "generated mcp runtime\n",
    );
    if (process.platform !== "win32") {
      expect(
        (await stat(join(destination, "scripts", "launch"))).mode & 0o111,
      ).toBe(0o111);
    }

    const firstBuild = await snapshot(destination);
    await buildBundledPlugin({ contractPath, destination, source });
    expect(await snapshot(destination)).toEqual(firstBuild);
  });

  test("fails when a declared runtime file is absent", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "plugins", "codex-security");
    const destination = join(root, "sdk", "typescript", "_bundled_plugin");
    const contractPath = join(source, "plugin-files.json");

    await writeFixture(source, ".codex-plugin/plugin.json", "{}\n");
    await writeFixture(
      source,
      "plugin-files.json",
      `${JSON.stringify({
        externalOwnedExact: [".codex-plugin/plugin.json"],
        shippedExact: ["scripts/missing.py"],
      })}\n`,
    );

    await expect(
      buildBundledPlugin({ contractPath, destination, source }),
    ).rejects.toThrow("Canonical plugin source is missing scripts/missing.py.");
  });
});

describe("generated plugin ownership", () => {
  test("allows an untracked local runtime payload", async () => {
    const root = await temporaryDirectory();
    const packageRoot = join(root, "sdk", "typescript");
    await execFileAsync("git", ["init", "--quiet", root]);
    await writeFixture(
      packageRoot,
      "_bundled_plugin/mcp/server.mjs",
      "generated runtime\n",
    );

    await expect(
      assertGeneratedPluginUntracked({ packageRoot }),
    ).resolves.toBeUndefined();
  });

  test("rejects a tracked runtime payload", async () => {
    const root = await temporaryDirectory();
    const packageRoot = join(root, "sdk", "typescript");
    await execFileAsync("git", ["init", "--quiet", root]);
    await writeFixture(
      packageRoot,
      "_bundled_plugin/mcp/server.mjs",
      "generated runtime\n",
    );
    await execFileAsync("git", [
      "-C",
      root,
      "add",
      "sdk/typescript/_bundled_plugin/mcp/server.mjs",
    ]);

    await expect(
      assertGeneratedPluginUntracked({ packageRoot }),
    ).rejects.toThrow(
      "Generated plugin payload must not be tracked: _bundled_plugin/mcp/server.mjs",
    );
  });
});
