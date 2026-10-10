import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  verifyInstalledPackage,
  verifyInstalledPlugin,
} from "../scripts/smoke-published-package.mjs";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const directories = createTemporaryDirectories();
afterEach(directories.cleanup);

async function installedFixture(cliVersion: string) {
  const consumer = await directories.create("published smoke ");
  const installedRoot = join(
    consumer,
    "node_modules",
    "@openai",
    "codex-security",
  );
  const bin = join(consumer, "node_modules", ".bin");
  await mkdir(installedRoot, { recursive: true });
  await mkdir(bin);
  await writeFile(
    join(installedRoot, "package.json"),
    JSON.stringify({
      name: "@openai/codex-security",
      version: "99.1.2",
    }),
  );
  const shim = join(
    bin,
    process.platform === "win32" ? "codex-security.cmd" : "codex-security",
  );
  await writeFile(
    shim,
    process.platform === "win32"
      ? `@echo off\r\nif "%~1"=="--version" (echo ${cliVersion}) else (echo Usage: codex-security)\r\n`
      : `#!/bin/sh\nif [ "$1" = "--version" ]; then printf '%s\\n' '${cliVersion}'; else printf '%s\\n' 'Usage: codex-security'; fi\n`,
  );
  await chmod(shim, 0o755);
  return { consumer, shim };
}

test.each([
  { args: [], version: "latest" },
  { args: ["99.1.2"], version: "99.1.2" },
])(
  "installs the requested published package $version",
  async ({ args, version }) => {
    const directory = await directories.create("published smoke npm ");
    const npm = join(directory, "npm-cli.js");
    const capturedArgs = join(directory, "arguments.json");
    await writeFile(
      npm,
      `require("node:fs").writeFileSync(process.env.SMOKE_NPM_ARGUMENTS, JSON.stringify(process.argv.slice(2))); process.exit(7);`,
    );
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(
          new URL("../scripts/smoke-published-package.mjs", import.meta.url),
        ),
        ...args,
      ],
      {
        env: {
          ...process.env,
          npm_execpath: npm,
          SMOKE_NPM_ARGUMENTS: capturedArgs,
        },
        encoding: "utf8",
      },
    );
    expect(result.status).not.toBe(0);
    expect(JSON.parse(await readFile(capturedArgs, "utf8"))).toContain(
      `@openai/codex-security@${version}`,
    );
  },
);

test("fails when the installed package differs from the requested release", async () => {
  const { consumer } = await installedFixture("99.1.2");
  await expect(
    verifyInstalledPackage(consumer, process.env, "99.1.3"),
  ).rejects.toThrow("99.1.3");
});

test("fails when the installed CLI reports a different package version", async () => {
  const { consumer } = await installedFixture("99.1.1");
  await expect(verifyInstalledPackage(consumer, process.env)).rejects.toThrow(
    "99.1.2",
  );
});

test("fails when the installed CLI cannot start", async () => {
  const { consumer, shim } = await installedFixture("99.1.2");
  await writeFile(
    shim,
    process.platform === "win32"
      ? "@echo off\r\necho synthetic CLI startup failure 1>&2\r\nexit /b 7\r\n"
      : "#!/bin/sh\nprintf '%s\\n' 'synthetic CLI startup failure' >&2\nexit 7\n",
  );
  await expect(verifyInstalledPackage(consumer, process.env)).rejects.toThrow(
    "synthetic CLI startup failure",
  );
});

test.each(["node", "./scripts/launch_codex_security_mcp"])(
  "initializes an installed plugin using %s",
  async (command) => {
    const pluginRoot = await directories.create("published plugin smoke ");
    await mkdir(join(pluginRoot, "mcp"));
    await mkdir(join(pluginRoot, "scripts"));
    await writeFile(
      join(pluginRoot, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          "codex-security": {
            command,
            args:
              command === "node"
                ? ["./mcp/server.mjs", "--stdio"]
                : ["--stdio"],
            cwd: ".",
          },
        },
      }),
    );
    await writeFile(
      join(pluginRoot, "mcp", "server.mjs"),
      `import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
assert.equal(process.argv[2], "--stdio");
assert.equal(realpathSync(process.cwd()), realpathSync(process.env.SMOKE_PLUGIN_ROOT));
const request = JSON.parse(readFileSync(0, "utf8"));
assert.equal(request.method, "initialize");
console.log(JSON.stringify({ id: request.id, result: { serverInfo: { name: "codex-security" } } }));
`,
    );
    const launcher = join(pluginRoot, "scripts", "launch_codex_security_mcp");
    await writeFile(
      launcher,
      '#!/bin/sh\nexec "$CODEX_MCP_NODE_PATH" ./mcp/server.mjs "$@"\n',
    );
    await chmod(launcher, 0o755);
    await writeFile(
      `${launcher}.cmd`,
      '@echo off\r\n"%CODEX_MCP_NODE_PATH%" .\\mcp\\server.mjs %*\r\n',
    );
    await verifyInstalledPlugin(pluginRoot, {
      ...process.env,
      CODEX_MCP_NODE_PATH: process.execPath,
      SMOKE_PLUGIN_ROOT: pluginRoot,
    });
  },
);
