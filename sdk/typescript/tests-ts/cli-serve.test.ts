import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { FindingsDocument } from "../src/models.js";
import {
  EMBEDDING_DIMENSIONS,
  EMBEDDING_MODEL,
} from "../src/server/embeddings.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";

const packageRoot = join(import.meta.dir, "..");
const cli = join(packageRoot, "src", "cli.ts");

for (const [name, args, port, customEmbeddings] of [
  ["CLI", [cli, "serve"], "0"],
  ["CLI --port overrides PORT", [cli, "serve", "--port", "0"], "invalid"],
  ["CLI --port=0 overrides PORT", [cli, "serve", "--port=0"], "invalid"],
  ["CLI with custom embeddings URL", [cli, "serve"], "0", true],
  [
    "standalone entrypoint",
    [join(packageRoot, "src", "server", "index.ts")],
    "0",
  ],
  [
    "standalone entrypoint with custom embeddings URL",
    [join(packageRoot, "src", "server", "index.ts")],
    "0",
    true,
  ],
] as const) {
  test(`${name} serves findings with isolated state and shuts down`, async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-serve-"));
    const state = join(root, "state with spaces");
    const requests: {
      url: string | undefined;
      authorization: string | undefined;
    }[] = [];
    const provider = customEmbeddings
      ? createServer((request, response) => {
          requests.push({
            url: request.url,
            authorization: request.headers.authorization,
          });
          request.resume();
          response.setHeader("Content-Type", "application/json");
          response.end(
            JSON.stringify({
              model: EMBEDDING_MODEL,
              data: [
                {
                  index: 0,
                  embedding: Array.from(
                    { length: EMBEDDING_DIMENSIONS },
                    (_, index) => (index === 0 ? 1 : 0),
                  ),
                },
              ],
            }),
          );
        })
      : undefined;
    let embeddingsUrl = "";
    if (provider) {
      provider.listen(0, "127.0.0.1");
      await once(provider, "listening");
      const address = provider.address();
      if (!address || typeof address === "string")
        throw new Error("No provider port");
      embeddingsUrl = `http://127.0.0.1:${address.port}/custom/embeddings?api-version=test`;
    }
    const child = spawn(process.execPath, [...args], {
      env: {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: state,
        HOST: "127.0.0.1",
        PORT: port,
        OPENAI_API_KEY: customEmbeddings ? "synthetic-key" : "",
        CODEX_API_KEY: "",
        CODEX_SECURITY_EMBEDDINGS_URL: embeddingsUrl,
      },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 20_000,
    });
    const exited = once(child, "exit");
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    try {
      let base: string | undefined;
      for await (const line of createInterface({ input: child.stdout })) {
        const match = /^Findings service listening on (127\.0\.0\.1:\d+)$/.exec(
          line,
        );
        if (match) {
          base = `http://${match[1]}`;
          break;
        }
      }
      expect(base, stderr).toBeDefined();
      const response = await fetch(`${base}/v1/findings`);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ findings: [], total: 0 });
      if (customEmbeddings) {
        const document = JSON.parse(
          await readFile(
            join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
            "utf8",
          ),
        ) as FindingsDocument;
        const imported = await fetch(`${base}/v1/bulk/findings`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repositoryId: "synthetic-repository",
            findings: [document.findings[0]],
          }),
        });
        expect(imported.status, await imported.text()).toBe(201);
        expect(requests).toEqual([
          {
            url: "/custom/embeddings?api-version=test",
            authorization: "Bearer synthetic-key",
          },
        ]);
      }
      expect((await stat(join(state, "workbench.sqlite3"))).isFile()).toBe(
        true,
      );
      child.kill("SIGTERM");
      const [code] = await exited;
      // Windows terminates child processes instead of delivering SIGTERM.
      if (process.platform !== "win32") expect(code).toBe(0);
      expect(stderr).toBe("");
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
      await exited;
      if (provider)
        await new Promise<void>((resolve, reject) =>
          provider.close((error) => (error ? reject(error) : resolve())),
        );
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
}

test("serve reports startup failures with a nonzero exit", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-security-serve-failure-"));
  try {
    const state = join(root, "not-a-directory");
    await writeFile(state, "synthetic file");
    const { status, stdout, stderr } = await runCommand(
      process.execPath,
      [cli, "serve"],
      {
        env: { ...process.env, CODEX_SECURITY_STATE_DIR: state },
        timeout: 20_000,
      },
    );
    expect(status, stderr).toBe(1);
    expect(stdout).toBe("");
    expect(stderr).toContain("Could not access the findings database");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("serve exposes help and schema without starting the service", async () => {
  for (const args of [
    ["--help"],
    ["serve", "--help"],
    ["serve", "--schema", "--json"],
  ]) {
    const stdout = capture();
    const stderr = capture();
    expect(await main(args, stdout.stream, stderr.stream, dependencies())).toBe(
      0,
    );
    if (args.includes("--schema")) {
      expect(JSON.parse(stdout.text())).toMatchObject({
        options: {
          properties: {
            port: { type: "integer", minimum: 0, maximum: 65535 },
          },
        },
      });
    } else {
      expect(stdout.text()).toContain("serve");
    }
    expect(stderr.text()).toBe("");
  }
});

test("serve rejects positional arguments and JSON output", async () => {
  for (const args of [
    ["serve", "repository"],
    ["serve", "--json"],
  ]) {
    const stdout = capture();
    const stderr = capture();
    expect(await main(args, stdout.stream, stderr.stream, dependencies())).toBe(
      2,
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("serve");
  }
});

test("serve rejects missing or invalid ports", async () => {
  for (const value of [undefined, "invalid", "-1", "65536", "1.5"]) {
    const stdout = capture();
    const stderr = capture();
    const args = ["serve", "--port", ...(value === undefined ? [] : [value])];
    expect(await main(args, stdout.stream, stderr.stream, dependencies())).toBe(
      2,
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("port");
  }
});
