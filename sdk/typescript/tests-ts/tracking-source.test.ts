import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  appendFile,
  chmod,
  copyFile,
  cp,
  mkdir,
  readFile,
  rename,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { createRequire } from "node:module";
import {
  widePath,
  windowsFileSystem,
} from "../../../plugins/codex-security/native/windows-files.mjs";
import type { WindowsBinding } from "../../../plugins/codex-security/native/windows-binding.mjs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { setFindingIdentity, sha256 } from "./support/finding-identity.js";
import { readJson, writeJson } from "./support/json.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const { validateTrackingSource } = (await import(pathToFileURL(helper).href))
  .default as {
  validateTrackingSource(
    scanDir: string,
    options?: {
      findingId?: string;
      fingerprint?: string;
      pluginRoot?: string;
      signal?: AbortSignal;
    },
  ): Promise<Finding[]>;
};
const { temporaryDirectory, cleanup } =
  createApiTestFixtures("tracking-source-");
afterEach(cleanup);

async function fixture(count = 1) {
  const root = await temporaryDirectory();
  const scanDir = join(root, "sealed scan");
  await copyCompletedScanFixture(scanDir);
  if (process.platform !== "win32") await chmod(scanDir, 0o700);
  const manifest = await readJson<ScanManifest>(
    join(scanDir, "scan-manifest.json"),
  );
  const findings = await readJson<FindingsDocument>(
    join(scanDir, "findings.json"),
  );
  const value = { root, scanDir, manifest, findings };
  if (count !== 1) {
    const template = findings.findings[0]!;
    findings.findings = Array.from({ length: count }, (_, index) => {
      const finding = structuredClone(template);
      finding.identity.instance = `synthetic-${count - index}`;
      setFindingIdentity(manifest.scan, finding);
      return finding;
    });
    await rewriteArtifact(value, "findings.json", findings);
  }
  return value;
}

type Fixture = Awaited<ReturnType<typeof fixture>>;

async function rewriteArtifact(
  f: Fixture,
  name: string,
  document: unknown,
): Promise<void> {
  await writeJson(join(f.scanDir, name), document);
  await reseal(f, name);
}

async function reseal(f: Fixture, name: string): Promise<void> {
  f.manifest.scan.artifacts!.find(
    (artifact) => artifact.path === name,
  )!.sha256 = sha256(await readFile(join(f.scanDir, name)));
  await writeJson(join(f.scanDir, "scan-manifest.json"), f.manifest);
}

function run(
  f: Pick<Fixture, "scanDir" | "root">,
  args: string[] = [],
  pluginRoot = PLUGIN_ROOT,
  env: NodeJS.ProcessEnv = {
    ...process.env,
    PATH: "",
    PYTHON: join(f.root, "unavailable-python"),
  },
) {
  return spawnSync(
    node,
    [
      join(pluginRoot, "mcp", "helpers.mjs"),
      "validate-tracking-source",
      f.scanDir,
      ...args,
    ],
    { cwd: f.root, env, encoding: "utf8" },
  );
}

describe("native tracking source validation", () => {
  test("escapes filesystem controls in a missing scan path", async () => {
    const f = await fixture();
    const result = run({
      ...f,
      scanDir: join(f.root, "missing-\u001b[2J"),
    });

    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toStartWith("tracking source preflight failed:");
    expect(result.stderr).toContain("missing-\\u001b[2J");
    expect(result.stderr).not.toContain("\u001b");
  });

  test.each(["artifact", "schema"])(
    "escapes controls in malformed %s JSON diagnostics while preserving credential-shaped text",
    async (source) => {
      const f = await fixture();
      const pathSuffix = process.platform === "win32" ? "" : "\u001b[2J";
      if (pathSuffix) {
        const scanDir = f.scanDir + pathSuffix;
        await rename(f.scanDir, scanDir);
        f.scanDir = scanDir;
      }
      let pluginRoot = PLUGIN_ROOT;
      if (source === "schema") {
        pluginRoot = join(f.root, "copied plugin" + pathSuffix);
        for (const directory of ["mcp", "schemas"])
          await cp(join(PLUGIN_ROOT, directory), join(pluginRoot, directory), {
            recursive: true,
          });
        await writeFile(
          join(pluginRoot, "schemas", "findings.schema.json"),
          "sk-test-1234\u001b[2J",
        );
      } else {
        await writeFile(
          join(f.scanDir, "findings.json"),
          "sk-test-1234\u001b[2J",
        );
        await reseal(f, "findings.json");
      }

      const result = run(f, [], pluginRoot);
      expect(result.status).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).toStartWith("tracking source preflight failed:");
      expect(result.stderr).toContain("invalid JSON");
      expect(result.stderr).toContain("sk-test-1234");
      expect(result.stderr).toContain("\\u001b[2J");
      if (source === "schema" && pathSuffix) {
        expect(result.stderr).toContain("copied plugin\\u001b[2J");
      } else if (source === "artifact") {
        expect(result.stderr).toStartWith(
          "tracking source preflight failed: findings.json:",
        );
      }
      expect(result.stderr).not.toContain("\u001b");
    },
  );

  test.each([
    [
      "invalid UTF-8",
      Buffer.from([0xff]),
      "findings.json: unreadable JSON document.",
    ],
    ["a top-level array", "[]", "findings.json: expected a JSON object."],
    [
      "a non-finite number",
      '{"extension":1e400}',
      'findings.json["extension"]: non-finite JSON numbers are not supported.',
    ],
  ] as const)(
    "uses relative scan document context for %s",
    async (_case, contents, detail) => {
      const f = await fixture();
      const pathSuffix = process.platform === "win32" ? "" : "\u001b[2J";
      if (pathSuffix) {
        const scanDir = f.scanDir + pathSuffix;
        await rename(f.scanDir, scanDir);
        f.scanDir = scanDir;
      }
      await writeFile(join(f.scanDir, "findings.json"), contents);
      await reseal(f, "findings.json");

      const sdkLoad = loadContract(f.scanDir, { pluginRoot: PLUGIN_ROOT });
      await expect(sdkLoad).rejects.toThrow(f.scanDir);
      await expect(sdkLoad).rejects.toThrow(detail);

      const result = run(f);
      expect(result.status).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).toStartWith("tracking source preflight failed:");
      expect(result.stderr).toContain(detail);
      expect(result.stderr).not.toContain("\u001b");
      expect(result.stderr).toStartWith(
        "tracking source preflight failed: findings.json",
      );
    },
  );

  test("escapes schema I/O context while preserving SDK diagnostics and causes", async () => {
    const f = await fixture();
    const pathSuffix = process.platform === "win32" ? "" : "\u001b[2J";
    const pluginRoot = join(f.root, "copied plugin-sk-test-1234" + pathSuffix);
    for (const directory of ["mcp", "schemas"])
      await cp(join(PLUGIN_ROOT, directory), join(pluginRoot, directory), {
        recursive: true,
      });
    const schemaPath = join(pluginRoot, "schemas", "findings.schema.json");
    await unlink(schemaPath);
    await mkdir(schemaPath);

    const underlyingError = {
      message: `${schemaPath}: unreadable JSON document.`,
      cause: { code: "EISDIR", errno: expect.any(Number) },
    };
    const sdkLoad = loadContract(f.scanDir, { pluginRoot });
    await expect(sdkLoad).rejects.toThrow(schemaPath);
    await expect(sdkLoad).rejects.toMatchObject({ cause: underlyingError });
    const trackingLoad = validateTrackingSource(f.scanDir, { pluginRoot });
    await expect(trackingLoad).rejects.toMatchObject({
      cause: underlyingError,
    });

    const result = run(f, [], pluginRoot);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toStartWith("tracking source preflight failed:");
    expect(result.stderr).toContain(
      "findings.schema.json: unreadable JSON document.",
    );
    expect(result.stderr).toContain("sk-test-1234");
    expect(result.stderr).not.toContain("\u001b");
    expect(result.stderr).toContain(schemaPath.replaceAll("\u001b", "\\u001b"));
  });

  test("requires the tracking report while the SDK accepts canonical artifacts alone", async () => {
    const f = await fixture();
    await unlink(join(f.scanDir, "report.md"));

    await expect(validateTrackingSource(f.scanDir)).rejects.toThrow(
      "report.md",
    );
    const result = run(f);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("report.md");
    expect(
      (await loadContract(f.scanDir, { pluginRoot: PLUGIN_ROOT })).findings,
    ).toEqual(f.findings);
  });

  test.each(["writeup", "hardening"] as const)(
    "tracks sealed findings without an optional %s file required by the SDK",
    async (kind) => {
      const f = await fixture();
      if (kind === "writeup") {
        f.findings.findings[0]!.writeup = {
          reportPath: "findings/missing/missing.md",
        };
        await rewriteArtifact(f, "findings.json", f.findings);
      } else {
        f.manifest.scan.hardening = {
          portfolioPath: "hardening/hardening.md",
        };
        await writeJson(join(f.scanDir, "scan-manifest.json"), f.manifest);
      }

      expect(await validateTrackingSource(f.scanDir)).toEqual(
        f.findings.findings,
      );
      const result = run(f);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(`${f.findings.findings[0]!.findingId}\n`);
      expect(result.stderr).toBe("");
      await expect(
        loadContract(f.scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow(
        kind === "writeup" ? "writeup.reportPath" : "hardening.portfolioPath",
      );
    },
  );

  test.skipIf(process.platform === "win32").each([0o755, 0o775])(
    "both readers accept an owned scan directory with mode %o without changing its permissions",
    async (mode) => {
      const f = await fixture();
      await chmod(f.scanDir, mode);

      expect(await validateTrackingSource(f.scanDir)).toEqual(
        f.findings.findings,
      );
      expect((await stat(f.scanDir)).mode & 0o777).toBe(mode);
      const result = run(f);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(`${f.findings.findings[0]!.findingId}\n`);
      expect(result.stderr).toBe("");
      expect((await stat(f.scanDir)).mode & 0o777).toBe(mode);
      expect(
        (await loadContract(f.scanDir, { pluginRoot: PLUGIN_ROOT })).findings,
      ).toEqual(f.findings);
      expect((await stat(f.scanDir)).mode & 0o777).toBe(mode);
    },
  );

  test.each([0, 1, 25])(
    "lists %i findings in source order without changing scan artifacts",
    async (count) => {
      const f = await fixture(count);
      const paths = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ].map((path) => join(f.scanDir, path));
      const before = await Promise.all(paths.map((path) => readFile(path)));

      expect(await validateTrackingSource(f.scanDir)).toEqual(
        f.findings.findings,
      );
      const result = run(f);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe(
        f.findings.findings.map((finding) => `${finding.findingId}\n`).join(""),
      );
      expect(await Promise.all(paths.map((path) => readFile(path)))).toEqual(
        before,
      );
    },
  );

  test.each(["findingId", "fingerprint"] as const)(
    "selects exactly one finding by %s",
    async (selector) => {
      const f = await fixture(3);
      const selected = f.findings.findings[1]!;
      const value =
        selector === "findingId"
          ? selected.findingId
          : selected.fingerprints.primary;
      expect(
        await validateTrackingSource(f.scanDir, { [selector]: value }),
      ).toEqual([selected]);
      const result = run(f, [
        selector === "findingId" ? "--finding-id" : "--fingerprint",
        value,
      ]);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(`${selected.findingId}\n`);
      expect(result.stderr).toBe("");
    },
  );

  test.each(["findingId", "fingerprint"] as const)(
    "rejects a %s selector that matches no finding",
    async (selector) => {
      const f = await fixture();
      await expect(
        validateTrackingSource(f.scanDir, { [selector]: "missing" }),
      ).rejects.toThrow("the selector did not resolve exactly one finding");
      const result = run(f, [
        selector === "findingId" ? "--finding-id" : "--fingerprint",
        "missing",
      ]);
      expect(result.status).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).toStartWith("tracking source preflight failed:");
      expect(result.stderr).toContain(
        "the selector did not resolve exactly one finding",
      );
    },
  );

  test("prints command help successfully", async () => {
    const f = await fixture();
    const result = run(f, ["--help"]);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("validate-tracking-source");
    expect(result.stdout).toContain("--finding-id");
    expect(result.stdout).toContain("--fingerprint");
    expect(result.stdout).not.toContain(f.findings.findings[0]!.findingId);
  });

  test("expands a quoted home-relative scan directory", async () => {
    const f = await fixture();
    const result = run(
      { ...f, scanDir: join("~", basename(f.scanDir)) },
      [],
      PLUGIN_ROOT,
      {
        ...process.env,
        HOME: f.root,
        USERPROFILE: f.root,
        PATH: "",
        PYTHON: join(f.root, "unavailable-python"),
      },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(`${f.findings.findings[0]!.findingId}\n`);
    expect(result.stderr).toBe("");
  });

  test("canonicalizes a scan directory symlink before validation", async () => {
    const f = await fixture();
    const alias = join(f.root, "scan alias");
    await symlink(
      f.scanDir,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      loadContract(alias, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("non-symlink directory");
    expect(await validateTrackingSource(alias)).toEqual(f.findings.findings);
    const result = run({ ...f, scanDir: alias });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(`${f.findings.findings[0]!.findingId}\n`);
    expect(result.stderr).toBe("");
  });

  test("accepts a scan beneath an ancestor directory alias", async () => {
    const f = await fixture();
    const aliasRoot = await temporaryDirectory();
    const alias = join(aliasRoot, "parent alias");
    await symlink(
      f.root,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const scanDir = join(alias, basename(f.scanDir));

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();
    expect(await validateTrackingSource(scanDir)).toEqual(f.findings.findings);
    const result = run({ ...f, scanDir });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(`${f.findings.findings[0]!.findingId}\n`);
    expect(result.stderr).toBe("");
  });

  test.skipIf(process.platform !== "win32")(
    "preserves a Windows UTF-16 scan root beside its replacement-character sibling",
    async () => {
      const original = await fixture(1);
      const decoy = await fixture(2);
      // Bun's path helpers replace lone surrogates; exercise the Node reader.
      const rawPath = `${original.root}\\scan-\ud800`;
      const replacementPath = `${original.root}\\scan-\ufffd`;
      expect(rawPath).not.toBe(replacementPath);
      const source = new URL("../src/contract.ts", import.meta.url);
      const built = await Bun.build({
        entrypoints: [fileURLToPath(source)],
        target: "node",
        format: "esm",
        define: { "import.meta.url": JSON.stringify(source.href) },
      });
      expect(built.success).toBe(true);
      const module = join(original.root, "contract-reader.mjs");
      await writeFile(module, await built.outputs[0]!.text());
      const native = createRequire(import.meta.url)(
        join(
          PLUGIN_ROOT,
          "mcp",
          "native",
          `win32-${process.arch}`,
          "windows.node",
        ),
      ) as WindowsBinding;
      const files = windowsFileSystem(native);
      files.rename(widePath(original.scanDir), widePath(rawPath));
      try {
        files.rename(widePath(decoy.scanDir), widePath(replacementPath));
        try {
          const result = spawnSync(
            node,
            [
              "--input-type=module",
              "--eval",
              `
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const input = JSON.parse(readFileSync(0, "utf8"));
const { loadContract } = await import(input.module);
const { validateTrackingSource } = (await import(input.helper)).default;
const loaded = await loadContract(input.rawPath, { pluginRoot: input.pluginRoot });
assert.deepEqual(loaded.findings.findings, input.original);
assert.deepEqual(await validateTrackingSource(input.rawPath), input.original);
assert.deepEqual(await validateTrackingSource(input.replacementPath), input.decoy);
`,
            ],
            {
              input: JSON.stringify({
                module: pathToFileURL(module).href,
                helper: pathToFileURL(helper).href,
                rawPath,
                replacementPath,
                pluginRoot: PLUGIN_ROOT,
                original: original.findings.findings,
                decoy: decoy.findings.findings,
              }),
              encoding: "utf8",
              windowsHide: true,
            },
          );
          expect(result.status, result.stderr).toBe(0);
        } finally {
          files.rename(widePath(replacementPath), widePath(decoy.scanDir));
        }
      } finally {
        files.rename(widePath(rawPath), widePath(original.scanDir));
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "launcher preserves POSIX scan directory path bytes",
    async () => {
      const f = await fixture();
      // APFS requires UTF-8 names; Linux permits undecodable path bytes.
      const suffix =
        process.platform === "darwin" ? Buffer.from("é") : Buffer.from([0xff]);
      const destination = Buffer.concat([
        Buffer.from(f.root + "/scan-"),
        suffix,
      ]);
      await rename(f.scanDir, destination);
      const shellSuffix = Array.from(
        suffix,
        (byte) => `\\${byte.toString(8).padStart(3, "0")}`,
      ).join("");
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          `exec "$1" --helper validate-tracking-source "$2/scan-$(printf '${shellSuffix}')"`,
          "sh",
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          f.root,
        ],
        {
          cwd: f.root,
          env: { ...process.env, CODEX_MCP_NODE_PATH: node },
          encoding: "utf8",
        },
      );
      expect(result.status, result.stderr || result.error?.message).toBe(0);
      expect(result.stdout).toBe(`${f.findings.findings[0]!.findingId}\n`);
      expect(result.stderr).toBe("");
    },
  );

  test("rejects simultaneous selectors in the API and command", async () => {
    const f = await fixture();
    const finding = f.findings.findings[0]!;
    await expect(
      validateTrackingSource(f.scanDir, {
        findingId: finding.findingId,
        fingerprint: finding.fingerprints.primary,
      }),
    ).rejects.toThrow("use only one of --finding-id or --fingerprint");
    const result = run(f, [
      "--finding-id",
      finding.findingId,
      "--fingerprint",
      finding.fingerprints.primary,
    ]);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toStartWith("tracking source preflight failed:");
    expect(result.stderr).toContain(
      "use only one of --finding-id or --fingerprint",
    );
  });

  test("rejects duplicate findings before returning a selector match", async () => {
    const f = await fixture();
    f.findings.findings.push(structuredClone(f.findings.findings[0]!));
    await rewriteArtifact(f, "findings.json", f.findings);
    await expect(
      validateTrackingSource(f.scanDir, {
        findingId: f.findings.findings[0]!.findingId,
      }),
    ).rejects.toThrow(/duplicate|exactly one/iu);
  });

  test("validates an unselected finding against the schema", async () => {
    const f = await fixture(2);
    Object.assign(f.findings.findings[1]!.severity, { level: "unsupported" });
    await rewriteArtifact(f, "findings.json", f.findings);
    await expect(
      validateTrackingSource(f.scanDir, {
        findingId: f.findings.findings[0]!.findingId,
      }),
    ).rejects.toThrow(/severity|schema/iu);
  });

  test("validates an unselected finding's derived identity", async () => {
    const f = await fixture(2);
    f.findings.findings[1]!.findingId = `csf_${"0".repeat(24)}`;
    await rewriteArtifact(f, "findings.json", f.findings);
    await expect(
      validateTrackingSource(f.scanDir, {
        findingId: f.findings.findings[0]!.findingId,
      }),
    ).rejects.toThrow(/identity|fingerprint/iu);
  });

  test.each(["findings.json", "coverage.json"])(
    "rejects changed bytes in sealed %s",
    async (name) => {
      const f = await fixture();
      await appendFile(join(f.scanDir, name), "\n");
      const result = run(f);
      expect(result.status).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).toStartWith("tracking source preflight failed:");
      expect(result.stderr).toMatch(/sealed artifact changed|sha256|digest/iu);
      expect(result.stderr).not.toContain("Traceback");
    },
  );

  test("tracks a completed scan without coverage.json and validates the derived coverage", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
      recursive: true,
    });
    if (process.platform !== "win32") await chmod(scanDir, 0o700);
    const findings = await readJson<FindingsDocument>(
      join(scanDir, "findings.json"),
    );
    const result = run({ root, scanDir });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(
      findings.findings.map(({ findingId }) => findingId + "\n").join(""),
    );

    const pluginRoot = join(root, "selected plugin");
    await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
      recursive: true,
    });
    const schemaPath = join(pluginRoot, "schemas", "coverage.schema.json");
    const schema = await readJson<Record<string, unknown>>(schemaPath);
    schema["maxProperties"] = 0;
    await writeJson(schemaPath, schema);
    await expect(
      validateTrackingSource(scanDir, { pluginRoot }),
    ).rejects.toThrow(/coverage.json.*maxProperties/u);
    const contract = await loadContract(scanDir, { pluginRoot });
    expect(contract.findings).toEqual(findings);
    expect(contract.mode).toBe("repository");
    expect(contract.review).toEqual({ excludedPaths: [] });
  });

  test("runs a copied launcher with its own schemas and no Python or SDK source", async () => {
    const f = await fixture();
    const copiedPlugin = join(f.root, "copied plugin");
    for (const directory of ["mcp", "schemas"]) {
      await cp(join(PLUGIN_ROOT, directory), join(copiedPlugin, directory), {
        recursive: true,
      });
    }
    const scripts = join(copiedPlugin, "scripts");
    await mkdir(scripts);
    const launcherName =
      process.platform === "win32"
        ? "launch_codex_security_mcp.cmd"
        : "launch_codex_security_mcp";
    const launcher = join(scripts, launcherName);
    await copyFile(join(PLUGIN_ROOT, "scripts", launcherName), launcher);
    const bin = join(f.root, "bin");
    await mkdir(bin);
    const marker = join(f.root, "python-called");
    const suffix = process.platform === "win32" ? ".cmd" : "";
    for (const name of ["python", "python3"]) {
      const sentinel = join(bin, name + suffix);
      await writeFile(
        sentinel,
        process.platform === "win32"
          ? '@echo off\r\necho invoked>"%TRACKING_PYTHON_MARKER%"\r\nexit /b 97\r\n'
          : '#!/bin/sh\nprintf invoked > "$TRACKING_PYTHON_MARKER"\nexit 97\n',
      );
      await chmod(sentinel, 0o755);
    }
    const env = {
      ...process.env,
      PATH: bin,
      NODE_PATH: "",
      PYTHON: join(bin, "python" + suffix),
      CODEX_MCP_NODE_PATH: node,
      TRACKING_PYTHON_MARKER: marker,
    };
    let result;
    if (process.platform === "win32") {
      const caller = join(f.root, "caller.cmd");
      await writeFile(
        caller,
        `@echo off\r\ncall "${launcher}" --helper validate-tracking-source "${f.scanDir}"\r\nexit /b %errorlevel%\r\n`,
      );
      result = spawnSync(
        process.env["ComSpec"] ?? "cmd.exe",
        ["/d", "/s", "/c", `""${caller}""`],
        {
          cwd: f.root,
          env,
          encoding: "utf8",
          windowsVerbatimArguments: true,
        },
      );
    } else {
      result = spawnSync(
        "/bin/sh",
        [launcher, "--helper", "validate-tracking-source", f.scanDir],
        { cwd: f.root, env, encoding: "utf8" },
      );
    }
    expect(result.status, result.stderr || result.error?.message).toBe(0);
    expect(result.stdout).toBe(`${f.findings.findings[0]!.findingId}\n`);
    expect(result.stderr).toBe("");
    expect(existsSync(marker)).toBe(false);

    const schemaPath = join(copiedPlugin, "schemas", "findings.schema.json");
    const schema = await readJson<Record<string, unknown>>(schemaPath);
    schema["maxProperties"] = 0;
    await writeJson(schemaPath, schema);
    const rejected = run(f, [], copiedPlugin, env);
    expect(rejected.status).toBe(2);
    expect(rejected.stdout).toBe("");
    expect(rejected.stderr).toStartWith("tracking source preflight failed:");
    expect(rejected.stderr).toMatch(/schema|maxProperties/iu);
    expect(existsSync(marker)).toBe(false);
  });
});
