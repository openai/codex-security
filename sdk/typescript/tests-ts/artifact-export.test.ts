import * as childProcess from "node:child_process";
import * as filesystem from "node:fs/promises";
import { EventEmitter } from "node:events";
import {
  cp,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  stat,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { describe, expect, spyOn, test } from "bun:test";
import { exportArtifact } from "../src/index.js";
import {
  resolveArtifactExportOutput,
  readThreatModelPath,
  runArtifactExport,
  runArtifactHelper,
  writeThreatModel,
} from "../src/artifact-export.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { PYTHON } from "./support/security-policy.js";

const caseProbe = await mkdtemp(join(tmpdir(), "codex-security-case-probe-"));
await mkdir(join(caseProbe, "reports"));
const caseInsensitiveVolume = await stat(join(caseProbe, "REPORTS")).then(
  () => true,
  () => false,
);
await rm(caseProbe, { recursive: true, force: true });

describe("offline artifact export", () => {
  test.each([
    { warnings: undefined },
    { warnings: [] },
    { warnings: ["Synthetic run warning."] },
  ])(
    "exports persisted run warnings %j without changing sealed documents",
    async ({ warnings }) => {
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-sarif-warning-"),
      );
      const scanDir = join(root, "scan");
      const output = join(root, "results.sarif");
      try {
        await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
          recursive: true,
        });
        const manifestPath = join(scanDir, "scan-manifest.json");
        if (warnings !== undefined) {
          const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
          manifest.scan.warnings = warnings;
          await writeFile(manifestPath, JSON.stringify(manifest));
        }
        const canonicalPaths = [
          manifestPath,
          join(scanDir, "findings.json"),
          join(scanDir, "coverage.json"),
        ];
        const before = await Promise.all(
          canonicalPaths.map((path) => readFile(path)),
        );
        const result = await exportArtifact({
          source: { directory: scanDir },
          format: "sarif",
          output,
          pythonPath: PYTHON,
        });
        expect(result.path).toBe(output);
        const run = JSON.parse(await readFile(output, "utf8")).runs[0];
        if (warnings?.length) {
          expect(run.invocations).toEqual([
            {
              executionSuccessful: true,
              toolExecutionNotifications: warnings.map((text) => ({
                level: "warning",
                message: { text },
              })),
            },
          ]);
        } else {
          expect(run.invocations).toBeUndefined();
        }
        expect(
          await Promise.all(canonicalPaths.map((path) => readFile(path))),
        ).toEqual(before);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.skipIf(process.platform === "win32").each([
    ["artifact helper", "PATH"],
    ["artifact helper", "PYTHON"],
    ["artifact helper", "configured"],
    ["SDK scan ID", "PYTHON"],
    ["SDK scan ID", "configured"],
    ["CLI scan ID", "PYTHON"],
    ["CLI scan ID", "configured"],
    ["CLI latest", "PYTHON"],
    ["CLI latest", "configured"],
  ] as const)(
    "%s does not execute Python in input directories when selected via %s",
    async (entrypoint, selection) => {
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-export-python-"),
      );
      const caller = join(root, "caller");
      const protectCaller =
        entrypoint === "artifact helper" && selection !== "PATH";
      const repository = protectCaller
        ? join(caller, "src")
        : join(root, "repository");
      const scanDir = join(root, "scan");
      const executable = join(
        protectCaller ? join(caller, "tools") : repository,
        "python3",
      );
      try {
        await mkdir(caller);
        await mkdir(repository);
        await mkdir(dirname(executable), { recursive: true });
        await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
          recursive: true,
        });
        await writeFile(
          executable,
          '#!/bin/sh\nprintf probed > "$0.probed"\nprintf "codex-security-python-ok\\n"\n',
          { mode: 0o700 },
        );
        const child = childProcess.spawnSync(
          process.execPath,
          [
            "-e",
            `
              const { exportArtifact, runArtifactExport } = await import(process.argv[1]);
              const options = {
                scanDir: process.argv[2],
                sourceRoot: process.argv[3],
                pythonPath: process.argv[4] || undefined,
                format: "sarif",
                output: "-",
              };
              const entrypoint = process.argv[5];
              if (entrypoint === "artifact helper") {
                process.stdout.write(await runArtifactExport(options));
              } else if (entrypoint === "SDK scan ID") {
                await exportArtifact({ ...options, source: { scanId: "synthetic-scan" } });
              } else {
                const { main } = await import(process.argv[6]);
                process.exitCode = await main([
                  "export",
                  ...(entrypoint === "CLI scan ID" ? ["--scan", "synthetic-scan"] : []),
                  "--source-root", options.sourceRoot,
                  "--output", "-",
                  ...(options.pythonPath ? ["--python", options.pythonPath] : []),
                ]);
              }
            `,
            fileURLToPath(
              new URL("../src/artifact-export.ts", import.meta.url),
            ),
            scanDir,
            repository,
            selection === "configured" ? executable : "",
            entrypoint,
            fileURLToPath(new URL("../src/cli.ts", import.meta.url)),
          ],
          {
            cwd: caller,
            encoding: "utf8",
            env: {
              ...process.env,
              PATH: [
                dirname(executable),
                dirname(PYTHON),
                process.env["PATH"],
              ].join(delimiter),
              PYTHON: selection === "PYTHON" ? executable : "",
              CODEX_SECURITY_STATE_DIR: join(root, "state"),
              XDG_CACHE_HOME: join(root, "cache"),
            },
          },
        );
        expect(await stat(`${executable}.probed`).catch(() => null)).toBeNull();
        if (selection === "PATH") {
          expect(child.status, child.stderr).toBe(0);
          expect(JSON.parse(child.stdout).version).toBe("2.1.0");
        } else {
          expect(child.status).not.toBe(0);
          expect(child.stderr).toContain(
            "interpreter is unavailable or unusable",
          );
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("exports with Python from the selected managed-runtime cache", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-export-cache-"));
    const environment = {
      XDG_CACHE_HOME: join(root, "cache"),
      HOME: root,
      USERPROFILE: root,
      PATH: "",
      PYTHON: undefined,
    };
    const previous = Object.keys(environment).map(
      (key) => [key, process.env[key]] as const,
    );
    try {
      const dependencies = join(
        environment.XDG_CACHE_HOME,
        "codex-runtimes",
        "codex-primary-runtime",
        "dependencies",
      );
      await mkdir(dependencies, { recursive: true });
      await symlink(
        process.platform === "win32"
          ? dirname(PYTHON)
          : dirname(dirname(PYTHON)),
        join(dependencies, "python"),
        "junction",
      );
      await writeFile(
        join(root, "THREAT_MODEL.md"),
        "# Synthetic saved model\n",
      );
      Object.assign(process.env, environment);
      delete process.env["PYTHON"];
      const result = await runArtifactHelper(
        [
          "--scan-dir",
          root,
          "--export-artifact",
          "threat-model",
          "--export-format",
          "md",
        ],
        { pluginRoot: PLUGIN_ROOT },
      );
      expect(result.stdout).toBe("# Synthetic saved model\n");
    } finally {
      for (const [key, value] of previous) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      await rm(root, { recursive: true, force: true });
    }
  });

  test.each([0, 1])(
    "preserves split UTF-8 diagnostics at exit %i",
    async (exitCode) => {
      const diagnostic = "synthetic diagnostic café 東 😀 retained\n";
      const child = Object.assign(new EventEmitter(), {
        stdout: new PassThrough(),
        stderr: new PassThrough(),
        kill: () => true,
      });
      const originalSpawn = childProcess.spawn;
      const script = join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py");
      const spawn = spyOn(childProcess, "spawn").mockImplementation(((
        ...args: Parameters<typeof originalSpawn>
      ) => {
        if (!Array.isArray(args[1]) || !args[1].includes(script)) {
          return originalSpawn(...args);
        }
        queueMicrotask(() => {
          child.stdout.end("synthetic stdout\n");
          for (const byte of Buffer.from(diagnostic)) {
            child.stderr.write(Buffer.from([byte]));
          }
          child.stderr.end();
          child.emit("close", exitCode, null);
        });
        return child;
      }) as typeof originalSpawn);
      try {
        const operation = runArtifactHelper([], {
          pluginRoot: PLUGIN_ROOT,
          pythonPath: PYTHON,
        });
        if (exitCode === 0) {
          expect(await operation).toEqual({
            stdout: "synthetic stdout\n",
            stderr: diagnostic,
          });
        } else {
          await expect(operation).rejects.toThrow(diagnostic.trim());
        }
      } finally {
        spawn.mockRestore();
        child.stdout.destroy();
        child.stderr.destroy();
      }
    },
  );

  test("resolves the current directory without traversing outside it", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cwd-output-"));
    try {
      const currentDirectory = join(root, "repository");
      const scanDir = join(root, "scan");
      await mkdir(currentDirectory);
      await mkdir(scanDir);
      const result = await resolveArtifactExportOutput(
        { scanDir, output: currentDirectory, format: "json" },
        currentDirectory,
      );
      expect(result.output).toBe(await realpath(currentDirectory));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("resolves a scan-local export before its exports directory exists", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-new-export-"));
    try {
      const scanDir = join(root, "scan");
      await mkdir(scanDir);
      const output = join(scanDir, "exports", "findings.json");
      expect(
        (
          await resolveArtifactExportOutput(
            { scanDir, output, format: "json" },
            root,
          )
        ).output,
      ).toBe(join(await realpath(scanDir), "exports", "findings.json"));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test.each(["external", "scan-local"])(
    "resolves %s exports outside the current directory",
    async (destination) => {
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-external-output-"),
      );
      const scanDir = join(root, "scan");
      try {
        await mkdir(scanDir);
        const output =
          destination === "scan-local"
            ? join(scanDir, "exports", "findings.json")
            : join(root, "findings.json");
        expect(
          (
            await resolveArtifactExportOutput(
              { scanDir, output, format: "json" },
              process.cwd(),
            )
          ).output,
        ).toBe(
          destination === "scan-local"
            ? join(await realpath(scanDir), "exports", "findings.json")
            : join(await realpath(root), "findings.json"),
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.skipIf(!caseInsensitiveVolume)(
    "accepts an export parent accessed through a case alias",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-case-output-"));
      await mkdir(join(root, "reports"));
      try {
        const result = await resolveArtifactExportOutput(
          {
            scanDir: join(root, "scan"),
            format: "json",
            output: join(root, "REPORTS", "result.json"),
          },
          root,
        );
        await writeFile(result.output, "synthetic export");
        expect(
          await readFile(join(root, "reports", "result.json"), "utf8"),
        ).toBe("synthetic export");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("resolves real export directories while refusing linked repository parents", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-output-path-"));
    const reports = join(root, "reports");
    await mkdir(reports);
    const link = join(root, "linked");
    await symlink(reports, link, "junction");
    try {
      const options = {
        scanDir: join(root, "scan"),
        format: "json" as const,
        output: join(reports, "result.json"),
      };
      expect((await resolveArtifactExportOutput(options, root)).output).toBe(
        join(await realpath(reports), "result.json"),
      );
      await expect(
        resolveArtifactExportOutput(
          { ...options, output: join(link, "result.json") },
          root,
        ),
      ).rejects.toThrow("cannot traverse a repository symlink");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a repository output ancestor replaced after resolution", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-export-binding-"),
    );
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    const outside = join(root, "outside");
    const parent = join(repository, "reports");
    const outsideOutput = join(outside, "result.md");
    await mkdir(repository);
    await mkdir(scanDir);
    await mkdir(outside);
    await writeFile(join(scanDir, "THREAT_MODEL.md"), "# Synthetic model\n");
    await writeFile(outsideOutput, "Unrelated file\n");
    await symlink(outside, parent, "junction");
    let replaced = false;
    const originalRealpath = filesystem.realpath;
    const resolving = spyOn(filesystem, "realpath").mockImplementation((async (
      ...args: Parameters<typeof originalRealpath>
    ) => {
      const canonical = await originalRealpath(...args);
      if (args[0] === parent && !replaced) {
        replaced = true;
        await rm(parent, { recursive: true, force: true });
        await mkdir(parent);
      }
      return canonical;
    }) as typeof originalRealpath);
    try {
      const exporting = async () => {
        const prepared = await resolveArtifactExportOutput(
          {
            scanDir,
            output: join(parent, "result.md"),
            artifact: "threat-model",
            format: "md",
          },
          repository,
        );
        await runArtifactExport(prepared);
      };
      await expect(exporting()).rejects.toThrow(
        "cannot traverse a repository symlink",
      );
      expect(replaced).toBe(true);
      expect(await readFile(outsideOutput, "utf8")).toBe("Unrelated file\n");
    } finally {
      resolving.mockRestore();
      await rm(root, { recursive: true, force: true });
    }
  });

  test.each(["repository", "descendant"])(
    "checks repository-owned symlinks below an external alias into a %s",
    async (destination) => {
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-output-alias-"),
      );
      const repository = join(root, "repository");
      const source =
        destination === "repository" ? repository : join(repository, "src");
      const alias = join(root, "alias");
      const outside = join(root, "outside");
      try {
        await mkdir(source, { recursive: true });
        await mkdir(outside);
        await symlink(source, alias, "junction");
        const options = {
          scanDir: join(root, "scan"),
          format: "sarif" as const,
          output: join(alias, "results.sarif"),
        };
        expect(
          (await resolveArtifactExportOutput(options, repository)).output,
        ).toBe(join(await realpath(source), "results.sarif"));
        for (const linkTarget of [outside, source]) {
          const reports = join(source, "reports");
          await symlink(linkTarget, reports, "junction");
          await expect(
            resolveArtifactExportOutput(
              { ...options, output: join(alias, "reports", "results.sarif") },
              repository,
            ),
          ).rejects.toThrow("cannot traverse a repository symlink");
          await rm(reports, { recursive: true, force: true });
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("preserves trusted output aliases outside the repository", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-trusted-output-"),
    );
    const repository = join(root, "repository");
    const reports = join(root, "reports");
    const alias = join(root, "alias");
    try {
      await mkdir(repository);
      await mkdir(reports);
      await symlink(reports, alias, "junction");
      expect(
        (
          await resolveArtifactExportOutput(
            {
              scanDir: join(root, "scan"),
              format: "sarif",
              output: join(alias, "results.sarif"),
            },
            repository,
          )
        ).output,
      ).toBe(join(await realpath(reports), "results.sarif"));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("only exposes a document matching the current canonical model", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-current-model-"));
    const modelPath = join(root, "threatmodel.md");
    const options = { pythonPath: PYTHON, pluginRoot: join(root, "plugin") };
    const scripts = join(options.pluginRoot, "scripts");
    const manifest = {
      documentType: "codex-security.policy-draft",
      status: "completed",
      threatModel: { format: "markdown", content: "# Original model\n" },
    };
    try {
      await cp(join(PLUGIN_ROOT, "scripts"), scripts, {
        recursive: true,
        filter: (path) => basename(path) !== "__pycache__",
      });
      await writeFile(
        join(root, "policy-draft.json"),
        JSON.stringify(manifest),
      );
      await writeThreatModel(root, options);
      expect(await readdir(scripts)).not.toContain("__pycache__");
      expect(await readThreatModelPath(root, options)).toBe(modelPath);
      manifest.threatModel.content = "# Updated model\n";
      await writeFile(
        join(root, "policy-draft.json"),
        JSON.stringify(manifest),
      );
      expect(await readThreatModelPath(root, options)).toBeNull();
      expect(await readFile(modelPath, "utf8")).toContain("Original model");
      await writeThreatModel(root, options);
      expect(await readThreatModelPath(root, options)).toBe(modelPath);
      expect(
        await readThreatModelPath(root, {
          ...options,
          pythonPath: join(root, "missing-python"),
        }),
      ).toBeNull();
      const controller = new AbortController();
      controller.abort(new Error("Synthetic path lookup cancellation"));
      await expect(
        readThreatModelPath(root, {
          ...options,
          signal: controller.signal,
        }),
      ).rejects.toThrow("Synthetic path lookup cancellation");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("exports canonical policy Markdown before completion without its convenience file", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-offline-model-"));
    const source = join(root, "policy");
    const output = join(root, "threatmodel.md");
    const content =
      "# Component model\n\n| Asset | Boundary |\n| --- | --- |\n| Café | Caller → service |\n\n```text\nline one\n  line two\n```\n";
    const manifest = {
      documentType: "codex-security.policy-draft",
      schemaVersion: "1.0",
      repository: "/synthetic/repository",
      scope: "services/api",
      revision: "synthetic-revision",
      status: "threat_model_ready",
      threatModel: {
        format: "markdown",
        content,
        scope: { includePaths: ["services/api"], excludePaths: [] },
        origin: "generated",
      },
    };
    await mkdir(source);
    const original = JSON.stringify(manifest);
    await writeFile(join(source, "policy-draft.json"), original);
    try {
      const result = await exportArtifact({
        source: { directory: source },
        artifact: "threat-model",
        output,
      });
      expect(result.path).toBe(output);
      expect(result.provenance).toMatchObject({
        status: "threat_model_ready",
        provisional: true,
      });
      const exported = await readFile(output, "utf8");
      expect(exported).toStartWith(content);
      expect(exported).toContain("services/api");
      expect(await readFile(join(source, "policy-draft.json"), "utf8")).toBe(
        original,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("exports historical Markdown and rejects missing models or overwriting source artifacts", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-legacy-model-"));
    const source = join(root, "policy");
    await mkdir(source);
    try {
      await expect(
        exportArtifact({
          source: { directory: source },
          artifact: "threat-model",
          output: join(root, "missing.md"),
        }),
      ).rejects.toThrow("No saved threat model");
      const original = "# Historical model\n\nSource-backed details.\n";
      await writeFile(join(source, "THREAT_MODEL.md"), original);
      expect(await readThreatModelPath(source)).toBe(
        join(source, "THREAT_MODEL.md"),
      );
      await exportArtifact({
        source: { directory: source },
        artifact: "threat-model",
        output: join(root, "threatmodel.md"),
      });
      expect(await readFile(join(root, "threatmodel.md"), "utf8")).toBe(
        original,
      );
      await expect(
        exportArtifact({
          source: { directory: source },
          artifact: "threat-model",
          output: join(source, "THREAT_MODEL.md"),
        }),
      ).rejects.toThrow("cannot overwrite a scan artifact");
      expect(await readFile(join(source, "THREAT_MODEL.md"), "utf8")).toBe(
        original,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("does not expose a historical model through a linked parent directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-linked-model-"));
    const source = join(root, "scan");
    const outside = join(root, "outside");
    await mkdir(source);
    await mkdir(join(outside, "01_context"), { recursive: true });
    await writeFile(
      join(outside, "01_context", "threat_model.md"),
      "# Unrelated model\n",
    );
    try {
      await symlink(
        outside,
        join(source, "artifacts"),
        process.platform === "win32" ? "junction" : "dir",
      );
      expect(await readThreatModelPath(source)).toBeNull();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
