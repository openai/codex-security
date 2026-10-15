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
import { basename, dirname, join } from "node:path";
import { PassThrough } from "node:stream";
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
