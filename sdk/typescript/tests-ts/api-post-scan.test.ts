import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import {
  prepareScanArtifactRestorer,
  type ScanArtifactRestorer,
} from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();

afterEach(cleanup);

interface FailedPostScanContext {
  artifactPath: string;
  outside: string;
  scanDir: string;
}

interface FailedPostScanScenario {
  artifact: string;
  initialContents?: string | Uint8Array;
  selectedPluginFinalizer?: string;
  mutate(context: FailedPostScanContext): Promise<void>;
  wrapRestorer?(
    restorer: ScanArtifactRestorer,
    context: FailedPostScanContext,
  ): ScanArtifactRestorer;
}

async function* failedEvents(): AsyncGenerator<ThreadEvent> {
  yield {
    type: "turn.failed",
    error: { message: "Could not draft fixes." },
  };
}

async function startFailedPostScan(scenario: FailedPostScanScenario) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  const outside = join(root, "outside");
  const artifactPath = join(scanDir, scenario.artifact);
  const context = { artifactPath, outside, scanDir };
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  const runtime = preparedRuntime(codexHome);
  if (scenario.selectedPluginFinalizer !== undefined) {
    const selectedPluginRoot = join(root, "selected-plugin");
    await cp(PLUGIN_ROOT, selectedPluginRoot, { recursive: true });
    await writeFile(
      join(selectedPluginRoot, "scripts", "finalize_scan_contract.py"),
      scenario.selectedPluginFinalizer,
    );
    runtime.plugin = {
      ...runtime.plugin,
      pluginRoot: selectedPluginRoot,
      installedRoot: selectedPluginRoot,
    };
  }
  let turns = 0;
  let original = Buffer.alloc(0);
  const client = new TestClient(
    {},
    {
      environment: {},
      prepareRuntime: async () => runtime,
      resolvePluginPython: async () => python!,
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      prepareScanArtifactRestorer: async (...args) => {
        const restorer = await prepareScanArtifactRestorer(...args);
        return scenario.wrapRestorer?.(restorer, context) ?? restorer;
      },
      createCodex: () => ({
        startThread: () => ({
          id: "thread-1",
          async runStreamed() {
            turns += 1;
            if (turns === 1) {
              await copyCompletedScan(root);
              if (scenario.initialContents !== undefined) {
                await mkdir(dirname(artifactPath), { recursive: true });
                await writeFile(artifactPath, scenario.initialContents);
                const manifestPath = join(scanDir, "scan-manifest.json");
                const manifest = JSON.parse(
                  await readFile(manifestPath, "utf8"),
                );
                manifest.scan.artifacts.push({
                  path: scenario.artifact,
                  sha256: createHash("sha256")
                    .update(await readFile(artifactPath))
                    .digest("hex"),
                  mediaType: scenario.artifact.endsWith(".bin")
                    ? "application/octet-stream"
                    : "application/json",
                });
                await writeFile(manifestPath, JSON.stringify(manifest));
              }
              original = await readFile(artifactPath);
              return { events: completedEvents() };
            }
            await scenario.mutate(context);
            return { events: failedEvents() };
          },
        }),
      }),
    },
  );
  const scan = client.run(repository, {
    postScanPrompt: "Draft confirmed fixes.",
  });
  return {
    client,
    scan,
    scanDir,
    artifactPath,
    outside,
    get turns() {
      return turns;
    },
    get original() {
      return original;
    },
  };
}

const ordinaryRestorationCases: ReadonlyArray<
  readonly [string, FailedPostScanScenario]
> = [
  [
    "missing report",
    { artifact: "report.md", mutate: ({ artifactPath }) => rm(artifactPath) },
  ],
  [
    "partial report",
    {
      artifact: "report.md",
      mutate: async ({ artifactPath }) => {
        await writeFile(artifactPath, "# Incomplete draft\n");
      },
    },
  ],
  [
    "replaced report",
    {
      artifact: "report.md",
      mutate: async ({ artifactPath }) => {
        await rm(artifactPath);
        await writeFile(artifactPath, "# Replacement\n");
      },
    },
  ],
  [
    "invalid findings",
    {
      artifact: "findings.json",
      mutate: async ({ artifactPath }) => {
        await writeFile(artifactPath, "{invalid");
      },
    },
  ],
  [
    "sealed nested artifact",
    {
      artifact: "artifacts/worker.json",
      initialContents: '{"complete":true}\n',
      mutate: async ({ artifactPath }) => {
        await writeFile(artifactPath, '{"partial":true}');
      },
    },
  ],
  [
    "binary artifact",
    {
      artifact: "artifacts/worker.bin",
      initialContents: Buffer.from([0, 255, 10, 1]),
      mutate: async ({ artifactPath }) => {
        await writeFile(artifactPath, Buffer.from([9, 0, 8]));
      },
    },
  ],
  [
    "selected custom plugin",
    {
      artifact: "report.md",
      selectedPluginFinalizer:
        "raise RuntimeError('selected plugin helper must not run')\n",
      mutate: ({ artifactPath }) =>
        writeFile(artifactPath, "# Incomplete draft\n"),
    },
  ],
  [
    "nested artifact with a missing parent",
    {
      artifact: "artifacts/worker.json",
      initialContents: '{"complete":true}\n',
      mutate: ({ artifactPath }) =>
        rm(dirname(artifactPath), { recursive: true }),
    },
  ],
];

describe("completed scan follow-up instructions", () => {
  test.each(ordinaryRestorationCases)(
    "restores completed scan artifacts after failed post-scan instructions: %s",
    async (_name, scenario) => {
      const fixture = await startFailedPostScan(scenario);
      expect(await fixture.scan).toMatchObject({ scanDir: fixture.scanDir });
      expect(fixture.turns).toBe(2);
      expect(await readFile(fixture.artifactPath)).toEqual(fixture.original);
      await fixture.client.close();
    },
  );

  test("does not rewrite artifacts unchanged by a failed follow-up", async () => {
    let before: { dev: number; ino: number; mtimeMs: number } | null = null;
    const fixture = await startFailedPostScan({
      artifact: "report.md",
      mutate: async ({ artifactPath }) => {
        const metadata = await stat(artifactPath);
        before = {
          dev: Number(metadata.dev),
          ino: Number(metadata.ino),
          mtimeMs: Number(metadata.mtimeMs),
        };
      },
    });

    expect(await fixture.scan).toMatchObject({ scanDir: fixture.scanDir });
    const after = await stat(fixture.artifactPath);
    expect(before).not.toBeNull();
    expect(Number(after.dev)).toBe(before!.dev);
    expect(Number(after.ino)).toBe(before!.ino);
    expect(Number(after.mtimeMs)).toBe(before!.mtimeMs);
    await fixture.client.close();
  });

  test.skipIf(process.platform === "win32")(
    "ordinary identical writes retain private replacement semantics",
    async () => {
      const root = await temporaryDirectory();
      const scanDir = join(root, "scan");
      const artifactPath = join(scanDir, "artifact.bin");
      const payload = Buffer.from("unchanged\n");
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      await mkdir(scanDir, { mode: 0o700 });
      await writeFile(artifactPath, payload);
      await chmod(artifactPath, 0o644);
      const before = await stat(artifactPath);
      const script = [
        "from pathlib import Path",
        "from runpy import run_path",
        "import sys",
        "module = run_path(sys.argv[1])",
        "scan_dir = Path(sys.argv[2])",
        "module['write_scan_local_bytes'](scan_dir, 'artifact.bin', b'unchanged\\n')",
      ].join("\n");
      const execution = Bun.spawnSync([
        python!,
        "-I",
        "-B",
        "-c",
        script,
        join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
        scanDir,
      ]);

      expect(
        execution.exitCode,
        new TextDecoder().decode(execution.stderr),
      ).toBe(0);
      const after = await stat(artifactPath);
      expect(after.mode & 0o777).toBe(0o600);
      expect(after.ino).not.toBe(before.ino);
      expect(await readFile(artifactPath)).toEqual(payload);
    },
  );

  test.skipIf(process.platform !== "linux")(
    "replaces a large sparse artifact within bounded comparison memory",
    async () => {
      const root = await temporaryDirectory();
      const scanDir = join(root, "scan");
      const artifactPath = join(scanDir, "artifact.bin");
      const artifactSize = 32 * 1024 * 1024;
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      await mkdir(scanDir, { mode: 0o700 });
      const script = [
        "from pathlib import Path",
        "from runpy import run_path",
        "import os",
        "import resource",
        "import sys",
        "module = run_path(sys.argv[1])",
        "scan_dir = Path(sys.argv[2])",
        "artifact = scan_dir / 'artifact.bin'",
        "size = 32 * 1024 * 1024",
        "payload = b'x' * size",
        "with artifact.open('wb') as stream:",
        "    stream.truncate(size)",
        "canonical, identity = module['scan_root_identity'](scan_dir)",
        "pages = int(Path('/proc/self/statm').read_text().split()[0])",
        "current_vms = pages * os.sysconf('SC_PAGE_SIZE')",
        "_, hard_limit = resource.getrlimit(resource.RLIMIT_AS)",
        "resource.setrlimit(resource.RLIMIT_AS, (current_vms + 8 * 1024 * 1024, hard_limit))",
        "module['write_scan_local_bytes'](canonical, 'artifact.bin', payload, expected_root_identity=identity)",
      ].join("\n");
      const execution = Bun.spawnSync([
        python!,
        "-I",
        "-B",
        "-c",
        script,
        join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
        scanDir,
      ]);

      expect(
        execution.exitCode,
        new TextDecoder().decode(execution.stderr),
      ).toBe(0);
      expect((await stat(artifactPath)).size).toBe(artifactSize);
      const artifact = await open(artifactPath, "r");
      try {
        const first = Buffer.alloc(1);
        const last = Buffer.alloc(1);
        await artifact.read(first, 0, 1, 0);
        await artifact.read(last, 0, 1, artifactSize - 1);
        expect(first).toEqual(Buffer.from("x"));
        expect(last).toEqual(Buffer.from("x"));
      } finally {
        await artifact.close();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "restores a changed artifact that cannot be read for comparison",
    async () => {
      const fixture = await startFailedPostScan({
        artifact: "report.md",
        mutate: async ({ artifactPath }) => {
          await writeFile(artifactPath, "# Incomplete draft\n");
          await chmod(artifactPath, 0);
        },
      });

      expect(await fixture.scan).toMatchObject({ scanDir: fixture.scanDir });
      expect(await readFile(fixture.artifactPath)).toEqual(fixture.original);
      await fixture.client.close();
    },
  );

  test("rejects a replaced artifact parent without writing through it", async () => {
    const fixture = await startFailedPostScan({
      artifact: "artifacts/worker.json",
      initialContents: '{"complete":true}\n',
      mutate: async ({ artifactPath, outside }) => {
        await mkdir(outside);
        await writeFile(join(outside, "worker.json"), "untouched\n");
        await rm(dirname(artifactPath), { recursive: true });
        await symlink(
          outside,
          dirname(artifactPath),
          process.platform === "win32" ? "junction" : "dir",
        );
      },
    });

    await expect(fixture.scan).rejects.toThrow("scan directory");
    expect(await readFile(join(fixture.outside, "worker.json"), "utf8")).toBe(
      "untouched\n",
    );
    await fixture.client.close();
  });

  test("rejects an artifact parent swapped immediately before the bound write", async () => {
    let swapped = false;
    const artifact = "artifacts/worker.json";
    const fixture = await startFailedPostScan({
      artifact,
      initialContents: '{"complete":true}\n',
      mutate: async ({ artifactPath, outside }) => {
        await mkdir(outside);
        await writeFile(join(outside, "worker.json"), "untouched\n");
        await writeFile(artifactPath, '{"partial":true}');
      },
      wrapRestorer: (restorer, { outside, scanDir }) => ({
        ...restorer,
        async restore(relativePath, contents) {
          if (!swapped && relativePath === artifact) {
            const parent = dirname(join(scanDir, relativePath));
            await rename(parent, `${parent}.original`);
            await symlink(
              outside,
              parent,
              process.platform === "win32" ? "junction" : "dir",
            );
            swapped = true;
          }
          await restorer.restore(relativePath, contents);
        },
      }),
    });

    await expect(fixture.scan).rejects.toThrow("scan directory");
    expect(await readFile(join(fixture.outside, "worker.json"), "utf8")).toBe(
      "untouched\n",
    );
    await fixture.client.close();
  });

  test("rejects a scan root replaced after restoration setup", async () => {
    const fixture = await startFailedPostScan({
      artifact: "report.md",
      mutate: async ({ scanDir }) => {
        await rename(scanDir, `${scanDir}.original`);
        await mkdir(scanDir, { mode: 0o700 });
        await writeFile(join(scanDir, "scan-manifest.json"), "untouched\n");
      },
    });

    await expect(fixture.scan).rejects.toThrow("scan directory");
    expect(
      await readFile(join(fixture.scanDir, "scan-manifest.json"), "utf8"),
    ).toBe("untouched\n");
    await fixture.client.close();
  });

  test.skipIf(process.platform === "win32")(
    "keeps the final rename bound to the validated parent when its path is replaced",
    async () => {
      const root = await temporaryDirectory();
      const scanDir = join(root, "scan");
      const parent = join(scanDir, "artifacts");
      const movedParent = join(root, "moved-artifacts");
      const outside = join(root, "outside");
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      await mkdir(scanDir, { mode: 0o700 });
      await mkdir(parent);
      await mkdir(outside);
      await writeFile(join(parent, "worker.bin"), Buffer.from([1]));
      await writeFile(join(outside, "worker.bin"), "untouched\n");
      const script = [
        "from pathlib import Path",
        "from runpy import run_path",
        "import sys",
        "module = run_path(sys.argv[1])",
        "scan_dir = Path(sys.argv[2])",
        "parent = scan_dir / 'artifacts'",
        "moved_parent = Path(sys.argv[4])",
        "outside = Path(sys.argv[3])",
        "canonical, identity = module['scan_root_identity'](scan_dir)",
        "original_replace = module['os'].replace",
        "swapped = False",
        "def replace(source, destination, *, src_dir_fd=None, dst_dir_fd=None):",
        "    global swapped",
        "    if not swapped:",
        "        parent.rename(moved_parent)",
        "        parent.symlink_to(outside, target_is_directory=True)",
        "        swapped = True",
        "    return original_replace(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)",
        "module['os'].replace = replace",
        "module['write_scan_local_bytes'](canonical, 'artifacts/worker.bin', bytes([0, 255, 10, 1]), expected_root_identity=identity)",
      ].join("\n");
      const execution = Bun.spawnSync([
        python!,
        "-I",
        "-B",
        "-c",
        script,
        join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
        scanDir,
        outside,
        movedParent,
      ]);

      expect(
        execution.exitCode,
        new TextDecoder().decode(execution.stderr),
      ).toBe(0);
      expect(await readFile(join(outside, "worker.bin"), "utf8")).toBe(
        "untouched\n",
      );
      expect(await readFile(join(movedParent, "worker.bin"))).toEqual(
        Buffer.from([0, 255, 10, 1]),
      );
    },
  );
});
