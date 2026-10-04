import {
  chmod,
  mkdir,
  open,
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { ScanInterruptedError } from "../src/errors.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();
afterEach(cleanup);

describe("completed scan follow-up instructions", () => {
  test("follow-up completes when saving its session fails", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    await mkdir(repository);
    await mkdir(codexHome);
    const scanDir = await copyCompletedScan(root);
    const warnings: string[] = [];
    let started = 0;
    let followUpCompleted = false;
    const client = new TestClient(
      {},
      {
        prepareRuntime: async () => preparedRuntime(codexHome),
        resolvePluginPython: async () => Bun.which("python3")!,
        repositoryRevision: async () => "deadbeef",
        prepareOutputDir: async () => scanDir,
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "set-scan-thread" && args.includes("follow-up")) {
            throw new Error("Synthetic history write failure");
          }
          return mockWorkbench(args, input);
        },
        createCodex: () => ({
          startThread() {
            const id = ++started === 1 ? "primary" : "follow-up";
            return {
              id,
              async runStreamed() {
                async function* events(): AsyncGenerator<ThreadEvent> {
                  for await (const event of completedEvents(id)) {
                    if (id === "follow-up" && event.type === "turn.completed") {
                      followUpCompleted = true;
                    }
                    yield event;
                  }
                }
                return { events: events() };
              },
            };
          },
        }),
      },
    );
    try {
      const result = await client.run(repository, {
        postScanPrompt: "Prepare follow-up notes.",
        onWarning: (message) => warnings.push(message),
      });
      expect(result.scanDir).toBe(scanDir);
      expect(followUpCompleted).toBe(true);
      expect(
        warnings.some((message) =>
          message.includes("Synthetic history write failure"),
        ),
      ).toBe(true);
    } finally {
      await client.close();
    }
  });

  test("failed follow-up writes fresh output without changing sealed evidence", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    let turns = 0;
    let original = Buffer.alloc(0);
    const receipt = "artifacts/follow-up/evidence.json";
    const evidence = '{"synthetic":"sealed receipt"}\n';
    let followUpDirectory = "";
    const warnings: string[] = [];
    const client = new TestClient(
      {},
      {
        prepareRuntime: async () => preparedRuntime(codexHome),
        resolvePluginPython: async () => Bun.which("python3")!,
        repositoryRevision: async () => "deadbeef",
        prepareOutputDir: async () => scanDir,
        createCodex: (options) => ({
          startThread: (threadOptions) => ({
            id: "thread-1",
            async runStreamed() {
              turns++;
              if (turns === 1) {
                await copyCompletedScan(root);
                await mkdir(dirname(join(scanDir, receipt)), {
                  recursive: true,
                });
                await writeFile(join(scanDir, receipt), evidence);
                const coveragePath = join(scanDir, "coverage.json");
                const coverage = JSON.parse(
                  await readFile(coveragePath, "utf8"),
                );
                coverage.surfaces[0].receiptRefs = [receipt];
                const coverageBytes = JSON.stringify(coverage);
                await writeFile(coveragePath, coverageBytes);
                const manifestPath = join(scanDir, "scan-manifest.json");
                const manifest = JSON.parse(
                  await readFile(manifestPath, "utf8"),
                );
                manifest.scan.artifacts.find(
                  (artifact: { path: string }) =>
                    artifact.path === "coverage.json",
                ).sha256 = createHash("sha256")
                  .update(coverageBytes)
                  .digest("hex");
                manifest.scan.artifacts.push({
                  path: receipt,
                  sha256: createHash("sha256").update(evidence).digest("hex"),
                  mediaType: "application/json",
                });
                await writeFile(manifestPath, JSON.stringify(manifest));
                await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
                original = await readFile(join(scanDir, "report.md"));
                return { events: completedEvents() };
              }
              followUpDirectory = threadOptions!.workingDirectory!;
              expect(options.config).toMatchObject({
                permissions: {
                  codex_security_scan: {
                    filesystem: {
                      [scanDir]: { ".": "read" },
                      [followUpDirectory]: { ".": "write" },
                    },
                  },
                },
              });
              await mkdir(followUpDirectory, { recursive: true });
              await writeFile(
                join(followUpDirectory, "evidence.json"),
                "follow-up output",
              );
              async function* failed(): AsyncGenerator<ThreadEvent> {
                yield {
                  type: "turn.failed",
                  error: { message: "Synthetic follow-up failure" },
                };
              }
              return { events: failed() };
            },
          }),
        }),
      },
    );
    try {
      const result = await client.run(repository, {
        postScanPrompt: "Prepare follow-up notes.",
        onWarning: (message) => warnings.push(message),
      });
      expect(result.scanDir).toBe(scanDir);
      expect(turns).toBe(2);
      expect(await readFile(result.reportPath)).toEqual(original);
      expect(await readFile(join(scanDir, receipt), "utf8")).toBe(evidence);
      expect(dirname(followUpDirectory)).toBe(
        join(scanDir, "artifacts/follow-up"),
      );
      await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
      expect(
        warnings.some((message) =>
          message.includes("Synthetic follow-up failure"),
        ),
      ).toBe(true);
    } finally {
      await client.close();
    }
  });

  test("cancellation settles a stalled follow-up history write", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await Promise.all(
      [repository, codexHome, scanDir].map((path) =>
        mkdir(path, { mode: 0o700 }),
      ),
    );
    const controller = new AbortController();
    let turns = 0;
    let historyAborted = false;
    const commands: string[] = [];
    const client = new TestClient(
      {},
      {
        prepareRuntime: async () => preparedRuntime(codexHome),
        resolvePluginPython: async () => "/managed/python",
        repositoryRevision: async () => "deadbeef",
        prepareOutputDir: async () => scanDir,
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              if (++turns === 1) await copyCompletedScan(root);
              return {
                events: completedEvents(turns === 1 ? "main" : "followup"),
              };
            },
          }),
        }),
        runWorkbench: async (options, args, input) => {
          commands.push(args[0]!);
          if (args[0] === "set-scan-thread" && args.at(-1) === "followup") {
            expect(options.signal).toBeDefined();
            return await new Promise((_resolve, reject) => {
              options.signal!.addEventListener(
                "abort",
                () => {
                  historyAborted = true;
                  reject(options.signal!.reason);
                },
                { once: true },
              );
              controller.abort(new Error("synthetic follow-up cancellation"));
            });
          }
          return mockWorkbench(args, input);
        },
      },
    );
    try {
      await expect(
        client.run(repository, {
          postScanPrompt: "Write notes.",
          signal: controller.signal,
        }),
      ).rejects.toBeInstanceOf(ScanInterruptedError);
      expect(historyAborted).toBe(true);
      expect(commands).toContain("complete-scan");
      expect(commands).not.toContain("cancel-scan");
      await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
    } finally {
      await client.close();
    }
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
