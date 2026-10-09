import {
  copyFile,
  mkdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join } from "node:path";
import { describe, expect, mock, spyOn, test } from "bun:test";
import { main } from "../src/cli.js";
import { CodexSecurity } from "../src/api.js";
import {
  environmentWithGit,
  resolvePluginPython,
  runWorkbench,
} from "../src/runtime.js";
import { inspectTrustedExecutable } from "../src/trusted-executable.js";
import { PLUGIN_ROOT, copyCompletedScan } from "./plugin-root.js";
import {
  codexFactory,
  completedEvents,
  preparedRuntime,
} from "./support/api-events.js";
import { dependencies, fakeResult } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { TestClient } from "./support/api-client.js";
import { createCliTest } from "./support/cli-run.js";
import { throwing } from "./support/errors.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { execNodePython } from "./support/python-probe.js";

describe("CLI scan validation preflight", () => {
  test.each([
    ["other head", false],
    ["local changes", false],
    ["other head", true],
    ["local changes", true],
  ] as const)(
    "rejects committed diffs with %s before scanning (workflow: %p)",
    async (checkout, workflow) => {
      const root = await temporaryDirectory("scan-validation-preflight-");
      try {
        const repository = join(root, "repository");
        await mkdir(repository);
        git(repository, "init", "-q", "-b", "main");
        const source = join(repository, "source.ts");
        await writeFile(source, "export const value = 'base';\n");
        git(repository, "add", ".");
        git(repository, "commit", "-qm", "base");
        const base = git(repository, "rev-parse", "HEAD");
        await writeFile(source, "export const value = 'head';\n");
        git(repository, "commit", "-qam", "head");
        const head = git(repository, "rev-parse", "HEAD");
        if (checkout === "other head") {
          git(repository, "checkout", "-q", "--detach", base);
        } else {
          await writeFile(source, "export const value = 'local';\n");
        }
        const prepareRuntime = mock(throwing("Unexpected runtime setup"));
        const createCodex = mock(throwing("Unexpected model invocation"));
        const { stdout, stderr, runCli } = createCliTest(main);
        expect(
          await runCli(
            [
              "scan",
              repository,
              "--diff",
              base,
              "--head",
              head,
              "--validate",
              ...(workflow ? ["--workflow-id", "diff-validation"] : []),
              "--json",
            ],
            {
              ...dependencies({ currentDirectory: root }),
              createSecurity: (config) =>
                new TestClient(config, { prepareRuntime, createCodex }),
            },
          ),
        ).toBe(2);
        expect(JSON.parse(stdout.text())).toMatchObject({ status: "failed" });
        expect(stderr.text()).toContain(
          checkout === "other head"
            ? "checkout to match the requested head revision"
            : "clean repository checkout",
        );
        expect(prepareRuntime).not.toHaveBeenCalled();
        expect(createCodex).not.toHaveBeenCalled();
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});

for (const changed of ["unchanged", "content", "head"] as const)
  test(`cached empty scan validation checks current target: ${changed}`, async () => {
    const root = await temporaryDirectory("empty-cached-scan-", true);
    const repository = join(root, "repository"),
      scanDir = join(root, "scan"),
      home = join(root, "codex");
    await mkdir(repository);
    await mkdir(home);
    await mkdir(scanDir, { mode: 0o700 });
    git(repository, "init", "-q", "-b", "main");
    await writeFile(join(repository, "source.ts"), "export const value = 1;\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "initial");
    const environment = {
      ...process.env,
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-cached-scan-key",
    };
    const python = await resolvePluginPython({
      environment,
      protectedRoot: repository,
    });
    let scanId = "",
      modelCalls = 0;
    let registration:
      | {
          contract: { target: { allowedKinds: string[] } };
          targetId: string;
          targetRevision?: string;
        }
      | undefined;
    let selectedWorkbench: Parameters<typeof runWorkbench>[0] | undefined;
    const workbench = async (
      options: Parameters<typeof runWorkbench>[0],
      args: readonly string[],
      input?: string,
    ) => {
      const answer = await runWorkbench(
        {
          ...options,
          python,
          environment: { ...options.environment, ...environment },
        },
        args,
        input,
      );
      if (args[0] === "register-cli-scan") {
        scanId = String(answer["scanId"]);
        registration = answer as unknown as NonNullable<typeof registration>;
        selectedWorkbench = {
          ...options,
          python,
          environment: { ...options.environment, ...environment },
        };
      }
      return answer;
    };
    const createSecurity = (
      config: ConstructorParameters<typeof TestClient>[0],
    ) =>
      new TestClient(
        { ...config, pythonPath: python, pluginPath: PLUGIN_ROOT },
        {
          environment,
          prepareRuntime: async () => {
            const r = preparedRuntime(home);
            r.environment = environment;
            r.plugin.version = JSON.parse(
              await readFile(
                join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
                "utf8",
              ),
            ).version;
            return r;
          },
          prepareOutputDir: async () => scanDir,
          resolvePluginPython: async () => python,
          runWorkbench: workbench,
          createCodex: codexFactory(async () => {
            modelCalls++;
            await copyCompletedScan(root);
            const manifest = JSON.parse(
              await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
            );
            manifest.scan.id = scanId;
            manifest.scan.target.kind =
              registration!.contract.target.allowedKinds[0];
            manifest.scan.target.targetId = registration!.targetId;
            manifest.scan.target.revision = registration!.targetRevision;
            manifest.scan.target.displayName = "repository";
            delete manifest.scan.target.snapshotDigest;
            delete manifest.scan.sealedAt;
            delete manifest.scan.artifacts;
            await writeFile(
              join(scanDir, "scan-manifest.json"),
              JSON.stringify(manifest),
            );
            const findings = JSON.parse(
              await readFile(join(scanDir, "findings.json"), "utf8"),
            );
            findings.scanId = scanId;
            findings.findings = [];
            await writeFile(
              join(scanDir, "findings.json"),
              JSON.stringify(findings),
            );
            const coverage = JSON.parse(
              await readFile(join(scanDir, "coverage.json"), "utf8"),
            );
            coverage.scanId = scanId;
            coverage.surfaces = [];
            await writeFile(
              join(scanDir, "coverage.json"),
              JSON.stringify(coverage),
            );
            return { events: completedEvents() };
          }, "empty-cached-conversation"),
        },
      );
    const cliDependencies = {
      ...dependencies({ currentDirectory: root, environment }),
      createSecurity,
      runWorkbench: async (
        args: readonly string[],
        input?: string,
        signal?: AbortSignal,
        configuredPython?: string,
        protectedRoot?: string,
      ) => {
        expect(configuredPython).toBe(python);
        expect(protectedRoot).toBe(repository);
        expect(selectedWorkbench).toBeDefined();
        return runWorkbench({ ...selectedWorkbench!, signal }, args, input);
      },
    };
    try {
      const first = createCliTest(main);
      const args = [
        "scan",
        repository,
        "--python",
        python,
        "--plugin-path",
        PLUGIN_ROOT,
        "--workflow-id",
        "empty-cached-workflow",
        "--json",
      ];
      const initial = await first.runCli(args, cliDependencies);
      expect(initial, first.stderr.text()).toBe(0);
      expect(JSON.parse(first.stdout.text()).findings.findings).toEqual([]);
      expect(modelCalls).toBe(1);
      if (changed !== "unchanged")
        await writeFile(
          join(repository, "source.ts"),
          "export const value = 2;\n",
        );
      if (changed === "head") git(repository, "commit", "-qam", "changed");
      const recorded = await runWorkbench(selectedWorkbench!, [
        "get-scan",
        "--scan-id",
        scanId,
        "--check-target",
      ]).then(
        () => "unchanged",
        (e) => (e as Error).message,
      );
      expect(recorded === "unchanged").toBe(changed === "unchanged");
      const second = createCliTest(main);
      const result = await second.runCli(
        [...args, "--validate"],
        cliDependencies,
      );

      expect(modelCalls).toBe(1);
      expect(result, second.stderr.text()).toBe(
        changed === "unchanged" ? 0 : 2,
      );
      const reused = JSON.parse(second.stdout.text());
      expect(reused.manifest.scan.id).toBe(scanId);
      if (changed === "unchanged")
        expect(reused.validation).toEqual({ status: "complete", findings: 0 });
      else
        expect(reused.validation).toMatchObject({
          status: "failed",
          findings: 0,
          message: expect.stringContaining("changed"),
        });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

test("empty scan validation preserves configured Python and Git ignore rules", async () => {
  if (
    runTestInSubprocess(
      import.meta.path,
      "empty scan validation preserves configured Python and Git ignore rules",
    )
  )
    return;
  const root = await temporaryDirectory("empty-scan-git-config-");
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const globalConfig = join(root, "gitconfig");
  const ignoreFile = join(root, "ignore");
  const overrides = {
    GIT_CONFIG_GLOBAL: globalConfig,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    PATH: process.env["PATH"] ?? "",
  };
  const previous = Object.fromEntries(
    Object.keys(overrides).map((name) => [name, process.env[name]]),
  );
  Object.assign(process.env, overrides);
  try {
    await mkdir(repository);
    await mkdir(scanDir, { mode: 0o700 });
    await writeFile(ignoreFile, "ignored.txt\n");
    git(repository, "init", "-q", "-b", "main");
    git(
      repository,
      "config",
      "--file",
      globalConfig,
      "core.excludesFile",
      ignoreFile,
    );
    const source = join(repository, "source.ts");
    await writeFile(source, "export const value = 1;\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "initial");
    await writeFile(
      join(repository, "ignored.txt"),
      "Synthetic ignored content.\n",
    );
    const python = await resolvePluginPython({
      environment: process.env,
      protectedRoot: repository,
    });
    const pythonHome = join(root, "python-runtime");
    execNodePython(
      python,
      ["-m", "venv", "--without-pip", "--system-site-packages", pythonHome],
      process.env,
    );
    const hostBin = join(
      pythonHome,
      process.platform === "win32" ? "Scripts" : "bin",
    );
    const suffix = process.platform === "win32" ? ".exe" : "";
    const barePython = "selected-python";
    await copyFile(
      join(hostBin, `python${suffix}`),
      join(hostBin, `${barePython}${suffix}`),
    );
    const repositoryGit = join(repository, `git${suffix}`);
    await writeFile(repositoryGit, "Synthetic repository-controlled Git.", {
      mode: 0o700,
    });
    await symlink(repositoryGit, join(hostBin, `git${suffix}`), "file");
    const registered = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment: process.env },
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          repository,
          mode: "standard",
          target: { kind: "repository", paths: [] },
          config: {},
        }),
      ],
    );
    const result = fakeResult();
    result.manifest.scan.id = String(registered["scanId"]);
    const scan = spyOn(CodexSecurity.prototype, "run").mockResolvedValue(
      result,
    );
    try {
      process.env["PATH"] = [hostBin, overrides.PATH].join(delimiter);
      for (const selectedPython of [python, barePython]) {
        await writeFile(source, "export const value = 1;\n");
        const outcomes = [];
        for (const changed of [false, true]) {
          if (changed) await writeFile(source, "export const value = 2;\n");
          const cli = createCliTest(main);
          const exitCode = await cli.runCli(
            [
              "scan",
              repository,
              "--python",
              selectedPython,
              "--validate",
              "--json",
            ],
            undefined,
          );
          outcomes.push({
            exitCode,
            stderr: cli.stderr.text(),
            validation: JSON.parse(cli.stdout.text()).validation,
          });
        }
        expect(
          outcomes.map(({ exitCode }) => exitCode),
          JSON.stringify({ selectedPython, outcomes }),
        ).toEqual([0, 2]);
        expect(outcomes[0]!.validation).toEqual({
          status: "complete",
          findings: 0,
        });
        expect(outcomes[1]!.validation).toMatchObject({
          status: "failed",
          message: expect.stringContaining("Scan target contents changed"),
        });
      }
    } finally {
      scan.mockRestore();
    }
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("empty scan validation preserves knowledge-base Git exclusions", async () => {
  if (
    runTestInSubprocess(
      import.meta.path,
      "empty scan validation preserves knowledge-base Git exclusions",
    )
  )
    return;
  const root = await temporaryDirectory("empty-scan-knowledge-git-");
  const repository = join(root, "repository");
  const knowledge = join(root, "knowledge");
  const python = await resolvePluginPython();
  const hostGit = await realpath(Bun.which("git")!);
  const previous = {
    PATH: process.env["PATH"],
    CODEX_SECURITY_STATE_DIR: process.env["CODEX_SECURITY_STATE_DIR"],
  };
  await mkdir(repository);
  await mkdir(knowledge);
  git(repository, "init", "-q", "-b", "main");
  await writeFile(join(repository, "source.ts"), "export const value = 1;\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "initial");
  const revision = git(repository, "rev-parse", "HEAD");
  await writeFile(join(knowledge, "policy.md"), "Synthetic project policy.\n");
  const pythonHome = join(knowledge, "python-runtime");
  execNodePython(
    python,
    ["-m", "venv", "--without-pip", "--system-site-packages", pythonHome],
    process.env,
  );
  const tools = join(
    pythonHome,
    process.platform === "win32" ? "Scripts" : "bin",
  );
  const suffix = process.platform === "win32" ? ".exe" : "";
  const selectedPython = join(tools, `selected-python${suffix}`);
  await copyFile(join(tools, `python${suffix}`), selectedPython);
  await symlink(hostGit, join(tools, `git${suffix}`), "file");
  process.env["CODEX_SECURITY_STATE_DIR"] = join(root, "state");
  try {
    for (const trustedFallback of [false, true]) {
      process.env["PATH"] = [
        tools,
        ...(trustedFallback ? [previous.PATH ?? ""] : []),
      ].join(delimiter);
      const scanDir = join(root, `scan-${trustedFallback}`);
      await mkdir(scanDir, { mode: 0o700 });
      const scan = spyOn(CodexSecurity.prototype, "run").mockImplementation(
        async (_repository, options = {}) => {
          expect(options.knowledgeBaseSnapshot?.protectedRoots).toEqual([
            await realpath(knowledge),
          ]);
          const selectedGit = await inspectTrustedExecutable(
            "git",
            process.env,
            [repository, ...options.knowledgeBaseSnapshot!.protectedRoots!],
          );
          const workbenchOptions = {
            python: selectedPython,
            pluginRoot: PLUGIN_ROOT,
            environment: environmentWithGit(
              selectedGit.environment,
              selectedGit,
            ),
          };
          const registered = await runWorkbench(workbenchOptions, [
            "register-cli-scan",
            "--repository",
            repository,
            "--scan-dir",
            scanDir,
            "--recipe-json",
            JSON.stringify({
              repository,
              mode: "standard",
              target: { kind: "repository", paths: [] },
              config: {},
            }),
          ]);
          expect(registered["targetRevision"]).toBe(
            trustedFallback ? revision : "unversioned",
          );
          const result = fakeResult();
          result.manifest.scan.id = String(registered["scanId"]);
          await runWorkbench(workbenchOptions, [
            "get-scan",
            "--scan-id",
            result.manifest.scan.id,
            "--check-target",
          ]);
          return result;
        },
      );
      try {
        const cli = createCliTest(main);
        const exitCode = await cli.runCli(
          [
            "scan",
            repository,
            "--python",
            selectedPython,
            "--knowledge-base",
            knowledge,
            "--validate",
            "--json",
          ],
          undefined,
        );
        expect(exitCode, cli.stderr.text()).toBe(0);
        expect(JSON.parse(cli.stdout.text()).validation).toEqual({
          status: "complete",
          findings: 0,
        });
        expect(scan).toHaveBeenCalledTimes(1);
      } finally {
        scan.mockRestore();
      }
    }
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});
